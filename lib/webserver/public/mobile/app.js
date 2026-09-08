'use strict';
/* app.js — the mobile client. It pairs with the desktop (a one-time code, usually carried in the URL after
 * a QR scan), pulls the vault's CIPHERTEXT, and decrypts everything HERE on the phone with the portable
 * reader. Plaintext lives only in memory and in transient blob URLs that are revoked as soon as a view
 * closes; it is never written to storage. The decryption key (the read capability) and the access bearer
 * ALSO live only in memory: they are never written to disk, so a lost or stolen phone yields no key at
 * rest, and reconnecting means pairing again (scan the QR / enter the code) rather than silently reopening.
 * Only CIPHERTEXT is ever cached (for offline use) — it is useless without the in-memory key. */
(function () {
	var R = window.RcloneReader;
	var el = function (id) { return document.getElementById(id); };
	var session = null;   // { base, list, bearer, name, dn }
	var keys = null;      // { dataKey, nameKey, nameTweak }
	var allFiles = [];    // [{ enc, path (decrypted), size }]
	var cwd = [];         // current directory as decrypted path segments
	var liveUrls = [];    // blob URLs to revoke on view close

	// ---- tiny IndexedDB (session metadata + optional ciphertext cache) ----
	function idb() {
		return new Promise(function (res, rej) {
			var r = indexedDB.open('vault-mobile', 1);
			r.onupgradeneeded = function () { var d = r.result; if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta'); if (!d.objectStoreNames.contains('cipher')) d.createObjectStore('cipher'); };
			r.onsuccess = function () { res(r.result); }; r.onerror = function () { rej(r.error); };
		});
	}
	function idbGet(store, key) { return idb().then(function (d) { return new Promise(function (res) { var t = d.transaction(store).objectStore(store).get(key); t.onsuccess = function () { res(t.result); }; t.onerror = function () { res(undefined); }; }); }).catch(function () { return undefined; }); }
	function idbPut(store, key, val) { return idb().then(function (d) { return new Promise(function (res) { var t = d.transaction(store, 'readwrite'); t.objectStore(store).put(val, key); t.oncomplete = function () { res(true); }; t.onerror = function () { res(false); }; }); }).catch(function () { return false; }); }
	function idbClear() { return idb().then(function (d) { return new Promise(function (res) { var t = d.transaction(['meta', 'cipher'], 'readwrite'); t.objectStore('meta').clear(); t.objectStore('cipher').clear(); t.oncomplete = function () { res(true); }; t.onerror = function () { res(false); }; }); }).catch(function () { return false; }); }
		function idbDel(store, key) { return idb().then(function (d) { return new Promise(function (res) { var t = d.transaction(store, 'readwrite'); t.objectStore(store).delete(key); t.oncomplete = function () { res(true); }; t.onerror = function () { res(false); }; }); }).catch(function () { return false; }); }

	function toast(msg, ms) { var t = el('toast'); t.setAttribute('aria-live', 'polite'); t.hidden = false; t.textContent = msg; clearTimeout(toast._t); toast._t = setTimeout(function () { t.hidden = true; }, ms || 2600); } // unhide before writing so the live region announces the message
	function setStatus(text, kind) { var s = el('status'); if (!text) { s.hidden = true; return; } s.hidden = false; s.textContent = text; s.className = 'status' + (kind ? ' ' + kind : ''); }

	// ---- fetch helpers (always carry the bearer) ----
	// A 401 means the paired session expired or was revoked. Handle it in ONE place so EVERY request — listing,
	// opening a file, saving offline — recovers the same way (clear the dead session, return to the connect
	// screen, and say so) instead of only the listing doing it while a file open showed a confusing generic
	// error. The thrown error carries `expired` so callers skip their own message; sessionExpired is idempotent
	// so a burst of 401s reconnects and toasts once.
	function sessionExpired() { if (sessionExpired._fired) return; sessionExpired._fired = true; try { forget(true); } catch (e) {} toast('The session expired — reconnect from the desktop.'); }
	function authFetch(url, opts) {
		opts = opts || {}; opts.headers = Object.assign({}, opts.headers, { Authorization: 'Bearer ' + session.bearer });
		return fetch(url, opts).then(function (r) { if (r.status === 401) { sessionExpired(); var e = new Error('expired'); e.expired = true; throw e; } return r; });
	}

	// ---- pairing ----
	function deriveFromCap(capToken) {
		var cap = JSON.parse(atob(capToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
		if (cap.exp && Date.now() > cap.exp) throw new Error('This access has expired. Reconnect from the desktop.'); keys = R.deriveKeys(cap.key, cap.salt);
		session.dn = cap.dn;
		session.name = session.name || cap.name;
	}
	function pair(code) {
		el('pairBtn').disabled = true; el('pairError').hidden = true;
		return fetch('pair', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code }) })
			.then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
			.then(function (res) {
				if (!res.ok || !res.j.ok) throw new Error(res.j.error || 'Could not connect.');
				session = { base: res.j.base, list: res.j.list, bearer: res.j.token, name: res.j.name, id: res.j.sessionId, local: !!res.j.local };
				sessionExpired._fired = false; // a fresh session — re-arm the expiry handler, so a LATER expiry of THIS session is handled (not swallowed as already-fired), which otherwise wedged the viewer on a stuck "Decrypting…"
				deriveFromCap(res.j.cap);
				return Promise.resolve(); }) // the read key and bearer are deliberately NOT persisted — they live in memory only, so a lost phone holds no key at rest
			.then(function () { return afterConnect(); })
			.catch(function (e) { el('pairError').textContent = e.message || String(e); el('pairError').hidden = false; })
			.then(function () { el('pairBtn').disabled = false; });
	}

	function afterConnect() {
		el('pairView').hidden = true; el('browseView').hidden = false;
		el('vaultName').textContent = session.name || 'Vault';
		// "Save offline" keeps encrypted copies in THIS browser for later. That is for a phone away from the desktop;
		// on a local in-app view (same machine as the vault) it is pointless and would only leave residue, so hide it.
		el('offlineBtn').hidden = !!session.local;
		postSessionToSW(); // hand the streaming worker this session's key + bearer so large media can play
		// No durable-storage request on connect: nothing is written to disk unless you opt in with "Save offline".
		// This keeps a fresh connection leaving no encrypted footprint behind on this device.
		setStatus('Connected');
		return loadList();
	}
	// The service worker streams large media by decrypting only the blocks a player asks for. Give it the
	// session's data key and bearer (in memory only); it never persists them or the decrypted bytes.
	function swControls() { return !!(navigator.serviceWorker && navigator.serviceWorker.controller && session && keys); }
	function postSessionToSW() {
		if (!navigator.serviceWorker || !keys || !session) return;
		navigator.serviceWorker.ready.then(function (reg) {
			var target = navigator.serviceWorker.controller || (reg && reg.active);
			if (target) target.postMessage({ type: 'session', bearer: session.bearer, dataKey: Array.from(keys.dataKey) });
		}).catch(function () {});
	}

	function loadList() {
		el('fileList').innerHTML = '<li class="fine" style="cursor:default">Loading…</li>';
		return authFetch(session.list).then(function (r) {
			return r.json();
		}).then(function (j) {
			allFiles = (j.files || []).map(function (f) {
				var name = null; try { name = R.decryptPath(keys.nameKey, keys.nameTweak, f.path, session.dn); } catch (e) { return null; }
				return { enc: f.path, path: name, size: f.size };
			}).filter(function (f) { return f && f.path && !isInternalName(f.path); });
			cwd = []; render();
		}).catch(function (e) {
			if (e && e.expired) return; // authFetch already reconnected and told the user
			el('fileList').innerHTML = ''; toast('Could not load the vault.');
		});
	}

	// ---- directory rendering ----
	function human(n) { if (n < 1024) return n + ' B'; var u = ['KB', 'MB', 'GB']; var i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 2); return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i]; }
	function iconFor(name, isDir) { if (isDir) return '📁'; var e = ext(name); if (/^(png|jpg|jpeg|gif|webp|bmp|svg|heic)$/.test(e)) return '🖼️'; if (/^(mp4|mov|webm|m4v|mkv)$/.test(e)) return '🎞️'; if (/^(mp3|m4a|wav|aac|ogg|flac)$/.test(e)) return '🎵'; if (e === 'pdf') return '📄'; if (/^(txt|md|json|csv|log|xml|yml|yaml|js|ts|html|css)$/.test(e)) return '📃'; return '📎'; }
	function ext(name) { var m = /\.([A-Za-z0-9]+)$/.exec(name || ''); return m ? m[1].toLowerCase() : ''; }
	// The tool's own metadata blobs and OS-noise files, matched by basename exactly as the desktop does, so a
	// vault's internal control files never show up as if they were the user's documents.
	function isInternalName(p) {
		var base = p.slice(p.lastIndexOf('/') + 1);
		if (base === '.vaultcheck' || base === '.vaultsnapshot' || base === '.vaultsnapshot.new' || base === '.vaultsession' || base === '.vaultsession.new') return true;
		return /^(\.DS_Store|\._.*|\.Spotlight-V100|\.metadata_never_index|\.Trashes|\.fseventsd|\.TemporaryItems|\.DocumentRevisions-V100|\.apDisk|Thumbs\.db|desktop\.ini|\.fuse_hidden.*|\.nfs.*)$/.test(base);
	}

	function render() {
		var prefix = cwd.length ? cwd.join('/') + '/' : '';
		var dirs = {}, filesHere = [];
		allFiles.forEach(function (f) {
			if (prefix && f.path.indexOf(prefix) !== 0) return;
			var rest = f.path.slice(prefix.length);
			var slash = rest.indexOf('/');
			if (slash >= 0) dirs[rest.slice(0, slash)] = true;
			else filesHere.push(f);
		});
		// breadcrumbs
		var cr = el('crumbs'); cr.innerHTML = '';
		var rootA = document.createElement('a'); rootA.href = '#'; rootA.setAttribute('dir', 'auto'); rootA.textContent = session.name || 'Vault'; rootA.onclick = function (e) { e.preventDefault(); cwd = []; render(); }; cr.appendChild(rootA);
		cwd.forEach(function (seg, i) { cr.appendChild(document.createTextNode('  /  ')); var a = document.createElement('a'); a.href = '#'; a.setAttribute('dir', 'auto'); a.textContent = seg; a.onclick = function (e) { e.preventDefault(); cwd = cwd.slice(0, i + 1); render(); }; cr.appendChild(a); });

		var ul = el('fileList'); ul.innerHTML = '';
		var dirNames = Object.keys(dirs).sort(function (a, b) { return a.localeCompare(b); });
		dirNames.forEach(function (d) { ul.appendChild(row(iconFor(d, true), d, '', function () { cwd = cwd.concat([d]); render(); })); });
		filesHere.sort(function (a, b) { return a.path.localeCompare(b.path); }).forEach(function (f) {
			var nm = f.path.slice(prefix.length);
			ul.appendChild(row(iconFor(nm, false), nm, human(f.size), function () { openFile(f, nm); }));
		});
		el('browseEmpty').hidden = !(dirNames.length === 0 && filesHere.length === 0);
	}
	function row(icon, name, size, onclick) {
		var li = document.createElement('li');
		// The row is the app's primary control (open a folder or file), so make it a real button for keyboard and
		// screen-reader users: focusable, announced as a button, and activated by Enter or Space, not just a tap.
		li.setAttribute('role', 'button'); li.tabIndex = 0;
		var i = document.createElement('span'); i.className = 'ic'; i.textContent = icon; i.setAttribute('aria-hidden', 'true'); // decorative emoji — don't let a screen reader announce "folder"/"note" before each name
		var n = document.createElement('span'); n.className = 'nm'; n.setAttribute('dir', 'auto'); n.textContent = name; // dir=auto so a non-Latin (e.g. RTL) file or folder name picks its own base direction
		var s = document.createElement('span'); s.className = 'sz'; s.textContent = size;
		li.appendChild(i); li.appendChild(n); li.appendChild(s);
		li.onclick = onclick;
		li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onclick(); } });
		return li;
	}

	// ---- fetch + decrypt one file ----
	function getCipher(enc) {
		return idbGet('cipher', enc).then(function (cached) {
			if (cached) return cached instanceof ArrayBuffer ? new Uint8Array(cached) : cached;
			var path = enc.split('/').map(encodeURIComponent).join('/');
			return authFetch(session.base + path).then(function (r) { if (!r.ok) throw new Error('fetch ' + r.status); return r.arrayBuffer(); }).then(function (ab) { return new Uint8Array(ab); });
		});
	}
	var MEDIA_EXT = /^(mp4|mov|webm|m4v|mp3|m4a|aac|wav|ogg|flac)$/;
	var MAX_INMEM_BYTES = 220 * 1024 * 1024; // the most we will decrypt whole into a phone tab's memory (media streams instead)
	function openFile(f, name) {
		// Media, when the streaming worker is available: play it straight from the worker so a large file plays
		// and seeks without decrypting the whole thing up front. Everything else decrypts fully in memory.
		if (MEDIA_EXT.test(ext(name)) && swControls()) { openMediaStream(f, name); return; }
		openFileFull(f, name);
	}
	// Decrypt a whole file in memory and render it. Used for non-media files, and as the fallback when media
	// streaming is not available (see openMediaStream).
	function openFileFull(f, name) {
		// A phone browser tab has limited memory: decrypting a very large file whole can crash the tab. Guard on the
		// known size BEFORE fetching or decrypting, rather than OOM-ing partway. (Media normally streams instead.)
		if (f && f.size > MAX_INMEM_BYTES) { showViewer(name, ''); setViewerBody('<p class="pad">This file is too large to open in a phone browser.<br><span class="fine">' + human(f.size) + '</span></p>'); return; }
		showViewer(name, '<div class="spin">Decrypting…</div>');
		getCipher(f.enc).then(function (cipher) {
			var plain = R.decryptContent(keys.dataKey, cipher);
			renderPlain(name, plain);
		}).catch(function (e) { if (e && e.expired) return; setViewerBody('<p class="pad">Could not open this file.<br><span class="fine">' + escapeHtml(e && e.message || '') + '</span></p>'); });
	}
	// Point a media element at the streaming worker's URL; it serves decrypted 206 ranges on demand.
	function openMediaStream(f, name) {
		var e = ext(name);
		var tag = /^(mp3|m4a|aac|wav|ogg|flac)$/.test(e) ? 'audio' : 'video';
		// Carry the DECRYPTED file extension to the worker as a query param: the streamed path is the ENCRYPTED
		// name, which has no extension, so without this the worker cannot set a real Content-Type and every 206 is
		// application/octet-stream — which iOS Safari refuses to play. The param rides in the query, not the path,
		// so the worker's ciphertext fetch (built from the pathname) is unaffected.
		var streamUrl = session.base.replace('/m/files/', '/m/stream/') + f.enc.split('/').map(encodeURIComponent).join('/') + '?e=' + encodeURIComponent(e);
		showViewer(name, '');
		var m = document.createElement(tag); m.src = streamUrl; m.controls = true; m.setAttribute('playsinline', ''); m.autoplay = false;
		var fellBack = false;
		m.addEventListener('error', function () {
			// Some browsers (notably iOS Safari) bypass the service worker for a media element's Range requests, so
			// the stream URL is never intercepted and cannot be decrypted on the fly. Fall back ONCE to decrypting
			// the whole file in memory — the same path every other file uses — which plays without the worker, up to
			// the in-memory size cap. If that also fails, it is a genuine decrypt/session error, so show the message.
			if (fellBack) { setViewerBody('<p class="pad">Could not play this file.<br><span class="fine">If the vault was locked or this session expired, open it again.</span></p>'); return; }
			fellBack = true;
			openFileFull(f, name);
		});
		var body = el('viewerBody'); body.innerHTML = ''; body.appendChild(m);
	}
	function renderPlain(name, bytes) {
		var e = ext(name), body = el('viewerBody');
		if (/^(png|jpg|jpeg|gif|webp|bmp|svg)$/.test(e)) {
			var url = blobUrl(bytes, e === 'svg' ? 'image/svg+xml' : 'image/' + (e === 'jpg' ? 'jpeg' : e));
			body.innerHTML = ''; var img = document.createElement('img'); img.alt = name; img.onload = function () { /* pixels retained by the element; free the blob */ URL.revokeObjectURL(url); }; img.src = url; body.appendChild(img);
		} else if (/^(mp4|mov|webm|m4v)$/.test(e)) {
			mediaEl('video', bytes, e === 'mov' ? 'video/quicktime' : 'video/' + (e === 'm4v' ? 'mp4' : e), name);
		} else if (/^(mp3|m4a|wav|aac|ogg|flac)$/.test(e)) {
			mediaEl('audio', bytes, 'audio/' + (e === 'm4a' ? 'mp4' : e), name);
		} else if (e === 'pdf') {
			var u = blobUrl(bytes, 'application/pdf'); body.innerHTML = '<iframe title="' + escapeHtml(name) + '" style="width:100%;height:100%;border:0;background:#fff" src="' + u + '"></iframe>';
		} else if (/^(txt|md|markdown|json|csv|log|xml|yml|yaml|js|ts|html|css|ini|conf|sh)$/.test(e) || bytes.length < 2 * 1024 * 1024) {
			var text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
			var pre = document.createElement('pre'); pre.textContent = text; body.innerHTML = ''; body.appendChild(pre);
		} else {
			body.innerHTML = '<p class="pad">This file type can\'t be previewed here.<br><span class="fine">' + escapeHtml(human(bytes.length)) + '</span></p>';
		}
	}
	function mediaEl(tag, bytes, type, name) {
		if (bytes.length > MAX_INMEM_BYTES) { setViewerBody('<p class="pad">This file is large to play fully in a phone browser.<br><span class="fine">' + human(bytes.length) + '</span></p>'); return; }
		var url = blobUrl(bytes, type); var m = document.createElement(tag); m.src = url; m.controls = true; m.setAttribute('playsinline', ''); m.autoplay = false;
		var body = el('viewerBody'); body.innerHTML = ''; body.appendChild(m);
	}
	function blobUrl(bytes, type) { var u = URL.createObjectURL(new Blob([bytes], { type: type })); liveUrls.push(u); return u; }
	function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

	// ---- viewer overlay ----
	// The viewer is a full-screen overlay, so treat it as a modal: move focus into it on open, make the content
	// behind it unreachable to the keyboard and screen readers (`inert`), and restore focus to whatever opened it on
	// close. This desktop page is also what the desktop "View files" action opens in a new tab, so keyboard users on
	// either device get Escape-to-close and never Tab into the file rows sitting behind the overlay.
	var lastFocusBeforeViewer = null;
	// Toggle `inert` on EVERY region behind the viewer overlay — the two views and the header (whose theme toggle
	// would otherwise stay Tab-focusable and screen-reader-reachable behind the opaque overlay). One place so a
	// region can't be missed.
	function setBgInert(on) {
		['browseView', 'pairView'].forEach(function (id) { var e = el(id); if (e) { try { e.inert = on; } catch (_) {} } });
		var hdr = document.querySelector('.topbar'); if (hdr) { try { hdr.inert = on; } catch (_) {} }
	}
	function showViewer(name, html) {
		lastFocusBeforeViewer = document.activeElement;
		el('viewerName').textContent = name; setViewerBody(html); el('viewer').hidden = false;
		setBgInert(true); // make EVERY region behind the overlay unreachable — the two views AND the header (its theme toggle)
		try { el('viewerClose').focus(); } catch (e) {}
	}
	function setViewerBody(html) { el('viewerBody').innerHTML = html; }
	function closeViewer() {
		var wasOpen = !el('viewer').hidden;
		el('viewer').hidden = true; el('viewerBody').innerHTML = ''; liveUrls.forEach(function (u) { try { URL.revokeObjectURL(u); } catch (e) {} }); liveUrls = [];
		setBgInert(false);
		if (wasOpen && lastFocusBeforeViewer && lastFocusBeforeViewer.focus) { try { lastFocusBeforeViewer.focus(); } catch (e) {} }
		lastFocusBeforeViewer = null;
	}

	// ---- offline copy ----
	function saveOffline() {
		if (!allFiles.length) return;
		// Ask for durable storage only now, when the user has chosen to keep an offline copy — so the encrypted
		// cache survives eviction. A connection that never saves offline leaves no persisted footprint.
		if (navigator.storage && navigator.storage.persist) { try { navigator.storage.persist(); } catch (e) {} }
		var i = 0, okc = 0; el('offlineBtn').disabled = true;
		function step() {
			if (i >= allFiles.length) { el('offlineBtn').disabled = false; toast('Saved ' + okc + ' files for offline use.'); return; }
			var f = allFiles[i++];
			var path = f.enc.split('/').map(encodeURIComponent).join('/');
			authFetch(session.base + path).then(function (r) { return r.arrayBuffer(); }).then(function (ab) { return idbPut('cipher', f.enc, ab); }).then(
				function (ok) { if (ok) okc++; toast('Saving offline… ' + i + '/' + allFiles.length, 1500); step(); },
				function (e) { if (e && e.expired) { el('offlineBtn').disabled = false; return; } step(); }); // stop the batch if the session expired; otherwise skip one bad file and continue
		}
		step();
	}

	// ---- forget / lock ----
	// End the server-side session too. On Lock (fetch) and, for a local session, on tab close (a sendBeacon, since an
	// unload handler cannot set an Authorization header — the route also accepts the bearer in the body for that).
	function stopServerSession(useBeacon) {
		if (!session || !session.id) return;
		var payload = JSON.stringify({ sessionId: session.id, bearer: session.bearer });
		try {
			if (useBeacon && navigator.sendBeacon) { navigator.sendBeacon('stop', new Blob([payload], { type: 'application/json' })); return; }
			fetch('stop', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + session.bearer }, body: payload, keepalive: true }).catch(function () {});
		} catch (e) {}
	}
	function forget(silent) {
		stopServerSession(false); // Lock means end it everywhere — drop the in-memory server session, not just this device's copy
		try { if (navigator.serviceWorker && navigator.serviceWorker.controller) navigator.serviceWorker.controller.postMessage({ type: 'session-clear' }); } catch (e) {} // wipe the streaming key from the worker
		session = null; keys = null; allFiles = []; cwd = []; closeViewer();
		idbClear();
		el('browseView').hidden = true; el('pairView').hidden = false; setStatus('');
		el('codeInput').value = '';
		if (!silent) toast('Locked on this device.');
	}

	// ---- boot ----
	function boot() {
		// name from the single-sourced brand
		fetch('config').then(function (r) { return r.json(); }).then(function (c) { if (c && c.name) { el('appName').textContent = c.name; document.title = c.name + ' viewer'; } }).catch(function () {});
		// service worker for offline app shell (secure contexts only: https or localhost)
		if ('serviceWorker' in navigator && window.isSecureContext) {
			navigator.serviceWorker.register('sw.js').catch(function () {});
			navigator.serviceWorker.addEventListener('controllerchange', postSessionToSW); // re-arm streaming if the worker (re)takes control
		}
		el('pairForm').addEventListener('submit', function (e) { e.preventDefault(); if (el('pairBtn').disabled) return; var code = (el('codeInput').value || '').trim().toUpperCase(); if (code) pair(code); }); // ignore Enter while a pairing is already in flight
		el('viewerClose').addEventListener('click', closeViewer);
		document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !el('viewer').hidden) { e.preventDefault(); closeViewer(); } }); // Escape closes the viewer overlay, like a native modal
		el('offlineBtn').addEventListener('click', saveOffline);
		el('lockBtn').addEventListener('click', function () { forget(false); });

		// Theme: the same four choices (auto / light / dark / sepia), cycle order, and 'vdisk-theme' storage as the
		// desktop interface. theme-boot.js already applied the saved value before paint; keep the meta theme-color in
		// step with the resolved background so the phone's status bar matches.
		(function initTheme() {
			var order = ['auto', 'light', 'dark', 'sepia'];
			var labels = { auto: 'Theme: match system', light: 'Theme: light', dark: 'Theme: dark', sepia: 'Theme: sepia' };
			function applyThemeColor() { try { var bg = getComputedStyle(document.body).backgroundColor, meta = document.querySelector('meta[name="theme-color"]'); if (bg && meta) meta.setAttribute('content', bg); } catch (e) {} }
			try { document.documentElement.setAttribute('data-theme', localStorage.getItem('vdisk-theme') || 'auto'); } catch (e) {}
			applyThemeColor();
			el('themeToggle').addEventListener('click', function () {
				var cur = document.documentElement.getAttribute('data-theme') || 'auto';
				var next = order[(order.indexOf(cur) + 1) % order.length];
				document.documentElement.setAttribute('data-theme', next);
				try { localStorage.setItem('vdisk-theme', next); } catch (e) {}
				applyThemeColor();
				toast(labels[next] || 'Theme: ' + next);
			});
			// Keep "auto" in step if the system flips light/dark while the viewer is open.
			try { window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyThemeColor); } catch (e) {}
		})();

		window.addEventListener('pagehide', function () {
			liveUrls.forEach(function (u) { try { URL.revokeObjectURL(u); } catch (e) {} });
			if (session && session.local) stopServerSession(true); // a local in-app session ends when its tab closes
		});

		// A pairing code carried in the URL fragment (from a scanned QR): auto-connect, then scrub it.
		var hash = (location.hash || '').replace(/^#/, '').trim();
		var m = /^([0-9A-Za-z]{5}-[0-9A-Za-z]{5})$/.exec(hash);
		if (m) { history.replaceState(null, '', location.pathname); el('codeInput').value = m[1].toUpperCase(); pair(m[1].toUpperCase()); return; }

		// Sessions are memory-only: there is nothing to auto-restore, so reconnecting means pairing again. As a
		// one-time remediation, delete any session blob a prior app version may have persisted (it could hold a
		// key or bearer), so no key is left at rest after this update.
		idbDel('meta', 'session');
	}
	if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
