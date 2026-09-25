'use strict';
/* app.js — the recipient side of a "Send" link. The link is /s/<id>#<key>: the id names a ciphertext the server
 * holds, and the key (in the URL fragment) never leaves this browser — the server never sees it. This page fetches
 * the ciphertext, decrypts it here with Web Crypto, and renders the item read-only using the same shared schema the
 * app uses. If the link is protected, the password is checked server-side to release the ciphertext (rate of use is
 * bounded by the view limit), but the decryption key is still only ever in this page. */
(function () {
	var VS = window.VaultSecret;
	var el = function (id) { return document.getElementById(id); };
	var toastT = null;
	function toast(m) { var t = el('toast'); t.hidden = false; t.textContent = m; clearTimeout(toastT); toastT = setTimeout(function () { t.hidden = true; }, 2400); }
	// For a password-protected link, the decryption key is derived HERE from the fragment key plus the passphrase, so the
	// link fragment alone cannot decrypt and the server (which never sees the fragment) cannot either. PBKDF2 via Web
	// Crypto matches the server's key derivation; the salt is the fragment key, unique per link.
	function pbkdf2Web(password, saltBytes, iter) {
		var enc = new TextEncoder();
		return window.crypto.subtle.importKey('raw', enc.encode(String(password || '')), { name: 'PBKDF2' }, false, ['deriveBits'])
			.then(function (km) { return window.crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' }, km, 256); })
			.then(function (bits) { return new Uint8Array(bits); });
	}
	function status(msg, err) { var s = el('status'); if (!msg) { s.hidden = true; return; } s.hidden = false; s.textContent = msg; s.className = 'status' + (err ? ' err' : ''); }

	// The id is the last path segment of /s/<id>; the key rides in the fragment and is never sent anywhere.
	var parts = location.pathname.replace(/\/+$/, '').split('/');
	var id = parts[parts.length - 1];
	var key = (location.hash || '').replace(/^#/, '').trim();
	if (id === 's') id = '';

	fetch('config').then(function (r) { return r.json(); }).then(function (c) { if (c && c.name) { el('appName').textContent = c.name; document.title = c.name + ' — shared securely'; } }).catch(function () {});

	function fail(msg) { el('title').textContent = 'This link cannot be opened'; el('sub').hidden = true; el('pwArea').hidden = true; status(msg, true); }
	if (!id || !key) { fail('This link is incomplete — ask the sender for the full link, including the part after the “#”.'); return; }
	if (!VS || !(window.crypto && window.crypto.subtle)) { fail('This browser cannot open the link (it needs Web Crypto over a secure connection).'); return; }

	// Redeeming spends one of the link's limited views and can self-destruct a view-once link, so a second submit
	// while the first is still in flight (an impatient double-click, or Enter-then-click) must never fire a second
	// redeem — the second would burn the last view and paint an "expired" error over the secret the first just
	// decrypted. `opening` gates every entry to open(); the action controls are disabled for the whole round trip and
	// re-enabled ONLY when the server says the password was wrong (the one case where the recipient tries again).
	var opening = false;
	function setBusy(on) {
		opening = on;
		var b = el('openBtn'), p = el('pw'), b2 = el('openNoPwBtn');
		if (b) b.disabled = on; if (p) p.disabled = on; if (b2) b2.disabled = on;
	}
	function open(password) {
		if (opening) return; // a redeem is already in flight — do not spend a second view
		setBusy(true);
		status('Opening…');
		fetch('redeem/' + encodeURIComponent(id), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: password || '' }) })
			.then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
			.then(function (res) {
				var j = res.j || {};
				if (j.gone) { fail('This link has expired or has already been opened the maximum number of times.'); return; }
				if (j.badPassword) { setBusy(false); status('That password is not correct.', true); try { el('pw').focus(); el('pw').select(); } catch (_) {} return; }
				if (!res.ok || !j.ciphertext) { status(j.error || 'Could not open this link.', true); return; }
				// Derive the decryption key. A password-protected link (meta.kdf) folds the passphrase into the key here,
				// client-side; an ordinary link uses the fragment key directly. Either way the key stays only in this page.
				var keyBytes = VS.b64ToBytes(key);
				var kdf = j.meta && j.meta.kdf;
				var deriveKey = (kdf && kdf.alg === 'pbkdf2-sha256') ? pbkdf2Web(password || '', keyBytes, Number(kdf.iter) || 310000) : Promise.resolve(keyBytes);
				return deriveKey.then(function (itemKey) { return VS.aesGcmOpen(j.ciphertext, itemKey); }).then(function (text) {
					var item; try { item = JSON.parse(text); } catch (_) { throw new Error('The shared item could not be read.'); }
					if (item && Number(item.v) > 1) { fail('This link was created by a newer version. Ask the sender to update, or open it in a newer viewer.'); return; }
					el('pwArea').hidden = true; status('');
					el('title').textContent = (VS.displaySafe ? VS.displaySafe(item.title) : String(item.title || '')) || 'Shared item';
					el('sub').textContent = 'Decrypted in your browser. ' + (VS.labelFor ? VS.labelFor(item.type) : 'Item') + '.';
					var cleanup = VS.renderItem(el('view'), item, { toast: toast }); // stop the live-code timer if the tab is dismissed
					try { window.addEventListener('pagehide', function () { try { cleanup && cleanup(); } catch (_) {} }, { once: true }); } catch (_) {}
					var m = el('meta'); m.hidden = false;
					var left = (typeof j.remaining === 'number') ? (j.remaining <= 0 ? 'This was the last time this link can be opened.' : j.remaining + ' more open(s) allowed.') : '';
					m.textContent = 'Nothing readable was sent to the server — only you, with this link, can see this. ' + left;
				});
			})
			.catch(function (e) { status((e && e.message) || 'Could not open this link.', true); });
	}

	// Find out whether a password is needed before trying to open (so a view is not spent on a guess).
	fetch('info/' + encodeURIComponent(id)).then(function (r) { return r.json(); }).then(function (j) {
		if (!j || j.gone) { fail('This link has expired or has already been opened the maximum number of times.'); return; }
		if (j.needsPassword) {
			el('pwArea').hidden = false;
			el('openBtn').addEventListener('click', function () { open(el('pw').value); });
			el('pw').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); open(el('pw').value); } });
			setTimeout(function () { el('pw').focus(); }, 50);
		} else {
			// Do NOT auto-open: redeeming spends a view and self-destructs a view-once link, so a chat/email link
			// preview, a crawler, or a prefetcher that merely loads this page would burn the only view before the
			// intended recipient ever sees it. Require an explicit click, exactly as the password path does.
			el('openArea').hidden = false;
			el('openNoPwBtn').addEventListener('click', function () { el('openArea').hidden = true; open(''); });
			setTimeout(function () { el('openNoPwBtn').focus(); }, 50); // move focus to the revealed action, matching the password path, so a keyboard/AT recipient is placed on it
		}
	}).catch(function () { fail('Could not reach the sender’s app. The link works only while their app is running and reachable.'); });
})();
