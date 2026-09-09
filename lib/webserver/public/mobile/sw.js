'use strict';
/* sw.js — the service worker. It makes the app shell available offline, and it STREAMS large media: a media
 * element points at /m/stream/…, and the worker turns each of its Range requests into a decrypted 206 by
 * fetching only the ciphertext blocks that range needs and decrypting them in memory — so a big video plays
 * and seeks without ever decrypting the whole file. It deliberately does NOT cache any DATA route (pair / list
 * / files / stream): those always go to the network, and the ciphertext the app keeps offline is stored by the
 * app in IndexedDB, not here. Plaintext is NEVER cached — a streamed 206 body is built fresh in memory per
 * request and handed straight to the element. */
importScripts('vendor/nacl.min.js', 'rclone-reader.js'); // the range decryptor (nacl secretbox) for media streaming
var R = self.RcloneReader;
// The cache name carries the app version (injected when this file is served), so every release makes it a new name;
// the activate handler then deletes the old caches and the updated shell is used at once, rather than one load later.
// Falls back to a fixed name if served without injection (e.g. opened directly).
var CACHE = 'vault-mobile-shell-' + (self.__SHELL_VERSION || 'v2');
var SHELL = ['./', 'index.html', 'theme-boot.js', 'app.css', 'app.js', 'rclone-reader.js', 'vendor/nacl.min.js', 'vendor/scrypt.js', 'vendor/aes-js.js', 'icon.svg', 'manifest.webmanifest', 'config'];

// The current session's decryption key + bearer, posted by the app after pairing (held in memory only).
var SESSION = null;
var META = new Map(); // ciphertext path -> { cipherLen, nonce, plainTotal }, cached so each seek is one block fetch
// The most plaintext a single streamed response decrypts and holds in memory. An open-ended media request
// ("bytes=0-", or no Range at all) would otherwise span the whole file, so a large video would decrypt entirely
// into one buffer and OOM the tab — defeating the streaming design. Cap each response to this and return a partial
// 206; the media element issues follow-up ranges to keep playing or seek. 64 KiB-block-aligned math handles the rest.
var MAX_STREAM_SPAN = 4 * 1024 * 1024;
self.addEventListener('message', function (e) {
	var d = e.data || {};
	if (d.type === 'session') { SESSION = { bearer: d.bearer, dataKey: new Uint8Array(d.dataKey) }; }
	else if (d.type === 'session-clear') { SESSION = null; META.clear(); }
});
// Map a plain file EXTENSION to a media MIME type. The extension comes from the app as the stream URL's `e` query
// param, because the streamed path is the ENCRYPTED name (no extension); iOS Safari refuses to play a media source
// served as application/octet-stream, so a correct type here is what makes phone playback work.
function contentType(ext) {
	var e = String(ext || '').toLowerCase();
	var map = { mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm', mp3: 'audio/mpeg', m4a: 'audio/mp4', aac: 'audio/aac', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac' };
	return map[e] || 'application/octet-stream';
}
// Serve one media Range request by decrypting only the covering blocks. Never caches; plaintext lives only in
// the Response body it returns. The ciphertext comes from the same /m/files endpoint (which supports Range).
function streamMedia(url, req) {
	if (!SESSION || !R) return Promise.resolve(new Response('', { status: 503 }));
	var cipherUrl = url.origin + url.pathname.replace('/m/stream/', '/m/files/');
	var auth = { Authorization: 'Bearer ' + SESSION.bearer };
	var ext = url.searchParams.get('e') || ''; // the DECRYPTED extension, passed by the app (the path itself is the encrypted, extension-less name)
	return Promise.resolve(META.get(url.pathname)).then(function (meta) {
		if (meta) return meta;
		return fetch(cipherUrl, { headers: Object.assign({ Range: 'bytes=0-' + (R.HEADER_SIZE - 1) }, auth) }).then(function (hr) {
			if (!(hr.ok || hr.status === 206)) throw new Error('meta ' + hr.status);
			var cr = hr.headers.get('Content-Range') || ''; var m = /\/(\d+)\s*$/.exec(cr);
			var cipherLen = m ? Number(m[1]) : Number(hr.headers.get('Content-Length'));
			return hr.arrayBuffer().then(function (ab) {
				var meta2 = { cipherLen: cipherLen, nonce: R.parseHeaderNonce(new Uint8Array(ab)), plainTotal: R.decryptedSize(cipherLen) };
				META.set(url.pathname, meta2); return meta2;
			});
		});
	}).then(function (meta) {
		var total = meta.plainTotal, start = 0, end = total - 1;
		var rh = req.headers.get('Range');
		if (rh) { var mm = /bytes=(\d*)-(\d*)/.exec(rh); if (mm) { if (mm[1] === '' && mm[2] !== '') { start = Math.max(0, total - Number(mm[2])); } else { if (mm[1] !== '') start = Number(mm[1]); if (mm[2] !== '') end = Number(mm[2]); } } }
		if (start > end || start >= total) return new Response('', { status: 416, headers: { 'Content-Range': 'bytes */' + total } });
		end = Math.min(end, total - 1);
		if (end - start + 1 > MAX_STREAM_SPAN) end = start + MAX_STREAM_SPAN - 1; // bound this response so an open-ended range never decrypts a whole large file into memory
		var rb = R.rangeToBlocks(start, end + 1, meta.cipherLen);
		return fetch(cipherUrl, { headers: Object.assign({ Range: 'bytes=' + rb.cipherStart + '-' + (rb.cipherEnd - 1) }, auth) }).then(function (cr2) {
			if (!(cr2.ok || cr2.status === 206)) throw new Error('cipher ' + cr2.status);
			return cr2.arrayBuffer();
		}).then(function (ab) {
			var plain = R.decryptBlocks(SESSION.dataKey, meta.nonce, new Uint8Array(ab), rb.firstBlock);
			var body = plain.subarray(rb.sliceStart, rb.sliceEnd);
			return new Response(body, { status: 206, headers: { 'Content-Type': contentType(ext), 'Content-Range': 'bytes ' + start + '-' + end + '/' + total, 'Content-Length': String(body.length), 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' } });
		});
	}).catch(function () { return new Response('', { status: 502 }); });
}

self.addEventListener('install', function (e) {
	e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL).catch(function () {}); }).then(function () { return self.skipWaiting(); }));
});
self.addEventListener('activate', function (e) {
	e.waitUntil(caches.keys().then(function (keys) { return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); })); }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (e) {
	var req = e.request;
	if (req.method !== 'GET') return; // pair is a POST; never touch it
	var url = new URL(req.url);
	// Media streaming: turn the element's Range requests into decrypted 206s from the covering blocks.
	if (/\/m\/stream\//.test(url.pathname)) { e.respondWith(streamMedia(url, req)); return; }
	// Data routes always go to the network and are never cached (they carry ciphertext / one-shot auth).
	if (/\/(files|list)\//.test(url.pathname) || /\/pair$/.test(url.pathname)) return;
	// App shell: cache-first, falling back to the network, updating the cache when online.
	e.respondWith(
		caches.match(req).then(function (hit) {
			var net = fetch(req).then(function (res) { if (res && res.ok && res.type === 'basic') { var copy = res.clone(); caches.open(CACHE).then(function (c) { return c.put(req, copy); }).catch(function () {}); } return res; }).catch(function () { return hit; });
			return hit || net;
		}).catch(function () { return fetch(req); }) // if the cache lookup itself rejects, fall back to the network rather than a bare error
	);
});
