'use strict';
// lib/test/mobileviewer.js — guards the in-browser viewer's media-streaming wiring, whose pieces span two files
// (the app builds the stream URL; the service worker turns Range requests into decrypted 206s). The streamed path
// is the ENCRYPTED, extension-less name, so the app must carry the real extension to the worker or every 206 is
// application/octet-stream — which iOS Safari refuses to play. It also guards the failed-stream error handler (so a
// broken stream never leaves a blank, dead player) and the service worker's shell fallback. Static source checks —
// no browser needed — matching the other drift/wiring guards.
//
// Run:  node lib/test/mobileviewer.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const mobile = path.join(__dirname, '..', 'webserver', 'public', 'mobile');
const read = (p) => fs.readFileSync(p, 'utf8');

function main() {
	const app = read(path.join(mobile, 'app.js'));
	const sw = read(path.join(mobile, 'sw.js'));

	// The app carries the decrypted extension to the worker on the stream URL, and attaches a media error handler.
	ok('the viewer appends the decrypted extension to the stream URL', /\/m\/stream\/[\s\S]{0,160}\?e='\s*\+\s*encodeURIComponent\(e\)/.test(app));
	// A media element whose stream is not intercepted (iOS Safari bypasses the worker) must fall back to a full
	// in-memory decrypt, then show a message only if THAT also fails — never a blank dead player.
	ok('a failed media stream falls back to a full in-memory decrypt', /addEventListener\('error'[\s\S]{0,800}openFileFull\(f, name\)/.test(app));
	ok('the fallback path decrypts the whole file (reused by non-media files too)', /function openFileFull\([\s\S]{0,600}R\.decryptContent\(/.test(app));
	// A very large file is refused before decryption rather than OOM-ing the phone tab.
	ok('openFileFull guards the in-memory size before decrypting', /function openFileFull\([\s\S]{0,300}MAX_INMEM_BYTES/.test(app));

	// The worker reads that extension and uses it for the streamed 206's Content-Type (not the encrypted path).
	ok('the worker reads the extension from the stream URL query', /searchParams\.get\('e'\)/.test(sw));
	ok('the worker sets the 206 Content-Type from the extension', /Content-Type':\s*contentType\(ext\)/.test(sw));
	ok('the worker maps common media extensions to real MIME types', /mp4:\s*'video\/mp4'/.test(sw) && /mp3:\s*'audio\/mpeg'/.test(sw));

	// The shell fetch handler falls back to the network if the cache lookup itself rejects.
	ok('the worker shell branch falls back to the network on a cache-match rejection', /\}\)\.catch\(function \(\) \{ return fetch\(req\); \}\)/.test(sw));

	// The PDF preview renders a blob: URL in an <iframe>, so the mobile CSP must allow a blob: frame — otherwise the
	// frame falls back to default-src 'self' (no blob:) and the preview is a silent blank. Guard both halves.
	const routes = read(path.join(__dirname, '..', 'webserver', 'mobileRoutes.js'));
	ok('the mobile CSP allows a blob: frame (PDF preview is not blocked)', /frame-src[^;]*\bblob:/.test(routes));
	ok('the viewer previews a PDF in an iframe (matching the frame-src allowance)', /application\/pdf'[\s\S]{0,140}<iframe/.test(app));
	// A /m/stream request that reaches the server (the worker was bypassed) must get a clean non-HTML error, not the
	// SPA shell served as if it were media.
	ok('a bypassed /m/stream request returns a non-2xx, not the app shell', /\^\\\/stream\\\//.test(routes) && /status\(415\)/.test(routes));

	// Theme parity with the desktop: the mobile viewer honors the same four themes (auto/light/dark/sepia), applies
	// the saved one before paint (theme-boot.js), and keeps the same token model, storage key, and toggle.
	const html = read(path.join(mobile, 'index.html'));
	const css = read(path.join(mobile, 'app.css'));
	ok('the mobile page defaults to data-theme="auto" and loads the pre-paint theme boot', /<html[^>]*data-theme="auto"/.test(html) && /src="theme-boot\.js"/.test(html));
	ok('the mobile CSS defines the pinned dark and sepia themes', /:root\[data-theme="dark"\]/.test(css) && /:root\[data-theme="sepia"\]/.test(css));
	ok('the mobile CSS follows the system preference for the auto theme', /prefers-color-scheme: dark[\s\S]{0,60}:root\[data-theme="auto"\]/.test(css));
	ok('the mobile viewer wires a theme toggle using the shared vdisk-theme storage', /getElementById\('themeToggle'\)|el\('themeToggle'\)/.test(app) && /vdisk-theme/.test(app));
	ok('the boot script uses the same vdisk-theme key as the desktop', /vdisk-theme/.test(read(path.join(mobile, 'theme-boot.js'))));
	ok('the service worker precaches the theme boot script', /'theme-boot\.js'/.test(sw));

	// The service-worker cache name must fold a CONTENT hash of the shell, not just the app version — otherwise a
	// release that edits a shell asset without bumping the version ships a byte-identical worker and an installed PWA
	// keeps serving the stale (possibly security-fixed) shell forever. Guard that the injected version carries a
	// content fingerprint.
	ok('the SW cache version folds a shell content fingerprint (not version alone)', /shellFingerprint/.test(routes) && /swVersion[\s\S]{0,200}shellFingerprint/.test(routes));
	// Returning to the foreground must re-prime the worker's in-memory stream session: a backgrounded worker can be
	// evicted, dropping the key, which would otherwise silently break media streaming until a re-pair.
	ok('the viewer re-primes the SW session on foreground (visibilitychange)', /visibilitychange'[\s\S]{0,160}postSessionToSW\(\)/.test(app));
	// The full-screen viewer overlay must expose dialog semantics so a screen reader announces it as a named modal
	// (its focus trap and inert background are already in place).
	ok('the mobile viewer overlay has dialog semantics', /id="viewer"[^>]*role="dialog"[^>]*aria-modal="true"[^>]*aria-labelledby="viewerName"/.test(html));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-VIEWER CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
