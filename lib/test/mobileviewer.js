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

	// Cross-platform: a PDF is drawn page by page onto a <canvas> with the bundled pdf.js, NOT handed to the browser's
	// own PDF viewer in a sub-frame. A WebView (the desktop app) renders nothing in that sub-frame — a blank page — so
	// the canvas path is what makes a PDF display the same in the desktop app and in every browser. Pin that the PDF
	// branch calls renderPdf (not an iframe), that pdf.js is loaded locally (never from a network CDN), and that its
	// worker is the vendored same-origin module.
	ok('the PDF branch renders to canvas via pdf.js (renderPdf), not a browser sub-frame', /e === 'pdf'[\s\S]{0,120}renderPdf\(/.test(app) && /function renderPdf\([\s\S]{0,900}getDocument\(/.test(app));
	// The dynamic import specifier must be an absolute URL resolved against the page base — a bare relative path like
	// "vendor/…" is treated as a module specifier and rejected at runtime, so the import goes through new URL().
	ok('pdf.js is loaded from the bundled same-origin module, not a network CDN', /import\(new URL\('vendor\/pdfjs\/pdf\.min\.mjs',\s*document\.baseURI\)\.href\)/.test(app) && /workerSrc\s*=\s*new URL\('vendor\/pdfjs\/pdf\.worker\.min\.mjs'/.test(app));
	// pdf.js must decode ONLY our bytes: no embedded-PDF JavaScript (isEvalSupported:false) and no network fetch of its
	// own (disableAutoFetch/disableStream). A regression here would let a hostile PDF reach out or run code.
	ok('the PDF is decoded offline with embedded scripting disabled', /isEvalSupported:\s*false[\s\S]{0,80}disableAutoFetch:\s*true[\s\S]{0,40}disableStream:\s*true/.test(app));
	// pdf.js spins up a Web Worker per document. Closing the viewer must destroy it and disconnect the page observer, or
	// every PDF opened leaks an idle worker and its pages. Pin that a teardown disposing the document is registered and
	// that closing the viewer drains those teardowns.
	ok('closing the viewer tears down the PDF worker and observer', /viewerTeardowns\.push\(function \(\)[\s\S]{0,80}io\.disconnect\(\)[\s\S]{0,60}pdf\.destroy\(\)/.test(app) && /function closeViewer\([\s\S]{0,400}runViewerTeardowns\(\)/.test(app));

	// The worker reads that extension and uses it for the streamed 206's Content-Type (not the encrypted path).
	ok('the worker reads the extension from the stream URL query', /searchParams\.get\('e'\)/.test(sw));
	ok('the worker sets the 206 Content-Type from the extension', /Content-Type':\s*contentType\(ext\)/.test(sw));
	ok('the worker maps common media extensions to real MIME types', /mp4:\s*'video\/mp4'/.test(sw) && /mp3:\s*'audio\/mpeg'/.test(sw));

	// The shell fetch handler falls back to the network if the cache lookup itself rejects.
	ok('the shell fetch is network-first with a cache fallback only when the network fails (fresh code on next open)', /e\.respondWith\(\s*fetch\(req\)/.test(sw) && /\.catch\(function \(\) \{ return caches\.match\(req\)[\s\S]{0,120}Promise\.reject/.test(sw));

	// pdf.js runs its rendering in a WebAssembly module, so the mobile CSP must permit wasm compilation
	// ('wasm-unsafe-eval') in script-src — otherwise the worker throws and the PDF never paints. Guard that.
	const routes = read(path.join(__dirname, '..', 'webserver', 'mobileRoutes.js'));
	ok('the mobile CSP allows wasm-unsafe-eval (pdf.js can compile its WebAssembly)', /script-src[^;]*'wasm-unsafe-eval'/.test(routes));
	// The vendored pdf.js module and its worker must actually be present and whole — a botched re-vendor that leaves an
	// empty or truncated file would make every PDF fail to open. Both are minified builds hundreds of KiB in size, so a
	// generous floor catches a stub without being brittle about exact bytes.
	for (const f of ['pdf.min.mjs', 'pdf.worker.min.mjs']) {
		let size = 0; try { size = fs.statSync(path.join(mobile, 'vendor', 'pdfjs', f)).size; } catch (e) {}
		ok('the vendored pdf.js file "' + f + '" is present and not truncated', size > 100 * 1024);
	}
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
