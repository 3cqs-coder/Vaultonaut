'use strict';
// lib/webserver/mobileRoutes.js — the /m Express router for mobile access. Factored out of the main web
// server so the exact routing (bearer auth, one-time pairing, ciphertext listing, Range streaming, path
// containment, the mobile-specific security headers) can be exercised directly by a test as well as by the
// running server. It is thin glue over lib/Mobile.js, which owns the session logic and the fail-closed rules.
//
// It is mounted BEFORE the UI login gate, but it is not an un-gated hole: every DATA route carries its own
// mandatory bearer auth. The static app shell it also serves is client code only, safe without the bearer.

const express = require('express');
const path = require('path');
const Mobile = require('../Mobile');
const Brand = require('../Brand');
const Common = require('../Common');

// The Host header's hostname, parsed the ONE shared, DNS-safe way every security gate in the app uses, so the /m
// router can never disagree with the main /api gate about what counts as loopback.
const hostOf = (req) => Common.splitHostPort(req.headers.host || '').host;

// Build the router. `mobileDir` is the folder of PWA assets; `isLoopbackAddr` and `exposed` come from the
// host server so the Host-allowlist (DNS-rebinding) defense matches the rest of the interface.
function buildRouter({ mobileDir, isLoopbackAddr, exposed } = {}) {
	const mobile = express.Router();

	mobile.use((req, res, next) => {
		if (!exposed) {
			if (isLoopbackAddr && !isLoopbackAddr(hostOf(req))) return res.status(403).type('text').send('Forbidden');
		}
		// The app shell needs a few capabilities the main UI forbids — the camera (to scan a pairing QR),
		// blob URLs and workers (to render decrypted bytes in memory), and WASM (the QR decoder) — so it
		// sets its own strict-but-wider policy here, overriding the global headers already set upstream.
		// frame-src blob: lets the viewer preview a decrypted PDF in an <iframe src="blob:…"> — without it the frame
		// falls back to default-src 'self', which excludes blob:, and the PDF preview silently shows a blank frame.
		// The crypto libraries are pure JS and there is no WebAssembly or in-app camera use (pairing uses the phone's
		// native camera to open the URL), so grant neither 'wasm-unsafe-eval' nor camera — keeping the surface minimal.
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
		res.setHeader('X-Content-Type-Options', 'nosniff');
		res.setHeader('Referrer-Policy', 'no-referrer');
		res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
		res.setHeader('Cache-Control', 'no-store');
		next();
	});

	const bearerOf = (req) => { const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || ''); return m ? m[1].trim() : ''; };

	// The product name and the web-app manifest, rendered from the single-sourced brand so nothing hardcodes
	// the name. Both are open (they carry no secret) and are declared before the static mount so they win.
	mobile.get('/config', (req, res) => res.json({ name: Brand.name }));
	mobile.get('/manifest.webmanifest', (req, res) => {
		res.type('application/manifest+json');
		res.json({
			name: Brand.name + ' viewer', short_name: Brand.name, start_url: './', scope: './', display: 'standalone',
			background_color: '#0e1117', theme_color: '#0e1117', orientation: 'any',
			icons: [
				{ src: './icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
				{ src: './icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
				{ src: './icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' },
			],
		});
	});

	// Redeem a one-time pairing code for the read cap + bearer. Fail-closed: unknown/expired/used -> 401.
	// Per-IP backoff (mirroring the desktop login gate) throttles guessing: the code is short-lived and single-use,
	// so this is defense-in-depth, but it keeps an exposed /pair from being hammered. Loopback is exempt (the local
	// in-app viewer redeems its own code and never guesses). The map is bounded.
	const pairFails = Common.failureBackoff(); // per-IP online-guessing backoff, shared with the desktop login gate
	mobile.post('/pair', (req, res) => {
		const ip = (req.socket && req.socket.remoteAddress) || 'unknown';
		// The throttle exemption for the local in-app viewer keys off the real SOCKET PEER, never the Host header:
		// on an exposed bind the Host header is attacker-controlled, so deciding "local" from it would let a remote
		// client send "Host: 127.0.0.1" to skip the per-IP guessing throttle. The socket address cannot be spoofed
		// that way. Fail-secure: an unrecognized/IPv4-mapped loopback peer simply gets the throttle too (harmless —
		// the real local viewer redeems a valid code once and never guesses).
		const local = isLoopbackAddr && isLoopbackAddr(ip);
		const now = Date.now();
		if (!local && pairFails.blocked(ip, now)) return res.status(429).json({ ok: false, error: 'Too many attempts — wait a moment and try again.' });
		const r = Mobile.redeem((req.body || {}).code);
		if (!r) {
			if (!local) pairFails.fail(ip, now);
			return res.status(401).json({ ok: false, error: 'That pairing code is not valid or has already been used. Start mobile access again on the desktop.' });
		}
		pairFails.clear(ip);
		res.json({ ok: true, cap: r.cap, token: r.bearer, name: r.name, base: r.base, list: r.list, sessionId: r.sessionId, local: !!r.local });
	});
	// End a session now. Used by the viewer's Lock button and — for a LOCAL in-app session — automatically when
	// its tab closes, so the decryption key does not linger in memory for the rest of the TTL. Authorized by the
	// bearer, accepted from the header (fetch) OR the JSON body (navigator.sendBeacon on tab close cannot set headers).
	mobile.post('/stop', (req, res) => {
		const body = req.body || {};
		const sid = String(body.sessionId || '');
		const bearer = bearerOf(req) || String(body.bearer || '');
		if (!Mobile.authorize(sid, bearer)) return res.status(401).type('text').send('Unauthorized');
		Mobile.stop(sid);
		res.json({ ok: true });
	});
	// List a session's encrypted files (names stay encrypted; the phone decrypts them locally).
	mobile.get('/list/:sid', async (req, res) => {
		const s = Mobile.authorize(req.params.sid, bearerOf(req));
		if (!s) return res.status(401).type('text').send('Unauthorized');
		try { res.json({ ok: true, files: await Mobile.list(s) }); }
		catch (_) { res.status(500).json({ ok: false, error: 'Could not list the vault.' }); }
	});
	// Stream one ciphertext file, Range handled by the battle-tested static sender. The session id is hex and
	// the rest is the encrypted relative path; containment is enforced in Mobile.resolveFile.
	mobile.get(/^\/files\/([0-9a-f]+)\/(.+)$/, async (req, res) => {
		const s = Mobile.authorize(req.params[0], bearerOf(req));
		if (!s) return res.status(401).type('text').send('Unauthorized');
		let rel;
		try { rel = decodeURIComponent(req.params[1]); }
		catch (e) { Common.warn('viewer: bad percent-encoding in a file path — ' + (e && e.message)); return res.status(404).type('text').send('Not found'); }
		let target;
		try { target = await Mobile.resolveFile(s, rel); }
		catch (e) { Common.warn('viewer: could not open a file (' + rel.split('/').length + ' path segment(s)) — ' + (e && e.message)); return res.status(404).type('text').send('Not found'); }
		res.setHeader('Content-Type', 'application/octet-stream');
		// dotfiles:'allow' is REQUIRED, not cosmetic: on Linux the per-user data dir is under ~/.local/share, and
		// res.sendFile defaults to dotfiles:'ignore', which 404s ANY path with a dot-directory component (".local")
		// — so a perfectly valid file failed to send there while it worked on Windows/macOS (no dot component). The
		// path is already contained and confirmed a real file by Mobile.resolveFile, so serving it is safe.
		res.sendFile(target.abs, { dotfiles: 'allow', acceptRanges: true, cacheControl: false, headers: { 'Cache-Control': 'no-store' } }, (err) => { if (err) { if (!res.headersSent) res.status(404).type('text').send('Not found'); Common.warn('viewer: could not send a resolved file — ' + (err && err.message)); } });
	});
	// Media streaming is served ENTIRELY by the service worker (it fetches ciphertext from /m/files and decrypts
	// each Range in the browser — the host never decrypts). A request that reaches THIS route means the worker did
	// not intercept it (e.g. iOS Safari bypasses the worker for a media element's Range requests) and, coming from a
	// media element, it cannot carry the bearer anyway. Answer with a clear, non-HTML error so the client falls back
	// to a full in-memory decrypt, rather than letting the SPA route below return index.html as if it were media.
	mobile.get(/^\/stream\//, (req, res) => res.status(415).type('text').send('Media streaming is handled in the app; this file will be opened another way.'));
	// The app shell (index.html, app.js, sw.js, manifest, the reader, the vendored primitives).
	if (mobileDir) {
		// Serve the service worker with the app version injected, so its cache name changes every release and an
		// installed PWA picks up an updated (or security-fixed) shell at once rather than a load later. Declared BEFORE
		// the static mount so it wins over the raw file; no-store so the worker file itself is always revalidated.
		const swVersion = (() => { try { return 'v-' + String(require('../../package.json').version || 'dev'); } catch (_) { return 'dev'; } })();
		let swBody = null; try { swBody = require('fs').readFileSync(path.join(mobileDir, 'sw.js'), 'utf8'); } catch (_) {}
		// Register the injecting route ONLY when the file was actually read: otherwise a transient boot-time read
		// failure would leave this route serving a permanent 404 and mask the good on-disk sw.js (disabling the service
		// worker until restart) — falling through to express.static is the safe degrade. Keep "use strict" the FIRST
		// statement so the injected line does not demote the worker's own directive to a no-op (sloppy mode).
		if (swBody != null) mobile.get('/sw.js', (req, res) => { res.type('application/javascript'); res.setHeader('Cache-Control', 'no-store'); res.send('"use strict";self.__SHELL_VERSION=' + JSON.stringify(swVersion) + ';\n' + swBody); });
		mobile.use(express.static(mobileDir, { index: 'index.html', extensions: ['html'] }));
		mobile.get(/^\/(?:$|[^.]*$)/, (req, res) => res.sendFile(path.join(mobileDir, 'index.html'), { dotfiles: 'allow' })); // SPA fallback; dotfiles:'allow' so a dot-directory install path never 404s the shell
	}
	return mobile;
}

module.exports = { buildRouter };
