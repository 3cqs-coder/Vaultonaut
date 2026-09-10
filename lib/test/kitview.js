'use strict';
// lib/test/kitview.js — the one-time Recovery Kit view endpoint (lib/webserver/kitView.js). A kit can carry a
// one-time recovery key, so it must be served EXACTLY ONCE, never persisted, and under its own kit-appropriate CSP
// (so the self-contained kit's inline styles render, while scripts stay blocked). This drives the real handler over a
// real socket: a fresh token serves the kit once, a second use is refused, an unknown token is refused, and an
// expired token is refused — and the security headers are exactly what the kit needs and nothing more.
//
// Run:  node lib/test/kitview.js

const express = require('express');
const { createKitView } = require('../webserver/kitView');

let failures = 0, server = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// A controllable clock so expiry is exercised without waiting.
	let clock = 1_000_000;
	const kit = createKitView({ ttlMs: 60_000, now: () => clock });

	const app = express();
	app.get('/kit-view', kit.handler);
	await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); });
	const port = server.address().port;
	const get = (token) => fetch('http://127.0.0.1:' + port + '/kit-view' + (token === undefined ? '' : '?token=' + encodeURIComponent(token)));

	const html = '<!doctype html><style>body{color:red}</style><body>KIT-SECRET-KEY</body>';
	const token = kit.stash(html);
	ok('stash returns a non-trivial token', typeof token === 'string' && token.length >= 20);
	ok('a stashed kit is held (size 1)', kit._size() === 1);

	// First view: served once, correct body, kit CSP that permits inline styles but not scripts, no-store.
	const r1 = await get(token);
	const body1 = await r1.text();
	ok('a valid token serves the kit (HTTP 200)', r1.status === 200);
	ok('the served body is exactly the kit HTML', body1 === html);
	const csp = r1.headers.get('content-security-policy') || '';
	ok('the CSP permits the kit\'s inline styles', /style-src\s+'unsafe-inline'/.test(csp));
	ok('the CSP blocks scripts (default-src none, no script-src)', /default-src\s+'none'/.test(csp) && !/script-src/.test(csp));
	ok('the CSP allows only data: images (the kit\'s QR)', /img-src\s+data:/.test(csp));
	ok('the response is not cached', /no-store/.test(r1.headers.get('cache-control') || ''));
	ok('nosniff is set', (r1.headers.get('x-content-type-options') || '') === 'nosniff');
	ok('the kit is dropped from memory after it is viewed (size 0)', kit._size() === 0);

	// Second use of the SAME token: refused (one-time), and never re-serves the key.
	const r2 = await get(token);
	const body2 = await r2.text();
	ok('a second use of the same token is refused (HTTP 410)', r2.status === 410);
	ok('the refused response does not contain the kit secret', !body2.includes('KIT-SECRET-KEY'));

	// An unknown/guessed token is refused and reveals nothing.
	const r3 = await get('not-a-real-token');
	ok('an unknown token is refused (HTTP 410)', r3.status === 410);

	// A missing token is refused (no 500, no crash).
	const r4 = await get(undefined);
	ok('a missing token is refused (HTTP 410), never a crash', r4.status === 410);

	// Expiry: a token not opened within its TTL is refused, and pruned.
	const t2 = kit.stash(html);
	ok('a second kit is stashed', kit._size() === 1);
	clock += 60_001; // advance past the TTL
	const r5 = await get(t2);
	ok('an expired token is refused (HTTP 410)', r5.status === 410);

	return done();
}

function done() {
	if (server) try { server.close(); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KIT-VIEW CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); if (server) try { server.close(); } catch (_) {} process.exit(1); });
