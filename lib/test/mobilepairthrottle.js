'use strict';
// lib/test/mobilepairthrottle.js — the /m/pair per-IP backoff. The one-time pairing code is short and single-use,
// so this is defense-in-depth, but an EXPOSED mobile interface must not let /pair be hammered for guesses. After a
// run of bad codes from one address the route returns 429 instead of testing more. Loopback (the local in-app
// viewer, which redeems its own code) is exempt and is covered by mobilehttp.js. Uses the REAL router over a real
// socket in exposed mode; no engine or vault needed (an unknown code is rejected before any vault work).
//
// Run:  node lib/test/mobilepairthrottle.js

const express = require('express');
const MobileRoutes = require('../webserver/mobileRoutes');
const closeServersThenExit = require('./_exit'); // Windows-safe exit (drain sockets, await close) — avoids a libuv abort on process.exit()

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let server = null;
async function main() {
	const app = express();
	app.use(express.json());
	// Exposed mode with nothing treated as loopback, so the per-IP throttle is active (loopback is exempt).
	app.use('/m', MobileRoutes.buildRouter({ mobileDir: null, isLoopbackAddr: () => false, exposed: true }));
	await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); });
	const base = 'http://127.0.0.1:' + server.address().port;

	const pair = (code) => fetch(base + '/m/pair', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });

	// The first five bad codes are rejected with 401 (wrong code), not yet throttled.
	let all401 = true;
	for (let i = 0; i < 5; i++) { const r = await pair('bad-code-' + i); if (r.status !== 401) all401 = false; }
	ok('the first five bad codes are rejected with 401 (not yet throttled)', all401);

	// After the run of failures, further attempts from the same address are throttled with 429.
	const sixth = await pair('bad-code-5');
	ok('a further attempt is throttled with 429', sixth.status === 429);

	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-PAIR-THROTTLE CHECKS PASSED'));
	closeServersThenExit(failures ? 1 : 0, server); // Windows-safe: drain sockets and await close before exit (see _exit.js)
}

main().catch(e => { console.error(e); closeServersThenExit(1, server); });
