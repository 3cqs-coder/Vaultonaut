'use strict';
// lib/test/ownerattach.js — the owner-identity proof used by the desktop app's "attach to the already-running
// instance" handshake. Before the app SHOWS a running instance in its trusted window, it must confirm the server
// answering the loopback port genuinely holds the owner secret from the trusted pidfile — so a stale pidfile whose
// process id was reused, or any other process that merely holds the port, can never be shown as the vault. This
// drives OwnerClient.verifyOwner against a stub that implements the /__owner-check contract, and asserts it is
// strictly fail-closed: true ONLY when the exact secret is proven, false on a wrong/absent secret, a non-loopback or
// non-http address, or an unreachable server. A source guard (routeguards.js) pins the real endpoint's behavior.
//
// Run:  node lib/test/ownerattach.js

const http = require('http');
const OwnerClient = require('../OwnerClient');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const SECRET = 'a'.repeat(64); // stand-in for the 32-byte hex owner token

// A stub that mimics the real /__owner-check: 200 only when the header carries the exact secret, 404 otherwise, and
// it NEVER puts the secret in its response. Records what it saw so the test can confirm the client's request shape.
function startStub() {
	let seenPath = null, seenHeader = null;
	return new Promise((resolve) => {
		const srv = http.createServer((req, res) => {
			seenPath = req.url; seenHeader = req.headers['x-vaultonaut-owner'] || null;
			if (req.url === '/__owner-check' && seenHeader === SECRET) { res.end(JSON.stringify({ ok: true })); }
			else { res.statusCode = 404; res.end(); }
		});
		srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port, seen: () => ({ seenPath, seenHeader }) }));
	});
}

async function main() {
	const stub = await startStub();
	const url = 'http://127.0.0.1:' + stub.port;
	try {
		ok('verifyOwner returns true when the server proves the exact secret', (await OwnerClient.verifyOwner(url, SECRET)) === true);
		ok('the client requested /__owner-check with the secret in the x-vaultonaut-owner header', stub.seen().seenPath === '/__owner-check' && stub.seen().seenHeader === SECRET);
		ok('verifyOwner returns false for a wrong secret (server answers 404)', (await OwnerClient.verifyOwner(url, 'b'.repeat(64))) === false);
		ok('verifyOwner returns false when no token is known (no request made)', (await OwnerClient.verifyOwner(url, null)) === false);
		ok('verifyOwner returns false for a non-loopback address (never probed)', (await OwnerClient.verifyOwner('http://example.com/', SECRET)) === false);
		ok('verifyOwner returns false for a non-http (TLS) address', (await OwnerClient.verifyOwner('https://127.0.0.1:' + stub.port + '/', SECRET)) === false);
	} finally {
		stub.srv.close();
	}
	// An unreachable loopback port fails closed (nothing is listening on the closed port). Bounded by verifyOwner's timeout.
	ok('verifyOwner returns false when the server is unreachable', (await OwnerClient.verifyOwner('http://127.0.0.1:' + stub.port + '/', SECRET)) === false);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OWNER-ATTACH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
