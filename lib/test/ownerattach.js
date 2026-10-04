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
const Common = require('../Common');
const OWNER_TOKEN_HEADER = Common.OWNER_TOKEN_HEADER; // single-sourced; the sender and the real checker must agree on it

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const SECRET = 'a'.repeat(64); // stand-in for the 32-byte hex owner token

// A stub that mimics the real /__owner-check: 200 only when the header carries the exact secret, 404 otherwise, and
// it NEVER puts the secret in its response. Records what it saw so the test can confirm the client's request shape.
function startStub() {
	let seenPath = null, seenHeader = null;
	return new Promise((resolve) => {
		const srv = http.createServer((req, res) => {
			seenPath = req.url; seenHeader = req.headers[OWNER_TOKEN_HEADER] || null;
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
		ok('the client requested /__owner-check with the secret in the owner-token header', stub.seen().seenPath === '/__owner-check' && stub.seen().seenHeader === SECRET);
		ok('verifyOwner returns false for a wrong secret (server answers 404)', (await OwnerClient.verifyOwner(url, 'b'.repeat(64))) === false);
		ok('verifyOwner returns false when no token is known (no request made)', (await OwnerClient.verifyOwner(url, null)) === false);
		ok('verifyOwner returns false for a non-loopback address (never probed)', (await OwnerClient.verifyOwner('http://example.com/', SECRET)) === false);
		ok('verifyOwner returns false for a non-http (TLS) address', (await OwnerClient.verifyOwner('https://127.0.0.1:' + stub.port + '/', SECRET)) === false);
	} finally {
		stub.srv.close();
	}
	// An unreachable loopback port fails closed (nothing is listening on the closed port). Bounded by verifyOwner's timeout.
	ok('verifyOwner returns false when the server is unreachable', (await OwnerClient.verifyOwner('http://127.0.0.1:' + stub.port + '/', SECRET)) === false);

	// clearStalePid: a leftover pidfile must never lock out a fresh start when its owner is dead OR alive-but-wedged
	// (serving nothing), yet must never disturb a healthy instance that still answers. This is what frees a user whose
	// cloud copy wedged a mount and left the service stuck, so `ui` kept refusing with "already running".
	const fs = require('fs'), fsp = fs.promises, os = require('os'), path = require('path');
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-ownerlock-'));
	const origRunDir = Common.runDir;
	Common.runDir = () => tmp;
	const pidFile = path.join(tmp, 'service.pid');
	try {
		// 1) A pidfile pointing at a DEAD pid is stale → removed.
		const deadPid = 2147480000; // not a live process
		await fsp.writeFile(pidFile, JSON.stringify({ pid: deadPid, url: 'http://127.0.0.1:1/', token: SECRET }));
		ok('clearStalePid removes a pidfile whose process is dead', (await OwnerClient.clearStalePid()) === true && !fs.existsSync(pidFile));
		// 2) A pidfile pointing at an ALIVE pid that does NOT answer (wedged) is stale → removed. Use THIS process's pid
		//    (certainly alive) with a url nothing serves, standing in for a wedged owner that cannot answer its check.
		await fsp.writeFile(pidFile, JSON.stringify({ pid: process.pid, url: 'http://127.0.0.1:1/', token: SECRET }));
		ok('clearStalePid removes a pidfile whose process is alive but wedged (no answer)', (await OwnerClient.clearStalePid()) === true && !fs.existsSync(pidFile));
		// 3) A pidfile pointing at a HEALTHY owner (alive pid + answers its owner-check) is kept.
		const live = await startStub();
		await fsp.writeFile(pidFile, JSON.stringify({ pid: process.pid, url: 'http://127.0.0.1:' + live.port + '/', token: SECRET }));
		const kept = (await OwnerClient.clearStalePid()) === false && fs.existsSync(pidFile);
		live.srv.close();
		ok('clearStalePid KEEPS a pidfile whose owner still answers (a healthy instance is never disturbed)', kept);
		// 4) No pidfile at all is a no-op.
		await fsp.unlink(pidFile).catch(() => {});
		ok('clearStalePid is a no-op when there is no pidfile', (await OwnerClient.clearStalePid()) === false);
	} finally {
		Common.runDir = origRunDir;
		try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OWNER-ATTACH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
