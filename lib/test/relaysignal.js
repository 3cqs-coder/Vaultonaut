'use strict';
// lib/test/relaysignal.js — Phase-2 relay signaling: the WHOAMI reflexive-address probe (Relay.reflexiveAddress).
// A node asks the hub what public address it is seen from, to advertise as a direct-connect candidate. Pure loopback
// TCP — no engine, no spawned binary, cross-platform. Follows the relay.js pattern (freePort + runHub on 127.0.0.1).
//
// Run:  node lib/test/relaysignal.js

const net = require('net');
const Relay = require('../Relay');
const Serve = require('../Serve');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const TOKEN = 'relay-signal-test-token-0123456789';

async function main() {
	const cport = await Serve.freePort();
	const pport = await Serve.freePort();
	const hub = Relay.runHub({ controlPort: cport, token: TOKEN, host: '127.0.0.1', portRange: [pport, pport] });
	try {
		// 1. A valid, token-authed WHOAMI returns the address the hub sees the node from (loopback here).
		const ip = await Relay.reflexiveAddress({ hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'node1', timeoutMs: 4000 });
		ok('reflexiveAddress returns the hub-observed source address for a valid token', ip === '127.0.0.1');

		// 2. WHOAMI is token-authed: a wrong token gets ERR (not an IP), so the probe resolves null — no reflexive leak.
		const bad = await Relay.reflexiveAddress({ hubHost: '127.0.0.1', hubPort: cport, token: 'wrong-token-abcdefghij', nodeId: 'node1', timeoutMs: 4000 });
		ok('reflexiveAddress returns null for a wrong token (WHOAMI is authenticated)', bad === null);

		// 3. Missing required fields fail closed without touching the network.
		ok('reflexiveAddress returns null when nodeId is missing', (await Relay.reflexiveAddress({ hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, timeoutMs: 300 })) === null);

		// 4. An OLDER hub (one that does not know WHOAMI) must not break a newer node: it closes the socket, and the
		//    probe degrades to null. Simulate that hub with a bare TCP server that reads a line and closes.
		const legacyPort = await Serve.freePort();
		const legacy = net.createServer((sock) => { sock.on('data', () => { try { sock.destroy(); } catch (_) {} }); });
		await new Promise((r) => legacy.listen(legacyPort, '127.0.0.1', r));
		const degraded = await Relay.reflexiveAddress({ hubHost: '127.0.0.1', hubPort: legacyPort, token: TOKEN, nodeId: 'node1', timeoutMs: 3000 });
		legacy.close();
		ok('reflexiveAddress degrades to null against an older hub that does not understand WHOAMI', degraded === null);

		// 5. An unreachable hub resolves null within the timeout (never hangs, never throws).
		const dead = await Serve.freePort(); // nothing is listening here
		const unreachable = await Relay.reflexiveAddress({ hubHost: '127.0.0.1', hubPort: dead, token: TOKEN, nodeId: 'node1', timeoutMs: 1500 });
		ok('reflexiveAddress resolves null for an unreachable hub (bounded, no hang)', unreachable === null);
	} finally { try { hub.close(); } catch (_) {} }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-SIGNAL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
