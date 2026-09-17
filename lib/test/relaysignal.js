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

// Send a one-line SIGNAL greeting `SIGNAL <token> <nodeId> <blob>` and resolve the hub's first reply line: the routed
// answer's blob (from a `SIGNAL <blob>` line), or the raw error line prefixed with '__' (e.g. '__ERR no node').
function signalExchange(port, token, nodeId, blob, timeoutMs = 4000) {
	return new Promise((resolve) => {
		const s = net.connect({ host: '127.0.0.1', port });
		let buf = '', settled = false;
		const finish = (v) => { if (settled) return; settled = true; try { s.destroy(); } catch (_) {} resolve(v); };
		s.on('connect', () => { try { s.write('SIGNAL ' + token + ' ' + nodeId + ' ' + blob + '\n'); } catch (_) {} });
		s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { const line = buf.slice(0, nl).trim(); const sp = line.indexOf(' '); finish(sp >= 0 && line.slice(0, sp) === 'SIGNAL' ? line.slice(sp + 1) : ('__' + line)); } });
		s.once('error', () => finish(null));
		const t = setTimeout(() => finish(null), timeoutMs); if (t.unref) t.unref();
	});
}

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

		// 6. SIGNAL routing (the hole-punch coordination path): a client's offer blob is forwarded to a LIVE node's
		//    control socket, and the node's answer is routed straight back to the client. Register a real node whose
		//    onSignal echoes a transformed blob, then run a client SIGNAL exchange against it.
		{
			const localSrv = net.createServer(() => {}); // a dummy local "serve" the node registers; unused by signaling
			await new Promise((r) => localSrv.listen(0, '127.0.0.1', r));
			const localPort = localSrv.address().port;
			let seenBlob = null, sawReply = false;
			const node = Relay.registerNode({
				hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'sig-node', localPort,
				onSignal: ({ blob, reply }) => { seenBlob = blob; sawReply = true; reply('ACKx' + blob); },
			});
			await node.ready;
			const reply = await signalExchange(cport, TOKEN, 'sig-node', 'b64offerblob');
			ok('a SIGNAL offer reaches the target node and its answer is routed back to the client', reply === 'ACKxb64offerblob' && seenBlob === 'b64offerblob' && sawReply === true);

			// A SIGNAL for an unknown node is refused (no node to route to), so the client is not left hanging.
			const noNode = await signalExchange(cport, TOKEN, 'no-such-node', 'b64offerblob');
			ok('a SIGNAL for an unknown node returns ERR (no hang)', noNode === '__ERR no node');

			// SIGNAL is token-authed like every other verb: a wrong token is rejected before any routing.
			const badTok = await signalExchange(cport, 'wrong-token-abcdefghij', 'sig-node', 'b64offerblob');
			ok('a SIGNAL with a wrong token is rejected (authenticated)', badTok === '__ERR auth');

			node.stop(); localSrv.close();
		}
	} finally { try { hub.close(); } catch (_) {} }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-SIGNAL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
