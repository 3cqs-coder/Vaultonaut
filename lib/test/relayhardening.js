'use strict';
// lib/test/relayhardening.js — the relay HUB is designed to run on a public host, so its front door must be hard
// to abuse. This drives runHub with raw sockets and checks the defenses the relay test does not: the shared-token
// auth gate, the greeting-flood cap (a peer that sends a huge line with no newline is dropped, not buffered
// forever), an unknown verb is dropped, and the MAX_WORKERS pool cap (a token holder cannot open unlimited worker
// connections to exhaust the hub's memory and file descriptors). No engine, no vault — pure loopback TCP.
//
// (The 8-second slow-greeting TIMEOUT is a real defense but too slow to exercise in the suite; it shares the same
// readGreeting path this test drives via the flood cap.)
//
// Run:  node lib/test/relayhardening.js

const net = require('net');
const Relay = require('../Relay');
const Serve = require('../Serve');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Send `data`, resolve with the first line the hub replies (or '' if it closes with no reply).
function exchange(port, data) {
	return new Promise((resolve) => {
		const s = net.connect({ host: '127.0.0.1', port }, () => s.write(data));
		let buf = ''; let settled = false;
		const finish = (v) => { if (settled) return; settled = true; try { s.destroy(); } catch (_) {} resolve(v); };
		s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) finish(buf.slice(0, nl)); });
		s.once('close', () => finish(buf.trim()));
		s.once('error', () => finish(''));
		setTimeout(() => finish(buf.trim()), 3000);
	});
}

async function main() {
	const controlPort = await Serve.freePort();
	const pub = await Serve.freePort();
	const TOKEN = 'sekret-relay-token';
	const hub = Relay.runHub({ controlPort, token: TOKEN, host: '127.0.0.1', portRange: [pub, pub] });
	await sleep(150); // let the control listener bind

	try {
		// --- auth gate ---
		ok('a wrong token is rejected with ERR auth', /^ERR auth/.test(await exchange(controlPort, 'HELLO wrong-token node1\n')));
		ok('a valid HELLO registers and is assigned a public port', /^OK \d+$/.test(await exchange(controlPort, 'HELLO ' + TOKEN + ' node1\n')));
		// --- unknown verb is dropped (no reply, socket closed) ---
		ok('an unknown verb is dropped without a reply', (await exchange(controlPort, 'BOGUS ' + TOKEN + ' node1\n')) === '');

		// --- greeting flood: a huge line with no newline is dropped promptly (not buffered, not held to the timeout) ---
		const floodClosedFast = await new Promise((resolve) => {
			const s = net.connect({ host: '127.0.0.1', port: controlPort }, () => s.write('X'.repeat(2000))); // > GREETING_MAX, no '\n'
			const t0 = Date.now();
			s.once('close', () => resolve(Date.now() - t0 < 2000)); // must be dropped well within the 8s timeout
			s.once('error', () => resolve(true));
			setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(false); }, 2500);
		});
		ok('a greeting flood (no newline, over the cap) is dropped promptly', floodClosedFast);

		// --- MAX_WORKERS cap: register a node, then open more workers than the cap; the surplus must be dropped ---
		const control = net.connect({ host: '127.0.0.1', port: controlPort }); // keep this registration open for the workers
		await new Promise((res) => { control.on('connect', () => { control.write('HELLO ' + TOKEN + ' node2\n'); }); control.once('data', () => res()); });
		const N = 70; // MAX_WORKERS is 64
		const socks = [];
		let closedByHub = 0;
		for (let i = 0; i < N; i++) {
			const w = net.connect({ host: '127.0.0.1', port: controlPort });
			w.on('connect', () => { try { w.write('WORKER ' + TOKEN + ' node2\n'); } catch (_) {} });
			w.once('close', () => { closedByHub++; });
			w.once('error', () => {});
			socks.push(w);
		}
		await sleep(1200); // let the hub read every greeting and pool/drop each worker
		const stillOpen = socks.filter(w => !w.destroyed && w.readyState !== 'closed').length;
		ok('the surplus workers over the cap are dropped', closedByHub >= (N - 64));
		ok('no more than MAX_WORKERS worker connections are kept', stillOpen <= 64);
		for (const w of socks) { try { w.destroy(); } catch (_) {} }
		try { control.destroy(); } catch (_) {}

		// --- reconnect churn: a node on a flaky link often reconnects on a NEW control socket before the hub has seen
		//     the OLD socket's FIN. The hub replaces the old registration with the new one; the old socket's LATE close
		//     event must NOT tear down the freshly reconnected node (the close/error handlers are identity-guarded). If
		//     it did, a node would be dropped the instant it reconnects and churn endlessly on exactly the unreliable
		//     links this relay serves. Register the same node id twice, then confirm the second registration's public
		//     port is still listening after the first socket's late close fires. ---
		const hello = (nodeId) => new Promise((resolve) => {
			const s = net.connect({ host: '127.0.0.1', port: controlPort }, () => s.write('HELLO ' + TOKEN + ' ' + nodeId + '\n'));
			let buf = '';
			s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { const m = /^OK (\d+)/.exec(buf.slice(0, nl)); resolve({ sock: s, port: m ? Number(m[1]) : 0 }); } });
			s.once('error', () => resolve({ sock: s, port: 0 }));
			setTimeout(() => resolve({ sock: s, port: 0 }), 3000);
		});
		const canConnect = (p) => new Promise((resolve) => {
			if (!p) { resolve(false); return; }
			const c = net.connect({ host: '127.0.0.1', port: p }, () => { c.destroy(); resolve(true); });
			c.once('error', () => resolve(false));
			setTimeout(() => { try { c.destroy(); } catch (_) {} resolve(false); }, 1500);
		});
		const first = await hello('node3');
		const second = await hello('node3'); // reconnect: same id, new socket → the hub drops `first` and installs this one
		await sleep(300);                    // let the hub's destroy of `first` fire its (guarded) stale close handler
		ok('a reconnected node is assigned a valid public port', second.port > 0);
		ok('the reconnected node survives the old socket\'s late close (no churn teardown)', await canConnect(second.port));
		try { first.sock.destroy(); } catch (_) {}
		try { second.sock.destroy(); } catch (_) {}
	} finally { hub.close(); }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-HARDENING CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
