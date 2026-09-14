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
// A VALID ascending, contiguous public-port range from a single free base port. Building a range from two independent
// freePort() calls can come back inverted (lo > hi) — order-dependent across machines — which breaks allocPort; and a
// sparse two-port range can include an occupied port between them. A contiguous span with headroom is robust: allocPort
// hashes into it and falls back to the next free port, so a couple of nodes always bind.
async function freeRange(span = 6) { const base = await Serve.freePort(); return [base, base + span - 1]; }

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

		// --- minimum token length: the token is the ONLY control-plane gate on a public hub, so the hub refuses to
		//     run with a guessably-short one. ---
		let shortThrew = false;
		try { Relay.runHub({ controlPort: await Serve.freePort(), token: 'short', host: '127.0.0.1' }); } catch (_) { shortThrew = true; }
		ok('the hub refuses to run with a token shorter than the minimum', shortThrew && Relay.MIN_TOKEN_LEN >= 16);

		// --- node-ID hijack refusal: a node registers with a per-node TAG; another party who knows the shared token
		//     but not the node's secret CANNOT evict it. A HELLO for the live nodeId with a mismatched tag is refused
		//     (ERR nodeid in use) and the original stays live; only the SAME tag (the real node reconnecting) replaces. ---
		function helloKeep(nodeId, tag) {
			return new Promise((resolve) => {
				const s = net.connect({ host: '127.0.0.1', port: controlPort }, () => s.write('HELLO ' + TOKEN + ' ' + nodeId + (tag ? ' ' + tag : '') + '\n'));
				let buf = '';
				s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) { const m = /^OK (\d+)/.exec(buf.slice(0, nl)); resolve({ sock: s, port: m ? Number(m[1]) : 0, reply: buf.slice(0, nl) }); } });
				s.once('error', () => resolve({ sock: s, port: 0, reply: '' }));
				setTimeout(() => resolve({ sock: s, port: 0, reply: buf.trim() }), 3000);
			});
		}
		const canReach = (p) => new Promise((resolve) => { if (!p) { resolve(false); return; } const c = net.connect({ host: '127.0.0.1', port: p }, () => { c.destroy(); resolve(true); }); c.once('error', () => resolve(false)); setTimeout(() => { try { c.destroy(); } catch (_) {} resolve(false); }, 1500); });
		// Like helloKeep but against an arbitrary hub port, keeping the control socket open so the registration stays live.
		function helloKeep2(port, nodeId, tag) {
			return new Promise((resolve) => {
				const s = net.connect({ host: '127.0.0.1', port }, () => s.write('HELLO ' + TOKEN + ' ' + nodeId + (tag ? ' ' + tag : '') + '\n'));
				let buf = '';
				s.on('data', (d) => { buf += d; const nl = buf.indexOf('\n'); if (nl >= 0) resolve({ sock: s, reply: buf.slice(0, nl) }); });
				s.once('error', () => resolve({ sock: s, reply: '' }));
				setTimeout(() => resolve({ sock: s, reply: buf.trim() }), 3000);
			});
		}
		const TAG = 'a'.repeat(64); // stands in for HMAC(nodeAuth, nodeId); the hub records it TOFU and requires it to match
		const victim = await helloKeep('htarget', TAG);
		ok('a node registers with a per-node tag', /^OK \d+$/.test(victim.reply));
		const hijack = await exchange(controlPort, 'HELLO ' + TOKEN + ' htarget ' + 'b'.repeat(64) + '\n'); // same id, WRONG tag
		ok('a HELLO for a live node with a wrong tag is refused (no eviction)', /^ERR nodeid in use/.test(hijack));
		ok('the original node is still live after the hijack attempt', await canReach(victim.port));
		const noTagHijack = await exchange(controlPort, 'HELLO ' + TOKEN + ' htarget\n'); // a tagless (legacy) HELLO cannot evict a tagged node either
		ok('a tagless HELLO cannot evict a tagged live node', /^ERR nodeid in use/.test(noTagHijack));
		const reconnect = await helloKeep('htarget', TAG); // the REAL node reconnecting (same tag) is accepted and replaces
		ok('the same node (matching tag) reconnects successfully', /^OK \d+$/.test(reconnect.reply));
		try { victim.sock.destroy(); } catch (_) {} try { reconnect.sock.destroy(); } catch (_) {}

		// --- WORKER-tag binding: a WORKER connection must prove the SAME per-node tag as the node's live registration,
		//     so a party with only the shared token cannot attach worker connections to (and carry client traffic for)
		//     a node identity that is not theirs. A wrong-tag WORKER is destroyed (no GO, not pooled); a right-tag one
		//     is pooled and stays open. This is a SEPARATE code path from the HELLO hijack refusal above. ---
		const wtarget = await helloKeep('wtarget', TAG);
		ok('a fresh node registers with a tag (for the WORKER-tag test)', /^OK \d+$/.test(wtarget.reply));
		// Returns true if the hub keeps the WORKER socket open (pooled), false if it destroys it (rejected).
		function workerStaysOpen(nodeId, tag) {
			return new Promise((resolve) => {
				const w = net.connect({ host: '127.0.0.1', port: controlPort }, () => w.write('WORKER ' + TOKEN + ' ' + nodeId + (tag ? ' ' + tag : '') + '\n'));
				let closed = false;
				w.once('close', () => { closed = true; resolve(false); });
				w.once('error', () => { closed = true; resolve(false); });
				setTimeout(() => { if (!closed) { try { w.destroy(); } catch (_) {} resolve(true); } }, 700); // still open after the grace -> pooled (accepted)
			});
		}
		ok('a WORKER with a WRONG tag for a live node is destroyed (not pooled)', (await workerStaysOpen('wtarget', 'c'.repeat(64))) === false);
		ok('a tagless WORKER for a tagged live node is destroyed', (await workerStaysOpen('wtarget', '')) === false);
		ok('a WORKER with the MATCHING tag is accepted and pooled', (await workerStaysOpen('wtarget', TAG)) === true);
		try { wtarget.sock.destroy(); } catch (_) {}

		// --- per-IP failed-auth throttle: after enough wrong-token attempts from one source, that source is blocked
		//     for a cooldown, so the shared token cannot be brute-forced by unbounded serial reconnects. Uses an
		//     ISOLATED hub so blocking loopback does not poison the other tests on the main hub. ---
		{
			const cpRL = await Serve.freePort();
			const hubRL = Relay.runHub({ controlPort: cpRL, token: TOKEN, host: '127.0.0.1', portRange: await freeRange(6) });
			await sleep(120);
			try {
				let lastErr = '';
				for (let i = 0; i < Relay.AUTH_FAIL_MAX; i++) lastErr = await exchange(cpRL, 'HELLO wrong-token n\n');
				ok('wrong-token attempts up to the ceiling are answered with ERR auth', /^ERR auth/.test(lastErr));
				// Now over the ceiling: further connections from this IP are dropped outright (no reply), and even a
				// VALID token is refused during the cooldown.
				const blocked = await exchange(cpRL, 'HELLO ' + TOKEN + ' after-block\n');
				ok('after too many failures the source is blocked (even a valid token gets no registration)', blocked === '' || !/^OK /.test(blocked));
			} finally { hubRL.close(); }
		}

		// --- node-count caps: a token holder cannot register unlimited node ids and exhaust the public port range.
		//     Test the total cap and the per-IP cap on isolated hubs with tiny injected limits. ---
		{
			const cpTot = await Serve.freePort();
			const hubTot = Relay.runHub({ controlPort: cpTot, token: TOKEN, host: '127.0.0.1', portRange: await freeRange(6), maxNodes: 2 });
			await sleep(120);
			try {
				const a = await helloKeep2(cpTot, 'c1'), b = await helloKeep2(cpTot, 'c2');
				ok('registrations up to the total-node cap succeed', /^OK \d+/.test(a.reply) && /^OK \d+/.test(b.reply));
				const over = await exchange(cpTot, 'HELLO ' + TOKEN + ' c3\n');
				ok('a new node past the total-node cap is refused (ERR hub full)', /^ERR hub full/.test(over));
				try { a.sock.destroy(); } catch (_) {} try { b.sock.destroy(); } catch (_) {}
			} finally { hubTot.close(); }

			const cpIp = await Serve.freePort();
			const hubIp = Relay.runHub({ controlPort: cpIp, token: TOKEN, host: '127.0.0.1', portRange: await freeRange(6), maxNodes: 50, maxNodesPerIp: 2 });
			await sleep(120);
			try {
				const a = await helloKeep2(cpIp, 'p1'), b = await helloKeep2(cpIp, 'p2');
				ok('registrations up to the per-IP cap succeed', /^OK \d+/.test(a.reply) && /^OK \d+/.test(b.reply));
				const over = await exchange(cpIp, 'HELLO ' + TOKEN + ' p3\n');
				ok('a new node past the per-IP cap is refused (ERR too many nodes from this host)', /too many nodes/.test(over));
				try { a.sock.destroy(); } catch (_) {} try { b.sock.destroy(); } catch (_) {}
			} finally { hubIp.close(); }
		}

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

		// --- spliced-connection idle timeout: a spliced connection with NO data in either direction is reaped, so a
		//     client that reaches a node's public port and then idles cannot tie up a pooled worker forever; ANY data
		//     resets the clock so a slow-but-active transfer is never cut. Exercise splice() directly (loopback sockets,
		//     no vault) with a tiny idle window. ---
		function splicedPair(idleMs) {
			return new Promise((resolve) => {
				const srv = net.createServer();
				const accepted = [];
				srv.listen(0, '127.0.0.1', () => {
					const p = srv.address().port;
					const ends = [];
					srv.on('connection', (s) => { accepted.push(s); if (accepted.length === 2) { Relay.splice(accepted[0], accepted[1], idleMs); resolve({ srv, ends }); } });
					ends.push(net.connect(p, '127.0.0.1'), net.connect(p, '127.0.0.1'));
				});
			});
		}
		{ // idle: no traffic -> both ends are closed soon after the idle window
			const { srv, ends } = await splicedPair(150);
			let closed = 0; ends.forEach(e => e.once('close', () => closed++));
			await sleep(500);
			ok('an idle spliced connection is reaped after its idle window', closed === 2);
			try { srv.close(); } catch (_) {} ends.forEach(e => { try { e.destroy(); } catch (_) {} });
		}
		{ // active: periodic data keeps it alive well past the idle window
			const { srv, ends } = await splicedPair(150);
			let closed = 0; ends.forEach(e => e.once('close', () => closed++));
			const beat = setInterval(() => { try { ends[0].write('x'); } catch (_) {} }, 50);
			await sleep(450); // three times the idle window
			clearInterval(beat);
			ok('an active spliced connection is NOT reaped while data flows (a slow transfer is never cut)', closed === 0);
			try { srv.close(); } catch (_) {} ends.forEach(e => { try { e.destroy(); } catch (_) {} });
		}

		// --- splice onEnd hook: fires EXACTLY once when the connection is reaped, so a caller can count concurrent
		//     live splices and release its slot. ---
		{
			const srv = net.createServer(); const acc = []; let ended = 0;
			await new Promise((res) => srv.listen(0, '127.0.0.1', res));
			const p = srv.address().port;
			await new Promise((res) => { srv.on('connection', (s) => { acc.push(s); if (acc.length === 2) { Relay.splice(acc[0], acc[1], 150, () => { ended++; }); res(); } }); net.connect(p, '127.0.0.1'); net.connect(p, '127.0.0.1'); });
			await sleep(500); // idle window elapses -> kill -> onEnd
			ok('splice onEnd fires exactly once when the connection ends', ended === 1);
			try { srv.close(); } catch (_) {} acc.forEach(s => { try { s.destroy(); } catch (_) {} });
		}

		// --- concurrent-splice cap (MAX_ACTIVE_SPLICES): the queue/pool caps bound only WAITING/IDLE sockets; a client
		//     flood could otherwise accumulate unbounded ESTABLISHED splices (each a loopback serve connection on the
		//     node) as workers are replenished. With a tiny injected cap and plenty of pooled workers, no more than the
		//     cap are served at once, and freeing an active splice lets a new client through (the counter decrements). ---
		{
			const cp2 = await Serve.freePort(), pub2 = await Serve.freePort();
			const hub2 = Relay.runHub({ controlPort: cp2, token: TOKEN, host: '127.0.0.1', portRange: [pub2, pub2], maxActiveSplices: 2 });
			await sleep(150);
			try {
				const ctl = net.connect({ host: '127.0.0.1', port: cp2 });
				await new Promise((res) => { ctl.on('connect', () => ctl.write('HELLO ' + TOKEN + ' node4\n')); let b = ''; ctl.on('data', (d) => { b += d; if (b.indexOf('\n') >= 0) res(); }); ctl.once('error', () => res()); });
				const ws = [];
				for (let i = 0; i < 3; i++) { const w = net.connect({ host: '127.0.0.1', port: cp2 }); w.on('connect', () => { try { w.write('WORKER ' + TOKEN + ' node4\n'); } catch (_) {} }); w.on('error', () => {}); ws.push(w); }
				await sleep(400); // let all three workers pool
				const cs = [], isClosed = [];
				for (let i = 0; i < 3; i++) { const c = net.connect({ host: '127.0.0.1', port: pub2 }); let cl = false; c.once('close', () => { cl = true; }); c.once('error', () => { cl = true; }); cs.push(c); isClosed.push(() => cl); }
				await sleep(500);
				ok('the concurrent-splice cap serves at most maxActiveSplices clients at once', cs.filter((_, i) => !isClosed[i]()).length === 2);
				cs[0].destroy(); // free one slot -> onEnd decrements the active counter
				await sleep(300);
				const c4 = net.connect({ host: '127.0.0.1', port: pub2 }); let c4closed = false; c4.once('close', () => { c4closed = true; }); c4.once('error', () => { c4closed = true; });
				await sleep(500);
				ok('freeing an active splice lets a new client be served (the counter decrements)', c4closed === false);
				for (const w of ws) { try { w.destroy(); } catch (_) {} }
				for (const c of cs) { try { c.destroy(); } catch (_) {} }
				try { c4.destroy(); } catch (_) {} try { ctl.destroy(); } catch (_) {}
			} finally { hub2.close(); }
		}
	} finally { hub.close(); }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-HARDENING CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
