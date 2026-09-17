'use strict';
// lib/test/tunnel.js — the stream multiplexer + local proxy (lib/Tunnel.js) that carries an engine's many WebDAV
// connections over ONE direct socket. Wire the two proxy ends back to back over a loopback socket pair (standing in
// for a hole-punched connection), point the node end at a mock echo "serve", and drive the client end like rclone
// would: many independent connections, each round-tripping its own bytes through the single tunnel. Also checks that a
// closed stream propagates, that concurrent streams stay isolated, and that a malformed frame tears the tunnel down.
//
// Run:  node lib/test/tunnel.js

const net = require('net');
const Tunnel = require('../Tunnel');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A connected pair of loopback TCP sockets, standing in for the two ends of a punched connection.
function socketPair() {
	return new Promise((resolve) => {
		const srv = net.createServer((s) => { srv.close(); resolve([client, s]); });
		let client;
		srv.listen(0, '127.0.0.1', () => { client = net.connect(srv.address().port, '127.0.0.1'); });
	});
}
// Round-trip one request over a fresh connection to the client proxy; resolve the bytes echoed back.
function roundTrip(port, msg, timeoutMs = 2000) {
	return new Promise((resolve) => {
		const c = net.connect(port, '127.0.0.1');
		let got = '', settled = false;
		const done = (v) => { if (settled) return; settled = true; try { c.destroy(); } catch (_) {} resolve(v); };
		c.on('connect', () => { try { c.write(msg); } catch (_) {} });
		c.on('data', (d) => { got += d; if (got.length >= msg.length) done(got); });
		c.on('error', () => done(null));
		setTimeout(() => done(got || null), timeoutMs);
	});
}

async function main() {
	const keepAlive = setInterval(() => {}, 60000); // hold the loop open; the tunnel's own timers are unref'd

	// Mock WebDAV "serve": a loopback echo server the node proxy connects a stream to for each OPEN.
	const echo = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); });
	await new Promise((r) => echo.listen(0, '127.0.0.1', r));
	const servePort = echo.address().port;

	// 1. One connection round-trips its bytes end to end through the multiplexer.
	{
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: servePort });
		const cp = await Tunnel.clientProxy(clientEnd);
		const got = await roundTrip(cp.port, 'hello-tunnel');
		ok('a single connection round-trips its bytes through the tunnel', got === 'hello-tunnel');

		// 2. Many concurrent connections stay isolated — each gets back its OWN payload, not another stream's.
		const msgs = ['alpha-1', 'bravo-22', 'charlie-333', 'delta-4444', 'echo-55555'];
		const results = await Promise.all(msgs.map((m) => roundTrip(cp.port, m)));
		ok('concurrent streams stay isolated (each gets its own payload back)', results.every((r, i) => r === msgs[i]));

		// 3. A larger payload (multiple frames' worth) reassembles intact.
		const big = 'x'.repeat(200000);
		const bigBack = await roundTrip(cp.port, big, 5000);
		ok('a large multi-frame payload reassembles intact', bigBack === big);

		cp.stop(); try { nodeEnd.destroy(); } catch (_) {}
	}

	// 4. Tearing down the punched socket stops the client proxy (its listener closes), so a caller can fall back.
	{
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: servePort });
		const cp = await Tunnel.clientProxy(clientEnd);
		let downFired = false;
		// Re-open with an onDown hook to observe teardown.
		cp.stop();
		const [c2, n2] = await socketPair();
		Tunnel.nodeProxy(n2, { localServePort: servePort });
		const cp2 = await Tunnel.clientProxy(c2, { onDown: () => { downFired = true; } });
		try { n2.destroy(); } catch (_) {} // kill the "punched" link
		await sleep(150);
		const afterDown = await roundTrip(cp2.port, 'nope', 600);
		ok('tearing down the punched link stops the client proxy (fails closed)', downFired === true && afterDown === null);
		cp2.stop();
	}

	// 5. A malformed frame (an absurd length header) tears the tunnel down rather than buffering forever.
	{
		const [clientEnd, nodeEnd] = await socketPair();
		let down = false;
		Tunnel.nodeProxy(nodeEnd, { localServePort: servePort, onDown: () => { down = true; } });
		// Send a frame header claiming a payload far over the cap.
		const bad = Buffer.alloc(9); bad.writeUInt8(2, 0); bad.writeUInt32BE(1, 1); bad.writeUInt32BE(9999999, 5);
		clientEnd.write(bad);
		await sleep(150);
		ok('a malformed (oversized) frame tears the tunnel down (fail closed)', down === true);
		try { clientEnd.destroy(); } catch (_) {}
	}

	// 5b. Stream-count cap: past MAX_STREAMS concurrent connections, the client proxy refuses new ones (fd-exhaustion
	//     guard, the tunnel's analogue of the relay's worker cap). Hold the cap open, then assert the next is refused.
	{
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: servePort });
		const cp = await Tunnel.clientProxy(clientEnd);
		const held = [];
		for (let i = 0; i < Tunnel.MAX_STREAMS; i++) { const c = net.connect(cp.port, '127.0.0.1'); c.on('error', () => {}); held.push(c); }
		await sleep(150);
		const overCap = await new Promise((res) => { const c = net.connect(cp.port, '127.0.0.1'); let closed = false; c.once('close', () => { closed = true; res('closed'); }); c.once('error', () => res('closed')); c.on('connect', () => c.write('x')); c.on('data', () => res('served')); setTimeout(() => res(closed ? 'closed' : 'nodata'), 600); });
		ok('the client proxy refuses a connection past MAX_STREAMS (fd-exhaustion guard)', overCap !== 'served');
		for (const c of held) { try { c.destroy(); } catch (_) {} }
		cp.stop(); try { nodeEnd.destroy(); } catch (_) {}
	}

	// 5c. Stream isolation on close: closing ONE stream ends only its node-side serve socket; a concurrent stream keeps
	//     working. Uses a mock serve that reports each accepted/closed connection so we can observe per-stream teardown.
	{
		let opened = 0, closed = 0;
		const serve = net.createServer((s) => { opened++; s.on('error', () => {}); s.on('close', () => { closed++; }); s.pipe(s); });
		await new Promise((r) => serve.listen(0, '127.0.0.1', r));
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: serve.address().port });
		const cp = await Tunnel.clientProxy(clientEnd);
		const a = net.connect(cp.port, '127.0.0.1'); a.on('error', () => {}); a.write('a');
		const b = net.connect(cp.port, '127.0.0.1'); b.on('error', () => {});
		await sleep(200);
		const openedAfterTwo = opened;
		a.destroy(); // close one stream
		await sleep(200);
		const closedAfterOne = closed;
		const bStillWorks = await new Promise((res) => { let g = ''; b.on('data', (d) => { g += d; if (g.length >= 3) res(true); }); b.write('bbb'); setTimeout(() => res(g === 'bbb'), 600); });
		ok('closing one stream tears down only its serve socket, leaving a concurrent stream working', openedAfterTwo === 2 && closedAfterOne === 1 && bStillWorks === true);
		try { b.destroy(); } catch (_) {} cp.stop(); try { nodeEnd.destroy(); } catch (_) {} serve.close();
	}

	// 5d. Keepalive PING is answered with PONG at the frame level (NAT-mapping warmth + liveness). Drive one raw end of
	//     a socket pair as a "peer": send an encoded PING, expect an encoded PONG back from the proxy's link.
	{
		const { encode, T, HEADER } = Tunnel._codec;
		const [peerEnd, proxyEnd] = await socketPair();
		Tunnel.nodeProxy(proxyEnd, { localServePort: servePort });
		const pong = await new Promise((res) => {
			let buf = Buffer.alloc(0);
			peerEnd.on('data', (d) => { buf = Buffer.concat([buf, d]); if (buf.length >= HEADER && buf.readUInt8(0) === T.PONG) res(true); });
			peerEnd.write(encode(T.PING, 0, null));
			setTimeout(() => res(false), 800);
		});
		ok('a PING is answered with a PONG (keepalive/liveness at the frame level)', pong === true);
		try { peerEnd.destroy(); } catch (_) {} try { proxyEnd.destroy(); } catch (_) {}
	}

	// 6. Cross-platform / non-blocking source contract.
	{
		const fs = require('fs'), path = require('path');
		const src = fs.readFileSync(path.join(__dirname, '..', 'Tunnel.js'), 'utf8');
		ok('Tunnel requires only net (no native module)', !/require\('(?!net')[^']+'\)/.test(src));
		ok('Tunnel spawns no binary', !/child_process|execFile\(|execSync\(|\bspawn\(/.test(src));
		ok('Tunnel is non-blocking (no *Sync I/O)', !/readFileSync|writeFileSync|execSync/.test(src));
		ok('Tunnel bounds frame size and stream count', /MAX_FRAME/.test(src) && /MAX_STREAMS/.test(src));
		ok('Tunnel never sets the non-portable reusePort option', !/reusePort\s*:/.test(src));
		ok('every timer in Tunnel is unref\'d', (src.match(/set(Timeout|Interval)\(/g) || []).length === (src.match(/\.unref\(\)/g) || []).length);
		ok('Tunnel has PONG liveness (tears down a dead-but-open peer)', /MAX_MISSED_PONGS/.test(src) && /missedPongs/.test(src));
	}

	clearInterval(keepAlive);
	echo.close();
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TUNNEL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
