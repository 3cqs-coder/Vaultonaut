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

	// 5b. Stream-count cap: past MAX_STREAMS concurrent streams, the client proxy refuses new connections (fd-exhaustion
	//     guard, the tunnel's analogue of the relay's worker cap). The cap is enforced synchronously at accept time
	//     (streams.size >= MAX_STREAMS -> destroy), so the guard can only be observed once the tunnel is truly AT the cap.
	//     Counting raw client sockets to decide that is not portable: opening MAX_STREAMS loopback connections in a burst
	//     can overflow the OS accept backlog on some platforms, so a few never reach the proxy's accept handler, a slot
	//     stays free, and the over-cap probe is served — a flake seen on Windows CI. Instead, gate on the NODE side: each
	//     accepted stream opens exactly one connection to the serve, so fill until the serve holds MAX_STREAMS live
	//     connections (proof the proxy is at capacity, refused over-cap sockets never reach it) and only then probe.
	{
		let liveServe = 0;
		const capServe = net.createServer((s) => { liveServe++; s.on('error', () => {}); s.on('close', () => { liveServe--; }); s.resume(); });
		await new Promise((r) => capServe.listen(0, '127.0.0.1', r));
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: capServe.address().port });
		const cp = await Tunnel.clientProxy(clientEnd);
		const held = [];
		// Top up the real deficit each poll until exactly MAX_STREAMS streams are live. Over-cap sockets are refused at
		// accept and never increment liveServe, so this self-corrects on any platform (a slow or backlog-limited runner
		// simply converges over a few more polls) instead of assuming one burst all lands within a fixed sleep.
		const deadline = Date.now() + 5000;
		while (liveServe < Tunnel.MAX_STREAMS && Date.now() < deadline) {
			for (let i = liveServe; i < Tunnel.MAX_STREAMS; i++) { const c = net.connect(cp.port, '127.0.0.1'); c.on('error', () => {}); held.push(c); }
			await sleep(50);
		}
		ok('the tunnel fills to exactly the stream cap before probing (deterministic precondition)', liveServe === Tunnel.MAX_STREAMS);
		const overCap = await new Promise((res) => { const c = net.connect(cp.port, '127.0.0.1'); let closed = false; c.once('close', () => { closed = true; res('closed'); }); c.once('error', () => res('closed')); c.on('connect', () => c.write('x')); c.on('data', () => res('served')); setTimeout(() => res(closed ? 'closed' : 'nodata'), 600); });
		ok('the client proxy refuses a connection past MAX_STREAMS (fd-exhaustion guard)', overCap !== 'served');
		for (const c of held) { try { c.destroy(); } catch (_) {} }
		cp.stop(); try { nodeEnd.destroy(); } catch (_) {} capServe.close();
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

	// 5e. Per-stream flow control: a stream whose consumer stops reading (congested) must NOT stall a concurrent fast
	//     stream. Open a SLOW stream, send ~2 MB and never read the echo (so its client-side buffer fills but stays
	//     under the aggregate cap), then confirm a FAST stream still round-trips promptly. On the old whole-socket-pause
	//     design a single congested stream paused the shared socket and blocked every other stream — this would fail.
	{
		const [clientEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: servePort });
		const cp = await Tunnel.clientProxy(clientEnd);
		const slow = net.connect(cp.port, '127.0.0.1'); slow.on('error', () => {});
		await new Promise((r) => slow.on('connect', r));
		slow.pause(); // never read the echo — its inbound buffer fills and the stream congests
		slow.write('S'.repeat(2 * 1024 * 1024)); // ~2 MB echoed back and left unread (below the 4 MB aggregate cap, so the shared socket is NOT paused)
		await sleep(300); // let the congestion build on the slow stream
		const fast = await roundTrip(cp.port, 'fast-path', 3000);
		ok('a slow (unread) stream does not block a concurrent fast stream (per-stream flow control)', fast === 'fast-path');
		try { slow.destroy(); } catch (_) {} cp.stop(); try { nodeEnd.destroy(); } catch (_) {}
	}

	// 5f. Per-stream idle reaping (relay path): a stream opened and then left SILENT is reaped after streamIdleMs, so a
	//     hostile peer cannot hold idle streams (and their downstream serve connections) open — matching the splice
	//     path's idle guard. Drive the node end raw: OPEN a stream (the node connects to the serve), send no data, and
	//     confirm the serve connection is dropped once idle. The default (streamIdleMs 0, the hole-punch path) never reaps.
	{
		const { encode, T } = Tunnel._codec;
		let liveServe = 0;
		const idleServe = net.createServer((s) => { liveServe++; s.on('error', () => {}); s.on('close', () => { liveServe--; }); });
		await new Promise((r) => idleServe.listen(0, '127.0.0.1', r));
		const [peerEnd, nodeEnd] = await socketPair();
		Tunnel.nodeProxy(nodeEnd, { localServePort: idleServe.address().port, streamIdleMs: 150 });
		peerEnd.write(encode(T.OPEN, 1, null)); // open a stream; the node connects to the serve but the stream stays silent
		await sleep(120);
		const openedWhileActive = liveServe; // 1: the serve connection exists
		await sleep(600);                    // exceed the idle window with no data in either direction
		ok('a silent mux stream is reaped after the idle window (matches the splice path)', openedWhileActive === 1 && liveServe === 0);
		try { peerEnd.destroy(); } catch (_) {} try { nodeEnd.destroy(); } catch (_) {} idleServe.close();
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
