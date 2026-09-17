'use strict';
// lib/test/holepunch.js — dependency-free TCP hole-punch primitives and coordination (lib/HolePunch.js).
//
// IMPORTANT (cross-platform): a real cross-NAT punch relies on TCP SIMULTANEOUS OPEN, whose success on plain loopback
// is OS-dependent — Linux and Windows refuse a SYN to a not-yet-listening port instantly (so two blind dials never
// cross), while macOS leaves a small window. That OS behavior is NOT our code, so this test never depends on a real
// loopback crossing. Instead it exercises everything WE control deterministically: the punch retry/recycle loop
// against a peer that becomes reachable, the bounded fail-closed fallback, the public-address safety gate, the
// reflexive WHERE probe, and — via an injected socket pair standing in for the punched socket — the full WHERE +
// SIGNAL + coordinate + nonce + tunnel pipeline. The real crossing is validated in the field, not in CI.
//
// Run:  node lib/test/holepunch.js

const net = require('net');
const HolePunch = require('../HolePunch');
const Relay = require('../Relay');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const anyHost = () => true; // test-only: exercise the mechanism on loopback, which the public-only gate would refuse
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
// A connected pair of loopback sockets, standing in for a successfully punched connection (an injected `dial`).
function socketPair() {
	return new Promise((resolve) => {
		const srv = net.createServer((s) => { srv.close(); resolve([client, s]); });
		let client;
		srv.listen(0, '127.0.0.1', () => { client = net.connect(srv.address().port, '127.0.0.1'); });
	});
}

async function main() {
	const keepAlive = setInterval(() => {}, 60000); // hold the loop open; HolePunch's own timers are unref'd

	// 1. The punch retry/recycle loop: punch keeps dialing (freeing its local port between tries) until the peer becomes
	//    reachable, then returns a LIVE, usable socket. Deterministic on every platform: the peer starts refusing
	//    (ECONNREFUSED) and a listener appears shortly after, which the retrying punch then connects to.
	{
		const A = await freePort(), B = await freePort();
		let echo = null;
		setTimeout(() => { echo = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); }); echo.listen(B, '127.0.0.1'); }, 250);
		const sock = await HolePunch.punch({ localPort: A, peerHost: '127.0.0.1', peerPort: B, budgetMs: 6000, intervalMs: 40, permitHost: anyHost });
		ok('punch retries until the peer is reachable and returns a live socket', !!sock && !sock.destroyed);
		if (sock) {
			const got = await new Promise((res) => { let g = ''; sock.on('data', (d) => { g += d; if (g.length >= 5) res(g); }); sock.write('hello'); setTimeout(() => res(g), 1000); });
			ok('the punched socket carries data end to end', got === 'hello');
			try { sock.destroy(); } catch (_) {}
		} else { ok('the punched socket carries data end to end', false); }
		try { if (echo) echo.close(); } catch (_) {}
	}

	// 2. Bounded fail-closed: a punch to a port nobody ever answers gives up within its budget and resolves null.
	{
		const t0 = Date.now();
		const r = await HolePunch.punch({ localPort: await freePort(), peerHost: '127.0.0.1', peerPort: await freePort(), budgetMs: 1200, intervalMs: 60, permitHost: anyHost });
		ok('a punch with no peer answering resolves null within its budget (bounded, no hang)', r === null && (Date.now() - t0) < 3000);
	}

	// 3. Address safety: by default the punch only ever dials a PUBLIC address, so a loopback/private target is refused
	//    outright and no packet is sent — a punch can never become a reflection primitive. Also validate the arg guards.
	{
		ok('the default punch refuses a loopback target', (await HolePunch.punch({ localPort: await freePort(), peerHost: '127.0.0.1', peerPort: 9, budgetMs: 500 })) === null);
		ok('the default punch refuses a private (RFC 1918) target', (await HolePunch.punch({ localPort: await freePort(), peerHost: '192.168.1.5', peerPort: 9, budgetMs: 500 })) === null);
		ok('punch rejects an out-of-range or non-integer port without dialing', (await HolePunch.punch({ localPort: await freePort(), peerHost: '203.0.113.7', peerPort: 70000, budgetMs: 500 })) === null && (await HolePunch.punch({ localPort: 1.5, peerHost: '203.0.113.7', peerPort: 9, budgetMs: 500, permitHost: anyHost })) === null);
		ok('isPunchableHost accepts a public address but rejects private/CGNAT/loopback', HolePunch.isPunchableHost('203.0.113.7') === true && HolePunch.isPunchableHost('10.0.0.1') === false && HolePunch.isPunchableHost('100.64.0.1') === false && HolePunch.isPunchableHost('127.0.0.1') === false);
	}

	// 4. reflexiveEndpoint reads the hub's `WHERE <ip> <port>` reply, returns { ip, port }, and RST-closes so the local
	//    port stays reusable. Also drops an oversized reply and an out-of-range port (fail closed).
	{
		const hub = net.createServer((s) => { s.on('data', () => { try { s.end('WHERE 203.0.113.9 51820\n'); } catch (_) {} }); s.on('error', () => {}); });
		await new Promise((r) => hub.listen(0, '127.0.0.1', r));
		const hubPort = hub.address().port, lp = await freePort();
		const ep = await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort, token: 'tok', nodeId: 'n1', localPort: lp, timeoutMs: 3000 });
		ok('reflexiveEndpoint returns the { ip, port } the hub reports via WHERE', !!ep && ep.ip === '203.0.113.9' && ep.port === 51820);
		const reuse = await new Promise((res) => { const s2 = net.connect({ host: '127.0.0.1', port: hubPort, localPort: lp }); s2.once('connect', () => { try { s2.destroy(); } catch (_) {} res(true); }); s2.once('error', (e) => res(e.code)); });
		ok('the reflexive probe frees its local port for immediate reuse (RST, not TIME_WAIT)', reuse === true);
		hub.close();

		const overflowHub = net.createServer((s) => { s.on('data', () => { try { s.write('WHERE ' + 'x'.repeat(400)); } catch (_) {} }); s.on('error', () => {}); });
		await new Promise((r) => overflowHub.listen(0, '127.0.0.1', r));
		ok('reflexiveEndpoint drops an oversized reply (fail closed)', (await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort: overflowHub.address().port, token: 't', nodeId: 'n', localPort: await freePort(), timeoutMs: 1500 })) === null);
		overflowHub.close();
	}

	// 5. reflexiveEndpoint fails closed against an OLDER hub that closes on WHERE, and against a non-public reflexive IP.
	{
		const legacy = net.createServer((s) => { s.on('data', () => { try { s.destroy(); } catch (_) {} }); });
		await new Promise((r) => legacy.listen(0, '127.0.0.1', r));
		ok('reflexiveEndpoint returns null against an older hub that closes on WHERE', (await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort: legacy.address().port, token: 'tok', nodeId: 'n1', localPort: await freePort(), timeoutMs: 1500 })) === null);
		legacy.close();
		const badHub = net.createServer((s) => { s.on('data', () => { try { s.end('WHERE 10.0.0.5 51820\n'); } catch (_) {} }); s.on('error', () => {}); });
		await new Promise((r) => badHub.listen(0, '127.0.0.1', r));
		ok('reflexiveEndpoint rejects a non-public reflexive address from the hub', (await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort: badHub.address().port, token: 'tok', nodeId: 'n1', localPort: await freePort(), timeoutMs: 1500 })) === null);
		badHub.close();
	}

	// 6. FULL PIPELINE, deterministic: a real hub + real WHERE + real SIGNAL + real tunnel, with the actual punch
	//    replaced by an injected socket pair (the `dial` seam). Proves coordination, the nonce binding, the scoped
	//    credential, the anti-reflection expectIp check, and the mux all work end to end without a real crossing.
	{
		const TOKEN = 'holepunch-e2e-token-0123456789';
		const echo = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); });
		await new Promise((r) => echo.listen(0, '127.0.0.1', r));
		const servePort = echo.address().port;
		const cport = await freePort(), base = await freePort();
		const hub = Relay.runHub({ controlPort: cport, token: TOKEN, host: '127.0.0.1', portRange: [base, base + 4] });
		const [clientEnd, nodeEnd] = await socketPair();
		let direct = null;
		try {
			const node = Relay.registerNode({
				hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'e2e-node', localPort: servePort,
				// The node answers with the REAL reflexive/expectIp/nonce logic; only the punch is injected (returns the node end).
				onSignal: ({ srcIp, blob, reply }) => HolePunch.answerSignal({ hubHost: '127.0.0.1', hubPort: cport, credential: TOKEN, nodeId: 'e2e-node', offerBlob: blob, reply, localServePort: servePort, expectIp: srcIp, permitHost: anyHost, dial: () => Promise.resolve(nodeEnd) }),
			});
			await node.ready;
			direct = await HolePunch.connectDirect({ hubHost: '127.0.0.1', hubPort: cport, credential: TOKEN, nodeId: 'e2e-node', permitHost: anyHost, dial: () => Promise.resolve(clientEnd) });
			ok('the client coordinates a direct path to the node (WHERE + SIGNAL + tunnel, end to end)', !!direct && direct.port > 0);
			if (direct) {
				let got = null;
				for (let i = 0; i < 20 && got !== 'punched-hello'; i++) { got = await new Promise((res) => { const c = net.connect(direct.port, direct.host); let g = ''; c.on('connect', () => c.write('punched-hello')); c.on('data', (d) => { g += d; if (g.length >= 13) res(g); }); c.on('error', () => res(null)); setTimeout(() => res(g || null), 300); }); if (got !== 'punched-hello') await sleep(50); }
				ok('data round-trips through the direct tunnel over the injected punched socket', got === 'punched-hello');
			} else { ok('data round-trips through the direct tunnel over the injected punched socket', false); }
			node.stop();
		} finally { if (direct) { try { direct.stop(); } catch (_) {} } try { hub.close(); } catch (_) {} echo.close(); try { clientEnd.destroy(); } catch (_) {} try { nodeEnd.destroy(); } catch (_) {} }
	}

	// 7. connectDirect fails closed (returns null, never throws) on every unhappy path, so the caller stays on the relay.
	{
		const TOKEN = 'holepunch-null-token-0123456789';
		ok('connectDirect returns null on missing arguments', (await HolePunch.connectDirect({})) === null);
		const cport = await freePort(), base = await freePort();
		const hub = Relay.runHub({ controlPort: cport, token: TOKEN, host: '127.0.0.1', portRange: [base, base + 4] });
		const localSrv = net.createServer(() => {}); await new Promise((r) => localSrv.listen(0, '127.0.0.1', r));
		let dialCalled = false;
		const spyDial = () => { dialCalled = true; return Promise.resolve(null); };
		try {
			// The node answers with a MISMATCHED nonce → connectDirect must reject it and never dial.
			const badNonce = Relay.registerNode({ hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'badnonce', nodeAuth: 'auth-badnonce-0123456789', localPort: localSrv.address().port,
				onSignal: ({ reply }) => reply(Buffer.from(JSON.stringify({ ip: '203.0.113.5', port: 40000, n: 'not-the-nonce' }), 'utf8').toString('base64url')) });
			await badNonce.ready;
			const r1 = await HolePunch.connectDirect({ hubHost: '127.0.0.1', hubPort: cport, credential: Relay.signalCredential('auth-badnonce-0123456789', 'badnonce'), nodeId: 'badnonce', permitHost: anyHost, dial: spyDial });
			ok('connectDirect rejects a node answer with a mismatched nonce (and never dials)', r1 === null && dialCalled === false);
			badNonce.stop();

			// The node answers with a NON-PUBLIC endpoint → rejected by the real public-only gate, no dial.
			dialCalled = false;
			const badEp = Relay.registerNode({ hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'badep', nodeAuth: 'auth-badep-0123456789', localPort: localSrv.address().port,
				onSignal: ({ blob, reply }) => { const n = JSON.parse(Buffer.from(blob, 'base64url').toString('utf8')).n; reply(Buffer.from(JSON.stringify({ ip: '10.0.0.9', port: 40000, n }), 'utf8').toString('base64url')); } });
			await badEp.ready;
			const r2 = await HolePunch.connectDirect({ hubHost: '127.0.0.1', hubPort: cport, credential: Relay.signalCredential('auth-badep-0123456789', 'badep'), nodeId: 'badep', dial: spyDial });
			ok('connectDirect rejects a non-public answer endpoint (and never dials)', r2 === null && dialCalled === false);
			badEp.stop();
		} finally { try { hub.close(); } catch (_) {} localSrv.close(); }
	}

	// 8. answerSignal refuses to punch a malformed/non-public offer or one whose endpoint does not match the hub-observed
	//    source (the anti-reflection guard): no reply is sent and the injected dial is never called.
	{
		const spy = { replied: false, dialed: false };
		const reply = () => { spy.replied = true; };
		const dial = () => { spy.dialed = true; return Promise.resolve(null); };
		const pack = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
		await HolePunch.answerSignal({ hubHost: '127.0.0.1', hubPort: 1, credential: 't', nodeId: 'n', offerBlob: pack({ ip: '10.0.0.5', port: 8443, n: 'x' }), reply, localServePort: 1234, dial });
		ok('answerSignal refuses a non-public offer (no reply, no punch)', spy.replied === false && spy.dialed === false);
		spy.replied = false; spy.dialed = false;
		await HolePunch.answerSignal({ hubHost: '127.0.0.1', hubPort: 1, credential: 't', nodeId: 'n', offerBlob: pack({ ip: '203.0.113.9', port: 8443, n: 'x' }), reply, localServePort: 1234, expectIp: '198.51.100.7', permitHost: anyHost, dial });
		ok('answerSignal refuses an offer whose IP differs from the hub-observed source (anti-reflection)', spy.replied === false && spy.dialed === false);
	}

	// 9. Cross-platform / non-blocking source contract.
	{
		const fs = require('fs'), path = require('path');
		const src = fs.readFileSync(path.join(__dirname, '..', 'HolePunch.js'), 'utf8');
		ok('HolePunch requires only Node built-ins and sibling modules (no native/third-party module)', !/require\('(?!net'|crypto'|\.\/PortMap'|\.\/Relay'|\.\/Tunnel')[^']+'\)/.test(src));
		ok('HolePunch spawns no binary', !/child_process|execFile\(|execSync\(|\bspawn\(/.test(src));
		ok('HolePunch never sets the non-portable reusePort option', !/reusePort\s*:/.test(src));
		ok('HolePunch is non-blocking (no *Sync I/O)', !/readFileSync|writeFileSync|execSync/.test(src));
		ok('HolePunch uses RST recycling (resetAndDestroy) for the reflexive probe', /resetAndDestroy/.test(src));
		ok('every timer in HolePunch is unref\'d', (src.match(/set(Timeout|Interval)\(/g) || []).length === (src.match(/\.unref\(\)/g) || []).length);
	}

	clearInterval(keepAlive);
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HOLE-PUNCH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
