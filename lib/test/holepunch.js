'use strict';
// lib/test/holepunch.js — dependency-free TCP hole-punch primitives (lib/HolePunch.js). A real cross-NAT punch cannot
// be exercised in CI (there is no NAT on loopback), so this proves the parts that ARE testable locally: the retry-based
// TCP simultaneous open actually forms a connection when two peers dial each other, the punch is bounded and fails
// closed when no peer answers, the public-address gate refuses an unsafe target, and the reflexive-endpoint probe reads
// the hub's WHERE reply (and fails closed against an older hub). Pure loopback TCP — no engine, no spawned binary.
//
// Run:  node lib/test/holepunch.js

const net = require('net');
const HolePunch = require('../HolePunch');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const anyHost = () => true; // test-only: exercise the mechanism on loopback, which the public-only gate would refuse

// A pair of free, adjacent-ish loopback ports we can bind for a simultaneous-open attempt.
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }

async function main() {
	// HolePunch's own timers are unref'd (correct for the app: they never hold the event loop open). In a STANDALONE
	// test run there is otherwise nothing ref'd between retries, so the loop could drain and exit before the punch
	// resolves — hold it open ourselves for the duration and release it right before exiting.
	const keepAlive = setInterval(() => {}, 60000);

	// 1. Retry-based TCP simultaneous open: two peers, each dialing the other FROM its own fixed local port, form a
	//    direct connection with no listener on either side. This is the core hole-punch mechanism.
	{
		// Loopback is a WORST case for simultaneous open: a SYN to a port with nobody dialing is RST'd instantly, so the
		// SYN_SENT overlap window is sub-millisecond (a real NAT drops the SYN and keeps retransmitting, giving a wide
		// window). A tight retry interval and a generous budget make the crossing reliable here.
		const A = await freePort(), B = await freePort();
		const [ra, rb] = await Promise.all([
			HolePunch.punch({ localPort: A, peerHost: '127.0.0.1', peerPort: B, budgetMs: 10000, intervalMs: 8, permitHost: anyHost }),
			HolePunch.punch({ localPort: B, peerHost: '127.0.0.1', peerPort: A, budgetMs: 10000, intervalMs: 8, permitHost: anyHost }),
		]);
		const bothConnected = ra && rb && !ra.destroyed && !rb.destroyed;
		ok('two peers simultaneously dialing each other form a direct connection (TCP simultaneous open)', !!bothConnected);
		// The punched sockets carry data both ways.
		if (bothConnected) {
			const got = await new Promise((res) => { let g = ''; rb.on('data', (d) => { g += d; if (g.length >= 5) res(g); }); ra.write('hello'); setTimeout(() => res(g), 500); });
			ok('the punched connection carries data end to end', got === 'hello');
		} else { ok('the punched connection carries data end to end', false); }
		try { ra && ra.destroy(); } catch (_) {} try { rb && rb.destroy(); } catch (_) {}
	}

	// 2. Bounded fail-closed: a punch to a port nobody is dialing back gives up within its budget and resolves null,
	//    never hanging (so the caller falls back to the relay promptly).
	{
		const A = await freePort(), dead = await freePort();
		const t0 = Date.now();
		const r = await HolePunch.punch({ localPort: A, peerHost: '127.0.0.1', peerPort: dead, budgetMs: 1200, intervalMs: 60, permitHost: anyHost });
		const elapsed = Date.now() - t0;
		ok('a punch with no peer dialing back resolves null within its budget (bounded, no hang)', r === null && elapsed < 3000);
	}

	// 3. Address safety: by default the punch only ever dials a PUBLIC address, so a loopback/private/multicast target
	//    is refused outright and no packet is sent — a punch can never become a reflection primitive.
	{
		ok('the default punch refuses a loopback target', (await HolePunch.punch({ localPort: await freePort(), peerHost: '127.0.0.1', peerPort: 9, budgetMs: 500 })) === null);
		ok('the default punch refuses a private (RFC 1918) target', (await HolePunch.punch({ localPort: await freePort(), peerHost: '192.168.1.5', peerPort: 9, budgetMs: 500 })) === null);
		ok('isPunchableHost accepts a public address but rejects private/CGNAT/loopback', HolePunch.isPunchableHost('203.0.113.7') === true && HolePunch.isPunchableHost('10.0.0.1') === false && HolePunch.isPunchableHost('100.64.0.1') === false && HolePunch.isPunchableHost('127.0.0.1') === false);
	}

	// 4. reflexiveEndpoint reads the hub's `WHERE <ip> <port>` reply. A mock hub reports a public test endpoint; the
	//    probe returns it. The probe connects FROM the given local port and RST-closes so that port stays reusable.
	{
		const hub = net.createServer((s) => { s.on('data', () => { try { s.end('WHERE 203.0.113.9 51820\n'); } catch (_) {} }); s.on('error', () => {}); });
		await new Promise((r) => hub.listen(0, '127.0.0.1', r));
		const hubPort = hub.address().port;
		const lp = await freePort();
		const ep = await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort, token: 'tok', nodeId: 'n1', localPort: lp, timeoutMs: 3000 });
		ok('reflexiveEndpoint returns the { ip, port } the hub reports via WHERE', !!ep && ep.ip === '203.0.113.9' && ep.port === 51820);
		// After the RST close, the same local port is immediately reusable (a FIN would strand it in TIME_WAIT).
		const reuse = await new Promise((res) => { const s2 = net.connect({ host: '127.0.0.1', port: hubPort, localPort: lp }); s2.once('connect', () => { try { s2.destroy(); } catch (_) {} res(true); }); s2.once('error', (e) => res(e.code)); });
		ok('the reflexive probe frees its local port for immediate reuse (RST, not TIME_WAIT)', reuse === true);
		hub.close();
	}

	// 5. reflexiveEndpoint fails closed against an OLDER hub that does not understand WHERE (it just closes), and when
	//    the hub reports a non-public (unsafe) reflexive address.
	{
		const legacy = net.createServer((s) => { s.on('data', () => { try { s.destroy(); } catch (_) {} }); });
		await new Promise((r) => legacy.listen(0, '127.0.0.1', r));
		const lport = legacy.address().port;
		ok('reflexiveEndpoint returns null against an older hub that closes on WHERE', (await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort: lport, token: 'tok', nodeId: 'n1', localPort: await freePort(), timeoutMs: 1500 })) === null);
		legacy.close();

		const badHub = net.createServer((s) => { s.on('data', () => { try { s.end('WHERE 10.0.0.5 51820\n'); } catch (_) {} }); s.on('error', () => {}); });
		await new Promise((r) => badHub.listen(0, '127.0.0.1', r));
		ok('reflexiveEndpoint rejects a non-public reflexive address from the hub', (await HolePunch.reflexiveEndpoint({ hubHost: '127.0.0.1', hubPort: badHub.address().port, token: 'tok', nodeId: 'n1', localPort: await freePort(), timeoutMs: 1500 })) === null);
		badHub.close();
	}

	// 6. FULL PIPELINE end to end on loopback: a real hub, a node that answers punch SIGNALs by bridging the punched
	//    socket to a mock echo "serve", and a client that coordinates over the hub, punches, and tunnels — then data
	//    round-trips through the DIRECT (hole-punched) path, not the relay. This exercises WHERE + SIGNAL + punch +
	//    tunnel together. The public-address gate is relaxed to loopback for the test (no public interface in CI).
	{
		const Relay = require('../Relay');
		const TOKEN = 'holepunch-e2e-token-0123456789';
		const echo = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); });
		await new Promise((r) => echo.listen(0, '127.0.0.1', r));
		const servePort = echo.address().port;
		const cport = await freePort();
		const base = await freePort();
		const hub = Relay.runHub({ controlPort: cport, token: TOKEN, host: '127.0.0.1', portRange: [base, base + 4] });
		let direct = null;
		try {
			const node = Relay.registerNode({
				hubHost: '127.0.0.1', hubPort: cport, token: TOKEN, nodeId: 'e2e-node', localPort: servePort,
				onSignal: ({ blob, reply }) => HolePunch.answerSignal({ hubHost: '127.0.0.1', hubPort: cport, credential: TOKEN, nodeId: 'e2e-node', offerBlob: blob, reply, localServePort: servePort, budgetMs: 10000, intervalMs: 8, permitHost: anyHost }),
			});
			await node.ready;
			direct = await HolePunch.connectDirect({ hubHost: '127.0.0.1', hubPort: cport, credential: TOKEN, nodeId: 'e2e-node', budgetMs: 10000, intervalMs: 8, permitHost: anyHost });
			ok('the client coordinates a direct hole-punched path to the node (end to end)', !!direct && direct.port > 0);
			if (direct) {
				const got = await new Promise((res) => { const c = net.connect(direct.port, direct.host); let g = ''; c.on('connect', () => c.write('punched-hello')); c.on('data', (d) => { g += d; if (g.length >= 13) res(g); }); c.on('error', () => res(null)); setTimeout(() => res(g || null), 3000); });
				ok('data round-trips through the direct hole-punched tunnel', got === 'punched-hello');
			} else { ok('data round-trips through the direct hole-punched tunnel', false); }
			node.stop();
		} finally { if (direct) { try { direct.stop(); } catch (_) {} } try { hub.close(); } catch (_) {} echo.close(); }
	}

	// 7. Cross-platform / non-blocking source contract: Node built-ins only (no native module, no spawned binary), no
	//    non-portable socket options (SO_REUSEPORT / reusePort throw on Windows and macOS), and no *Sync I/O.
	{
		const fs = require('fs'), path = require('path');
		const src = fs.readFileSync(path.join(__dirname, '..', 'HolePunch.js'), 'utf8');
		ok('HolePunch requires only Node built-ins and sibling modules (no native/third-party module)', !/require\('(?!net'|crypto'|\.\/PortMap'|\.\/Relay'|\.\/Tunnel')[^']+'\)/.test(src));
		ok('HolePunch spawns no binary', !/child_process|execFile\(|execSync\(|\bspawn\(/.test(src)); // .exec() (regex) is fine; a spawned process is not
		ok('HolePunch never sets the non-portable reusePort option', !/reusePort\s*:/.test(src)); // the comment may name it; only an actual `reusePort:` usage is a failure
		ok('HolePunch is non-blocking (no *Sync I/O)', !/readFileSync|writeFileSync|execSync/.test(src));
		ok('HolePunch uses RST recycling (resetAndDestroy) for the reflexive probe', /resetAndDestroy/.test(src));
	}

	clearInterval(keepAlive);
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HOLE-PUNCH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
