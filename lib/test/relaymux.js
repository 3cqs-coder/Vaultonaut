'use strict';
// lib/test/relaymux.js — the OPTIONAL relay multiplexing path (VAULTONAUT_RELAY_MUX, on by default). When both the node
// and the hub support it, every client connection for a node is carried as a STREAM over ONE persistent node link
// instead of a whole fresh worker TCP per client. It is NEGOTIATED and additive: the node advertises MUX in its HELLO,
// the hub confirms with `OK <port> MUX`, and EITHER side transparently falls back to the classic worker-pool splice
// otherwise. Covers the mux round-trip, that mux is actually negotiated, isolation and a large multi-frame response,
// and that a mismatch on either side falls back cleanly and still works. Loopback only; no engine, no network.
//
// Run:  node lib/test/relaymux.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const Relay = require('../Relay');
const Serve = require('../Serve'); // freePort() — ephemeral ports, so a co-tenant or a crashed prior run cannot flake this

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function get(port, path) { return new Promise((resolve, reject) => { const r = http.get({ host: '127.0.0.1', port, path }, (res) => { let d = ''; res.on('data', (c) => d += c); res.on('end', () => resolve(d)); }); r.on('error', reject); r.setTimeout(5000, () => { r.destroy(); reject(new Error('timeout')); }); }); }

const TOKEN = 'relay-mux-secret-token-0123456789';
const AUTH = 'node-auth-secret-xyz'; // a per-node auth secret gives the node a tag, which is what enables the mux request

async function serve() {
	const local = http.createServer((req, res) => res.end(req.url === '/big' ? 'B'.repeat(120000) : ('NODE ' + req.url)));
	await new Promise((r) => local.listen(0, '127.0.0.1', r));
	return { local, localPort: local.address().port };
}
// Register a node and capture whether mux was negotiated, from its 'up' event.
function register(opts) {
	let muxUp = null;
	const r = Relay.registerNode({ ...opts, onEvent: (e) => { if (e.type === 'up') muxUp = !!e.mux; } });
	return { ready: r.ready, stop: r.stop, muxUp: () => muxUp };
}
async function scenario({ hubMux, nodeMux, id }) {
	const { local, localPort } = await serve();
	const controlPort = await Serve.freePort();
	const pub = await Serve.freePort();
	const hub = Relay.runHub({ controlPort, token: TOKEN, host: '127.0.0.1', portRange: [pub, pub], mux: hubMux });
	await sleep(200);
	const opts = { hubHost: '127.0.0.1', hubPort: controlPort, token: TOKEN, nodeId: id, nodeAuth: AUTH, localPort };
	if (nodeMux != null) opts.mux = nodeMux;
	const node = register(opts);
	const info = await node.ready;
	await sleep(350); // let the mux link (or the worker pool) establish
	return { hub, node, local, publicPort: info.publicPort };
}

async function main() {
	// ── 1. Both ends support mux → it is negotiated and carries all traffic over one node link ──
	{
		const s = await scenario({ hubMux: true, nodeMux: true, id: 'mux-a' });
		ok('mux is negotiated when both the node and the hub support it', s.node.muxUp() === true);
		ok('a client reaches the node over the mux link', (await get(s.publicPort, '/one')) === 'NODE /one');
		const many = await Promise.all([get(s.publicPort, '/a'), get(s.publicPort, '/b'), get(s.publicPort, '/c'), get(s.publicPort, '/d')]);
		ok('concurrent clients are each carried as their own isolated mux stream', many.join(',') === 'NODE /a,NODE /b,NODE /c,NODE /d');
		ok('a large multi-frame response reassembles intact over the mux', (await get(s.publicPort, '/big')).length === 120000);
		s.node.stop(); s.hub.close(); s.local.close(); await sleep(100);
	}

	// ── 2. Hub has mux disabled → a mux-capable node falls back to the worker pool, still works ──
	{
		const s = await scenario({ hubMux: false, nodeMux: true, id: 'mux-b' });
		ok('a mux-capable node falls back to the worker pool when the hub declines mux', s.node.muxUp() === false);
		ok('the client still reaches the node via the splice fallback (hub declined mux)', (await get(s.publicPort, '/x')) === 'NODE /x');
		s.node.stop(); s.hub.close(); s.local.close(); await sleep(100);
	}

	// ── 3. Node has mux disabled → the hub serves it via workers even though the hub offers mux, still works ──
	{
		const s = await scenario({ hubMux: true, nodeMux: false, id: 'mux-c' });
		ok('a node with mux disabled uses the worker pool even when the hub offers mux', s.node.muxUp() === false);
		ok('the client still reaches the node via the splice fallback (node declined mux)', (await get(s.publicPort, '/y')) === 'NODE /y');
		s.node.stop(); s.hub.close(); s.local.close(); await sleep(100);
	}

	// ── 4. The mux path enforces the concurrent-connection ceiling (maxActiveSplices), just like the splice path ──
	//    A hostile client flood over the single mux link must not accumulate unbounded loopback-serve connections.
	{
		let liveServe = 0;
		const capServe = http.createServer((req, res) => { /* hold the request open so the stream stays live */ liveServe; res.write('x'); });
		capServe.on('connection', (s) => { liveServe++; s.on('close', () => { liveServe--; }); });
		await new Promise((r) => capServe.listen(0, '127.0.0.1', r));
		const controlPort = await Serve.freePort(); const pub = await Serve.freePort();
		const CAP = 4;
		const hub = Relay.runHub({ controlPort, token: TOKEN, host: '127.0.0.1', portRange: [pub, pub], mux: true, maxActiveSplices: CAP });
		await sleep(200);
		const node = register({ hubHost: '127.0.0.1', hubPort: controlPort, token: TOKEN, nodeId: 'mux-cap', nodeAuth: AUTH, localPort: capServe.address().port });
		const info = await node.ready; await sleep(350);
		const held = [];
		for (let i = 0; i < CAP + 4; i++) { const c = require('net').connect(info.publicPort, '127.0.0.1'); c.on('error', () => {}); c.write('GET /' + i + ' HTTP/1.0\r\n\r\n'); held.push(c); }
		// Give the hub time to admit up to the cap and refuse the rest.
		await new Promise((r) => setTimeout(r, 600));
		ok('the mux path admits no more than maxActiveSplices concurrent connections (mux streams counted)', liveServe <= CAP);
		for (const c of held) { try { c.destroy(); } catch (_) {} }
		node.stop(); hub.close(); capServe.close(); await sleep(100);
	}

	// ── 5. Static wire-drift guard: the negotiation shape is split across the hub and node sides and must stay in
	//    agreement, and additive so a 1.0.0 peer keeps working. Pin the four literals that must line up.
	{
		const src = fs.readFileSync(path.join(__dirname, '..', 'Relay.js'), 'utf8');
		ok('hub appends MUX to the OK reply and the node parser accepts a trailing MUX', /'OK ' \+ publicPort \+ \(n\.muxWanted \? ' MUX' : ''\)/.test(src) && /\/\^OK \(\\d\+\)\( MUX\)\?\$\//.test(src));
		ok('the node advertises MUX in HELLO and the hub detects it (same token)', /wantMux \? ' MUX' : ''/.test(src) && /parts\.includes\('MUX'\)/.test(src));
		ok('the MUXCONN verb is used by the node and handled by the hub (same token)', /greet\('MUXCONN'\)/.test(src) && /verb === 'MUXCONN'/.test(src));
		ok('mux is on by default and opt-out via VAULTONAUT_RELAY_MUX (additive, negotiated)', /process\.env\.VAULTONAUT_RELAY_MUX !== '0'/.test(src));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-MUX CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
