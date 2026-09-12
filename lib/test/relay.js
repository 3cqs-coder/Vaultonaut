'use strict';
// lib/test/relay.js — the self-hosted relay hub + node registration. A node behind NAT reaches the
// hub outbound; a client reaches the node THROUGH the hub's public port with no relay code of its own.
// Runs entirely on loopback with a stand-in local HTTP service (the vault serve, in real use), so it
// needs no engine and no network. Covers relaying, token auth, a stable per-node public port, and
// concurrent requests.
//
// Run:  node lib/test/relay.js

const http = require('http');
const net = require('net');
const Relay = require('../Relay');
const Serve = require('../Serve'); // freePort() — bind ephemeral ports instead of fixed ones, so a co-tenant process or a crashed prior run cannot make this test flake

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function get(port, path) { return new Promise((resolve, reject) => { const r = http.get({ host: '127.0.0.1', port, path }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d)); }); r.on('error', reject); r.setTimeout(4000, () => { r.destroy(); reject(new Error('timeout')); }); }); }

let local = null, hub = null, node = null;
async function main() {
	// Stand-in for a vault's local WebDAV serve.
	local = http.createServer((req, res) => res.end('NODE ' + req.url));
	await new Promise(r => local.listen(0, '127.0.0.1', r));
	const localPort = local.address().port;

	console.log('[hub + node registration]');
	const controlPort = await Serve.freePort();
	const pub = await Serve.freePort(); // a single-port public range, as relayhardening does — the node id hashes into it deterministically
	hub = Relay.runHub({ controlPort, token: 'secret', host: '127.0.0.1', portRange: [pub, pub] });
	await sleep(250);
	{ const r = Relay.registerNode({ hubHost: '127.0.0.1', hubPort: controlPort, token: 'secret', nodeId: 'node-alpha', localPort }); const info = await r.ready; node = { publicPort: info.publicPort, stop: r.stop }; }
	ok('the node is assigned a public port on the hub', Number.isInteger(node.publicPort) && node.publicPort === pub);
	await sleep(300); // let the worker pool connect

	console.log('[relaying through the hub]');
	ok('a client reaches the node through the hub public port', (await get(node.publicPort, '/one')) === 'NODE /one');
	ok('a second request works too (workers replenish)', (await get(node.publicPort, '/two')) === 'NODE /two');
	const many = await Promise.all([get(node.publicPort, '/a'), get(node.publicPort, '/b'), get(node.publicPort, '/c')]);
	ok('several concurrent requests all reach the node', many.join(',') === 'NODE /a,NODE /b,NODE /c');

	console.log('[auth + stability]');
	const bad = await new Promise((resolve) => { const s = net.connect(controlPort, '127.0.0.1', () => s.write('HELLO wrongtoken n2\n')); let b = ''; s.on('data', d => b += d); s.on('close', () => resolve(b.trim())); setTimeout(() => { s.destroy(); resolve(b.trim()); }, 600); });
	ok('a wrong token is refused', /ERR auth/.test(bad));
	// The public port for a given node id is deterministic (a hash into the range), so a reconnecting
	// node keeps the same address — verify a fresh registration of the same id lands on the same port.
	const r2 = Relay.registerNode({ hubHost: '127.0.0.1', hubPort: controlPort, token: 'secret', nodeId: 'node-alpha', localPort });
	const node2 = await r2.ready;
	ok('the same node id keeps the same public port across reconnects', node2.publicPort === node.publicPort);
	r2.stop();

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { if (node) node.stop(); } catch (_) {}
	try { if (hub) hub.close(); } catch (_) {}
	try { if (local) local.close(); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
