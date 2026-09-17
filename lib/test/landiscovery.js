'use strict';
// lib/test/landiscovery.js — LAN discovery (lib/LanDiscovery.js). Pure UDP over loopback, so it needs no engine, no
// spawned binary, and no native module, and runs identically on macOS/Windows/Linux. It uses a HIGH random discovery
// port (never the real 7421) and sends to 127.0.0.1 only, so it neither collides with a running instance nor depends
// on the CI runner permitting subnet broadcast.
//
// Run:  node lib/test/landiscovery.js

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const LanDiscovery = require('../LanDiscovery');
const Cert = require('../Cert');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// A high, test-local discovery port, so we never touch the real 7421 or a running node.
let nextPort = 39000 + Math.floor(Math.random() * 2000);
const testPort = () => nextPort++;

async function main() {
	// 1. Announce -> discover: find() resolves the announced node with the SENDER's host, the announced port, and fp.
	{
		const port = testPort();
		const ann = LanDiscovery.announce({ nodeId: 'node-abc', port: 55555, fp: 'AA:BB:CC', discoveryPort: port, targets: ['127.0.0.1'] });
		const found = await LanDiscovery.find((p) => p.nodeId === 'node-abc', { timeoutMs: 2000, discoveryPort: port });
		ann.stop();
		ok('discovers an announced node (id, port, fp, sender host)',
			!!found && found.nodeId === 'node-abc' && found.port === 55555 && found.fp === 'AA:BB:CC' && found.host === '127.0.0.1');
	}

	// 2. find() resolves null when no announcement matches within the timeout (never hangs, never rejects).
	{
		const port = testPort();
		const ann = LanDiscovery.announce({ nodeId: 'node-xyz', port: 1234, discoveryPort: port, targets: ['127.0.0.1'] });
		const none = await LanDiscovery.find((p) => p.nodeId === 'does-not-exist', { timeoutMs: 700, discoveryPort: port });
		ann.stop();
		ok('find() returns null when nothing matches (bounded, no hang)', none === null);
	}

	// 3. browse() ignores malformed, foreign-protocol, and oversized packets, accepting only a valid VDLAN1 datagram.
	{
		const port = testPort();
		const got = [];
		const b = LanDiscovery.browse((p) => got.push(p), { discoveryPort: port });
		const s = dgram.createSocket('udp4');
		const to = (buf) => new Promise((res) => s.send(buf, port, '127.0.0.1', () => res()));
		await to(Buffer.from('not json at all'));                                        // garbage
		await to(Buffer.from(JSON.stringify({ m: 'OTHERAPP', id: 'x', port: 10 })));      // wrong MAGIC
		await to(Buffer.from(JSON.stringify({ m: LanDiscovery.MAGIC, id: 5, port: 10 }))); // id not a string
		await to(Buffer.alloc(LanDiscovery.MAX_PACKET + 50, 0x7b));                        // oversized
		await to(Buffer.from(JSON.stringify({ m: LanDiscovery.MAGIC, id: 'good', port: 4321 }))); // the only valid one
		await sleep(250);
		b.stop(); s.close();
		ok('browse() accepts only a valid announcement, ignoring junk/foreign/oversized', got.length === 1 && got[0].nodeId === 'good' && got[0].port === 4321);
	}

	// 3b. Replay/dedup hardening: a stale timestamp is dropped, a repeated nonce is delivered at most once, and a fresh
	//     packet with a new nonce still gets through. (A packet with no ts/n at all is accepted — see the valid case in
	//     test 3 above, which carries neither — so an older/minimal sender keeps working.)
	{
		const port = testPort();
		const got = [];
		const b = LanDiscovery.browse((p) => got.push(p), { discoveryPort: port });
		const s = dgram.createSocket('udp4');
		const to = (buf) => new Promise((res) => s.send(buf, port, '127.0.0.1', () => res()));
		const M = LanDiscovery.MAGIC;
		// Stale: a timestamp well outside the freshness window is rejected.
		await to(Buffer.from(JSON.stringify({ m: M, id: 'stale', port: 100, ts: Date.now() - (LanDiscovery.MAX_SKEW_MS + 60000), n: 'aaaa' })));
		// Duplicate nonce: the SAME nonce sent twice is delivered only once.
		const dup = JSON.stringify({ m: M, id: 'dup', port: 200, ts: Date.now(), n: 'dup-nonce' });
		await to(Buffer.from(dup)); await to(Buffer.from(dup));
		// Fresh, distinct nonce: delivered.
		await to(Buffer.from(JSON.stringify({ m: M, id: 'fresh', port: 300, ts: Date.now(), n: 'fresh-nonce' })));
		await sleep(300);
		b.stop(); s.close();
		const ids = got.map((p) => p.nodeId);
		ok('browse() drops a stale (replayed) timestamp', !ids.includes('stale'));
		ok('browse() delivers a repeated nonce at most once', ids.filter((x) => x === 'dup').length === 1);
		ok('browse() delivers a fresh, distinct announcement', ids.includes('fresh'));
	}

	// 3c. Multi-homed announce targets: directedBroadcast computes the subnet broadcast, and broadcastTargets always
	//     includes the global-broadcast and loopback base targets (so a single-homed host still behaves as before).
	{
		ok('directedBroadcast computes the subnet broadcast for a /24', LanDiscovery.directedBroadcast('192.168.1.42', '255.255.255.0') === '192.168.1.255');
		ok('directedBroadcast computes the subnet broadcast for a /16', LanDiscovery.directedBroadcast('10.5.9.3', '255.255.0.0') === '10.5.255.255');
		ok('directedBroadcast returns null for malformed input', LanDiscovery.directedBroadcast('nope', '255.255.255.0') === null && LanDiscovery.directedBroadcast('1.2.3.4', '') === null);
		const targets = LanDiscovery.broadcastTargets();
		ok('broadcastTargets always includes the base global-broadcast and loopback targets', targets.includes('255.255.255.255') && targets.includes('127.0.0.1'));
		ok('broadcastTargets is deduplicated', new Set(targets).size === targets.length);
	}

	// 4. certFp(): a real self-signed PEM yields a colon-separated SHA-256 fingerprint; garbage yields null (fail closed).
	{
		ok('certFp() returns null for non-PEM input', LanDiscovery.certFp('-----garbage-----') === null);
		const { certPem } = Cert.generateSelfSigned('127.0.0.1');
		const fp = LanDiscovery.certFp(certPem);
		ok('certFp() returns a SHA-256 fingerprint for a real cert', typeof fp === 'string' && /^[0-9A-F]{2}(:[0-9A-F]{2})+$/i.test(fp));
		// The SAME cert always fingerprints the same way — this is what lets a peer match an announcement to its stored ca.
		ok('certFp() is stable for the same cert', LanDiscovery.certFp(certPem) === fp);
	}

	// 5. Cross-platform contract: the module loads ONLY dgram + crypto (no native addon), and spawns no binary.
	{
		const src = fs.readFileSync(path.join(__dirname, '..', 'LanDiscovery.js'), 'utf8');
		const reqs = [...src.matchAll(/require\('([^']+)'\)/g)].map((m) => m[1]);
		ok('LanDiscovery requires only dgram, crypto and os (no native module)', reqs.length > 0 && reqs.every((r) => r === 'dgram' || r === 'crypto' || r === 'os'));
		ok('LanDiscovery spawns no binary (no child_process/exec)', !/child_process|spawnSync|\bspawn\(|\bexec(File)?\(/.test(src));
		ok('LanDiscovery is non-blocking (no *Sync file/IO calls)', !/readFileSync|writeFileSync|execSync/.test(src));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LAN-DISCOVERY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
