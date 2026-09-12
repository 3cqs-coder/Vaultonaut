'use strict';
// lib/test/tls.js — the relay hop is encrypted end to end. A node served through the relay presents a
// self-signed TLS certificate, the client PINS it (so the hub and the network only ever see opaque
// bytes), and a mirror runs over the TLS relay. Skips cleanly if the engine or openssl is unavailable
// (the relay still works over plain HTTP in that case — this only tests the encrypted path).
//
// Run:  node lib/test/tls.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');
const Relay = require('../Relay');
const Cert = require('../Cert');
const Serve = require('../Serve'); // freePort() — bind ephemeral ports instead of fixed ones, so this cannot flake on a busy port

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

let hub = null, handle = null, workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	if (!(await Cert.ensureCert('127.0.0.1'))) { console.log('openssl unavailable — skipping (the relay works over plain HTTP without it).'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-tls-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.bin'), crypto.randomBytes(200 * 1024));
	const A = path.join(tmp, 'A.vault'); await vdisk.importFolder(A, { password: 'pw', sourceDir: src });

	console.log('[serve through the relay over TLS]');
	const controlPort = await Serve.freePort();
	const pub = await Serve.freePort();
	hub = Relay.runHub({ controlPort, token: 'tok', host: '127.0.0.1', portRange: [pub, pub] });
	await sleep(300);
	const peerDir = path.join(tmp, 'nodeB');
	handle = await vdisk.serveVault(peerDir, { relay: { host: '127.0.0.1', port: controlPort, token: 'tok' } });
	ok('the relay serve is over TLS (https) with a pinned certificate', /^https:/.test(handle.url) && handle.secure === true && !!handle.ca);

	console.log('[one-paste connection code]');
	const code = vdisk.makePeerCode({ url: handle.url, user: handle.user, pass: handle.pass, ca: handle.ca });
	const p = vdisk.parsePeerCode(code);
	ok('the connection code carries the address, login, and certificate', p.url === handle.url && p.password === handle.pass && p.ca === handle.ca);

	console.log('[pinned mirror over the TLS relay]');
	await sleep(400);
	const { id } = await vdisk.savePeer({ label: 'B', url: p.url, user: p.user, password: p.password, ca: p.ca });
	ok('the peer connects over the pinned TLS relay', (await vdisk.testPeer(id)).ok === true);
	await vdisk.setMirrorDest(A, 'webdav:' + id);
	const r = await vdisk.syncMirror(A, { prime: true });
	ok('a mirror primes over the TLS relay', r.primed === true && fs.existsSync(path.join(peerDir, 'vault.json')));
	ok('only ciphertext reached the peer (no plaintext source name)', fs.existsSync(path.join(peerDir, 'data')) && !fs.existsSync(path.join(peerDir, 'a.bin')));
	await vdisk.removeMirror(A).catch(() => {}); await vdisk.removePeer(id).catch(() => {});

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TLS CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { if (handle) await handle.stop(); } catch (_) {}
	try { if (hub) hub.close(); } catch (_) {}
	try { for (const kv of await vdisk.listKnownVaults()) if ((kv.path || kv).includes('vdisk-tls-')) await vdisk.removeKnownVault(kv.path || kv); } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
