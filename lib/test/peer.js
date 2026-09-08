'use strict';
// lib/test/peer.js — end-to-end tests for Tier 2 "Anywhere access": serving a vault's ciphertext over
// WebDAV (the node side) and two-way mirroring another node against it (the peer mirror). Runs
// entirely over loopback with the bundled engine — no network, no relay — which is exactly the
// substrate a tunnel/VPN would carry between machines.
//
// Run:  node lib/test/peer.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const has = (p) => fs.existsSync(p);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

let workspace = null, serveHandle = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-peer-'));
	workspace = tmp;

	// Node A: a real vault with content. Node B: a fresh, empty target folder a first mirror will prime.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.bin'), crypto.randomBytes(300 * 1024));
	const A = path.join(tmp, 'A.vault');
	await vdisk.importFolder(A, { password: 'pw', sourceDir: src });
	const peerDir = path.join(tmp, 'nodeB');

	console.log('[serve a node]');
	serveHandle = await vdisk.serveVault(peerDir, {});
	ok('serving over loopback WebDAV with generated credentials', /^http:\/\/127\.0\.0\.1:\d+\/$/.test(serveHandle.url) && !!serveHandle.user && !!serveHandle.pass);
	ok('a fresh peer target is not yet a vault', serveHandle.isVault === false);

	const { id } = await vdisk.savePeer({ label: 'B', url: serveHandle.url, user: serveHandle.user, password: serveHandle.pass });
	ok('the peer connects and authenticates', (await vdisk.testPeer(id)).ok === true);
	ok('a saved peer never exposes its stored password', (await vdisk.listPeers()).find(p => p.id === id).hasPassword === true && (await vdisk.listPeers()).find(p => p.id === id).password === undefined);
	// SECURITY: the served endpoint must reject an unauthenticated or wrong-credential caller — only someone with the
	// generated credential may read even the ciphertext.
	const noAuth = await fetch(serveHandle.url).then(r => r.status).catch(() => 0);
	ok('the served endpoint rejects a request with no credentials (401)', noAuth === 401);
	const badAuth = await fetch(serveHandle.url, { headers: { Authorization: 'Basic ' + Buffer.from('nobody:wrong').toString('base64') } }).then(r => r.status).catch(() => 0);
	ok('the served endpoint rejects a wrong credential (401)', badAuth === 401);

	console.log('[prime + two-way over the peer]');
	await vdisk.setMirrorDest(A, 'webdav:' + id);
	const r1 = await vdisk.syncMirror(A, { prime: true });
	ok('priming copies the whole vault to the peer (a mountable copy lands there)', r1.primed === true && has(path.join(peerDir, 'vault.json')) && has(path.join(peerDir, 'data')));
	ok('only ciphertext reaches the peer (no plaintext source name)', has(path.join(peerDir, 'data')) && !has(path.join(peerDir, 'a.bin')));

	await fsp.writeFile(path.join(A, 'data', 'fromA.bin'), crypto.randomBytes(2048));
	await vdisk.syncMirror(A);
	ok('a change on this node propagates to the peer', has(path.join(peerDir, 'data', 'fromA.bin')));

	await fsp.writeFile(path.join(peerDir, 'data', 'fromB.bin'), crypto.randomBytes(2048));
	await sleep(6000); // let the serve's short dir-cache pick up the out-of-band change
	await vdisk.syncMirror(A);
	ok('a change on the peer propagates back to this node', has(path.join(A, 'data', 'fromB.bin')));
	ok('the vault still decrypts after peer round-trips', (await vdisk.verify(A, { password: 'pw', deep: true })).integrity === 'ok');

	console.log('[version capture, browse, and restore over the WebDAV peer]');
	// Real encrypted content written through a crypt remote (no mount needed), so the version browse can actually
	// decrypt the snapshot that was captured on the REMOTE side. This exercises the remote code paths end-to-end:
	// listing snapshot dirs over WebDAV, decrypting file names through a crypt-over-remote config, and restoring.
	const Vault = require('../Vault'), Rclone = require('../Rclone');
	const bin = require('../RcloneSetup').resolve();
	const mf = JSON.parse(await fsp.readFile(path.join(A, 'vault.json'), 'utf8'));
	const master = Vault.parseReadCap((await vdisk.makeReadCap(A, { password: 'pw' })).token).master;
	const cfgA = await Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: path.join(A, 'data'), passwordObscured: await Rclone.obscure(bin, master), saltObscured: mf.crypt.salt, filenameEnc: mf.crypt.filename_encryption, dirNameEnc: mf.crypt.directory_name_encryption }));
	await Rclone.run(bin, ['rcat', 'vault:doc.txt'], { configPath: cfgA, input: 'PEER ONE' });
	await vdisk.syncMirror(A);                 // baseline doc.txt on both sides
	await sleep(50);
	await Rclone.run(bin, ['rcat', 'vault:doc.txt'], { configPath: cfgA, input: 'PEER TWO (longer, distinct size)' });
	await vdisk.syncMirror(A);                 // overwrite → the peer's OLD copy is captured to the peer's .versions
	await sleep(6000);                          // let the serve's dir-cache surface the newly written .versions
	const vlist = await vdisk.listVersions(A, { password: 'pw' });
	const psnap = vlist.snapshots.find(s => s.origin === 'mirror-dest' && (s.files || []).includes('doc.txt'));
	ok('a snapshot on the WebDAV peer lists the prior file (decrypted over the remote)', !!psnap);
	if (psnap) {
		const rr = await vdisk.restoreVersion(A, { password: 'pw', origin: 'mirror-dest', timestamp: psnap.timestamp, file: 'doc.txt' });
		const got = await Rclone.run(bin, ['cat', 'vault:' + rr.restoredAs], { configPath: cfgA });
		ok('restoring from the WebDAV peer decrypts to the prior content', got.status === 0 && got.stdout === 'PEER ONE');
	}
	await Rclone.removeConfig(cfgA);

	console.log('[teardown]');
	await serveHandle.stop(); serveHandle = null;
	ok('the peer becomes unreachable once serving stops', (await vdisk.testPeer(id)).ok === false);
	await vdisk.removeMirror(A);
	await vdisk.removePeer(id);
	ok('removing the peer forgets it', !(await vdisk.listPeers()).some(p => p.id === id));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PEER CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { if (serveHandle) await serveHandle.stop(); } catch (_) {}
	try { for (const kv of await vdisk.listKnownVaults()) if ((kv.path || kv).includes('vdisk-peer-')) await vdisk.removeKnownVault(kv.path || kv); } catch (_) {}
	try { const s = await vdisk.getSettings(); for (const p of await vdisk.listPeers()) if (String(p.label) === 'B') await vdisk.removePeer(p.id); void s; } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
