'use strict';
// lib/test/mesh.js — Tier 3 end to end. Disperse a real vault across n folders, lose more than the
// budget and confirm it can't rebuild, then gather k shards and reconstruct a working vault that still
// decrypts. Also: repair a missing shard from the survivors, and split the unlock key k-of-n so any k
// key shares mount the vault while k-1 do not.
//
// Run:  node lib/test/mesh.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function refused(fn) { try { await fn(); return false; } catch (_) { return true; } }
async function exists(p) { try { await fsp.stat(p); return true; } catch (_) { return false; } }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mesh-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	const secretText = 'top secret ' + crypto.randomBytes(8).toString('hex');
	await fsp.writeFile(path.join(src, 'notes.txt'), secretText);
	await fsp.writeFile(path.join(src, 'blob.bin'), crypto.randomBytes(300 * 1024));
	const v = path.join(tmp, 'Mesh.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	console.log('[disperse 3-of-5 across folders]');
	const nodes = Array.from({ length: 5 }, (_, i) => path.join(tmp, 'node' + i));
	const d = await vdisk.disperse(v, { n: 5, k: 3, dests: nodes });
	ok('five shards were written, one per node', d.shards.length === 5 && (await Promise.all(d.shards.map(exists))).every(Boolean));
	ok('the guidance reports the expansion factor and tolerance', d.expansionFactor === Math.round(5 / 3 * 100) / 100 && d.tolerate === 2);

	console.log('[losing more than the budget cannot rebuild]');
	// Only 2 shards (k=3 needed) -> must fail.
	const outDir = path.join(tmp, 'restored');
	ok('two of five shards refuse to reconstruct', await refused(() => vdisk.reconstructFromShards([d.shards[0], d.shards[4]], outDir)));

	console.log('[any k shards reconstruct a working vault]');
	const r = await vdisk.reconstructFromShards([d.shards[4], d.shards[1], d.shards[2]], outDir);
	ok('reconstruct produced a vault', !!r.vault && await exists(r.vault));
	// Mount it and confirm the plaintext survived the whole round trip.
	const mnt = await vdisk.mount(r.vault, { password: 'pw' });
	let readBack = '';
	try { readBack = await fsp.readFile(path.join(mnt.mountpoint, 'notes.txt'), 'utf8'); } catch (_) {}
	await vdisk.unmount(mnt.mountpoint).catch(() => {});
	ok('the reconstructed vault decrypts to the original contents', readBack === secretText);

	console.log('[repair a lost shard from the survivors]');
	await fsp.rm(d.shards[0], { force: true }); // node0 churned out
	const rep = await vdisk.repairDispersal(d.shards);
	ok('the missing shard was re-created', rep.repaired === 1 && await exists(d.shards[0]));
	ok('all five shards are healthy again', (await vdisk.inspectShards(d.shards)).good === 5);

	console.log('[threshold key: k-of-n unlock]');
	const t = await vdisk.addThresholdKey(v, { password: 'pw', n: 4, k: 2 });
	ok('four key shares were issued', t.shares.length === 4);
	// Any 2 shares reconstruct the unlock secret; mount the ORIGINAL vault with it.
	const secretFrom2 = vdisk.unlockSecretFromShares([t.shares[3], t.shares[1]]);
	const m2 = await vdisk.mount(v, { password: secretFrom2 });
	ok('any two key shares unlock the vault', !!m2.mountpoint);
	await vdisk.unmount(m2.mountpoint).catch(() => {});
	ok('one key share cannot even reconstruct the secret', await refused(async () => vdisk.unlockSecretFromShares([t.shares[0]])));
	// A wrong-but-complete reconstruction (2 shares from a different split) must not unlock.
	const other = await vdisk.addThresholdKey(v, { password: 'pw', n: 4, k: 2 });
	ok('key shares from a different split do not unlock', await refused(async () => { const bad = vdisk.unlockSecretFromShares([t.shares[0], other.shares[1]]); const mm = await vdisk.mount(v, { password: bad }); await vdisk.unmount(mm.mountpoint).catch(() => {}); }));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MESH CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-mesh-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
