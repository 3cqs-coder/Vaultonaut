'use strict';
// lib/test/mirrorversions.js — two-way mirror VERSION CAPTURE, plus browsing and restoring those versions.
// When a bisync overwrites a file, the prior copy is kept: the destination's old copies go into the destination's
// own `.versions/`, and the local vault's old copies go into an app-data-dir store OUTSIDE the vault (so the live
// vault folder is never touched). This uses REAL encrypted content (written through the crypt remote, no mount
// needed) so it can also verify that listVersions decrypts the snapshots and restoreVersion brings a prior version
// back non-destructively — for BOTH the destination store and the local (out-of-vault) store. Local destination,
// so it needs only the bundled engine. The remote (SFTP/WebDAV) destination path shares this exact code.
//
// Run:  node lib/test/mirrorversions.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// A crypt config over an arbitrary cipher `data/` dir (the vault's or the mirror copy's), so the test can write
// and read real encrypted files without mounting — exactly how the version browse/restore reaches a snapshot.
async function cryptCfg(bin, dataDir, manifest, master) {
	const c = manifest.crypt;
	return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: dataDir, passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption }));
}
async function put(bin, cfg, name, content) { await Rclone.run(bin, ['rcat', 'vault:' + name], { configPath: cfg, input: content }); }
async function get(bin, cfg, name) { const r = await Rclone.run(bin, ['cat', 'vault:' + name], { configPath: cfg }); return r.status === 0 ? r.stdout : null; }

let workspace = null;
let path1Store = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const bin = require('../RcloneSetup').resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mirrorversions-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'seed.txt'), 'seed');
	const v = path.join(tmp, 'MV.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const manifest = JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
	const master = Vault.parseReadCap((await vdisk.makeReadCap(v, { password: 'pw' })).token).master;
	const vaultCfg = await cryptCfg(bin, path.join(v, 'data'), manifest, master);
	const h = crypto.createHash('sha256').update(path.resolve(v)).digest('hex').slice(0, 16);
	path1Store = path.join(Common.dataDir(), 'mirror-versions', h);

	const dest = path.join(tmp, 'dest');
	await vdisk.setMirrorDest(v, dest);
	await vdisk.syncMirror(v, { prime: true });
	const destCfg = await cryptCfg(bin, path.join(dest, 'MV.vault', 'data'), manifest, master);

	// ---- destination-side capture + browse + restore: a file overwritten on the VAULT keeps its OLD copy at dest ----
	await put(bin, vaultCfg, 'keep.txt', 'ONE');
	await vdisk.syncMirror(v);                        // baseline keep.txt=ONE on both sides
	await new Promise(r => setTimeout(r, 20));         // a distinct version timestamp
	await put(bin, vaultCfg, 'keep.txt', 'TWO');
	await vdisk.syncMirror(v);                        // vault→dest overwrite; dest's ONE is captured to dest .versions
	ok('the destination now holds the new content', (await get(bin, destCfg, 'keep.txt')) === 'TWO');

	let list = await vdisk.listVersions(v, { password: 'pw' });
	ok('version history is reported from a store', list.hasStore === true);
	const destSnap = list.snapshots.find(s => s.origin === 'mirror-dest' && (s.files || []).includes('keep.txt'));
	ok('a destination snapshot lists the prior file (decrypted name)', !!destSnap);
	ok('the destination snapshot is labeled for the user', destSnap && destSnap.originLabel === 'Mirror');
	if (destSnap) {
		const rr = await vdisk.restoreVersion(v, { password: 'pw', origin: 'mirror-dest', timestamp: destSnap.timestamp, file: 'keep.txt' });
		ok('restoring names a non-clobbering copy', /keep \(restored .*\)\.txt/.test(rr.restoredAs));
		ok('the restored copy decrypts to the OLD content', (await get(bin, vaultCfg, rr.restoredAs)) === 'ONE');
		ok('the current file was left untouched by the restore', (await get(bin, vaultCfg, 'keep.txt')) === 'TWO');
	}

	// ---- local-side capture + browse: a file overwritten on the DESTINATION keeps the VAULT's OLD copy, outside the vault ----
	await put(bin, vaultCfg, 'edit.txt', 'C');
	await vdisk.syncMirror(v);                        // baseline edit.txt=C on both sides
	await new Promise(r => setTimeout(r, 20));
	await put(bin, destCfg, 'edit.txt', 'D');          // change it on the DESTINATION side
	await vdisk.syncMirror(v);                        // dest→vault overwrite; the vault's C is captured to the local store
	ok('the vault received the destination edit', (await get(bin, vaultCfg, 'edit.txt')) === 'D');
	ok('the local (out-of-vault) store exists', fs.existsSync(path1Store));
	list = await vdisk.listVersions(v, { password: 'pw' });
	const localSnap = list.snapshots.find(s => s.origin === 'mirror-local' && (s.files || []).includes('edit.txt'));
	ok('a local-store snapshot lists the vault\'s prior file', !!localSnap);
	if (localSnap) {
		const rr = await vdisk.restoreVersion(v, { password: 'pw', origin: 'mirror-local', timestamp: localSnap.timestamp, file: 'edit.txt' });
		ok('restoring the local-store version decrypts to the prior content', (await get(bin, vaultCfg, rr.restoredAs)) === 'C');
	}

	// ---- the version store must never leak back into the live vault ----
	ok('no .versions folder appears at the live vault root (the filter holds)', !fs.existsSync(path.join(v, '.versions')));
	ok('the live vault decrypts cleanly after all captures', (await vdisk.verify(v, { password: 'pw', deep: true })).integrity === 'ok');

	await Rclone.removeConfig(vaultCfg); await Rclone.removeConfig(destCfg);
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MIRROR-VERSION CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-mirrorversions-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (path1Store) await fsp.rm(path1Store, { recursive: true, force: true }); } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
