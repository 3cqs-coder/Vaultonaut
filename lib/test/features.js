'use strict';
// lib/test/features.js — focused regression checks for the key-management and safety features that
// do NOT need a mount driver: the no-auto-overwrite guarantee, keyfiles, security levels, folder
// import, and cloud-sync leftover detection. These run entirely through the encryption engine (no
// FUSE), so they are fast and portable.
//
// Run:  node lib/test/features.js
// Requires the bundled engine to be present.

const fsp = require('fs').promises;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const vdisk = require('../index');
const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-features-'));
	workspace = tmp; // remembered so the finally-cleanup can remove it and de-register its vaults
	console.log('Workspace: ' + tmp);

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('\nEngine missing — run "node vaultonaut.js setup". Skipping.'); return; }

	// --- No auto-overwrite: backup must not mirror over a DIFFERENT vault of the same name ---
	console.log('\n[no auto-overwrite]');
	const aDir = path.join(tmp, 'a'), bDir = path.join(tmp, 'b');
	await fsp.mkdir(aDir, { recursive: true }); await fsp.mkdir(bDir, { recursive: true });
	const vA = path.join(aDir, 'Personal.vault'), vB = path.join(bDir, 'Personal.vault');
	await vdisk.create(vA, { password: 'pw' });
	await vdisk.create(vB, { password: 'pw' });
	const dest = path.join(tmp, 'backups');
	await vdisk.backup(vA, dest);
	ok('first backup of a same-named vault succeeds', true);
	let refusedDiff = false;
	try { await vdisk.backup(vB, dest); } catch (e) { refusedDiff = /DIFFERENT vault/.test(e.message); }
	ok('backing up a DIFFERENT same-named vault is refused (no overwrite)', refusedDiff);
	await vdisk.backup(vA, dest); // same vault over its own prior backup is allowed
	ok('re-backing up the SAME vault over its prior backup is allowed', true);
	let refusedCreate = false;
	try { await vdisk.create(vA, { password: 'pw' }); } catch (e) { refusedCreate = /already exists/.test(e.message); }
	ok('create refuses to overwrite an existing vault', refusedCreate);
	// restore must refuse over a vault that exists with ONLY its backup manifest (no vault.json),
	// which readManifest still self-heals from — otherwise a restore could orphan it without --force.
	const rDest = path.join(tmp, 'rdest');
	const existing = path.join(rDest, 'Personal.vault');
	await vdisk.create(existing, { password: 'pw' });
	await fsp.rm(path.join(existing, 'vault.json')); // leave only .vault.bak
	let refusedRestore = false;
	try { await vdisk.restore(vB, rDest); } catch (e) { refusedRestore = /already exists/.test(e.message); }
	ok('restore refuses over a backup-only-manifest vault without --force', refusedRestore);

	// --- Backup deletion cap: refuse to mirror a large source loss onto the backup (>50% deletions) ---
	console.log('\n[backup deletion cap]');
	const bigSrc = path.join(tmp, 'bigsrc'); await fsp.mkdir(bigSrc, { recursive: true });
	for (let i = 0; i < 30; i++) await fsp.writeFile(path.join(bigSrc, 'f' + i + '.bin'), crypto.randomBytes(2048));
	const vBig = path.join(tmp, 'Big.vault');
	await vdisk.importFolder(vBig, { password: 'pw', sourceDir: bigSrc });
	const bigDest = path.join(tmp, 'bigbackup');
	await vdisk.backup(vBig, bigDest); // establish the backup (encrypted blobs + manifest)
	ok('backup of a 30-file vault succeeds', true);
	// Simulate a source loss: delete most of the encrypted blobs at rest, then try to back up again. The
	// deterministic list-and-diff must see the deletions and refuse before the sync can wipe the good backup.
	async function dataBlobs(dir) { const out = []; for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) out.push(...await dataBlobs(p)); else out.push(p); } return out; }
	const blobs = await dataBlobs(path.join(vBig, 'data'));
	for (const b of blobs.slice(0, Math.ceil(blobs.length * 0.7))) await fsp.rm(b); // remove ~70%
	let refusedWipe = false;
	try { await vdisk.backup(vBig, bigDest); } catch (e) { refusedWipe = !!e.sourceDamaged && /would delete \d+ of \d+/.test(e.message); }
	ok('backup is refused when the source lost more than half its files (the backup is not wiped)', refusedWipe);

	// --- Keyfiles ---
	console.log('\n[keyfiles]');
	const kfVault = path.join(tmp, 'KF.vault');
	await vdisk.create(kfVault, { password: 'the-password' });
	const kfPath = path.join(tmp, 'secret.key');
	await fsp.writeFile(kfPath, crypto.randomBytes(2048));
	const digest = await vdisk.keyfileDigestFromFile(kfPath);
	await vdisk.addKeyfile(kfVault, { password: 'the-password', keyfileDigest: digest, keyfileName: 'secret.key' });
	const kfSlot = (await vdisk.listKeys(kfVault)).slots.find(s => s.kind === 'keyfile');
	ok('keyfile slot is added with its name hint', !!kfSlot && kfSlot.keyfileName === 'secret.key');
	ok('the keyfile digest opens the vault', (await vdisk.verify(kfVault, { password: digest })).password === 'ok');
	ok('the original password still opens the vault', (await vdisk.verify(kfVault, { password: 'the-password' })).password === 'ok');
	const wrongDigest = crypto.createHash('sha256').update(crypto.randomBytes(2048)).digest('base64');
	// A key-wrapping vault throws on a secret that opens no slot — that IS the rejection.
	let wrongRejected = false;
	try { wrongRejected = (await vdisk.verify(kfVault, { password: wrongDigest })).password !== 'ok'; } catch (e) { wrongRejected = !!e.wrongPassword; }
	ok('a different keyfile does NOT open the vault', wrongRejected);

	// --- Security levels (Argon2id) preserved across password change and add-key ---
	console.log('\n[security levels]');
	const hiVault = path.join(tmp, 'High.vault');
	await vdisk.create(hiVault, { password: 'p1', level: 'high' });
	ok('created at the high level', Kdf.levelOf((await vdisk.readManifest(hiVault)).crypt.keySlots[0].kdf) === 'high');
	await vdisk.changePassword(hiVault, { oldPassword: 'p1', newPassword: 'p2' });
	ok('level survives a password change', Kdf.levelOf((await vdisk.readManifest(hiVault)).crypt.keySlots[0].kdf) === 'high');
	await vdisk.addKey(hiVault, { password: 'p2', newPassword: 'p3', label: 'Second' });
	const added = (await vdisk.readManifest(hiVault)).crypt.keySlots.find(s => s.label === 'Second');
	ok('an added key matches the vault level', Kdf.levelOf(added.kdf) === 'high');
	const stdVault = path.join(tmp, 'Std.vault');
	await vdisk.create(stdVault, { password: 'p' });
	ok('a default create is the standard level', Kdf.levelOf((await vdisk.readManifest(stdVault)).crypt.keySlots[0].kdf) === 'standard');

	// --- Folder import ---
	console.log('\n[folder import]');
	const src = path.join(tmp, 'MyDocs');
	await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), 'alpha');
	await fsp.writeFile(path.join(src, 'sub', 'b.txt'), 'bravo');
	const impVault = path.join(tmp, 'Imported.vault');
	const imp = await vdisk.importFolder(impVault, { password: 'pw', sourceDir: src });
	ok('import copies every file in', imp.count === 2);
	ok('the originals are left untouched', fs.readFileSync(path.join(src, 'a.txt'), 'utf8') === 'alpha');
	ok('the vault holds the imported files', (await vdisk.list(impVault, { password: 'pw' })).filter(f => !f.endsWith('/')).length === 2);
	let refusedImp = false;
	try { await vdisk.importFolder(impVault, { password: 'pw', sourceDir: src }); } catch (e) { refusedImp = /already exists/.test(e.message); }
	ok('import refuses to overwrite an existing vault', refusedImp);

	// --- Cloud-sync leftover detection ---
	console.log('\n[sync leftovers]');
	const syncVault = path.join(tmp, 'Synced.vault');
	await vdisk.create(syncVault, { password: 'pw' });
	const store = path.join(syncVault, 'data');
	await fsp.writeFile(path.join(store, 'blob1 (conflicted copy 2024-05-01).bin'), 'x');
	await fsp.writeFile(path.join(store, 'blob2.part'), 'x');
	const issues = await vdisk.scanSyncArtifacts(syncVault);
	ok('a conflicted copy is detected', issues.some(i => i.kind === 'conflict'));
	ok('a partial upload is detected', issues.some(i => i.kind === 'partial'));
	ok('a clean vault reports no sync leftovers', (await vdisk.scanSyncArtifacts(stdVault)).length === 0);
	// A sync leftover (an undecryptable-named blob) must NOT make a deep verify report corruption —
	// it is a sync issue, not a content-integrity failure. Import a real file first so the deep scan
	// actually reads content, then plant a conflict blob among the encrypted files.
	const realSrc = path.join(tmp, 'real'); await fsp.mkdir(realSrc, { recursive: true });
	await fsp.writeFile(path.join(realSrc, 'doc.txt'), 'real content');
	const dvVault = path.join(tmp, 'DeepVerify.vault');
	await vdisk.importFolder(dvVault, { password: 'pw', sourceDir: realSrc });
	await fsp.writeFile(path.join(dvVault, 'data', 'blob (conflicted copy).bin'), 'x');
	const dv = await vdisk.verify(dvVault, { password: 'pw', deep: true });
	ok('a sync leftover does not make a deep verify report corruption', dv.integrity === 'ok');
	ok('the deep verify still flags the leftover as a sync issue', dv.syncIssues.length >= 1);

	// --- Schema versioning of the local sidecar stores ---
	console.log('\n[schema versioning]');
	const Common = require('../Common');
	ok('a store with no version is stamped at the current version', Common.schemaVersionFor('t', {}) === Common.SCHEMA_VERSION);
	ok('a store at the current version stays there', Common.schemaVersionFor('t', { schemaVersion: Common.SCHEMA_VERSION }) === Common.SCHEMA_VERSION);
	ok('a NEWER file is never downgraded (its version is kept)', Common.schemaVersionFor('t2', { schemaVersion: 999 }) === 999);
	// End to end: creating a vault writes state.json, which must now carry the schema version.
	const svVault = path.join(tmp, 'SchemaV.vault');
	await vdisk.create(svVault, { password: 'pw' });
	let stateRaw = {};
	try { stateRaw = JSON.parse(fs.readFileSync(Common.statePath(), 'utf8')); } catch (_) {}
	ok('state.json is stamped with the schema version', stateRaw.schemaVersion === Common.SCHEMA_VERSION);
	// A settings write stamps the version and preserves an unknown (future) field rather than dropping it.
	await vdisk.setSettings({ __futureField: 'keep-me' });
	const settings = await vdisk.getSettings();
	ok('settings.json is stamped with the schema version', settings.schemaVersion === Common.SCHEMA_VERSION);
	ok('a settings write preserves an unknown future field', settings.__futureField === 'keep-me');
	await vdisk.setSettings({ __futureField: undefined }); // tidy the probe field back out

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FEATURE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

// Creating a vault auto-registers it in the known-vaults list; since every vault here lives in the
// throwaway workspace, forget them all so a test run never leaves ghost entries in the real UI.
async function cleanup() {
	try {
		for (const v of await vdisk.listKnownVaults()) {
			if (v.includes('vdisk-features-')) { try { await vdisk.removeKnownVault(v); } catch (_) {} }
		}
		if (workspace) await fsp.rm(workspace, { recursive: true, force: true });
	} catch (_) {}
}

let workspace = null;
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
