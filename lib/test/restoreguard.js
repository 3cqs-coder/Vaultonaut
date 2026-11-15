'use strict';
// lib/test/restoreguard.js — restore()'s same-vault identity guard. Restoring a backup into a folder that already
// holds a DIFFERENT vault would, with --force, overlay one vault's manifest and ciphertext onto another and leave a
// union that opens under neither key. Every other clobbering path (backup, mirror, off-site) refuses that; restore
// must too. This verifies: a fresh restore into an empty destination works; restoring over the SAME vault's own
// copy is allowed; and restoring over a DIFFERENT vault is refused even with overwrite.
//
// Run:  node lib/test/restoreguard.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function refused(fn) { try { await fn(); return false; } catch (_) { return true; } }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-restoreguard-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');

	// Source-level guard (runs even without the engine): restoring OVER an existing copy of the SAME vault must snapshot
	// the files it overwrites — routing each about-to-be-overwritten file into a timestamped version folder, like backup
	// and the mirror do — so a restore from a STALE backup never silently loses a post-backup edit. Lock that wiring.
	const vsrc = fs.readFileSync(path.join(__dirname, '..', 'vault', 'Vault.js'), 'utf8');
	const restoreBody = (vsrc.match(/async function restore\([\s\S]*?\n}\n/) || [''])[0];
	ok('restore-over-existing routes overwritten files through a version snapshot (--backup-dir, gated on overwrite)', /destLooksVault && opts\.overwrite\)\s*\{[\s\S]*?'--backup-dir'/.test(restoreBody) && /VERSIONS_DIR/.test(restoreBody));

	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'hello.txt'), 'hello world');

	// Vault A, backed up to backupRoot/A.vault.
	const a = path.join(tmp, 'A.vault');
	await vdisk.importFolder(a, { password: 'pw-a', sourceDir: src });
	const backupRoot = path.join(tmp, 'backup'); await fsp.mkdir(backupRoot, { recursive: true });
	await vdisk.backup(a, backupRoot);
	const backupOfA = path.join(backupRoot, 'A.vault');

	// A fresh restore into an empty destination succeeds and registers the vault.
	const emptyDest = path.join(tmp, 'empty'); await fsp.mkdir(emptyDest, { recursive: true });
	const r1 = await vdisk.restore(backupOfA, emptyDest);
	ok('a fresh restore into an empty folder succeeds', !!r1 && !!r1.vault && fs.existsSync(path.join(emptyDest, 'A.vault', 'vault.json')));

	// Restoring over the SAME vault's own copy (same salt) is allowed with overwrite.
	const r2 = await vdisk.restore(backupOfA, emptyDest, { overwrite: true });
	ok('restoring over this vault\'s own copy is allowed with --force', !!r2 && !!r2.vault);

	// A DIFFERENT vault occupying the restore target: destRoot/A.vault holds an unrelated vault (different salt).
	const clashDest = path.join(tmp, 'clash'); await fsp.mkdir(clashDest, { recursive: true });
	const foreign = path.join(clashDest, 'A.vault'); // same basename the restore will target
	await vdisk.importFolder(foreign, { password: 'pw-other', sourceDir: src });

	// Without overwrite: refused because a vault already exists there.
	ok('restoring onto an occupied target without --force is refused', await refused(() => vdisk.restore(backupOfA, clashDest)));
	// With overwrite: STILL refused, because the occupant is a DIFFERENT vault (the identity guard).
	ok('restoring onto a DIFFERENT vault is refused even with --force', await refused(() => vdisk.restore(backupOfA, clashDest, { overwrite: true })));
	// The foreign vault is untouched — its manifest still opens under its own password.
	const stillForeign = JSON.parse(await fsp.readFile(path.join(foreign, 'vault.json'), 'utf8'));
	const aManifest = JSON.parse(await fsp.readFile(path.join(a, 'vault.json'), 'utf8'));
	ok('the different vault was left intact (its salt is unchanged)', stillForeign.crypt.salt && stillForeign.crypt.salt !== aManifest.crypt.salt);

	// --- restoreFromBackup: recover a KNOWN vault IN PLACE from its OWN recorded backup (the Manage "Restore from
	// backup" action / the `restore-from-backup` CLI). backup() above recorded backupRoot as A's destination, so this
	// resolves it with NO path passed — the one source of truth the poll also reads as v.backupDest. It delegates the
	// overwrite to the same restore() guarded above, so identity/integrity/version-snapshot protection is inherited.
	ok('the vault\'s recorded backup is the destination restoreFromBackup resolves (single source)', (await vdisk.backupDestFor(a)) === backupRoot);
	const rb = await vdisk.restoreFromBackup(a);
	ok('restoreFromBackup restores the vault in place from its recorded backup', !!rb && !!rb.vault && path.resolve(rb.vault) === path.resolve(a) && fs.existsSync(path.join(a, 'vault.json')));
	// (The pre-restore version-snapshot on a real overwrite is covered by the --backup-dir wiring check above; it is
	// delegated to the same restore() path, which only snapshots files that actually change.)

	// A vault with NO backup on record is refused with a clear message — never a silent no-op that looks like success.
	const nob = path.join(tmp, 'NoBackup.vault');
	await vdisk.importFolder(nob, { password: 'pw-nb', sourceDir: src });
	ok('restoreFromBackup on a vault with no backup on record is refused', await refused(() => vdisk.restoreFromBackup(nob)));

	// --- restoreDrill: prove the backup actually RESTORES AND OPENS, against a THROWAWAY copy (the Manage/backup-dialog
	// "Test restore" and the `restore-drill` CLI). It must open the copy with the right password, register NOTHING, and
	// leave no staging copy behind. A's backup is backupRoot; its password is 'pw-a'.
	const knownBefore = (await vdisk.listKnownVaults()).length;
	const drill = await vdisk.restoreDrill(a, { password: 'pw-a' });
	ok('restoreDrill reports OPENS when the backup restores and the password opens it', !!drill && drill.verdict === 'OPENS' && drill.files >= 1);
	ok('restoreDrill registered nothing — it tests a throwaway copy, not a real vault', (await vdisk.listKnownVaults()).length === knownBefore);
	const stagingDir = path.join(dataDir, 'staging');
	ok('restoreDrill left no staging copy behind', !fs.existsSync(stagingDir) || fs.readdirSync(stagingDir).filter((n) => /drill/.test(n)).length === 0);
	const wrong = await vdisk.restoreDrill(a, { password: 'not-the-password' });
	ok('restoreDrill reports WRONG_PASSWORD when the password does not open the restored copy', !!wrong && wrong.verdict === 'WRONG_PASSWORD');
	ok('restoreDrill requires a password (it proves the backup OPENS)', await refused(() => vdisk.restoreDrill(a, {})));
	ok('restoreDrill on a vault with no backup on record is refused', await refused(() => vdisk.restoreDrill(nob, { password: 'pw-nb' })));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RESTORE-GUARD CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
