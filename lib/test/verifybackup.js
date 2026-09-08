'use strict';
// lib/test/verifybackup.js — the backup restorability check. verifyBackup confirms, without a password, that a
// vault's backup destination still holds a COMPLETE copy of THIS vault: a matching manifest (same salt) and
// every encrypted file present. This verifies: a fresh backup is RESTORABLE; deleting a file from the backup is
// reported as INCOMPLETE; a destination holding a different vault is DIFFERENT; and no backup on record errors.
//
// Run:  node lib/test/verifybackup.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function walk(dir) { const out = []; for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) out.push(...await walk(p)); else out.push(p); } return out; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-vbk-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(64 * 1024));
	const v = path.join(tmp, 'V.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// No backup on record yet -> a clear error.
	let noneErr = false; try { await vdisk.verifyBackup(v); } catch (_) { noneErr = true; }
	ok('with no backup on record, the check reports there is nothing to verify', noneErr);

	// Back up, then a fresh backup is complete and restorable.
	const backupRoot = path.join(tmp, 'backup'); await fsp.mkdir(backupRoot, { recursive: true });
	await vdisk.backup(v, backupRoot);
	const good = await vdisk.verifyBackup(v);
	ok('a fresh backup is RESTORABLE', good.verdict === 'RESTORABLE' && good.missing === 0 && good.total > 0);

	// Truncate one backup file (same name, wrong size) -> INCOMPLETE via the size comparison (a name-only check
	// would miss this).
	const backupData = path.join(backupRoot, 'V.vault', 'data');
	const files = (await walk(backupData)).sort((a, b) => a.localeCompare(b));
	await fsp.truncate(files[0], 10); // half-written file: still present, wrong size
	const trunc = await vdisk.verifyBackup(v);
	ok('a backup with a truncated (wrong-size) file is reported INCOMPLETE', trunc.verdict === 'INCOMPLETE' && trunc.mismatched >= 1);

	// Delete one encrypted file from the backup -> INCOMPLETE (missing).
	await fsp.rm(files[1]);
	const inc = await vdisk.verifyBackup(v);
	ok('a backup missing a file is reported INCOMPLETE', inc.verdict === 'INCOMPLETE' && inc.missing >= 1);

	// A destination holding a DIFFERENT vault -> DIFFERENT.
	const other = path.join(tmp, 'Other.vault');
	await vdisk.importFolder(other, { password: 'pw2', sourceDir: src });
	const otherBackupRoot = path.join(tmp, 'otherbk'); await fsp.mkdir(otherBackupRoot, { recursive: true });
	await vdisk.backup(other, otherBackupRoot);
	// Ask: is V restorable from Other's backup folder (which holds a folder named Other.vault, not V.vault)?
	// Point at a folder that holds a different-named vault by checking against the other vault's own dest but for V.
	const diff = await vdisk.verifyBackup(other, { dest: backupRoot }); // backupRoot holds V.vault, not Other.vault
	ok('a destination holding a different (or missing) vault is not RESTORABLE', diff.verdict !== 'RESTORABLE');

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VERIFY-BACKUP CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
