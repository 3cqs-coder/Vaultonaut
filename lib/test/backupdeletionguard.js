'use strict';
// lib/test/backupdeletionguard.js — the all-or-nothing backup backstop. A one-way backup mirrors deletions, so if
// the source is emptied or damaged (a drive fault, an errant delete, a half-finished sync) an unguarded run would
// mirror-delete the good copies at the destination. assertBackupDeletionsSafe refuses a suspicious MASS deletion.
// The threshold tightens as the backup shrinks so a small vault is still protected, without second-guessing an
// ordinary edit of a few files. This pins: a mass wipe is refused (source damaged) even for a small vault, and a
// routine small deletion still backs up cleanly.
//
// Run:  node lib/test/backupdeletionguard.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-bkdel-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');

	// Source-level guard (runs even without the engine): a one-way backup's mass-deletion protection must never be lost
	// for a vault whose file listing over-caps (more than ~1.3M files). The deterministic set-difference guard reports
	// whether it could verify; when it could NOT, it falls back to a cheap object count (rclone size, which does not
	// buffer the listing) so the sync still carries an engine-level --max-delete backstop at ~half the destination.
	// Lock that wiring so a refactor can't drop it and silently leave an over-cap vault unguarded against a wipe.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the deletion guard reports whether it verified (verified flag)', /return \{ verified: false/.test(vaultSrc) && /return \{ verified: true \}/.test(vaultSrc));
	ok('the guard falls back to a cheap object count when the listing over-caps', /'size',\s*'--json'/.test(vaultSrc) && /destCount:/.test(vaultSrc));
	ok('both backup syncs add a --max-delete backstop only when the guard could not verify', (vaultSrc.match(/verified === false && delChk\.destCount > 0\) syncArgs\.push\('--max-delete',/g) || []).length >= 2);

	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// A vault with enough files that emptying its store is unambiguously a mass deletion, not an edit.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 40; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(8 * 1024));
	const v = path.join(tmp, 'Big.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	const backupRoot = path.join(tmp, 'backup'); await fsp.mkdir(backupRoot, { recursive: true });
	await vdisk.backup(v, backupRoot);
	ok('the first backup succeeds', fs.existsSync(path.join(backupRoot, 'Big.vault', 'vault.json')));

	// Simulate the source store being emptied (a drive fault), leaving the manifest so the backup can still start.
	await fsp.rm(path.join(vdisk.resolveVaultDir(v), 'data'), { recursive: true, force: true });
	let refused = false, damaged = false, msg = '';
	try { await vdisk.backup(v, backupRoot); } catch (e) { refused = true; damaged = !!e.sourceDamaged; msg = e.message || ''; }
	ok('a backup that would mass-delete the destination is refused', refused && damaged);
	ok('the refusal explains it would delete backed-up files', /would delete \d+ of \d+/.test(msg));
	// The destination must be untouched — the refusal happens BEFORE the sync runs, so the good backup's files are
	// all still physically present (never mirror-deleted).
	async function countFiles(d) { let n = 0; for (const e of await fsp.readdir(d, { withFileTypes: true })) { if (e.isDirectory()) n += await countFiles(path.join(d, e.name)); else n++; } return n; }
	ok('the existing backup is left intact (never mirror-deleted)', (await countFiles(path.join(backupRoot, 'Big.vault', 'data'))) >= 40);

	// A routine small deletion is NOT second-guessed: a tiny vault that legitimately drops one file backs up cleanly.
	const src2 = path.join(tmp, 'src2'); await fsp.mkdir(src2, { recursive: true });
	for (let i = 0; i < 4; i++) await fsp.writeFile(path.join(src2, 'g' + i + '.bin'), crypto.randomBytes(8 * 1024));
	const v2 = path.join(tmp, 'Small.vault');
	await vdisk.importFolder(v2, { password: 'pw', sourceDir: src2 });
	const backupRoot2 = path.join(tmp, 'backup2'); await fsp.mkdir(backupRoot2, { recursive: true });
	await vdisk.backup(v2, backupRoot2);
	// Delete one plaintext file by mounting? Simpler: remove one cipher blob from the SOURCE to emulate one dropped
	// file, which is a minority deletion and must still be allowed.
	const v2data = path.join(vdisk.resolveVaultDir(v2), 'data');
	async function firstBlob(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { const r = await firstBlob(p); if (r) return r; } else return p; } return null; }
	const one = await firstBlob(v2data);
	if (one) await fsp.rm(one, { force: true });
	let okSmall = true; try { await vdisk.backup(v2, backupRoot2); } catch (_) { okSmall = false; }
	ok('an ordinary minority deletion is NOT refused (no false alarm)', okSmall);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BACKUP-DELETION-GUARD CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
