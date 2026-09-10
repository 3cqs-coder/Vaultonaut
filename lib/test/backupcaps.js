'use strict';
// lib/test/backupcaps.js — the guard that stands between a drive fault and a wiped backup. A backup is an
// rclone sync, which mirror-DELETES at the destination to match the source. If the source was emptied or
// damaged (a failing drive, an errant delete, a half-finished sync), a plain sync would propagate that loss to
// the one surviving backup. assertBackupDeletionsSafe refuses a sync that would delete more than half the
// backed-up files, and exempts a small backup where ordinary edits shouldn't be second-guessed. This proves both.
//
// Run:  node lib/test/backupcaps.js  (needs the engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const countFiles = async (dir) => { let n = 0; for (const e of await fsp.readdir(dir, { withFileTypes: true }).catch(() => [])) { if (e.isFile()) n++; else if (e.isDirectory()) n += await countFiles(path.join(dir, e.name)); } return n; };
// Delete `howMany` of the vault's encrypted blobs directly — simulating a drive fault / errant delete on the store.
async function deleteSourceBlobs(vaultDir, howMany) {
	const store = path.join(vaultDir, 'data');
	const files = (await fsp.readdir(store, { withFileTypes: true })).filter(e => e.isFile()).map(e => e.name);
	for (let i = 0; i < howMany && i < files.length; i++) await fsp.rm(path.join(store, files[i]), { force: true });
}

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping the backup-cap checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-bcaps-')); workspace = tmp;

	// --- >50% deletion is refused, and the existing backup survives ---
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	for (let i = 0; i < 30; i++) await fsp.writeFile(path.join(src, 'f' + i + '.txt'), 'content number ' + i);
	const v = path.join(tmp, 'Big.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const dest = path.join(tmp, 'backup'); await fsp.mkdir(dest);
	await vdisk.backup(v, dest);
	const destBefore = await countFiles(dest);
	ok('the first backup populated the destination (>= 20 files)', destBefore >= 20);

	await deleteSourceBlobs(v, 20); // remove well over half the ~30 blobs, as a drive fault would
	let refused = null;
	try { await vdisk.backup(v, dest); } catch (e) { refused = e; }
	// Match the DELETION-cap message specifically, not just the shared sourceDamaged flag (which the
	// missing-protected-files guard also sets) — so this keeps testing the cap even if imports ever auto-protect.
	ok('a backup that would delete more than half the files is refused', !!refused && !!refused.sourceDamaged && /delete .*of .*file|more than half/i.test(refused.message));
	ok('the existing backup was NOT wiped by the refused sync', (await countFiles(dest)) === destBefore);

	// --- a small backup (< 20 files) is exempt: ordinary edits are not second-guessed at low file counts ---
	const src2 = path.join(tmp, 'src2'); await fsp.mkdir(src2);
	for (let i = 0; i < 8; i++) await fsp.writeFile(path.join(src2, 'g' + i + '.txt'), 'small ' + i);
	const v2 = path.join(tmp, 'Small.vault'); await vdisk.importFolder(v2, { password: 'pw', sourceDir: src2 });
	const dest2 = path.join(tmp, 'backup2'); await fsp.mkdir(dest2);
	await vdisk.backup(v2, dest2);
	await deleteSourceBlobs(v2, 6); // most of a small vault
	let smallOk = true;
	try { await vdisk.backup(v2, dest2); } catch (_) { smallOk = false; }
	ok('a small backup (under the file-count floor) is not second-guessed', smallOk);

	// --- version history OFF must NOT mass-delete the destination's retained .versions/ folder ---
	// The .versions/ folder holds prior copies (the only surviving copy of a file later edited or deleted in the
	// vault), so a plain sync must never treat it as destination-only content and delete it. The exclude filter is
	// applied UNCONDITIONALLY, not only while history is on — otherwise turning history off would silently wipe all
	// retained recovery points on the very next backup. Simulate accumulated history at the destination, turn
	// history off, back up, and confirm the folder survives.
	const src3 = path.join(tmp, 'src3'); await fsp.mkdir(src3);
	for (let i = 0; i < 25; i++) await fsp.writeFile(path.join(src3, 'h' + i + '.txt'), 'history test ' + i);
	const v3 = path.join(tmp, 'History.vault'); await vdisk.importFolder(v3, { password: 'pw', sourceDir: src3 });
	const dest3 = path.join(tmp, 'backup3'); await fsp.mkdir(dest3);
	await vdisk.backup(v3, dest3); // history on by default; the sync target is dest3/<vault-name>/
	// The version folder name is single-sourced in Sync; read it rather than hardcoding it here. It lives INSIDE the
	// per-vault destination folder (dest3/<name>/.versions/), the same scope the sync mirrors — which is exactly why
	// an un-excluded sync would delete it.
	const VERSIONS_DIR = require('../Sync').VERSIONS_DIR;
	const histDir = path.join(dest3, path.basename(v3), VERSIONS_DIR, '20200101-000000');
	await fsp.mkdir(histDir, { recursive: true });
	await fsp.writeFile(path.join(histDir, 'kept-blob'), 'a retained prior version');
	const prior = (await vdisk.getSettings()).versionsKeep;
	try {
		await vdisk.setSettings({ versionsKeep: 0 }); // history OFF
		await vdisk.backup(v3, dest3); // the bug: this used to drop the exclude filter and delete .versions/
		ok('turning version history off does not mass-delete the destination version history', fs.existsSync(path.join(histDir, 'kept-blob')));
	} finally { await vdisk.setSettings({ versionsKeep: prior === undefined ? null : prior }); } // restore so later tests in the shared test-data dir are unaffected
	await vdisk.removeKnownVault(v3).catch(() => {});

	await vdisk.removeKnownVault(v).catch(() => {});
	await vdisk.removeKnownVault(v2).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BACKUP-CAP CHECKS PASSED'));
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} } process.exit(1); });
