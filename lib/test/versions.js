'use strict';
// lib/test/versions.js — file version history (#4). Prior versions of changed files are captured at BACKUP
// time (rclone --backup-dir into a timestamped snapshot under the destination's .versions/), browsable and
// restorable through the vault's own key, and restore is non-destructive (the current file is untouched).
// Versions live at the backup destination, so the vault and its tamper baseline are structurally unchanged.
// Needs the engine; no mount driver (edits go through the crypt remote).
//
// Run:  node lib/test/versions.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');
const RcloneSetup = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

// Write/read a file's content through the vault's crypt remote (mount-free), like the tool does internally.
async function cryptConfig(bin, v, master) {
	const m = await Vault.readManifest(v), c = m.crypt;
	return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: path.join(v, 'data'), passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption }));
}

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const bin = RcloneSetup.resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-versions-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'note.txt'), 'VERSION ONE');
	const v = path.join(tmp, 'Ver.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	const master = Vault.parseReadCap((await vdisk.makeReadCap(v, { password: 'pw1' })).token).master;
	const destRoot = path.join(tmp, 'backup'); await fsp.mkdir(destRoot);

	// First backup: nothing to version yet.
	await vdisk.backup(v, destRoot);
	ok('a first backup creates no version snapshot', (await vdisk.listVersions(v)).snapshots.length === 0);

	// Change note.txt through the crypt remote, then back up again → the OLD version is captured.
	let cfg = await cryptConfig(bin, v, master);
	await Rclone.run(bin, ['rcat', 'vault:note.txt'], { configPath: cfg, input: 'VERSION TWO CHANGED' });
	await Rclone.removeConfig(cfg);
	await new Promise(r => setTimeout(r, 20)); // ensure a distinct version timestamp
	await vdisk.backup(v, destRoot);

	const list = await vdisk.listVersions(v, { password: 'pw1' });
	ok('a version snapshot is captured after a change', list.snapshots.length === 1);
	ok('the snapshot lists the changed file (decrypted name)', list.snapshots[0] && list.snapshots[0].files.includes('note.txt'));
	ok('the snapshot has a parseable timestamp', !!(list.snapshots[0] && list.snapshots[0].at));

	// Baseline the current state so a later audit can attribute the restored file as a change.
	await vdisk.snapshot(v, { password: 'pw1' });

	// Restore the old version — non-destructively (current file untouched).
	const rr = await vdisk.restoreVersion(v, { password: 'pw1', timestamp: list.snapshots[0].timestamp, file: 'note.txt' });
	ok('restore returns a non-clobbering name', !!rr.restoredAs && rr.restoredAs.includes('restored') && rr.restoredAs !== 'note.txt');

	// Verify: the restored copy holds the OLD content; the current file still holds the NEW content.
	cfg = await cryptConfig(bin, v, master);
	try {
		const cur = await Rclone.run(bin, ['cat', 'vault:note.txt'], { configPath: cfg });
		const old = await Rclone.run(bin, ['cat', 'vault:' + rr.restoredAs], { configPath: cfg });
		ok('the current file is unchanged by restore (still the new content)', cur.stdout === 'VERSION TWO CHANGED');
		ok('the restored copy holds the old version content', old.stdout === 'VERSION ONE');
	} finally { await Rclone.removeConfig(cfg); }

	// A bad timestamp / traversal is refused.
	let refused = false;
	try { await vdisk.restoreVersion(v, { password: 'pw1', timestamp: '../../etc', file: 'note.txt' }); } catch (_) { refused = true; }
	ok('an invalid version timestamp is refused', refused);

	// Tamper detection still sees the restored file as a real change to the vault (nothing is hidden).
	const audit = await vdisk.audit(v, { password: 'pw1' });
	ok('tamper detection still works and sees the restored file as an added change', audit.added.some(p => /restored/.test(p)));

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VERSION CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
