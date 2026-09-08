'use strict';
// lib/test/foreign.js — a foreign file dropped straight into the encrypted store MUST be detected.
// The tamper baseline is captured over the DECRYPTED view (rclone lsf on the crypt remote), and rclone
// crypt silently SKIPS any file it cannot decrypt — so a foreign file added by someone WITHOUT the key
// is invisible to a file-by-file compare and once slipped past the audit entirely. The fix parses the
// engine's own "Skipping undecryptable file name" notice, so both the manual audit and the on-mount
// check now surface those files as tampering and refuse to trust (and therefore never bless) the state.
// This verifies detection in a root folder and a subfolder, that a clean vault stays clean, that the
// finding is recoverable once the foreign files are removed, and that the on-mount check flags it too.
// Needs the bundled engine only — no mount driver (nothing is mounted).
//
// Run:  node lib/test/foreign.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function firstSubdir(dir) {
	for (const e of await fsp.readdir(dir, { withFileTypes: true })) if (e.isDirectory()) return path.join(dir, e.name);
	return null;
}

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-foreign-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4096));
	await fsp.writeFile(path.join(src, 'sub', 'b.txt'), crypto.randomBytes(4096));
	const v = path.join(tmp, 'Foreign.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw' });

	const clean = await vdisk.audit(v, { password: 'pw', deep: true });
	ok('a fresh vault audits clean with no foreign files', clean.clean === true && clean.foreign.length === 0);

	// Attacker with no key drops raw files straight into the encrypted store, vault unmounted: one with a
	// plain name (illegal base32) and one with a base32-looking name that still fails to decrypt.
	const dataDir = path.join(v, 'data');
	await fsp.writeFile(path.join(dataDir, 'attacker-trojan.exe'), 'MZ not-really-encrypted');
	const sub = await firstSubdir(dataDir);
	if (sub) await fsp.writeFile(path.join(sub, 'deadbeef00112233445566'), crypto.randomBytes(64));

	const rep = await vdisk.audit(v, { password: 'pw', deep: true });
	ok('the audit is no longer clean once foreign files are present', rep.clean === false);
	ok('both foreign files are detected (root + subfolder)', rep.foreign.length === (sub ? 2 : 1));
	ok('a self-explanatory tamper note is raised', rep.tamper.length >= 1 && /could not be decrypted/.test(rep.tamper.join(' ')));
	ok('the foreign files are NOT counted as ordinary added/modified changes', rep.added.length === 0 && rep.modified.length === 0);

	// The on-mount check must also flag them AND refuse to trust the session, so unmounting can never
	// silently bless the injected files into the baseline.
	const om = await vdisk.checkOnMount(v, 'pw');
	ok('the on-mount check refuses to trust a vault with foreign files', om.trusted === false);
	ok('the on-mount warning reports the foreign files', !!(om.warn && om.warn.foreign && om.warn.foreign.length === (sub ? 2 : 1)));

	// Non-destructive and recoverable: removing the foreign files restores a clean audit. Detection never
	// touched the real data or the baseline.
	await fsp.rm(path.join(dataDir, 'attacker-trojan.exe'));
	if (sub) await fsp.rm(path.join(sub, 'deadbeef00112233445566'));
	const after = await vdisk.audit(v, { password: 'pw', deep: true });
	ok('removing the foreign files restores a clean audit', after.clean === true && after.foreign.length === 0);

	// A foreign DIRECTORY (rclone logs "undecryptable dir name") must be reported like a foreign file, and
	// must NOT make the default DEEP audit throw — the deep hashsum pass treats that notice as benign.
	await fsp.mkdir(path.join(dataDir, 'foreign-dir-xyz'), { recursive: true });
	const withDir = await vdisk.audit(v, { password: 'pw', deep: true });
	ok('a deep audit with a foreign directory does not error', (withDir.errors || []).length === 0);
	ok('a foreign directory is reported, not silently ignored', withDir.foreign.length >= 1 && withDir.clean === false);
	await fsp.rm(path.join(dataDir, 'foreign-dir-xyz'), { recursive: true, force: true });

	// A cloud-sync tool's conflicted copy is ALSO undecryptable-by-name, but it is a benign leftover — it must
	// be reported as a sync issue, NEVER as hard tampering (foreign), or a synced-folder vault would false-alarm
	// on every mount.
	await fsp.writeFile(path.join(dataDir, 'someblob (conflicted copy).bin'), crypto.randomBytes(64));
	const withConflict = await vdisk.audit(v, { password: 'pw', deep: true });
	ok('a sync conflicted-copy is not flagged as a foreign/tamper file', withConflict.foreign.length === 0);
	ok('a sync conflicted-copy is surfaced as a sync issue instead', (withConflict.syncIssues || []).some(s => /conflict/i.test(s.kind)));
	// It must also be surfaced ON MOUNT (not silent), so a file named like a conflict to dodge the foreign
	// finding is still shown — as a benign leftover that does not block trust.
	const omConflict = await vdisk.checkOnMount(v, 'pw');
	ok('a sync conflicted-copy is surfaced on mount, not silent', !!(omConflict.warn && /leftover/i.test((omConflict.warn.tamper || []).join(' '))));
	ok('a sync conflicted-copy does not block trust on mount', omConflict.trusted === true);
	await fsp.rm(path.join(dataDir, 'someblob (conflicted copy).bin'));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FOREIGN-FILE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-foreign-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
