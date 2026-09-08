'use strict';
// lib/test/recoveryreminder.js — a rotation invalidates every non-rotating credential, so a vault that had a
// recovery key can be left with no forgot-password safety net without the owner noticing. After such a rotation the
// vault carries a local reminder (listKeys.recoveryReminder, surfaced by the boot self-check) until a recovery key
// or owner recovery is restored. This proves: a rotation that drops a recovery key sets the reminder and reports
// recoveryDropped; the self-check surfaces it; adding a recovery key clears it; and a vault that never had one
// raises nothing.
//
// Run:  node lib/test/recoveryreminder.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const SelfCheck = require('../SelfCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function reminderFindings() { const r = await SelfCheck.run({ quiet: true, label: 'test' }); return r.filter(f => f.check === 'roster_rollback' && /no recovery key/i.test(f.message)); }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recrem-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(256));

	// --- A vault WITH a recovery key: rotation drops it and raises the reminder ---
	const v = path.join(tmp, 'R.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw' });
	await vdisk.addRecoveryKey(v, { password: 'pw' });
	ok('a vault with a recovery key shows no reminder', (await vdisk.listKeys(v)).recoveryReminder === false);

	const rot = await vdisk.rotate(v, { password: 'pw', reason: 'test' });
	ok('rotation reports that it dropped the recovery key', rot.recoveryDropped === true);
	ok('listKeys now flags the missing recovery key', (await vdisk.listKeys(v)).recoveryReminder === true);
	const flagged = await reminderFindings();
	ok('the boot self-check surfaces the missing recovery key', flagged.length === 1 && flagged[0].message.includes(v));

	// Restoring a recovery key clears the reminder.
	await vdisk.addRecoveryKey(v, { password: 'pw' });
	ok('adding a fresh recovery key clears the reminder', (await vdisk.listKeys(v)).recoveryReminder === false);
	ok('the boot self-check no longer surfaces it', (await reminderFindings()).length === 0);

	// --- A vault that NEVER had a recovery key: rotation raises nothing ---
	const v2 = path.join(tmp, 'Plain.vault'); await vdisk.importFolder(v2, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v2, { password: 'pw' });
	const rot2 = await vdisk.rotate(v2, { password: 'pw', reason: 'test' });
	ok('rotating a vault that never had a recovery key reports no drop', rot2.recoveryDropped === false);
	ok('and raises no reminder', (await vdisk.listKeys(v2)).recoveryReminder === false);

	await vdisk.removeKnownVault(v).catch(() => {});
	await vdisk.removeKnownVault(v2).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-REMINDER CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
