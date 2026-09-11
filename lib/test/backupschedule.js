'use strict';
// lib/test/backupschedule.js — the scheduled-backup tick (backupScheduleTick). Covers its observable contract so
// the shared schedule-tick machinery cannot regress silently: an empty store runs cleanly; a due, unmounted vault
// is backed up and its run time recorded so it does not immediately repeat; a schedule whose vault no longer
// exists is skipped without throwing; and a failing backup records an error and is then backed off on the next
// pass instead of hammering it. Needs the bundled engine (no mount driver).
//
// Run:  node lib/test/backupschedule.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-bsched-'));
	const Common = require('../Common');
	Common.dataDir = () => path.join(tmp, 'data'); Common.statePath = () => path.join(tmp, 'data', 'state.json');
	await fsp.mkdir(Common.dataDir(), { recursive: true });
	const Vault = require('../Vault');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('  skip  (engine missing)'); return done(tmp); }

	// An empty store returns the clean { ran: [] } shape.
	const empty = await Vault.backupScheduleTick();
	ok('an empty schedule store returns { ran: [] }', empty && Array.isArray(empty.ran) && empty.ran.length === 0);

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'secret.txt'), 'top secret payload');

	// --- A due schedule backs the vault up and records the run, then does not immediately repeat ---
	const v = path.join(tmp, 'Sched.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	const dest = path.join(tmp, 'backup'); await fsp.mkdir(dest, { recursive: true });
	await Vault.setBackupSchedule(v, { mode: 'interval', intervalHours: 1, dest }); // fresh interval = immediately due
	const first = await Vault.backupScheduleTick();
	ok('a due schedule backs up the vault', first.ran.includes(path.resolve(v)));
	ok('the backup actually landed at the destination', fs.existsSync(path.join(dest, 'Sched.vault', 'vault.json')));
	const afterRun = await Vault.getBackupSchedule(v);
	ok('the successful run time is recorded', !!afterRun.lastRunAt);
	const second = await Vault.backupScheduleTick();
	ok('a freshly-run schedule is not run again on the next pass', !second.ran.includes(path.resolve(v)));

	// --- A schedule whose vault was removed is skipped without throwing (the missing-vault preflight) ---
	const gone = path.join(tmp, 'Gone.vault');
	await vdisk.importFolder(gone, { password: 'pw2', sourceDir: src });
	await Vault.setBackupSchedule(gone, { mode: 'interval', intervalHours: 1, dest });
	await fsp.rm(gone, { recursive: true, force: true }); // delete the vault folder before the tick runs
	let threw = false; let missingRan = null;
	try { missingRan = await Vault.backupScheduleTick(); } catch (_) { threw = true; }
	ok('the tick never throws when a scheduled vault is missing', !threw);
	ok('a missing vault is skipped, not backed up', !!missingRan && !missingRan.ran.includes(path.resolve(gone)));

	// --- A failing backup records an error and is backed off on the next pass (not hammered) ---
	const v3 = path.join(tmp, 'Fails.vault');
	await vdisk.importFolder(v3, { password: 'pw3', sourceDir: src });
	const badDest = path.join(tmp, 'not-a-directory'); await fsp.writeFile(badDest, 'x'); // a FILE where a folder is expected -> backup fails
	await Vault.setBackupSchedule(v3, { mode: 'interval', intervalHours: 1, dest: badDest });
	const failPass = await Vault.backupScheduleTick();
	ok('a failing backup is not reported as run', !failPass.ran.includes(path.resolve(v3)));
	const afterFail = await Vault.getBackupSchedule(v3);
	ok('a failing backup records an error timestamp', !!afterFail.lastErrorAt && /^error/i.test(String(afterFail.lastResult || '')));
	const errAt = afterFail.lastErrorAt;
	const backoffPass = await Vault.backupScheduleTick();
	ok('the next pass backs off (does not retry immediately)', !backoffPass.ran.includes(path.resolve(v3)));
	ok('the backed-off schedule was not re-attempted (error timestamp unchanged)', (await Vault.getBackupSchedule(v3)).lastErrorAt === errAt);

	// --- Source pin: lastRunAt is anchored at the tick's PASS-START (as the scrub and repair ticks are), NOT at
	//     completion. A completion-time anchor drifts the cadence — a daily near-midnight slot that finishes after
	//     midnight stamps the next day and skips that slot, and an interval's true period becomes intervalHours plus
	//     each run's own duration, walking later every cycle. A fast test backup finishes in milliseconds, so the two
	//     anchors are not distinguishable by timing here; pin the mechanism statically so a revert to completion-time
	//     stamping fails the build. Both halves must hold: the tick threads its pass-start `now` into the backup, and
	//     recordBackup stamps the time it is handed rather than a fresh Date. ---
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the backup tick threads its pass-start time into the backup as runAt',
		/handle:\s*async\s*\(abs,\s*sched,\s*now\)\s*=>\s*\{\s*await backup\(abs,\s*sched\.dest,\s*\{\s*runAt:\s*now\s*\}\)/.test(vaultSrc));
	ok('recordBackup accepts a runAt and stamps it (not a hard-coded completion Date)',
		/async function recordBackup\(abs,\s*destKey,\s*runAt\)/.test(vaultSrc)
		&& /const stamp = runAt instanceof Date/.test(vaultSrc)
		&& /lastRunAt:\s*stamp\b/.test(vaultSrc));

	return done(tmp);
}

async function done(tmp) {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BACKUP-SCHEDULE CHECKS PASSED'));
	try { await fsp.rm(tmp, { recursive: true, force: true }); } catch (_) {}
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); process.exit(1); });
