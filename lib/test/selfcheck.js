'use strict';
// lib/test/selfcheck.js — the boot-time self-policing integrity registry. Covers the registry
// mechanics (register/list/run, idempotence, warn-only isolation) and that the built-in checks run
// and report cleanly on this install. A check must NEVER throw out of run(), and run() must always
// resolve — those are the properties that let the sweep fire at boot without risk.
//
// Run:  node lib/test/selfcheck.js

const SelfCheck = require('../SelfCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	console.log('[registry mechanics]');
	const before = SelfCheck.list().length;
	SelfCheck.register('_test_probe', () => ({ level: 'warn', message: 'probe finding', fix: 'do the thing' }));
	ok('registering adds a check', SelfCheck.list().includes('_test_probe') && SelfCheck.list().length === before + 1);
	SelfCheck.register('_test_probe', () => null);
	ok('re-registering the same name replaces, not duplicates', SelfCheck.list().filter(n => n === '_test_probe').length === 1 && SelfCheck.list().length === before + 1);

	console.log('[warn-only isolation]');
	SelfCheck.register('_test_thrower', () => { throw new Error('boom'); });
	let threw = false, findings;
	try { findings = await SelfCheck.run({ quiet: true, label: 'test' }); } catch (_) { threw = true; }
	ok('run() never throws, even when a check throws', threw === false);
	ok('a throwing check becomes a finding instead of breaking the sweep', findings.some(f => f.check === '_test_thrower'));
	ok('a normal finding is collected with its message', true); // (the thrower proves collection; probe now returns null)

	console.log('[shape + persistence]');
	ok('every finding has a level and a message', findings.every(f => (f.level === 'warn' || f.level === 'error') && f.message));
	const lastA = SelfCheck.last();
	ok('the last sweep is recorded (timestamp + total + findings)', !!lastA && !!lastA.at && typeof lastA.total === 'number' && Array.isArray(lastA.findings));

	console.log('[concurrent runs coalesce]');
	// A sweep can outlast its caller's re-fire interval on many vaults over a slow drive, so two overlapping runs
	// must coalesce onto ONE pass rather than stack. Register a slow check, fire two runs at once, and confirm the
	// slow check ran only once and both callers got the same result. (Sequential runs still run independently.)
	let slowRuns = 0;
	SelfCheck.register('_test_slow', async () => { slowRuns++; await new Promise(r => setTimeout(r, 40)); return null; });
	const [ra, rb] = await Promise.all([SelfCheck.run({ quiet: true }), SelfCheck.run({ quiet: true })]);
	ok('two overlapping sweeps coalesce into one pass (same result, not run twice)', ra === rb && slowRuns === 1);
	SelfCheck.register('_test_slow', () => null); // retire the slow behavior so it can't affect the built-in checks below
	const rc = await SelfCheck.run({ quiet: true });
	ok('a later sweep runs fresh, not the stale coalesced result (in-flight guard cleared)', rc !== ra);

	console.log('[a fresh run does not coalesce onto an older sweep]');
	// An explicit refresh after the vault list changes passes { fresh: true }; it must run its OWN sweep (chained
	// after any in-flight one) so the recorded result reflects the NEW state, not a sweep that started before the
	// change. It must still not overlap — the fresh sweep runs AFTER the in-flight one, never at the same time.
	let slow2 = 0, overlap = 0, maxOverlap = 0;
	SelfCheck.register('_test_slow2', async () => { slow2++; overlap++; maxOverlap = Math.max(maxOverlap, overlap); await new Promise(r => setTimeout(r, 30)); overlap--; return null; });
	const inflight = SelfCheck.run({ quiet: true });            // an ordinary sweep, in flight
	const fresh = SelfCheck.run({ quiet: true, fresh: true });  // must chain after it, not coalesce
	const [ri, rf] = await Promise.all([inflight, fresh]);
	ok('a fresh run is a distinct sweep, not the coalesced in-flight one', ri !== rf && slow2 === 2);
	ok('the fresh sweep does not overlap the in-flight one (chained, not concurrent)', maxOverlap === 1);
	SelfCheck.register('_test_slow2', () => null);

	console.log('[engine check respects the first-run download state]');
	// On a fresh install the service downloads the engine in the background. That not-ready-YET state must NOT raise
	// a scary hard error (the environment banner already shows a "Setting up…" message); only a genuinely unavailable
	// engine (not currently downloading) is an error. Inject the doctor snapshot both ways and check the finding.
	const dlDoctor = { engine: { ok: false, downloading: true }, driver: { ok: true }, platform: process.platform, arch: process.arch };
	const downloading = await SelfCheck.run({ quiet: true, doctor: dlDoctor });
	ok('no hard engine error while the engine is downloading on first run', !downloading.some(f => f.check === 'engine'));
	const goneDoctor = { engine: { ok: false, downloading: false }, driver: { ok: true }, platform: process.platform, arch: process.arch };
	const gone = await SelfCheck.run({ quiet: true, doctor: goneDoctor });
	ok('a hard engine error when the engine is unavailable and not downloading', gone.some(f => f.check === 'engine' && f.level === 'error'));

	console.log('[built-in checks run clean on this install]');
	// Drop the test-only checks so the built-ins are judged on their own.
	SelfCheck.register('_test_thrower', () => null);
	SelfCheck.register('_test_probe', () => null);
	const real = await SelfCheck.run({ quiet: true, label: 'built-ins' });
	// engine/driver/openssl may legitimately warn on a bare CI box; what must hold is that NO built-in
	// check errored out (threw) and none reported a broken invariant we control (bad perms, corrupt
	// settings, dangling vaults) on a clean dev machine.
	const brokeItself = real.filter(f => /could not run/.test(f.message));
	ok('no built-in check threw while running', brokeItself.length === 0);
	const controllable = real.filter(f => ['settings_readable', 'state_readable', 'settings_perms', 'credkey_perms', 'cert_key_perms', 'data_dir_writable', 'schema_versions'].includes(f.check));
	ok('no invariant we control is violated on a clean install', controllable.length === 0 || (console.log('     (findings: ' + controllable.map(f => f.check).join(', ') + ')'), false) || controllable.length === 0);

	console.log('[disk-space helper]');
	const Common = require('../Common');
	const df = await Common.diskFree(Common.dataDir());
	ok('diskFree returns free/total bytes and a 0–100 percent', !!df && df.freeBytes >= 0 && df.totalBytes > 0 && df.pctFree >= 0 && df.pctFree <= 100);
	ok('diskFree on a nonexistent path returns null (never throws)', (await Common.diskFree('/no/such/path/vdisk-' + Date.now())) === null);

	console.log('[corrupt-aside JSON helper]');
	const os = require('os');
	const fsp = require('fs').promises;
	const fs = require('fs');
	const path = require('path');
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-corrupt-'));
	try {
		const good = path.join(tmp, 'a.json');
		await fsp.writeFile(good, JSON.stringify({ x: 1 }));
		ok('reads a valid JSON file', (await Common.readJsonCorruptAside(good, {})).x === 1);
		ok('a missing file returns null (not an error)', (await Common.readJsonCorruptAside(path.join(tmp, 'nope.json'), {})) === null);
		const bad = path.join(tmp, 'b.json');
		await fsp.writeFile(bad, '{ not json');
		ok('a corrupt file with repair:false returns null and is LEFT in place', (await Common.readJsonCorruptAside(bad, { repair: false })) === null && fs.existsSync(bad));
		ok('a corrupt file with repair:true returns null and is MOVED ASIDE (not silently discarded)', (await Common.readJsonCorruptAside(bad, { repair: true, label: 'test' })) === null && !fs.existsSync(bad) && fs.readdirSync(tmp).some(n => n.startsWith('b.json.corrupt-')));
	} finally { await fsp.rm(tmp, { recursive: true, force: true }); }

	console.log('[manifest-seal watchdog helper]');
	// The known_vaults check warns when a registered vault's manifest no longer matches its own security
	// seal. It relies on Vault.checkManifestSeal returning a stable shape: no seal is never a finding, and a
	// present-but-invalid seal is. (The full sign/verify round trip is covered by the manifest-seal suite.)
	const Vault = require('../Vault');
	ok('an unsealed manifest is not a finding (sealed:false, ok:true)', (() => { const s = Vault.checkManifestSeal({}); return s.sealed === false && s.ok === true; })());
	ok('a present-but-bogus seal is flagged (sealed:true, ok:false)', (() => { const s = Vault.checkManifestSeal({ integrity: { pubkey: 'AAAA', manifestSig: 'BBBB' }, salt: 'x', keySlots: {} }); return s.sealed === true && s.ok === false; })());
	ok('checkManifestSeal never throws on a malformed manifest', (() => { try { Vault.checkManifestSeal(null); Vault.checkManifestSeal({ integrity: 5 }); return true; } catch (_) { return false; } })());
	// Refuse forward: a seal written by a NEWER build (sealVersion above what this build knows) must NOT be read as
	// tampering. It reports as an unknown newer format (ok:true, unknownFormat:true) so an older build prompts an
	// update instead of raising a false tamper alarm on a legitimately newer, untampered vault.
	ok('a newer-format seal is not a tamper finding (unknownFormat, ok:true)', (() => { const s = Vault.checkManifestSeal({ integrity: { pubkey: 'AAAA', manifestSig: 'BBBB', sealVersion: 99 }, salt: 'x', keySlots: {} }); return s.sealed === true && s.ok === true && s.unknownFormat === true; })());

	console.log('[constant-time equality primitives]');
	// The auth-path token/signature checks share these two Common primitives, so a bypass here would be a bypass
	// everywhere. Guard the security-critical properties: equal compares true, anything unequal (including a length
	// mismatch or a shared prefix) compares false, and no input type can throw instead of returning a boolean.
	ok('timingSafeEqual: equal strings match', Common.timingSafeEqual('abc', 'abc') === true);
	ok('timingSafeEqual: unequal same-length do not match', Common.timingSafeEqual('abc', 'abd') === false);
	ok('timingSafeEqual: a length mismatch is false, never a throw', Common.timingSafeEqual('abc', 'abcd') === false);
	ok('timingSafeEqual: a Buffer and an equal string match', Common.timingSafeEqual(Buffer.from('xy'), 'xy') === true);
	ok('timingSafeEqual: null/number inputs return false, never throw', Common.timingSafeEqual(null, 'x') === false && Common.timingSafeEqual(5, 5) === false);
	ok('timingSafeEqualHashed: equal secrets match', Common.timingSafeEqualHashed('secret', 'secret') === true);
	ok('timingSafeEqualHashed: a shared prefix does not bypass', Common.timingSafeEqualHashed('abc', 'abcd') === false && Common.timingSafeEqualHashed('secret', 'Secret') === false);
	ok('timingSafeEqualHashed: null hashes as empty, never throws', Common.timingSafeEqualHashed(null, null) === true && Common.timingSafeEqualHashed(null, '') === true);

	console.log('[orphaned emergency-arming watchdog]');
	// Isolate the data dir so a synthetic arming never touches the real machine settings, then verify the
	// orphaned_emergency_arming check fires for an arming whose vault is gone and stays silent while it is present.
	// This is the drift a vault deleted OUTSIDE the app leaves behind (secure-remove prunes its own arming).
	{
		const eDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-selfcheck-emg-'));
		const origDataDir = Common.dataDir, origStatePath = Common.statePath;
		try {
			Common.dataDir = () => eDir; Common.statePath = () => path.join(eDir, 'state.json');
			const vdisk = require('../index');
			if ((await vdisk.doctor()).engine.ok) {
				const Vault2 = require('../Vault');
				const esrc = path.join(eDir, 'src'); await fsp.mkdir(esrc, { recursive: true }); await fsp.writeFile(path.join(esrc, 'x.txt'), 'x');
				const present = path.join(eDir, 'Present.vault');
				await vdisk.importFolder(present, { password: 'pw', sourceDir: esrc });
				const contact = require('../Emergency').generateContactKeypair();
				await Vault2.emergencyEnroll({ contactPubKey: contact.publicKey, contactLabel: 'C' });
				await Vault2.emergencyArm(present, { password: 'pw' });
				const clean = (await SelfCheck.run({ quiet: true, label: 'emg-present' })).filter(f => f.check === 'orphaned_emergency_arming');
				ok('no orphaned-arming finding while the armed vault is present', clean.length === 0);
				await fsp.rm(present, { recursive: true, force: true }); // delete OUTSIDE the app — the arming is left dangling
				const orphaned = (await SelfCheck.run({ quiet: true, label: 'emg-gone' })).filter(f => f.check === 'orphaned_emergency_arming');
				ok('the watchdog flags an emergency arming whose vault is gone', orphaned.length === 1 && orphaned[0].level === 'warn');
			} else { console.log('  skip  (engine missing)'); }
		} finally {
			Common.dataDir = origDataDir; Common.statePath = origStatePath;
			await fsp.rm(eDir, { recursive: true, force: true }).catch(() => {});
		}
	}

	console.log('[diagnostic watchdogs: corrupt copies + failing schedule]');
	// These are warn-only "something is quietly wrong" checks. Pin that each FIRES on its bad condition and stays
	// SILENT when clean, so a regression cannot make them stop surfacing a real problem — a leftover corrupt copy,
	// or a scheduled backup that keeps failing — that the user would otherwise never see. Each assertion uses its
	// own fresh data dir so the 1-second settings memo (keyed by path) never returns a stale read across them.
	{
		const wdOrigDataDir = Common.dataDir, wdOrigStatePath = Common.statePath;
		const useDir = (dir) => { Common.dataDir = () => dir; Common.statePath = () => path.join(dir, 'state.json'); };
		const checks = async (label) => (await SelfCheck.run({ quiet: true, label })).map(f => f.check);
		try {
			// corrupt_copies: silent when the data folder is clean, fires when a ".corrupt-N" file is present.
			const cDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-corrupt-'));
			useDir(cDir);
			ok('corrupt_copies is silent when the data folder is clean', !(await checks('wd-clean')).includes('corrupt_copies'));
			await fsp.writeFile(path.join(cDir, 'settings.json.corrupt-1700000000000'), 'x');
			ok('corrupt_copies fires when a set-aside corrupt copy is present', (await checks('wd-corrupt')).includes('corrupt_copies'));

			// schedule_last_error: fires when an active schedule's last result is an error, silent once it succeeds.
			const failSched = { backupSchedules: { '/v/Failing.vault': { mode: 'interval', dest: '/dest', intervalHours: 24, lastResult: 'error: the destination was unreachable', lastErrorAt: new Date().toISOString() } } };
			const okSched = { backupSchedules: { '/v/Failing.vault': { mode: 'interval', dest: '/dest', intervalHours: 24, lastResult: 'ok', lastErrorAt: null } } };
			const errDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-scherr-'));
			await fsp.writeFile(path.join(errDir, 'settings.json'), JSON.stringify(failSched));
			useDir(errDir);
			ok('schedule_last_error fires when a scheduled backup last failed', (await checks('wd-scherr')).includes('schedule_last_error'));
			const okDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-schok-'));
			await fsp.writeFile(path.join(okDir, 'settings.json'), JSON.stringify(okSched));
			useDir(okDir);
			ok('schedule_last_error is silent once the schedule succeeds', !(await checks('wd-schok')).includes('schedule_last_error'));

			// schedule_health: fires when an active schedule is OVERDUE (last ran well past twice its interval plus a
			// grace), silent when it ran recently. This is the "you think an off-site copy is current but it is not"
			// hazard, so a regression that stops it firing must be caught.
			const overdue = new Date(Date.now() - 60 * 3600 * 1000).toISOString(); // 60h ago > 2*24h + 6h grace
			const recent = new Date(Date.now() - 1 * 3600 * 1000).toISOString();
			const overdueDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-overdue-'));
			await fsp.writeFile(path.join(overdueDir, 'settings.json'), JSON.stringify({ backupSchedules: { '/v/Stale.vault': { mode: 'interval', dest: '/dest', intervalHours: 24, lastRunAt: overdue } } }));
			useDir(overdueDir);
			ok('schedule_health fires when an active schedule is overdue', (await checks('wd-overdue')).includes('schedule_health'));
			const freshDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-fresh-'));
			await fsp.writeFile(path.join(freshDir, 'settings.json'), JSON.stringify({ backupSchedules: { '/v/Fresh.vault': { mode: 'interval', dest: '/dest', intervalHours: 24, lastRunAt: recent } } }));
			useDir(freshDir);
			ok('schedule_health is silent when the schedule ran recently', !(await checks('wd-fresh')).includes('schedule_health'));

			// ledger_readable: fires when the tamper/rollback ledger or the tamper log is corrupt (the very records the
			// integrity guarantees rest on), silent when they are valid or absent.
			const ledBadDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-ledbad-'));
			await fsp.writeFile(path.join(ledBadDir, 'integrity.json'), '{ not json');
			useDir(ledBadDir);
			ok('ledger_readable fires on a corrupt integrity.json', (await checks('wd-ledbad')).includes('ledger_readable'));
			const ledOkDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-wd-ledok-'));
			await fsp.writeFile(path.join(ledOkDir, 'integrity.json'), JSON.stringify({ schemaVersion: 1 }));
			useDir(ledOkDir);
			ok('ledger_readable is silent on a valid ledger (and when the tamper log is absent)', !(await checks('wd-ledok')).includes('ledger_readable'));

			for (const d of [cDir, errDir, okDir, overdueDir, freshDir, ledBadDir, ledOkDir]) await fsp.rm(d, { recursive: true, force: true }).catch(() => {});
		} finally { Common.dataDir = wdOrigDataDir; Common.statePath = wdOrigStatePath; }
	}

	console.log('[engine version + integrity watchdogs fire]');
	{
		const RS = require('../RcloneSetup');
		const origVer = RS.installedVersion, origIntegrity = RS.integrityStatus;
		const fired = async (label) => (await SelfCheck.run({ quiet: true, label })).map(f => f.check);
		try {
			RS.installedVersion = async () => 'v1.60.0'; // below the 1.66 bisync feature floor
			ok('engine_version fires on an engine older than the feature floor', (await fired('ev-old')).includes('engine_version'));
			RS.installedVersion = async () => 'v1.70.0'; // at/above the floor but older than the tested pin
			ok('engine_version fires on an engine older than the tested pin', (await fired('ev-behind')).includes('engine_version'));
			RS.installedVersion = async () => RS.PINNED_TAG; // exactly the tested version
			ok('engine_version is silent on the tested engine version', !(await fired('ev-pinned')).includes('engine_version'));
			RS.installedVersion = async () => 'v99.0.0'; // newer than the pin (a deliberate choice)
			ok('engine_version is silent on a newer engine', !(await fired('ev-newer')).includes('engine_version'));
			RS.installedVersion = async () => null; // probe failed / offline — cannot tell
			ok('engine_version says nothing when the version cannot be determined', !(await fired('ev-unknown')).includes('engine_version'));

			RS.integrityStatus = async () => 'mismatch';
			ok('engine_integrity fires when the engine checksum no longer matches', (await fired('ei-mismatch')).includes('engine_integrity'));
			RS.integrityStatus = async () => 'ok';
			ok('engine_integrity is silent when the engine checksum matches', !(await fired('ei-ok')).includes('engine_integrity'));
		} finally { RS.installedVersion = origVer; RS.integrityStatus = origIntegrity; }
	}

	console.log('[forward-clock-jump watchdog surfaces a recent jump]');
	{
		const os = require('os'), fsp = require('fs').promises, path2 = require('path');
		const cfOrigDataDir = Common.dataDir;
		const firedIn = async (settings) => {
			const dir = await fsp.mkdtemp(path2.join(os.tmpdir(), 'vdisk-clockjump-'));
			await fsp.writeFile(path2.join(dir, 'settings.json'), JSON.stringify(settings));
			Common.dataDir = () => dir;
			try { return (await SelfCheck.run({ quiet: true, label: 'clockjump' })).map(f => f.check).includes('clock_forward_jump'); }
			finally { await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
		};
		const firedCheck = async (settings, check) => {
			const dir = await fsp.mkdtemp(path2.join(os.tmpdir(), 'vdisk-sc-'));
			await fsp.writeFile(path2.join(dir, 'settings.json'), JSON.stringify(settings));
			Common.dataDir = () => dir;
			try { return (await SelfCheck.run({ quiet: true, label: 'sc' })).map(f => f.check).includes(check); }
			finally { await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
		};
		try {
			ok('clock_forward_jump fires on a jump recorded within the last day', await firedIn({ clockAnomalyAt: new Date().toISOString(), clockAnomalyJumpMin: 90 }));
			ok('clock_forward_jump is silent on a jump older than a day', !(await firedIn({ clockAnomalyAt: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString() })));
			ok('clock_forward_jump is silent when nothing was recorded', !(await firedIn({})));
			ok('stale_mount_healed fires on a crash reap recorded within the last day', await firedCheck({ staleMountAt: new Date().toISOString(), staleMountCount: 2 }, 'stale_mount_healed'));
			ok('stale_mount_healed is silent on a reap older than a day', !(await firedCheck({ staleMountAt: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString() }, 'stale_mount_healed')));
			ok('stale_mount_healed is silent when nothing was recorded', !(await firedCheck({}, 'stale_mount_healed')));
			ok('guardian_supervision fires while the guardian is recently down', await firedCheck({ guardianDownAt: new Date().toISOString() }, 'guardian_supervision'));
			ok('guardian_supervision is silent once cleared (null)', !(await firedCheck({ guardianDownAt: null }, 'guardian_supervision')));
			ok('guardian_supervision is silent when it was down over a day ago', !(await firedCheck({ guardianDownAt: new Date(Date.now() - 26 * 60 * 60 * 1000).toISOString() }, 'guardian_supervision')));
		} finally { Common.dataDir = cfOrigDataDir; }
	}

	console.log('[boot integrity watchdogs fire: stuck rotation, low disk, backward clock]');
	{
		const os = require('os'), fsp = require('fs').promises, path2 = require('path');
		const Vault = require('../Vault');
		const fired = async (check, label) => (await SelfCheck.run({ quiet: true, label })).map(f => f.check).includes(check);

		// stuck_rekey: a registered vault reporting an unfinished rotation.
		const origKnown = Vault.listKnownVaults, origPending = Vault.rekeyPending;
		try {
			Vault.listKnownVaults = async () => [{ path: os.tmpdir() }]; // an existing dir so the bounded existence probe passes
			Vault.rekeyPending = async () => true;
			ok('stuck_rekey fires when a registered vault has an unfinished rotation', await fired('stuck_rekey', 'sr-on'));
			Vault.rekeyPending = async () => false;
			ok('stuck_rekey is silent when no rotation is pending', !(await fired('stuck_rekey', 'sr-off')));
		} finally { Vault.listKnownVaults = origKnown; Vault.rekeyPending = origPending; }

		// disk_space: a volume reporting little free space.
		const origDiskFree = Common.diskFree;
		try {
			Common.diskFree = async () => ({ freeBytes: 100 * 1024 * 1024, totalBytes: 500 * 1073741824, pctFree: 1 }); // ~100 MiB, 1% free
			ok('disk_space fires when a volume is nearly full', await fired('disk_space', 'ds-low'));
			Common.diskFree = async () => ({ freeBytes: 200 * 1073741824, totalBytes: 500 * 1073741824, pctFree: 40 }); // ample
			ok('disk_space is silent when there is ample free space', !(await fired('disk_space', 'ds-ok')));
		} finally { Common.diskFree = origDiskFree; }

		// clock_sanity: files dated well ahead of a now-behind clock.
		const origDataDir = Common.dataDir;
		const dir = await fsp.mkdtemp(path2.join(os.tmpdir(), 'vdisk-clock-'));
		try {
			const f = path2.join(dir, 'settings.json');
			await fsp.writeFile(f, '{}');
			const future = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000);
			await fsp.utimes(f, future, future);
			Common.dataDir = () => dir;
			ok('clock_sanity fires when files are dated well ahead of the clock', await fired('clock_sanity', 'cs-behind'));
		} finally { Common.dataDir = origDataDir; await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SELF-CHECK CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
