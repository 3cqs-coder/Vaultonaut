'use strict';
// lib/test/travel.js — travel mode: hide every known vault and its path-keyed settings under a travel password,
// restore them with it, and confirm nothing about the vault folders (their contents, tamper baseline, or
// self-heal data) is touched. Also checks the honest safety properties: a wrong travel password restores
// nothing, the app's plaintext state names no hidden vault while travelling, and the vault is still openable
// after a hide/restore round-trip.
//
// Run:  node lib/test/travel.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-travel-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const State = require('../State');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// Two vaults with content, registered as known, plus a favorite and a backup destination (path-keyed
	// settings that name a vault and must not leak while travelling).
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'secret.txt'), 'do not reveal at the border');
	const v1 = path.join(tmp, 'Personal.vault'), v2 = path.join(tmp, 'Work.vault');
	await vdisk.importFolder(v1, { password: 'pw1', sourceDir: src });
	await vdisk.create(v2, { password: 'pw2' });
	await vdisk.setFavorite(v1, true);
	await vdisk.setSettings({ backupDests: { [path.resolve(v1)]: 'somedest' } });
	// An emergency (dead-man) config names a vault by its ABSOLUTE PATH — travel must hide it too, or the path
	// leaks into plaintext settings. The leak scan below covers this once the config holds v2's path.
	await vdisk.setSettings({ emergency: { contactPubKey: 'stub-pub', contactLabel: 'Contact', inactivityMs: 86400000, graceMs: 86400000, lastCheckIn: new Date().toISOString(), armed: { vid1: { path: path.resolve(v2), name: 'V2', sealed: 'x', at: new Date().toISOString() } } } });
	// A scheduled dispersal repair is keyed by a schedule id (not a vault path), but its VALUE names the absolute
	// shard-folder paths a vault's data is dispersed across, plus a user label. That is a data-location leak, so
	// travel must hide it too. Use a distinctive path/label the leak scan below checks for.
	const shardPath = path.join(tmp, 'shards-XYZZY-secret-location');
	await vdisk.setSettings({ repairSchedules: { sched1: { folders: [shardPath], label: 'Personal shards secret-label', intervalHours: 24 } } });

	ok('both vaults are known before travel', (await State.listVaults()).length === 2);
	ok('travel mode is off by default', vdisk.travelStatus().active === false);

	// Take a tamper snapshot so we can prove it survives a hide/restore untouched.
	await vdisk.snapshot(v1, { password: 'pw1' });
	const auditBefore = await vdisk.audit(v1, { password: 'pw1' });
	ok('tamper check passes before travel', auditBefore.clean === true);

	// Enable travel mode.
	const en = await vdisk.travelEnable({ travelPassword: 'trip-2026' });
	ok('enabling travel hides both vaults', en.hidden === 2 && vdisk.travelStatus().active === true);
	ok('the known-vault list is now empty', (await State.listVaults()).length === 0);

	// The plaintext state must name NEITHER vault path anywhere (list or path-keyed settings).
	const stateText = await fsp.readFile(Common.statePath(), 'utf8');
	const settingsText = fs.existsSync(path.join(dataDir, 'settings.json')) ? await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8') : '';
	const leaks = [path.resolve(v1), path.resolve(v2), shardPath, 'secret-label'].some(p => stateText.includes(p) || settingsText.includes(p));
	ok('no hidden vault path (including a dispersal shard path or its label) appears in the app\'s plaintext state', !leaks);

	// A wrong travel password restores nothing and leaves travel mode on.
	let wrong = false; try { await vdisk.travelRestore({ travelPassword: 'guess' }); } catch (_) { wrong = true; }
	ok('a wrong travel password restores nothing', wrong && vdisk.travelStatus().active === true && (await State.listVaults()).length === 0);

	// Restore with the correct password.
	const re = await vdisk.travelRestore({ travelPassword: 'trip-2026' });
	ok('restoring brings both vaults back', re.restored === 2 && vdisk.travelStatus().active === false);
	ok('both vaults are known again', (await State.listVaults()).length === 2);

	// The path-keyed settings came back intact.
	const s = await vdisk.getSettings();
	ok('the favorite and backup destination were restored', (s.favorites || {})[path.resolve(v1)] && (s.backupDests || {})[path.resolve(v1)] === 'somedest');
	// The emergency config was hidden during travel (checked by the leak scan above) and is restored on exit, with
	// its last check-in refreshed so it does not fire just because the window elapsed while hidden.
	ok('the emergency config was restored', !!(s.emergency && s.emergency.armed && s.emergency.armed.vid1 && s.emergency.armed.vid1.path === path.resolve(v2)));
	ok('the scheduled dispersal repair (shard paths) was restored', !!(s.repairSchedules && s.repairSchedules.sched1 && s.repairSchedules.sched1.folders[0] === shardPath));

	// The vault folder is untouched: it still mounts/opens and its tamper baseline still verifies.
	const auditAfter = await vdisk.audit(v1, { password: 'pw1' });
	ok('the tamper check still passes after a hide/restore (the vault was untouched)', auditAfter.clean === true && auditAfter.fingerprint === auditBefore.fingerprint);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TRAVEL CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
