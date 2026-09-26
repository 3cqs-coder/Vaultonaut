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

	// COMPLETENESS GUARD: seed a DISTINCTIVE marker into EVERY per-vault, path-keyed settings store (the VAULT_PATH_KEYED
	// list read from the source), each keyed by v1's real path, so the leak scan below proves travel hides the WHOLE list —
	// not just the few stores this test happens to name. A future store added to VAULT_PATH_KEYED is covered automatically;
	// a store the hide loop forgets to clear would leak its marker and fail here. This is the guard against the realistic
	// "added a new path-keyed store but forgot to make travel hide it" privacy regression.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	const pathKeyed = (vaultSrc.match(/const VAULT_PATH_KEYED = \[([^\]]*)\]/) || [])[1].split(',').map(s => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
	ok('VAULT_PATH_KEYED was parsed from the source (guard is live)', pathKeyed.length >= 10);
	// Merge a synthetic marker entry into each store (travel clears the WHOLE store, so the key can be synthetic) without
	// disturbing the real entries other assertions check (the favorite, the backup destination).
	const curForMarkers = await vdisk.getSettings();
	const markers = [];
	for (const store of pathKeyed) {
		const marker = 'TRAVELMARK-' + store + '-' + path.resolve(v1);
		markers.push(marker);
		await vdisk.setSettings({ [store]: { ...(curForMarkers[store] || {}), ['mk-' + store]: marker } });
	}

	ok('both vaults are known before travel', (await State.listVaults()).length === 2);
	ok('travel mode is off by default', vdisk.travelStatus().active === false);

	// Take a tamper snapshot so we can prove it survives a hide/restore untouched.
	await vdisk.snapshot(v1, { password: 'pw1' });
	const auditBefore = await vdisk.audit(v1, { password: 'pw1' });
	ok('tamper check passes before travel', auditBefore.clean === true);

	// A pre-existing emergency RELEASE tree names vaults and beneficiaries in plaintext folder/file names, so travel
	// mode must remove it too (not just the emergency config) — or it would leave exactly the identifying material it
	// exists to hide.
	const relDir = path.join(dataDir, 'emergency-release');
	await fsp.mkdir(path.join(relDir, 'beneficiary-A'), { recursive: true });
	await fsp.writeFile(path.join(relDir, 'beneficiary-A', 'V2.sealed'), 'x');

	// Enable travel mode.
	const en = await vdisk.travelEnable({ travelPassword: 'trip-2026' });
	ok('enabling travel hides both vaults', en.hidden === 2 && vdisk.travelStatus().active === true);
	ok('enabling travel removes any on-disk emergency release material', !fs.existsSync(relDir));
	ok('the known-vault list is now empty', (await State.listVaults()).length === 0);

	// The plaintext state must name NEITHER vault path anywhere (list or path-keyed settings).
	const stateText = await fsp.readFile(Common.statePath(), 'utf8');
	const settingsText = fs.existsSync(path.join(dataDir, 'settings.json')) ? await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8') : '';
	const leaks = [path.resolve(v1), path.resolve(v2), shardPath, 'secret-label'].some(p => stateText.includes(p) || settingsText.includes(p));
	ok('no hidden vault path (including a dispersal shard path or its label) appears in the app\'s plaintext state', !leaks);
	// EVERY path-keyed store's marker must be gone — proving travel hides the whole VAULT_PATH_KEYED list, not just the
	// few stores named above. If any store leaks its marker, name it so the failure points straight at the missed store.
	const leakedStores = pathKeyed.filter((store, i) => stateText.includes(markers[i]) || settingsText.includes(markers[i]));
	ok('every path-keyed settings store is hidden by travel (none leaks its marker): ' + (leakedStores.join(', ') || 'none'), leakedStores.length === 0);

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
	// Travel mode's guarantee (hide the vaults AND stop all live access to them) must hold no matter which surface
	// turns it on. A live serve or mobile session lives only in the long-running service's memory, so a separate CLI
	// process cannot stop it — the CLI must route travel through the running service. Pin both halves at the source:
	// the web endpoint stops serve/mobile/lease sessions before hiding, and the CLI routes travel on AND off through
	// the owner (falling back to a direct hide only when no service is running).
	const rd = (rel) => { try { return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8'); } catch (_) { return ''; } };
	const server = rd(path.join('webserver', 'index.js'));
	ok('the web travel-start endpoint stops serve, mobile, and lease sessions before hiding', /travel-start'[\s\S]{0,160}stopAllLeaseHeartbeats\(\)[\s\S]{0,60}Mobile\.stopAll\(\)[\s\S]{0,60}stopAllServing\(\)[\s\S]{0,200}travelEnable/.test(server));
	const cmds = rd('Commands.js');
	ok('the CLI routes travel ON through the running owner (so it stops live sessions)', /OwnerClient\.post\(ownerOn\.url, '\/api\/travel-start'/.test(cmds));
	ok('the CLI routes travel OFF through the running owner', /OwnerClient\.post\(ownerOff\.url, '\/api\/travel-restore'/.test(cmds));
	ok('the CLI still falls back to a direct hide/restore when no service is running', /if \(!r\) r = await vdisk\.travelEnable/.test(cmds) && /if \(!r\) r = await vdisk\.travelRestore/.test(cmds));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TRAVEL CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
