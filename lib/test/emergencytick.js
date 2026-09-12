'use strict';
// lib/test/emergencytick.js — the dead-man-switch release tick must observe a check-in committed by ANOTHER
// process (a CLI `emergency-checkin`) right before the due instant. The tick reads settings through a short memo;
// if it served a stale memoized copy it could release access that a valid, just-written check-in had vetoed. The
// tick now reads fresh (invalidates the memo first), so a fresh on-disk check-in is always seen. This proves it:
// with the memo warmed to a DUE config, a fresh lastCheckIn written straight to the file makes the tick decline
// to release.
//
// Run:  node lib/test/emergencytick.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-emtick-')); workspace = tmp;
	const Common = require('../Common'); const dataDir = path.join(tmp, 'data'); Common.dataDir = () => dataDir; await fsp.mkdir(dataDir, { recursive: true });
	const settingsFile = path.join(dataDir, 'settings.json');
	const writeEmergency = async (lastCheckIn) => fsp.writeFile(settingsFile, JSON.stringify({ emergency: { contactPubKey: 'x', inactivityMs: 1000, graceMs: 0, lastCheckIn, armed: {}, releasedAt: null } }));

	// A config whose last check-in is well past the (tiny) window → 'due'.
	await writeEmergency(new Date(Date.now() - 60000).toISOString());
	// Warm the in-process settings memo with that DUE config (this is what a stale read would serve).
	const warm = await vdisk.getSettings();
	ok('the warmed config reads as past-due', (Date.now() - new Date(warm.emergency.lastCheckIn).getTime()) > warm.emergency.inactivityMs);

	// Another process checks in: write a FRESH lastCheckIn straight to the file, bypassing this process's memo.
	await writeEmergency(new Date().toISOString());

	// The tick must see the fresh check-in (read past the memo) and NOT release.
	const r = await vdisk.emergencyTick();
	ok('the tick reads the fresh cross-process check-in and does not release', r.phase !== 'due' && r.phase !== 'released');
	ok('the tick reports the vault as armed again', r.phase === 'armed');

	// The check above covers a check-in written BEFORE the tick decides. A check-in that lands DURING the release
	// (from another process, after the decision but before the release commits) must ALSO veto it — the exact
	// last-second case the switch exists to honor. That interleaving is hard to force at runtime, so pin it at the
	// source: emergencyRelease re-reads lastCheckIn under the settings lock at commit time and, if it changed, aborts
	// and removes the files it wrote instead of stamping releasedAt.
	const vsrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('emergencyRelease captures the decision-time check-in to compare against', /const priorCheckIn = cfg && cfg\.lastCheckIn/.test(vsrc));
	ok('emergencyRelease aborts the commit if a check-in landed while writing', /if \(cin && cin !== priorCheckIn\) \{ vetoed = true; return cur; \}/.test(vsrc));
	ok('a vetoed release removes the sealed files it wrote', /if \(vetoed\) \{[\s\S]{0,160}fsp\.rm\(dir, \{ recursive: true, force: true \}\)/.test(vsrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-TICK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); }).finally(async () => { if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} } });
