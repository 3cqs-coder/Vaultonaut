'use strict';
// lib/test/emergencyconfig.js — fail-safe rules for the dead-man switch's CONFIG, independent of any vault or the
// engine. Two invariants that a corrupt or edited config must never break:
//   1. A missing or unparseable check-in time (or a non-finite inactivity/grace window) must read as ARMED, never
//      "due" — the switch may only ever fire on a real, positive elapsed time. The old code did `lastCheckIn || 0`,
//      which turned a missing timestamp into 1970 and fired immediately: a fail-OPEN in a must-fail-closed path.
//   2. Changing the enrolled contact's KEY unarms every already-armed vault (they were sealed to the old key, which
//      we cannot re-seal without the old contact's private half). A label-only change keeps them.
//
// Run:  node lib/test/emergencyconfig.js   (no engine, no network)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-emergcfg-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');

	// Contact keypairs are pure crypto — no engine needed. A and B are two different contacts.
	const A = vdisk.emergencyKeypair(), B = vdisk.emergencyKeypair();
	ok('two distinct contact keys generated', A.publicKey && B.publicKey && A.publicKey !== B.publicKey);

	// --- 1. Missing / invalid check-in must be ARMED, not "due" ---
	await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'A', inactivityDays: 30, graceDays: 14 });
	ok('freshly enrolled config is armed', (await vdisk.emergencyStatus()).phase === 'armed');

	const emg = (await vdisk.getSettings()).emergency;
	// Positive control: an ancient check-in (well past inactivity+grace) really does read as "due", so the fail-safe
	// below is proving something — not just that the phase is always "armed".
	await vdisk.setSettings({ emergency: { ...emg, lastCheckIn: new Date(Date.now() - 100 * 86400000).toISOString() } });
	ok('an ancient check-in reads as due (positive control)', (await vdisk.emergencyStatus()).phase === 'due');

	// The fail-safe: strip the check-in time entirely (a corrupt/partially written config).
	const { lastCheckIn, ...noCheckIn } = emg;
	await vdisk.setSettings({ emergency: noCheckIn });
	const sMissing = await vdisk.emergencyStatus();
	ok('a MISSING check-in reads as armed, never due', sMissing.phase === 'armed');
	ok('a missing check-in reports daysUntilRelease as null (not NaN or 0)', sMissing.daysUntilRelease === null);

	// A non-finite window (JSON cannot hold NaN, so a corrupt file surfaces as null) is also treated as armed even
	// with an ancient check-in present.
	await vdisk.setSettings({ emergency: { ...emg, lastCheckIn: new Date(Date.now() - 100 * 86400000).toISOString(), inactivityMs: null } });
	ok('a non-finite inactivity window reads as armed even with an old check-in', (await vdisk.emergencyStatus()).phase === 'armed');

	// --- 2. Contact-key change unarms; label-only change keeps ---
	await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'A', inactivityDays: 30, graceDays: 14 });
	const withArmed = (await vdisk.getSettings()).emergency;
	await vdisk.setSettings({ emergency: { ...withArmed, armed: { v1: { path: '/x', name: 'X', sealed: 'ZZ', at: new Date().toISOString() } } } });

	const sameKey = await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'A renamed', inactivityDays: 30, graceDays: 14 });
	ok('a label-only re-enroll does not unarm', sameKey.rearmNeeded === 0 && !!(await vdisk.getSettings()).emergency.armed.v1);

	const newKey = await vdisk.emergencyEnroll({ contactPubKey: B.publicKey, contactLabel: 'B', inactivityDays: 30, graceDays: 14 });
	ok('changing the contact key reports the number unarmed', newKey.rearmNeeded === 1);
	ok('changing the contact key clears the armed grants', Object.keys((await vdisk.getSettings()).emergency.armed || {}).length === 0);

	// --- 3. A detected forward clock jump is discounted, so it cannot fire the switch early ---
	await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'A', inactivityDays: 30, graceDays: 14 });
	const cfg3 = (await vdisk.getSettings()).emergency;
	// An "old" check-in that is JUST past the 44-day window would be due — but only because time really passed.
	const past = 45 * 86400000;
	await vdisk.setSettings({ emergency: { ...cfg3, lastCheckIn: new Date(Date.now() - past).toISOString() } });
	ok('a genuinely overdue timer is due (control)', (await vdisk.emergencyStatus()).phase === 'due');
	// Record that most of that elapsed time was a spurious forward clock jump: it must be discounted back to armed.
	const noted = await vdisk.emergencyNoteClockDrift(past);
	ok('a clock jump is recorded when enrolled', noted.noted === true);
	ok('discounting the jumped time returns the timer to armed (no early fire)', (await vdisk.emergencyStatus()).phase === 'armed');
	// The accumulated credit is CAPPED at one inactivity+grace window, so a flapping clock (many jumps) cannot hold
	// the timer suppressed forever — a genuinely inactive owner's switch is delayed by at most one window.
	const windowMs = (44) * 86400000; // 30 inactivity + 14 grace
	for (let i = 0; i < 5; i++) await vdisk.emergencyNoteClockDrift(past); // pile on far more than a window
	ok('the drift credit is capped at one inactivity+grace window', (Number((await vdisk.getSettings()).emergency.driftCreditMs) || 0) === windowMs);
	// A check-in clears the drift credit and re-baselines.
	await vdisk.emergencyCheckIn();
	ok('a check-in clears the drift credit', (Number((await vdisk.getSettings()).emergency.driftCreditMs) || 0) === 0);
	// Noting a jump when NOT enrolled is a harmless no-op.
	await vdisk.setSettings({ emergency: undefined });
	ok('recording a jump with nothing enrolled is a no-op', (await vdisk.emergencyNoteClockDrift(past)).noted === false);

	return done();
}

function done() {
	try { if (tmp) fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-CONFIG CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
