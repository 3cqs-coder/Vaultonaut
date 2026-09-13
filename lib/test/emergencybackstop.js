'use strict';
// lib/test/emergencybackstop.js — the OPTIONAL trustee-quorum backstop for emergency access. A released read cap can
// be reconstructed WITHOUT the time-lock beacon by a k-of-n quorum of owner-chosen trustees (Shamir shares, each
// sealed to a trustee's key). This is the "no data loss even if the beacon is ever unreachable" guarantee. It is off
// unless the owner sets it up. Verifies: a grant armed with trustees carries sealed shares; each trustee opens only
// their own; a quorum reconstructs the SAME read cap the time-lock protects; fewer than the threshold fails; and a
// grant armed with no backstop configured carries none (it is optional). Offline, uses the same interop round vector.
//
// Run:  node lib/test/emergencybackstop.js  (needs the engine to derive a read capability)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const REAL_ROUND = 1000000;
const REAL_SIG = '83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72';

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-embs-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Timelock = require('../Timelock');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const contact = vdisk.emergencyKeypair();
	const trustees = [vdisk.emergencyKeypair(), vdisk.emergencyKeypair(), vdisk.emergencyKeypair()]; // three trustees
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'w.txt'), 'estate');
	const v = path.join(tmp, 'Estate.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.emergencyEnroll({ contactPubKey: contact.publicKey, contactLabel: 'Heir', inactivityDays: 30, graceDays: 14 });

	// Backstop is OFF by default: arming without it produces a grant with no backstop.
	const dateMs = Timelock.timeOfRoundMs(REAL_ROUND);
	const armedNoBs = await vdisk.emergencyArm(v, { password: 'pw1', mode: 'date', dateMs });
	ok('the backstop is optional — arming without trustees produces no backstop', armedNoBs.backstop === null && (await vdisk.emergencyStatus()).backstop === null);

	// Enroll a 2-of-3 trustee backstop, then re-arm so the grant is sealed with it.
	const setBs = await vdisk.emergencySetBackstop({ trustees: trustees.map((t, i) => ({ label: 'T' + i, pub: t.publicKey })), k: 2 });
	ok('the backstop enrolls with n trustees and a threshold', setBs.n === 3 && setBs.k === 2 && (await vdisk.emergencyStatus()).backstop.n === 3);
	const armed = await vdisk.emergencyArm(v, { password: 'pw1', mode: 'date', dateMs });
	ok('arming with a backstop reports its k-of-n', armed.backstop && armed.backstop.k === 2 && armed.backstop.n === 3);

	const settings = JSON.parse(await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8'));
	const grant = Object.values(settings.emergency.armed)[0];
	ok('the grant stores one sealed share per trustee', grant.backstop && grant.backstop.shares.length === 3);

	// The read cap the time-lock protects, for comparison.
	const timelockToken = await vdisk.emergencyOpen(contact.privateKey, grant.sealed, { signature: REAL_SIG });

	// Each trustee opens exactly their own sealed share.
	const opened = grant.backstop.shares.map((sh, i) => vdisk.emergencyTrusteeShare(sh.sealed, trustees[i].privateKey));
	ok('each trustee opens their own sealed share', opened.every(Boolean) && new Set(opened).size === 3);
	ok('a trustee cannot open another trustee\'s share', vdisk.emergencyTrusteeShare(grant.backstop.shares[0].sealed, trustees[1].privateKey) === null);

	// A quorum (k=2) reconstructs the SAME read cap — the beacon-free path.
	const recovered = vdisk.emergencyRecoverToken({ shares: [opened[0], opened[1]] });
	ok('a quorum of trustees reconstructs a valid read link', !!vdisk.parseReadCap(recovered));
	ok('the reconstructed read cap matches the time-locked one (same access, no beacon needed)', recovered === timelockToken);
	// A different quorum (0 and 2) reconstructs the same secret too.
	ok('any k trustees reconstruct the same read cap', vdisk.emergencyRecoverToken({ shares: [opened[0], opened[2]] }) === timelockToken);

	// Fewer than the threshold fails.
	let tooFew = false; try { vdisk.emergencyRecoverToken({ shares: [opened[0]] }); } catch (_) { tooFew = true; }
	ok('fewer than the threshold cannot reconstruct (fail-closed)', tooFew);

	// Turning the backstop off leaves new grants without one.
	await vdisk.emergencyClearBackstop();
	const armed2 = await vdisk.emergencyArm(v, { password: 'pw1', mode: 'date', dateMs });
	ok('clearing the backstop turns it off for new grants', armed2.backstop === null);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-BACKSTOP CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
