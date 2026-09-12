'use strict';
// lib/test/deadman.js — the emergency / inheritance dead-man's switch. A contact makes a keypair and shares
// only the public half; the owner enrolls it, arms a vault (its READ capability is sealed to that public key AND
// time-locked to a release round), and checks in to stay alive. Simulated time (the tick takes an explicit `now`)
// drives the phases: armed → grace (past the inactivity window, still vetoable) → due (released). On release the
// sealed grant is written out. The grant is TIME-LOCKED, so a beneficiary who receives it cannot open it before its
// release round matures — proven here by opening reporting a clear, recoverable "not yet" message. A check-in vetoes
// and withdraws a release. Read-only throughout — the sealed material is a read capability, never write authority.
// (The successful beneficiary open, once a round is mature, is covered offline by emergencyrelease.js using a real
// drand signature vector.)
//
// Run:  node lib/test/deadman.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-deadman-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// The trusted contact generates a keypair on their own device and shares only the public key.
	const contact = vdisk.emergencyKeypair();
	ok('a contact keypair is generated (public + private)', !!contact.publicKey && !!contact.privateKey && contact.publicKey !== contact.privateKey);

	// Create a vault with a secret file.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'estate.txt'), 'the combination is 12-24-36');
	const v = path.join(tmp, 'Estate.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	ok('emergency access is off by default', (await vdisk.emergencyStatus()).enrolled === false);
	// Arming before enrolling is refused.
	let noEnroll = false; try { await vdisk.emergencyArm(v, { password: 'pw1' }); } catch (_) { noEnroll = true; }
	ok('arming before enrolling a contact is refused', noEnroll);

	// Enroll the contact and arm the vault.
	await vdisk.emergencyEnroll({ contactPubKey: contact.publicKey, contactLabel: 'My sister', inactivityDays: 30, graceDays: 14 });
	await vdisk.emergencyArm(v, { password: 'pw1' });
	let st = await vdisk.emergencyStatus();
	ok('after enroll + arm the switch is armed', st.enrolled && st.phase === 'armed' && st.armed.length === 1);

	const start = new Date(st.lastCheckIn).getTime();
	const DAY = 86400000;

	// A tick well within the window does nothing.
	ok('a tick within the window does not release', (await vdisk.emergencyTick(start + 10 * DAY)).phase === 'armed');
	// Past the inactivity window but inside grace: grace phase, still no release.
	ok('past inactivity but within grace is the grace phase (still vetoable)', (await vdisk.emergencyTick(start + 40 * DAY)).phase === 'grace');
	ok('no release directory exists during grace', !fs.existsSync(path.join(dataDir, 'emergency-release')));

	// Past inactivity + grace: release.
	const rel = await vdisk.emergencyTick(start + 45 * DAY);
	ok('past inactivity + grace releases the sealed access', rel.released === true && rel.count === 1);
	const relDir = path.join(dataDir, 'emergency-release');
	// Each beneficiary gets their OWN subfolder (holding only their vaults' grants + a how-to), so look one level down.
	const cfolders = (await fsp.readdir(relDir, { withFileTypes: true })).filter(e => e.isDirectory()).map(e => e.name);
	const cdir = path.join(relDir, cfolders[0] || '');
	const sealedFiles = cfolders.length ? (await fsp.readdir(cdir)).filter(f => f.endsWith('.sealed')) : [];
	ok('a sealed blob and a how-to file are written to the beneficiary\'s release folder', cfolders.length === 1 && sealedFiles.length === 1 && fs.existsSync(path.join(cdir, 'HOW-TO-OPEN.txt')));

	// The delivered grant is TIME-LOCKED to a release round in the (real) future, so it cannot be opened yet — even by
	// the beneficiary, and even though it was just delivered. Opening reports a clear, recoverable "not yet" message
	// rather than failing hard. (The identity gate — that only the beneficiary's key opens a MATURE grant — is proven
	// in emergencyrelease.js, which uses a real drand signature to open a past-dated grant offline.)
	const sealed = await fsp.readFile(path.join(cdir, sealedFiles[0]), 'utf8');
	let notYet = false; try { await vdisk.emergencyOpen(contact.privateKey, sealed); } catch (e) { notYet = /time-locked|cannot be opened until|due to open/.test(e.message); }
	ok('the delivered grant is time-locked and does not open before its release round', notYet);

	// A check-in vetoes: it resets the timer and withdraws the release.
	await vdisk.emergencyCheckIn();
	st = await vdisk.emergencyStatus();
	ok('checking in returns to armed and withdraws the release', st.phase === 'armed' && !fs.existsSync(relDir));

	// Disarm removes the arrangement entirely.
	await vdisk.emergencyDisarm();
	ok('disarming clears the switch', (await vdisk.emergencyStatus()).enrolled === false);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DEAD-MAN CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
