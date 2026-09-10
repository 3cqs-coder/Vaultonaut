'use strict';
// lib/test/deadman.js — the emergency / inheritance dead-man's switch. A contact makes a keypair and shares
// only the public half; the owner enrolls it, arms a vault (its READ capability is sealed to that public key),
// and checks in to stay alive. Simulated time (the tick takes an explicit `now`) drives the phases: armed →
// grace (past the inactivity window, still vetoable) → due (released). On release the sealed blob is written
// out and the CONTACT opens it with their private key, recovering a real read link. A check-in vetoes and
// withdraws a release. Read-only throughout — the sealed material is a read capability, never write authority.
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

	// The CONTACT opens the sealed blob with their PRIVATE key and recovers a real read link.
	const sealed = await fsp.readFile(path.join(cdir, sealedFiles[0]), 'utf8');
	const readLink = vdisk.emergencyOpen(contact.privateKey, sealed);
	ok('the contact opens the sealed blob into a valid read link', !!vdisk.parseReadCap(readLink));
	// A different key cannot open it.
	const stranger = vdisk.emergencyKeypair();
	let strangerFails = false; try { vdisk.emergencyOpen(stranger.privateKey, sealed); } catch (_) { strangerFails = true; }
	ok('a stranger\'s key cannot open the sealed blob', strangerFails);

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
