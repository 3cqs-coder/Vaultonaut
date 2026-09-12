'use strict';
// lib/test/emergencyrelease.js — the beneficiary OPEN path for a time-locked grant, proven OFFLINE. A grant is
// sealed to the beneficiary's key AND time-locked to a drand round; opening needs both the beneficiary's private key
// and the round's beacon signature. To exercise a MATURE round without the network, the vault is armed with a
// scheduled-unlock date that maps to drand round 1,000,000, and opened with that round's real published signature
// (frozen as a vector). This covers: a correct open recovers the read capability; the offline signature-import path;
// the identity gate (a different key cannot open even with the right signature); fail-closed on a wrong signature;
// and the recoverable "not yet" message for a grant whose round has not matured (no network is touched for that case).
//
// Run:  node lib/test/emergencyrelease.js  (needs the engine to derive a read capability)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Round 1,000,000 on quicknet and its real published 48-byte compressed-G1 signature (the same interop vector the
// time-lock test pins). Its round time is in the past, so a grant scheduled to it is already mature.
const REAL_ROUND = 1000000;
const REAL_SIG = '83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72';

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-emrel-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Timelock = require('../Timelock');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const contact = vdisk.emergencyKeypair();
	const stranger = vdisk.emergencyKeypair();
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'will.txt'), 'last will and testament');
	const v = path.join(tmp, 'Legacy.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.emergencyEnroll({ contactPubKey: contact.publicKey, contactLabel: 'Executor', inactivityDays: 30, graceDays: 14 });

	// Arm with a scheduled-unlock date that resolves to round 1,000,000 (a past, already-mature round).
	const dateMs = Timelock.timeOfRoundMs(REAL_ROUND);
	const armed = await vdisk.emergencyArm(v, { password: 'pw1', mode: 'date', dateMs });
	ok('a date-mode grant reports its scheduled unlock and round', armed.mode === 'date' && armed.round === REAL_ROUND);

	// The stored grant blob (what the owner would hand over, or the release folder would deliver).
	const settings = JSON.parse(await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8'));
	const grant = Object.values(settings.emergency.armed)[0];
	ok('the stored grant is time-locked to the scheduled round', grant && Timelock.blobRound(grant.sealed) === REAL_ROUND);

	// Correct open: the beneficiary's key + the round's real signature (imported, offline) recovers a read capability.
	const link = await vdisk.emergencyOpen(contact.privateKey, grant.sealed, { signature: REAL_SIG });
	ok('the beneficiary opens the mature grant with the imported signature and recovers a read link', !!vdisk.parseReadCap(link));

	// Identity gate: a different key cannot open it even with the right signature.
	let strangerFails = false; try { await vdisk.emergencyOpen(stranger.privateKey, grant.sealed, { signature: REAL_SIG }); } catch (_) { strangerFails = true; }
	ok('a different beneficiary key cannot open it even with the right signature', strangerFails);

	// Fail-closed: a wrong signature is refused before it is ever used as a key.
	const badSig = REAL_SIG.slice(0, -2) + (REAL_SIG.endsWith('00') ? '11' : '00');
	let badSigFails = false; try { await vdisk.emergencyOpen(contact.privateKey, grant.sealed, { signature: badSig }); } catch (e) { badSigFails = /not valid/.test(e.message); }
	ok('a wrong time-lock signature is refused', badSigFails);

	// A grant whose round has NOT matured reports a recoverable "not yet" message, and touches no network to do so.
	const future = await vdisk.emergencyArm(v, { password: 'pw1', mode: 'date', dateMs: Date.now() + 365 * 86400000 });
	const s2 = JSON.parse(await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8'));
	const futureGrant = Object.values(s2.emergency.armed)[0];
	let notYet = false; try { await vdisk.emergencyOpen(contact.privateKey, futureGrant.sealed); } catch (e) { notYet = /cannot be opened until/.test(e.message); }
	ok('a not-yet-due grant reports a recoverable "not yet" message (no network needed)', notYet && future.mode === 'date');

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-RELEASE CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
