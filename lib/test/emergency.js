'use strict';
// lib/test/emergency.js — read-only emergency / inheritance access via a threshold (Shamir) key. A read-only
// threshold splits an unlock secret into n shares; any k reconstruct a credential that can READ the vault but
// never change it or rotate the owner out. A plain threshold key stays read-write (self-recovery). Needs the
// engine (no mount driver — reconstruct + open/verify runs unmounted).
//
// Run:  node lib/test/emergency.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-emerg-'));
	const Common = require('../Common');
	Common.statePath = () => path.join(tmp, 'state.json');
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'will.txt'), 'the estate');
	const v = path.join(tmp, 'Estate.vault');
	await vdisk.importFolder(v, { password: 'owner-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'owner-pw' }); // a baseline to audit against later

	// --- Read-only emergency access ---
	const em = await vdisk.addThresholdKey(v, { password: 'owner-pw', n: 3, k: 2, readOnly: true });
	ok('emergency access reports read-only and n shares', em.readOnly === true && em.shares.length === 3);
	const secret = vdisk.unlockSecretFromShares([em.shares[0], em.shares[2]]); // any 2 of 3
	// The reconstructed credential can READ the vault...
	let canRead = true; try { await vdisk.list(v, { password: secret }); } catch (_) { canRead = false; }
	ok('any k shares reconstruct a credential that can READ the vault', canRead);
	// ...but it is READ-ONLY: it cannot sign a new baseline (snapshot needs the write seed).
	let writeRefused = false;
	try { await vdisk.snapshot(v, { password: secret }); } catch (e) { writeRefused = /read-only|cannot sign|write/i.test(e.message) || !!e.readOnly; }
	ok('the emergency credential cannot change the vault (no write authority)', writeRefused);
	// Fewer than k shares cannot reconstruct.
	let tooFew = false; try { vdisk.unlockSecretFromShares([em.shares[0]]); } catch (_) { tooFew = true; }
	ok('fewer than k shares cannot reconstruct the secret', tooFew);

	// --- A plain (non-read-only) threshold key stays read-write (self-recovery) ---
	const rw = await vdisk.addThresholdKey(v, { password: 'owner-pw', n: 2, k: 2 });
	ok('a plain threshold key is read-write', rw.readOnly === false);
	const rwSecret = vdisk.unlockSecretFromShares(rw.shares);
	let canWrite = true; try { await vdisk.snapshot(v, { password: rwSecret }); } catch (_) { canWrite = false; }
	ok('a plain threshold credential can change the vault (write authority)', canWrite);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-ACCESS CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
