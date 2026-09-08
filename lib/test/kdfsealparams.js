'use strict';
// lib/test/kdfsealparams.js — the manifest seal must authenticate each key slot's CONCRETE Argon2 cost
// parameters, not just its level LABEL. Otherwise an attacker with write access to the vault folder could keep
// level:"max" while lowering memKiB/iterations: the seal would still verify as authentic, but unlock would derive
// a different key and fail — a mysterious "wrong password" lockout on a manifest that reads as genuine. The fix
// makes Kdf.levelOf match by the real numbers (so a mutated slot resolves to "custom", which no longer equals the
// sealed label). The seal further folds each slot's FULL KDF (salt and hash length included, via the v2 seal), so
// mutating those — which also change the derived key — is caught too. This test proves each tamper is flagged, and
// that a legitimate preset slot still maps to its label (backward-compatible — existing seals must not
// false-alarm). Needs the engine; no mount driver.
//
// Run:  node lib/test/kdfsealparams.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault');
const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	// Pure unit checks first (no engine needed): levelOf matches by concrete numbers, not the label.
	ok('a standard-preset param set maps to "standard"', Kdf.levelOf({ memKiB: 65536, iterations: 3, parallelism: 4, level: 'standard' }) === 'standard');
	ok('a max-preset param set maps to "max"', Kdf.levelOf({ memKiB: 524288, iterations: 4, parallelism: 4, level: 'max' }) === 'max');
	ok('a slot claiming level:"max" but with weak numbers resolves to "custom" (not the trusted label)', Kdf.levelOf({ memKiB: 8, iterations: 1, parallelism: 1, level: 'max' }) === 'custom');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the seal checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-kdfseal-')); workspace = tmp;
	const v = path.join(tmp, 'K.vault');
	await vdisk.create(v, { password: 'pw', level: 'max' });
	await vdisk.snapshot(v, { password: 'pw' }); // publish the key and seal the manifest
	// The seal is checked PASSWORD-FREE (checkManifestSeal), which matters here: weakening the params below makes
	// the password no longer derive the right key, so an audit-with-password could not even run — the seal check is
	// the layer that must still catch the mutation.
	const sealed = Vault.checkManifestSeal(await Vault.readManifest(v));
	ok('the snapshot produced a verifiable manifest seal', sealed.sealed && sealed.ok);

	// Tamper: keep the level label, but weaken the concrete cost parameters of the unlock slot.
	const mf = path.join(v, 'vault.json'), bak = path.join(v, '.vault.bak');
	const raw = JSON.parse(await fsp.readFile(mf, 'utf8'));
	const slot = raw.crypt.keySlots[0];
	ok('the created slot carries the max preset', slot.kdf.memKiB === 524288 && (slot.kdf.level === 'max' || Kdf.levelOf(slot.kdf) === 'max'));
	const pristine = JSON.stringify(raw); // a clean, sealed copy to base each independent tamper on
	slot.kdf.memKiB = 8; slot.kdf.iterations = 1; slot.kdf.parallelism = 1; // label left as-is (the attack)
	await fsp.writeFile(mf, JSON.stringify(raw));
	const after = Vault.checkManifestSeal(JSON.parse(await fsp.readFile(mf, 'utf8')));
	ok('weakening a slot\'s KDF parameters (keeping the level label) breaks the manifest seal', after.sealed && !after.ok);

	// The seal must ALSO cover the salt and the hash length: both change the derived key, and the cost-parameter
	// level check ignored them, so mutating either left the seal "genuine" while causing a wrong-password lockout.
	// The v2 seal folds the full KDF, so both are now caught. Each mutation starts from the pristine sealed copy.
	const tamper = async (mutate) => { const r = JSON.parse(pristine); mutate(r.crypt.keySlots[0].kdf); await fsp.writeFile(mf, JSON.stringify(r)); return Vault.checkManifestSeal(JSON.parse(await fsp.readFile(mf, 'utf8'))); };
	const saltT = await tamper(kdf => { kdf.salt = Buffer.alloc(16).toString('base64'); });
	ok('mutating a slot\'s KDF salt breaks the manifest seal', saltT.sealed && !saltT.ok);
	const lenT = await tamper(kdf => { kdf.hashLen = 16; });
	ok('mutating a slot\'s KDF hash length breaks the manifest seal', lenT.sealed && !lenT.ok);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KDF-SEAL-PARAM CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
