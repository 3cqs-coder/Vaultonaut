'use strict';
// lib/test/recoveryfloorseal.js — the recovery-version floor is only trustworthy when the manifest seal verifies.
// The cross-machine anti-rollback floor travels in the manifest's recoveryVersion field, which is authenticated ONLY
// by the manifest seal. If the heal/verify path trusted that field without checking the seal, a folder-level attacker
// (no vault credential) could lower recoveryVersion to collapse the floor to 0 on a fresh machine and slip a
// rolled-back, still-validly-signed recovery index past the downgrade gate. This test proves the heal and verify
// paths now DETECT a broken manifest seal: verify reports tampered, and heal refuses by default (force overrides so a
// genuinely corrupt manifest never blocks recovery). Needs the bundled engine; runs unmounted (no mount driver).
//
// Run:  node lib/test/recoveryfloorseal.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recfloor-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 4; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(32 * 1024));
	const v = path.join(tmp, 'Floor.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// protect builds the self-healing recovery data; a snapshot then seals the manifest. protect runs before the
	// snapshot so it does not need the mount-computed protected-metadata list that a tamper baseline would demand.
	await vdisk.protect(v, { password: 'pw' });
	await vdisk.snapshot(v, { password: 'pw' });

	// Baseline: an untampered vault verifies its recovery data without a tamper flag, and heals cleanly.
	const clean = await vdisk.verifyRecovery(v);
	ok('a sealed, protected vault verifies its recovery data without a tamper flag', !!clean && !(clean.authenticity && clean.authenticity.tampered));
	const cleanHeal = await vdisk.heal(v);
	ok('heal proceeds on an untampered vault', !!cleanHeal && cleanHeal.protected === true);

	// Break the manifest seal exactly as a folder-level attacker lowering the floor would: edit the manifest (and its
	// backup, so the resilient-read cannot rescue it) so it no longer matches its own seal.
	const mf = path.join(v, 'vault.json'), bak = path.join(v, '.vault.bak');
	const raw = JSON.parse(await fsp.readFile(mf, 'utf8'));
	// Add a key slot the seal never covered — the same class of manifest tamper as lowering the sealed recoveryVersion
	// floor; either breaks the seal, and a broken seal is what makes the floor untrustworthy on the heal/verify path.
	raw.crypt.keySlots.push({ id: 'deadbeef', kind: 'password', label: 'x', createdAt: new Date().toISOString(), kdf: raw.crypt.keySlots[0].kdf, wrappedKey: 'AAAA' });
	const tampered = JSON.stringify(raw, null, 2);
	await fsp.writeFile(mf, tampered);
	await fsp.writeFile(bak, tampered).catch(() => {});

	// Verify now surfaces the manifest tamper on the recovery path (previously it was silent here).
	const bad = await vdisk.verifyRecovery(v);
	ok('verify reports a tamper when the manifest seal is broken', !!(bad && bad.authenticity && bad.authenticity.tampered));
	ok('the tamper is attributed to the manifest', !!(bad && bad.authenticity && bad.authenticity.manifestTampered));

	// Heal refuses by default rather than repairing against an untrusted floor.
	let refused = false;
	try { await vdisk.heal(v); } catch (e) { refused = (e.code === 'AUTH_REFUSED') && !!e.manifestTampered; }
	ok('heal refuses by default when the manifest seal is broken', refused);

	// The explicit "repair anyway" escape still lets the owner proceed, so a genuinely corrupt manifest never blocks
	// recovery outright.
	const forced = await vdisk.heal(v, { force: true });
	ok('heal proceeds with the force override even on a broken seal', !!forced && forced.protected === true);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-FLOOR-SEAL CHECKS PASSED'));
	if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
