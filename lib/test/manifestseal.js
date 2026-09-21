'use strict';
// lib/test/manifestseal.js — the manifest seal (G3). A snapshot signs the vault's stable security fields
// (salt, key slots, published key) with the write key; an audit verifies that seal. Tampering with the
// key slots or settings is flagged, while a LEGITIMATE key change (which re-seals) must NOT false-alarm.
// Needs the engine; no mount driver (audit runs unmounted).
//
// Run:  node lib/test/manifestseal.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const hasManifestFinding = (rep) => (rep.tamper || []).some(t => /manifest/i.test(t));

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mseal-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(1024));
	const v = path.join(tmp, 'Seal.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// A snapshot publishes the key and seals the manifest.
	await vdisk.snapshot(v, { password: 'pw1' });
	const m = await Vault.readManifest(v);
	ok('a snapshot seals the manifest (a write-key signature is stored)', !!(m.integrity && m.integrity.manifestSig));
	ok('audit is clean right after a snapshot', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// A LEGITIMATE key change must re-seal and NOT be mistaken for tampering.
	await vdisk.addRecoveryKey(v, { password: 'pw1' });
	ok('adding a key does not false-alarm (the seal is refreshed)', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// Tamper the manifest directly — add a bogus key slot the seal never covered.
	const mf = path.join(v, 'vault.json'), bak = path.join(v, '.vault.bak');
	const raw = JSON.parse(await fsp.readFile(mf, 'utf8'));
	raw.crypt.keySlots.push({ id: 'deadbeef', kind: 'password', label: 'x', createdAt: new Date().toISOString(), kdf: raw.crypt.keySlots[0].kdf, wrappedKey: 'AAAA' });
	const tampered = JSON.stringify(raw, null, 2);
	await fsp.writeFile(mf, tampered);
	await fsp.writeFile(bak, tampered).catch(() => {}); // tamper the backup too, so no resilient-read rescue
	ok('a tampered manifest (an added key slot) is flagged', hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// Re-snapshotting re-seals over the current state → clean again.
	await vdisk.snapshot(v, { password: 'pw1' });
	ok('re-snapshot re-seals the manifest (clean again)', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// The recovery-version floor is folded into the seal, so a folder-level attacker who LOWERS it (to slip a
	// downgraded recovery index past the cross-machine gate) breaks the seal and is flagged. Set a high value, re-seal
	// cleanly by re-snapshotting, then lower it on disk and confirm the audit catches it.
	const raw2 = JSON.parse(await fsp.readFile(mf, 'utf8'));
	raw2.recoveryVersion = 9; const withRV = JSON.stringify(raw2, null, 2);
	await fsp.writeFile(mf, withRV); await fsp.writeFile(bak, withRV).catch(() => {});
	await vdisk.snapshot(v, { password: 'pw1' }); // re-seal over recoveryVersion=9
	ok('a vault with a sealed recoveryVersion audits clean', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));
	const raw3 = JSON.parse(await fsp.readFile(mf, 'utf8'));
	raw3.recoveryVersion = 1; const lowered = JSON.stringify(raw3, null, 2); // roll the floor back
	await fsp.writeFile(mf, lowered); await fsp.writeFile(bak, lowered).catch(() => {});
	ok('lowering the sealed recoveryVersion breaks the seal (a downgrade of the floor is flagged)', hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// Restore a clean sealed state for the seal-signature tests below.
	await vdisk.snapshot(v, { password: 'pw1' });
	ok('re-snapshot restores a clean sealed state', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));

	// Behavioral post-quantum-downgrade guard: the seal is HYBRID (a classical AND a post-quantum signature over the
	// same fields), so stripping ONLY the post-quantum signature — leaving a valid classical one — must still be
	// flagged. This replaces a source-regex pin with a real audit assertion, so a refactor that quietly accepted a
	// classical-only seal is caught. Both the primary manifest and its backup are edited so no resilient-read rescue
	// masks the change.
	{
		const r = JSON.parse(await fsp.readFile(mf, 'utf8'));
		delete r.integrity.manifestSigPq;
		const s = JSON.stringify(r, null, 2);
		await fsp.writeFile(mf, s); await fsp.writeFile(bak, s).catch(() => {});
		ok('stripping only the post-quantum signature (the classical one left valid) is flagged', hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));
		await vdisk.snapshot(v, { password: 'pw1' }); // re-seal for the next check
	}

	// Whole-seal removal is a KNOWN, BOUNDED defense-in-depth gap (tracked in docs/BACKLOG.md): audit treats a vault
	// whose seal has vanished ENTIRELY as "not sealed" rather than flagging the removal. It is bounded because removal
	// grants nothing usable — without the master an attacker cannot forge a working credential, downgrade the KDF
	// undetected (unlock fails closed), or lower the recoveryVersion (its own anchor catches that). This test PINS the
	// current behavior so a change in either direction is deliberate: if the gap is later closed (removal starts being
	// flagged), update this assertion; if a regression ever made a forged change slip past some OTHER guard, that guard's
	// own test catches it. Editing both the manifest and its backup so no resilient-read rescue is involved.
	{
		const r = JSON.parse(await fsp.readFile(mf, 'utf8'));
		delete r.integrity.manifestSig; delete r.integrity.manifestSigPq;
		const s = JSON.stringify(r, null, 2);
		await fsp.writeFile(mf, s); await fsp.writeFile(bak, s).catch(() => {});
		ok('removing the whole seal is not yet flagged by audit (known bounded gap — see docs/BACKLOG.md)', !hasManifestFinding(await vdisk.audit(v, { password: 'pw1' })));
	}

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MANIFEST-SEAL CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
