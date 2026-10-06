'use strict';
// lib/test/ownerkeyrotation.js — owner-seed ROTATION (rotateOwnerKey): the true revocation step for team vaults.
// Verifies that rotating the owner key keeps every CURRENT owner (re-sealing the new seed to them), makes any OLD copy
// of the owner seed worthless (a downgraded co-owner's password can still READ but can no longer manage membership),
// bumps keyGeneration (so owner recovery reads as stale), keeps the roster validly signed, is manifest-only (no
// re-encryption — content still decrypts), and is safe to run again. Uses real encrypted content (no mount).
//
// Run:  node lib/test/ownerkeyrotation.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function cryptCfg(bin, dataDir, mf, master) { const c = mf.crypt; return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: dataDir, passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption })); }
async function get(bin, cfg, name) { const r = await Rclone.run(bin, ['cat', 'vault:' + name], { configPath: cfg }); return r.status === 0 ? r.stdout : null; }
const mfOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
const canAddMember = (v, cred, pub) => vdisk.addMember(v, { ...cred, memberPub: pub, role: 'read' }).then(() => true, () => false);

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const bin = require('../RcloneSetup').resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-ownerrot-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'OWNED');
	const v = path.join(tmp, 'OR.vault');
	await vdisk.importFolder(v, { password: 'creator-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'creator-pw' });
	await vdisk.enableTeam(v, { password: 'creator-pw' });

	// Bob is a MEMBER-owner (owner seed sealed to his public key); recovered-pw is a second PASSWORD-owner.
	const bob = vdisk.emergencyKeypair();
	const b = await vdisk.addMember(v, { password: 'creator-pw', memberPub: bob.publicKey, role: 'write', label: 'Bob' });
	await vdisk.setMemberOwner(v, { password: 'creator-pw', memberId: b.memberId, owner: true });
	const t1 = vdisk.emergencyKeypair(), t2 = vdisk.emergencyKeypair();
	await vdisk.setupOwnerRecovery(v, { password: 'creator-pw', k: 2, trustees: [{ pub: t1.publicKey, label: 'T1' }, { pub: t2.publicKey, label: 'T2' }] });
	const s1 = await vdisk.getRecoveryShare(v, t1.privateKey), s2 = await vdisk.getRecoveryShare(v, t2.privateKey);
	await vdisk.recoverOwner(v, { shares: [s1.share, s2.share], newPassword: 'recovered-pw', label: 'Recovered' });

	// Baseline: all three owners can manage membership.
	const p = () => vdisk.emergencyKeypair().publicKey;
	ok('baseline — creator (password owner) can manage', await canAddMember(v, { password: 'creator-pw' }, p()));
	ok('baseline — the recovered password is also an owner', await canAddMember(v, { password: 'recovered-pw' }, p()));
	ok('baseline — Bob (member owner) can manage with his key', await canAddMember(v, { memberKey: bob.privateKey }, p()));
	const genBefore = (await vdisk.listMembers(v)).keyGeneration;
	const fpBefore = (await vdisk.listMembers(v)).ownerFingerprint;

	// ---- ROTATE the owner key, authenticated by the creator's owner password ----
	const r = await vdisk.rotateOwnerKey(v, { password: 'creator-pw' });
	ok('rotation kept at least the creator and Bob as owners', r.ownersKept >= 2);
	ok('rotation downgraded the other password-owner it could not re-seal', r.passwordOwnersDowngraded >= 1);
	ok('rotation reports owner recovery was invalidated', r.recoveryInvalidated === true);
	ok('rotation minted a new owner identity', r.ownerFingerprint && r.ownerFingerprint !== fpBefore);

	const roster = await vdisk.listMembers(v);
	ok('the roster is still validly signed after rotation', roster.rosterValid === true);
	ok('keyGeneration was bumped', roster.keyGeneration === genBefore + 1);
	ok('owner recovery reads as stale after rotation', roster.recovery && roster.recovery.stale === true);

	// Kept owners still manage; the downgraded co-owner's OLD seed is now DEAD (revoked), but it can still READ.
	ok('the creator stays an owner after rotation', await canAddMember(v, { password: 'creator-pw' }, p()));
	ok('Bob (member owner) stays an owner after rotation', await canAddMember(v, { memberKey: bob.privateKey }, p()));
	ok('the rotated-out password can NO LONGER manage membership (revoked)', (await canAddMember(v, { password: 'recovered-pw' }, p())) === false);
	let revokedMsg = false;
	try { await vdisk.addMember(v, { password: 'recovered-pw', memberPub: p(), role: 'read' }); } catch (e) { revokedMsg = /rotated|revoked/i.test(e.message); }
	ok('the revoked owner gets a clear "rotated/revoked" message', revokedMsg);

	// Manifest-only: the write seed never changed, so the downgraded owner still DECRYPTS content with its password.
	const mf = await mfOf(v);
	const recoveredMaster = Vault.parseReadCap((await vdisk.makeReadCap(v, { password: 'recovered-pw' })).token).master;
	const cfg = await cryptCfg(bin, path.join(v, 'data'), mf, recoveredMaster);
	ok('the downgraded owner still DECRYPTS content (no re-encryption happened)', (await get(bin, cfg, 'doc.txt')) === 'OWNED');
	await Rclone.removeConfig(cfg);

	// Safe to run again (idempotent-safe): a second rotation succeeds and mints yet another identity.
	const r2 = await vdisk.rotateOwnerKey(v, { password: 'creator-pw' });
	ok('a second owner-key rotation succeeds and mints a new identity', r2.ownerFingerprint && r2.ownerFingerprint !== r.ownerFingerprint);
	ok('the roster still verifies after a second rotation', (await vdisk.listMembers(v)).rosterValid === true);

	// REGRESSION GUARD (owner marker is single-sourced in makeSlot): a password change or a content re-key rebuilds the
	// owner's passphrase slot, and it must carry the owner marker forward. If it did not, the slot would keep the owner
	// seed (so the person still authorizes) yet lose its `owner:true` marker, so the NEXT owner-key rotation would skip
	// it — and on a sole-owner vault that throws "would leave no owner," quietly making revocation impossible.
	{
		const w = path.join(tmp, 'OR2.vault');
		await vdisk.importFolder(w, { password: 'owner-pw', sourceDir: src });
		await vdisk.enableTeam(w, { password: 'owner-pw' });
		await vdisk.changePassword(w, { oldPassword: 'owner-pw', newPassword: 'owner-pw2' });
		ok('after a password change the sole owner can still manage membership', await canAddMember(w, { password: 'owner-pw2' }, p()));
		const rr = await vdisk.rotateOwnerKey(w, { password: 'owner-pw2' });
		ok('after a password change the sole owner can still rotate the owner key', rr.ok === true && rr.ownersKept >= 1);
		await vdisk.rotate(w, { password: 'owner-pw2' });
		ok('after a content re-key the sole owner can still manage membership', await canAddMember(w, { password: 'owner-pw2' }, p()));
		const rr2 = await vdisk.rotateOwnerKey(w, { password: 'owner-pw2' });
		ok('after a content re-key the sole owner can still rotate the owner key', rr2.ok === true && rr2.ownersKept >= 1);
	}

	// A non-team vault is refused cleanly.
	const solo = path.join(tmp, 'SOLO.vault');
	await vdisk.importFolder(solo, { password: 'solo-pw', sourceDir: src });
	let soloRefused = false;
	try { await vdisk.rotateOwnerKey(solo, { password: 'solo-pw' }); } catch (e) { soloRefused = /not a team vault/i.test(e.message); }
	ok('rotating the owner key on a non-team vault is refused', soloRefused);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OWNER-KEY-ROTATION CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const pth = kv.path || kv; if (pth.includes('vdisk-ownerrot-')) await vdisk.removeKnownVault(pth); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
