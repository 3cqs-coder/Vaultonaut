'use strict';
// lib/test/teamowners.js — multiple owners (promote/demote) and N-of-M owner recovery via Shamir. Verifies a
// promoted member can manage membership, demotion, and that owner recovery reconstructs owner+write access from k
// trustee shares WITH self-verification (a wrong/corrupt share or too few shares fails closed rather than yielding
// a bad key). Uses real encrypted content through the crypt remote (no mount).
//
// Run:  node lib/test/teamowners.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function cryptCfg(bin, dataDir, mf, master) { const c = mf.crypt; return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: dataDir, passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption })); }
async function get(bin, cfg, name) { const r = await Rclone.run(bin, ['cat', 'vault:' + name], { configPath: cfg }); return r.status === 0 ? r.stdout : null; }
const mfOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const bin = require('../RcloneSetup').resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-teamowners-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'OWNED');
	const v = path.join(tmp, 'TO.vault');
	await vdisk.importFolder(v, { password: 'creator-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'creator-pw' });
	await vdisk.enableTeam(v, { password: 'creator-pw' });

	const bob = vdisk.emergencyKeypair(), carol = vdisk.emergencyKeypair();
	const b = await vdisk.addMember(v, { password: 'creator-pw', memberPub: bob.publicKey, role: 'write', label: 'Bob' });

	// ---- promote to owner ----
	await vdisk.setMemberOwner(v, { password: 'creator-pw', memberId: b.memberId, owner: true });
	let roster = await vdisk.listMembers(v);
	ok('the promoted member is listed as owner', roster.members.find(m => m.memberId === b.memberId).owner === true && roster.memberOwners === 1);
	ok('the roster stays validly signed after promotion', roster.rosterValid === true);
	// Bob, now an owner, can add a member using his OWN member key (he holds the owner seed).
	ok('a promoted owner can add members with their own key', await vdisk.addMember(v, { memberKey: bob.privateKey, memberPub: carol.publicKey, role: 'read', label: 'Carol' }).then(() => true).catch(() => false));

	// ---- demote ----
	await vdisk.setMemberOwner(v, { password: 'creator-pw', memberId: b.memberId, owner: false });
	roster = await vdisk.listMembers(v);
	ok('the demoted member is no longer an owner', roster.members.find(m => m.memberId === b.memberId).owner === false && roster.memberOwners === 0);

	// ---- owner recovery: setup ----
	const t1 = vdisk.emergencyKeypair(), t2 = vdisk.emergencyKeypair(), t3 = vdisk.emergencyKeypair();
	const setup = await vdisk.setupOwnerRecovery(v, { password: 'creator-pw', k: 2, trustees: [{ pub: t1.publicKey, label: 'T1' }, { pub: t2.publicKey, label: 'T2' }, { pub: t3.publicKey, label: 'T3' }] });
	ok('recovery setup reports k of n', setup.k === 2 && setup.n === 3);
	ok('listMembers reports the recovery config', (await vdisk.listMembers(v)).recovery.k === 2);
	ok('the roster stays validly signed after recovery setup', (await vdisk.listMembers(v)).rosterValid === true);

	// ---- trustees open their shares ----
	const s1 = await vdisk.getRecoveryShare(v, t1.privateKey);
	const s2 = await vdisk.getRecoveryShare(v, t2.privateKey);
	ok('two trustees each open their own share', !!s1 && !!s1.share && !!s2 && !!s2.share && s1.share !== s2.share);
	ok('a non-trustee key opens no share', (await vdisk.getRecoveryShare(v, carol.privateKey)) === null);

	// ---- recover owner access from k shares ----
	const rec = await vdisk.recoverOwner(v, { shares: [s1.share, s2.share], newPassword: 'recovered-pw', label: 'Recovered' });
	ok('recovery with k valid shares succeeds', rec.recovered === true);
	// The recovered password now opens the vault as an OWNER (can manage membership) and decrypts content.
	const dave = vdisk.emergencyKeypair();
	ok('the recovered password is an owner (can add members)', await vdisk.addMember(v, { password: 'recovered-pw', memberPub: dave.publicKey, role: 'read' }).then(() => true).catch(() => false));
	const mf = await mfOf(v);
	const recoveredMaster = Vault.parseReadCap((await vdisk.makeReadCap(v, { password: 'recovered-pw' })).token).master;
	const cfg = await cryptCfg(bin, path.join(v, 'data'), mf, recoveredMaster);
	ok('the recovered password decrypts vault content', (await get(bin, cfg, 'doc.txt')) === 'OWNED');
	await Rclone.removeConfig(cfg);

	// ---- fail-closed: a corrupted share, and too few shares ----
	const s3 = await vdisk.getRecoveryShare(v, t3.privateKey);
	const parts = s1.share.split('.');
	const badY = crypto.randomBytes(Buffer.from(parts[3], 'base64').length).toString('base64');
	const corrupted = parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + badY;
	let corruptRefused = false;
	try { await vdisk.recoverOwner(v, { shares: [corrupted, s3.share], newPassword: 'x-pw-1' }); } catch (_) { corruptRefused = true; }
	ok('a corrupted share is detected and recovery is refused (self-verification)', corruptRefused);
	let fewRefused = false;
	try { await vdisk.recoverOwner(v, { shares: [s3.share], newPassword: 'x-pw-2' }); } catch (_) { fewRefused = true; }
	ok('too few shares are refused', fewRefused);

	// Recovery must fail CLOSED on a tampered roster: the self-verify trusts the published owner key, so a manifest
	// whose owner-signed roster no longer verifies (a slot or role changed without the owner key) must be refused
	// before recovery can validate reconstructed keys against it. Corrupt the roster signature and confirm refusal.
	const tam = await mfOf(v);
	tam.members.sig = Buffer.from(crypto.randomBytes(64)).toString('base64'); // a well-formed but wrong signature
	await fsp.writeFile(path.join(v, 'vault.json'), JSON.stringify(tam));
	await fsp.writeFile(path.join(v, '.vault.bak'), JSON.stringify(tam));
	let tamperRefused = false;
	try { await vdisk.recoverOwner(v, { shares: [s1.share, s3.share], newPassword: 'x-pw-3' }); } catch (e) { tamperRefused = /roster|integrity|altered/i.test(e.message); }
	ok('owner recovery is refused when the membership roster fails its signature', tamperRefused);

	// ---- regression: audit findings ----
	// An owner changing their password must STAY an owner (capBundle must carry the owner seed).
	await vdisk.changePassword(v, { oldPassword: 'creator-pw', newPassword: 'creator-pw2' });
	const eve = vdisk.emergencyKeypair();
	ok('an owner stays an owner after a password change', await vdisk.addMember(v, { password: 'creator-pw2', memberPub: eve.publicKey, role: 'read' }).then(() => true).catch(() => false));
	// Member slots must not appear as removable keys, and removeKey must refuse them.
	const keys = await vdisk.listKeys(v);
	ok('member slots are not listed as keys', !keys.slots.some(s => s.kind === 'member'));
	const aMemberSlot = (await mfOf(v)).crypt.keySlots.find(s => s.kind === 'member').id;
	let rkRefused = false;
	try { await vdisk.removeKey(v, { password: 'creator-pw2', slotId: aMemberSlot }); } catch (_) { rkRefused = true; }
	ok('removeKey refuses a member slot', rkRefused);
	// Rotating a team vault with a NON-owner read-write password is refused (would break the roster signature).
	await vdisk.addKey(v, { password: 'creator-pw2', newPassword: 'plain-rw', label: 'Plain rw' });
	let rotRefused = false;
	try { await vdisk.rotate(v, { password: 'plain-rw' }); } catch (_) { rotRefused = true; }
	ok('rotating a team vault with a non-owner password is refused', rotRefused);
	// Recovery is flagged stale after a rotation (its shares encode the old write seed).
	await vdisk.removeMember(v, { password: 'creator-pw2', memberId: b.memberId, rotate: true }).catch(() => {});
	ok('owner recovery is flagged stale after a key rotation', (await vdisk.listMembers(v)).recovery.stale === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TEAM-OWNER CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-teamowners-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
