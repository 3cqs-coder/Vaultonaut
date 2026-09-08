'use strict';
// lib/test/team.js — team / multi-user vault foundation (Phases A–C): member slots sealed to a member's public
// key, an owner key that signs the membership roster, role separation (read vs read-write), member unlock that
// recovers a working key, a monotonic epoch with a signed roster (rollback/forgery detection), and soft remove.
// Uses real encrypted content through the crypt remote (no mount needed). Hard remove (rotate) is a later phase.
//
// Run:  node lib/test/team.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function cryptCfgFromMaster(bin, dataDir, manifest, master) {
	const c = manifest.crypt;
	return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: dataDir, passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption }));
}
async function get(bin, cfg, name) { const r = await Rclone.run(bin, ['cat', 'vault:' + name], { configPath: cfg }); return r.status === 0 ? r.stdout : null; }
async function put(bin, cfg, name, content) { await Rclone.run(bin, ['rcat', 'vault:' + name], { configPath: cfg, input: content }); }
const manifestOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const bin = require('../RcloneSetup').resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-team-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'HELLO TEAM');
	const v = path.join(tmp, 'Team.vault');
	await vdisk.importFolder(v, { password: 'owner-pw', sourceDir: src });
	// A signed identity is required before enabling team access; a snapshot establishes it.
	await vdisk.snapshot(v, { password: 'owner-pw' });

	// ---- enable team ----
	ok('a solo vault reports team:false', (await vdisk.listMembers(v)).team === false);
	await vdisk.enableTeam(v, { password: 'owner-pw' });
	let roster = await vdisk.listMembers(v);
	ok('enabling team makes it a team vault with a valid signed roster', roster.team === true && roster.rosterValid === true);
	ok('the owner can still open the vault by password', (await vdisk.verify(v, { password: 'owner-pw', deep: false })).password === 'ok');

	// ---- add a read member and a write member ----
	const alice = vdisk.emergencyKeypair();  // a read member
	const bob = vdisk.emergencyKeypair();    // a read-write member
	const a = await vdisk.addMember(v, { password: 'owner-pw', memberPub: alice.publicKey, role: 'read', label: 'Alice' });
	const b = await vdisk.addMember(v, { password: 'owner-pw', memberPub: bob.publicKey, role: 'write', label: 'Bob' });
	ok('adding members returns ids and bumps the epoch', !!a.memberId && !!b.memberId && b.epoch > a.epoch);
	roster = await vdisk.listMembers(v);
	ok('the roster lists both members with their roles', roster.members.length === 2 && roster.members.some(m => m.role === 'read') && roster.members.some(m => m.role === 'write'));

	// ---- a team vault's proof bundle must verify in BOTH verifiers ----
	// The dependency-free verifier must exclude member slots from the manifest seal exactly as the writer does,
	// or every team bundle reads as TAMPERED in the standalone tool.
	const bundleOut = path.join(tmp, 'team-proof');
	await vdisk.makeBundle(v, { password: 'owner-pw', outDir: bundleOut });
	ok('a team vault proof bundle verifies GENUINE (in-repo verifier)', (await vdisk.verifyBundle(bundleOut)).verdict === 'GENUINE');
	ok('the standalone verifier agrees a team bundle is GENUINE (member slots excluded from the seal)', require('../verify-bundle').verifyBundle(bundleOut).verdict === 'GENUINE');
	ok('the roster is still validly signed after additions', roster.rosterValid === true);

	// ---- removing a key on a team vault is an OWNER action ----
	// addKey (unlocking as the owner) grants a read-write password that is NOT an owner (it carries no owner
	// seed). Such a non-owner password must not be able to strip a key — otherwise it could remove the owner's key
	// and leave the vault with no one who can manage membership.
	const ownerSlotId = ((await manifestOf(v)).crypt.keySlots || []).find(s => s.kind !== 'member').id; // the owner's real password-slot id (a random hex, not "primary")
	const p2 = await vdisk.addKey(v, { password: 'owner-pw', newPassword: 'rw-nonowner-pw', label: 'RW (non-owner)' });
	let rmRefused = false;
	try { await vdisk.removeKey(v, { password: 'rw-nonowner-pw', slotId: ownerSlotId }); } catch (e) { rmRefused = /only an owner/i.test(e.message); }
	ok('a non-owner read-write password cannot remove a key on a team vault', rmRefused);
	const ownerCanRemove = await vdisk.removeKey(v, { password: 'owner-pw', slotId: p2.slotId }).then(r => !!r.ok).catch(() => false);
	ok('an owner can remove a key on a team vault', ownerCanRemove);

	// ---- a member unlocks with their private key and decrypts real content ----
	const mf = await manifestOf(v);
	const ac = await vdisk.unlockByMemberKey(alice.privateKey, mf);
	ok('the read member opens their slot', !!ac && ac.capability === 'ro');
	ok('the read member has no write seed and no owner seed', ac.writeSeed === null && !ac.ownerSeed);
	const cfgA = await cryptCfgFromMaster(bin, path.join(v, 'data'), mf, ac.master);
	ok('the read member decrypts the vault content', (await get(bin, cfgA, 'doc.txt')) === 'HELLO TEAM');
	await Rclone.removeConfig(cfgA);
	const aliceCapturedMaster = ac.master; // a copy a member could keep — used below to show why soft remove is not revocation

	const bc = await vdisk.unlockByMemberKey(bob.privateKey, mf);
	ok('the write member opens their slot with a write seed', !!bc && bc.capability === 'rw' && !!bc.writeSeed);
	ok('the write member is NOT an owner (no owner seed)', !bc.ownerSeed);
	const cfgB = await cryptCfgFromMaster(bin, path.join(v, 'data'), mf, bc.master);
	ok('the write member can read and write content', (await get(bin, cfgB, 'doc.txt')) === 'HELLO TEAM' && (await put(bin, cfgB, 'bob.txt', 'BY BOB'), (await get(bin, cfgB, 'bob.txt')) === 'BY BOB'));
	await Rclone.removeConfig(cfgB);

	// ---- a non-member key opens nothing ----
	const mallory = vdisk.emergencyKeypair();
	ok('a non-member key opens no slot', (await vdisk.unlockByMemberKey(mallory.privateKey, mf)) === null);

	// ---- only an owner can change membership ----
	let readerRefused = false;
	try { await vdisk.addMember(v, { memberKey: alice.privateKey, memberPub: mallory.publicKey, role: 'read' }); } catch (_) { readerRefused = true; }
	ok('a read member cannot add members (not an owner)', readerRefused);
	let writerRefused = false;
	try { await vdisk.addMember(v, { memberKey: bob.privateKey, memberPub: mallory.publicKey, role: 'read' }); } catch (_) { writerRefused = true; }
	ok('a write member cannot add members either (only an owner can)', writerRefused);

	// ---- soft remove (explicit rotate:false) on the clean, signed state ----
	const preRemoveManifest = await manifestOf(v); // capture the Alice-present, validly-signed manifest for the rollback test below
	const rem = await vdisk.removeMember(v, { password: 'owner-pw', memberId: a.memberId, rotate: false });
	ok('soft remove reports it is not real revocation (pending rotation)', rem.revoked === false && rem.pendingRotation === true);
	roster = await vdisk.listMembers(v);
	ok('the removed member is gone from the roster and it is re-signed', roster.members.length === 1 && roster.rosterValid === true && roster.members[0].role === 'write');
	// Soft remove drops the slot, so the member can no longer unlock via the shared roster going forward…
	ok('the removed member can no longer unlock via the shared roster (slot gone)', (await vdisk.unlockByMemberKey(alice.privateKey, await manifestOf(v))) === null);
	// ROLLBACK detection: restoring the older (Alice-present) manifest is a VALIDLY-SIGNED rollback that silently
	// re-lists the removed member. The members-epoch anchor (bumped by the removal) must flag it on read.
	const postRemoveManifest = await manifestOf(v);
	await fsp.writeFile(path.join(v, 'vault.json'), JSON.stringify(preRemoveManifest, null, 2));
	await fsp.writeFile(path.join(v, '.vault.bak'), JSON.stringify(preRemoveManifest, null, 2));
	ok('listMembers flags a members-roster rollback (older manifest re-listing a removed member)', (await vdisk.listMembers(v)).rolledBack === true);
	await fsp.writeFile(path.join(v, 'vault.json'), JSON.stringify(postRemoveManifest, null, 2)); // restore the true post-removal state for the rest of the test
	await fsp.writeFile(path.join(v, '.vault.bak'), JSON.stringify(postRemoveManifest, null, 2));
	ok('the rollback flag clears once the current roster is back', (await vdisk.listMembers(v)).rolledBack === false);
	// …BUT the master key value is unchanged, so a copy the member captured before removal still decrypts current
	// content. This is the honest limitation the UX must state, and why hard remove (rotate) is the real revocation.
	const cfgStale = await cryptCfgFromMaster(bin, path.join(v, 'data'), await manifestOf(v), aliceCapturedMaster);
	ok('a master captured before removal still decrypts (why hard remove/rotate is needed)', (await get(bin, cfgStale, 'doc.txt')) === 'HELLO TEAM');
	await Rclone.removeConfig(cfgStale);

	// A HARD remove re-encrypts (rotate) right after dropping the slot, so its certain preconditions — the owner
	// password and an unmounted vault — are checked BEFORE the slot is dropped. Otherwise a predictable failure would
	// leave the member off the roster yet still able to decrypt (the re-encryption never ran). Attempt a hard remove
	// with no owner password: it must be refused and leave the member FULLY present, with no pending-rotation state.
	{
		const roster0 = await vdisk.listMembers(v);
		const before = roster0.members.length;
		let refused = false;
		try { await vdisk.removeMember(v, { memberKey: bob.privateKey, memberId: b.memberId, rotate: true }); } catch (_) { refused = true; }
		const after = await vdisk.listMembers(v);
		ok('a hard remove without the owner password is refused before the slot is dropped', refused && after.members.length === before && after.members.some(m => m.memberId === b.memberId));
		ok('the refused hard remove did not change the roster state', after.rotationPending === roster0.rotationPending);
	}

	// ---- hard remove (rotate) truly revokes, and re-seals the remaining members ----
	// Add Alice back, then hard-remove Bob; Alice (remaining) must still open under the NEW key, Bob must not, and
	// a master captured before the rotation must no longer decrypt the (re-encrypted) content.
	const alice2 = vdisk.emergencyKeypair();
	await vdisk.addMember(v, { password: 'owner-pw', memberPub: alice2.publicKey, role: 'read', label: 'Alice2' });
	const bobMaster = (await vdisk.unlockByMemberKey(bob.privateKey, await manifestOf(v))).master;
	const hr = await vdisk.removeMember(v, { password: 'owner-pw', memberId: b.memberId, rotate: true });
	ok('hard remove reports true revocation', hr.revoked === true);
	const mf2 = await manifestOf(v);
	const rosterAfter = await vdisk.listMembers(v);
	ok('the roster is valid and key generation advanced after rotation', rosterAfter.rosterValid === true && rosterAfter.keyGeneration >= 2);
	ok('the revoked member can no longer unlock', (await vdisk.unlockByMemberKey(bob.privateKey, mf2)) === null);
	const aliceStill = await vdisk.unlockByMemberKey(alice2.privateKey, mf2);
	ok('a remaining member still opens under the new key', !!aliceStill);
	const cfgAlice2 = await cryptCfgFromMaster(bin, path.join(v, 'data'), mf2, aliceStill.master);
	ok('a remaining member decrypts content after rotation', (await get(bin, cfgAlice2, 'doc.txt')) === 'HELLO TEAM');
	await Rclone.removeConfig(cfgAlice2);
	const cfgBobStale = await cryptCfgFromMaster(bin, path.join(v, 'data'), mf2, bobMaster);
	ok('a master captured before the rotation no longer decrypts (true revocation)', (await get(bin, cfgBobStale, 'doc.txt')) !== 'HELLO TEAM');
	await Rclone.removeConfig(cfgBobStale);
	// The owner still owns after rotation (can change membership again).
	const carol = vdisk.emergencyKeypair();
	ok('the owner is still an owner after rotation', await vdisk.addMember(v, { password: 'owner-pw', memberPub: carol.publicKey, role: 'read' }).then(() => true).catch(() => false));

	// ---- the audit surfaces a tampered roster ----
	const forged = await manifestOf(v);
	forged.crypt.keySlots.push({ id: 'zz', kind: 'member', label: 'Rogue', createdAt: new Date().toISOString(), role: 'write', memberId: 'rogue', pub: mallory.publicKey, pubFp: 'x', sealed: 'AAAA' });
	await fsp.writeFile(path.join(v, 'vault.json'), JSON.stringify(forged, null, 2));
	await fsp.writeFile(path.join(v, '.vault.bak'), JSON.stringify(forged, null, 2));
	ok('listMembers reports the roster signature invalid after a rogue addition', (await vdisk.listMembers(v)).rosterValid === false);
	const audit = await vdisk.audit(v, { password: 'owner-pw' });
	ok('the audit surfaces the roster tampering', Array.isArray(audit.tamper) && audit.tamper.some(t => /roster/i.test(t)));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TEAM CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-team-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
