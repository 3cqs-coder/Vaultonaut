'use strict';
// lib/test/lastownerguard.js — a team vault must never be driven to ZERO owners (a governance lockout: no one left
// who can manage membership, rotate keys, or recover). Owner authority is now tracked AUTHORITATIVELY by an explicit
// `owner: true` marker on the credential — a passphrase slot that carries the owner seed, or a member slot with the
// owner role. A plain read-write password (added with addKey) is NOT an owner and must never be miscounted as one.
//
// The regression this pins: the old owner accounting guessed from a slot's KIND — any non-member password/primary
// slot counted as an owner. So adding a plain read-write password made the accounting believe an owner still existed,
// which could let the last real owner be demoted, stranding the vault with no owner. The authoritative marker closes
// that. The marker is also folded into the manifest seal, so a folder-level attacker who forges or strips it — to fake
// an owner or defeat the last-owner guard — breaks the seal and is caught (see manifestSealInput).
//
// Part 1 (pure, always runs) pins the authoritative accounting against the exact old-heuristic false positive.
// Part 2 (engine-gated) drives the real add-key / promote / demote / remove-key paths and the seal-tamper check.
//
// Run:  node lib/test/lastownerguard.js   (Part 2 needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const mfOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));

// ---------------------------------------------------------------------------
// Part 1 — authoritative owner accounting (pure; the core regression pin)
// ---------------------------------------------------------------------------
function part1() {
	const { ownerHasPasswordSlot } = Vault._governance;
	const mf = (keySlots) => ({ crypt: { keySlots } });

	// The exact old-heuristic false positive: a plain read-write password (kind 'password', NO owner marker) is the
	// ONLY passphrase slot. It is NOT an owner. The old kind-based guess returned true here — the bug.
	ok('a plain read-write password is not counted as an owner', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'password' }])) === false);
	// primary / no-kind passphrase slots without the marker are likewise not owners (the old guess counted these too).
	ok('a primary passphrase slot without the marker is not an owner', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'primary' }, { id: 'b' }])) === false);
	// The dangerous state the guard must catch: the only real owner is a MEMBER-owner, alongside a plain read-write
	// password. There is NO password-owner, so demoting that member-owner would strand the vault — the accounting must
	// report no password-owner (false) so the demote guard fires. The old heuristic returned true and let it through.
	ok('a plain password alongside a member-owner is still not a password-owner', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'password' }, { id: 'm', kind: 'member', owner: true }])) === false);
	// Only an explicit marker counts.
	ok('a passphrase slot marked owner is counted', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'password', owner: true }])) === true);
	ok('a non-owner mixed with an owner-marked slot is counted', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'password' }, { id: 'b', kind: 'password', owner: true }])) === true);
	// A member slot's owner role must NOT satisfy the password-owner check (it is a separate credential class).
	ok('a member-owner is not a password-owner', ownerHasPasswordSlot(mf([{ id: 'm', kind: 'member', owner: true }])) === false);
	// Defensive: only strict boolean true counts, never a stray truthy value.
	ok('only a strict-true marker counts', ownerHasPasswordSlot(mf([{ id: 'a', kind: 'password', owner: 'yes' }])) === false);
}

// ---------------------------------------------------------------------------
// Part 2 — end-to-end governance paths + seal tamper (engine-gated)
// ---------------------------------------------------------------------------
let workspace = null;
async function part2() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping the end-to-end checks.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-lastowner-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'OWNED');
	const v = path.join(tmp, 'LO.vault');
	await vdisk.importFolder(v, { password: 'creator-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'creator-pw' });
	await vdisk.enableTeam(v, { password: 'creator-pw' });

	// The creator's passphrase slot carries the owner seed, so it is marked owner and counts authoritatively.
	{
		const mf = await mfOf(v);
		const ownerSlots = mf.crypt.keySlots.filter(s => s.kind !== 'member' && s.owner === true);
		ok('enableTeam marks the creator passphrase slot as owner', ownerSlots.length === 1);
		ok('the vault manifest is sealed at the current version', Number(mf.integrity.sealVersion) === Vault._bundleVersions.SEAL_VERSION);
		ok('the creator owner marker is covered by the manifest seal (genuine seal verifies)', Vault.checkManifestSeal(mf).ok === true);
	}

	// Add a plain read-write password. It is NOT an owner: the authoritative accounting must still report exactly one
	// owner (the creator), and this plain password must be refused when it attempts an owner-only action.
	await vdisk.addKey(v, { password: 'creator-pw', newPassword: 'plain-rw', label: 'Plain rw' });
	{
		const mf = await mfOf(v);
		ok('adding a plain read-write password does not create a second owner', Vault._governance.ownerHasPasswordSlot(mf) === true && mf.crypt.keySlots.filter(s => s.kind !== 'member' && s.owner === true).length === 1);
	}
	// A non-owner password cannot remove a key on a team vault (owner-only action).
	let plainRemoveRefused = false;
	try {
		const ownerSlotId = (await mfOf(v)).crypt.keySlots.find(s => s.owner === true).id;
		await vdisk.removeKey(v, { password: 'plain-rw', slotId: ownerSlotId });
	} catch (e) { plainRemoveRefused = /only an owner/i.test(e.message); }
	ok('a plain read-write password cannot remove a key on a team vault', plainRemoveRefused);
	// The owner cannot remove the very slot it unlocked with (never lock yourself out) — this also means the sole
	// owner passphrase slot can never be stripped through removeKey.
	let selfRemoveRefused = false;
	try {
		const ownerSlotId = (await mfOf(v)).crypt.keySlots.find(s => s.owner === true).id;
		await vdisk.removeKey(v, { password: 'creator-pw', slotId: ownerSlotId });
	} catch (e) { selfRemoveRefused = /different key|last owner/i.test(e.message); }
	ok('the owner cannot remove the slot it unlocked with', selfRemoveRefused);

	// Promote a member to owner, then demote them again. Because the creator remains a password-owner throughout, the
	// demote is allowed and never falsely refused — and the vault is never at risk of zero owners.
	const bob = vdisk.emergencyKeypair();
	const b = await vdisk.addMember(v, { password: 'creator-pw', memberPub: bob.publicKey, role: 'write', label: 'Bob' });
	await vdisk.setMemberOwner(v, { password: 'creator-pw', memberId: b.memberId, owner: true });
	ok('the promoted member is an owner', (await vdisk.listMembers(v)).members.find(m => m.memberId === b.memberId).owner === true);
	await vdisk.setMemberOwner(v, { password: 'creator-pw', memberId: b.memberId, owner: false });
	ok('the member can be demoted while the creator remains a password-owner (no false lockout refusal)', (await vdisk.listMembers(v)).members.find(m => m.memberId === b.memberId).owner === false);
	// The vault is still fully manageable by the owner afterward.
	const carol = vdisk.emergencyKeypair();
	ok('the vault is still manageable by the owner after the promote/demote cycle', await vdisk.addMember(v, { password: 'creator-pw', memberPub: carol.publicKey, role: 'read', label: 'Carol' }).then(() => true).catch(() => false));

	// Seal tamper: a folder-level attacker who forges or strips the owner marker (to fake an owner, or to defeat the
	// last-owner guard) must be caught by the manifest seal. Flip the marker directly on disk and confirm the seal
	// fails; restore it and confirm the seal verifies again (no false alarm).
	{
		const mf = await mfOf(v);
		ok('the genuine sealed manifest still verifies before tampering', Vault.checkManifestSeal(mf).ok === true);

		const stripped = JSON.parse(JSON.stringify(mf));
		delete stripped.crypt.keySlots.find(s => s.owner === true).owner;
		ok('stripping the owner marker breaks the manifest seal', Vault.checkManifestSeal(stripped).ok === false);

		const forged = JSON.parse(JSON.stringify(mf));
		const nonOwner = forged.crypt.keySlots.find(s => s.kind !== 'member' && !s.owner);
		if (nonOwner) { nonOwner.owner = true; ok('forging an owner marker onto a plain slot breaks the manifest seal', Vault.checkManifestSeal(forged).ok === false); }
		else ok('forging an owner marker onto a plain slot breaks the manifest seal', true);

		const promoted = JSON.parse(JSON.stringify(mf));
		promoted.crypt.keySlots.find(s => s.owner === true).kind = 'super';
		ok('promoting a slot kind breaks the manifest seal', Vault.checkManifestSeal(promoted).ok === false);

		// The untouched manifest is unaffected — no false tamper alarm on the genuine article.
		ok('the untouched manifest still verifies (no false alarm)', Vault.checkManifestSeal(mf).ok === true);
	}
}

async function main() {
	part1();
	await part2();
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LAST-OWNER-GUARD CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-lastowner-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
