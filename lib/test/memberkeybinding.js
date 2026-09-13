'use strict';
// lib/test/memberkeybinding.js — a team member's stored public key (`pub`) is what an owner mutation re-seals fresh
// capabilities to during a rotation or a promotion. The owner-signed roster binds each member only through its key
// FINGERPRINT (`pubFp`), not the raw key, so two guards must protect every re-seal: the roster signature must verify
// first (so the fingerprints are authentic), and each stored pub must still match its signed fingerprint. Without them,
// a party with write access to the vault folder could swap a member's `pub` for their own key and have the next owner
// action seal live access to it. This drives the real add-member path, then simulates both folder-level tampers and
// confirms the owner mutation is refused.
//
// Run:  node lib/test/memberkeybinding.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const mfOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
const writeMf = async (v, m) => { const s = JSON.stringify(m); await fsp.writeFile(path.join(v, 'vault.json'), s); await fsp.writeFile(path.join(v, '.vault.bak'), s); };
// Byte-identical to Vault.memberFingerprint (internal), so a tamper can compute a matching fingerprint the way an attacker would.
const fpOf = (pub) => Integrity.identity(crypto.createHash('sha256').update(String(pub)).digest('hex'));

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-memberkey-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'TEAM');
	const v = path.join(tmp, 'MK.vault');
	await vdisk.importFolder(v, { password: 'owner-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'owner-pw' });
	await vdisk.enableTeam(v, { password: 'owner-pw' });
	const bob = vdisk.emergencyKeypair();
	const b = await vdisk.addMember(v, { password: 'owner-pw', memberPub: bob.publicKey, role: 'write', label: 'Bob' });
	ok('the roster is valid after adding a member', (await vdisk.listMembers(v)).rosterValid === true);

	const clean = await mfOf(v); // a pristine, correctly-signed snapshot to restore between attacks
	const attacker = vdisk.emergencyKeypair();

	// --- Attack A: swap ONLY the member's pub (leave the signed pubFp). The roster still verifies (pub is not in the
	// signed bytes), so this slips past the signature check — but the pub no longer matches its fingerprint, and the
	// key-binding guard must refuse the owner mutation before sealing anything to the attacker's key. ---
	{
		const m = JSON.parse(JSON.stringify(clean));
		const slot = m.crypt.keySlots.find(s => s.kind === 'member');
		slot.pub = attacker.publicKey; // pubFp left as Bob's
		await writeMf(v, m);
		ok('the roster still verifies after a pub-only swap (the gap this guard closes)', (await vdisk.listMembers(v)).rosterValid === true);
		let refused = false;
		try { await vdisk.setMemberOwner(v, { password: 'owner-pw', memberId: b.memberId, owner: true }); }
		catch (e) { refused = /fingerprint|tamper/i.test(e.message); }
		ok('promoting a member whose pub was swapped is REFUSED (key-binding guard)', refused);
	}

	// --- Attack B: swap BOTH pub and pubFp to the attacker's (a consistent pair). Now the pub matches its fingerprint,
	// but that fingerprint was never signed by the owner, so the roster signature no longer verifies — the roster-
	// authenticity guard must refuse the owner mutation. ---
	{
		const m = JSON.parse(JSON.stringify(clean));
		const slot = m.crypt.keySlots.find(s => s.kind === 'member');
		slot.pub = attacker.publicKey; slot.pubFp = fpOf(attacker.publicKey);
		await writeMf(v, m);
		ok('the roster FAILS its signature after a pub+pubFp swap', (await vdisk.listMembers(v)).rosterValid === false);
		let refused = false;
		try { await vdisk.setMemberOwner(v, { password: 'owner-pw', memberId: b.memberId, owner: true }); }
		catch (e) { refused = /roster|signature|altered|tamper/i.test(e.message); }
		ok('an owner mutation on a forged roster is REFUSED (roster-authenticity guard)', refused);
	}

	// --- Control: restore the pristine roster and confirm a legitimate promotion still works (no false refusal). ---
	{
		await writeMf(v, clean);
		ok('the restored roster verifies again', (await vdisk.listMembers(v)).rosterValid === true);
		await vdisk.setMemberOwner(v, { password: 'owner-pw', memberId: b.memberId, owner: true });
		ok('a legitimate promotion succeeds on an authentic roster', (await vdisk.listMembers(v)).members.find(mm => mm.memberId === b.memberId).owner === true);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MEMBER-KEY-BINDING CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-memberkey-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
