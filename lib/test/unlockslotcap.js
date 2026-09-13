'use strict';
// lib/test/unlockslotcap.js — a passphrase credential must never be stranded behind a large team's member slots.
// An unlock attempt caps how many slots it tries (a hostile shared vault could otherwise list thousands to multiply
// the Argon2id cost into a DoS). Member slots are opened with a private key, not a passphrase, and cost no derivation,
// so they must be EXCLUDED before that cap — otherwise a big member set crowds out a passphrase credential (recovery
// key, extra password, keyfile, or inheritance threshold key) added after it, and that credential is silently never
// tried, permanently stranding it. This drives the real add-member / add-key / unlock path with more than the 64-slot
// passphrase cap in members, then confirms a password added AFTER them still opens the vault.
//
// Run:  node lib/test/unlockslotcap.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-slotcap-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'HELLO');
	const v = path.join(tmp, 'SlotCap.vault');
	await vdisk.importFolder(v, { password: 'owner-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'owner-pw' }); // a signed identity is required before enabling team access
	await vdisk.enableTeam(v, { password: 'owner-pw' });

	// Enroll MORE than the 64-slot passphrase cap in members, so a passphrase slot added afterward lands past it.
	const MEMBERS = 70;
	for (let i = 0; i < MEMBERS; i++) {
		const kp = vdisk.emergencyKeypair();
		await vdisk.addMember(v, { password: 'owner-pw', memberPub: kp.publicKey, role: 'read', label: 'M' + i });
	}
	const roster = await vdisk.listMembers(v);
	ok('the vault has more members than the passphrase slot cap', roster.members.length === MEMBERS && MEMBERS > 64);

	// Add an extra read-write password AFTER all the members (it is appended, so it sits past slot 64).
	await vdisk.addKey(v, { password: 'owner-pw', newPassword: 'recovery-pw', label: 'Recovery' });

	// The crux: the late-added password must still open the vault. Before the fix (member slots counted toward the
	// 64-slot cap), this password sat past the cap and was never tried — verify would report the password as wrong.
	ok('a password added after 64+ members still unlocks the vault', (await vdisk.verify(v, { password: 'recovery-pw', deep: false })).password === 'ok');
	// The original owner password (slot 0) still works too.
	ok('the original owner password still unlocks the vault', (await vdisk.verify(v, { password: 'owner-pw', deep: false })).password === 'ok');
	// A genuinely wrong password is still rejected (the cap change did not weaken rejection). verify throws a
	// wrong-password error rather than returning a result, so assert the throw.
	let wrongRejected = false;
	try { await vdisk.verify(v, { password: 'nope-wrong', deep: false }); } catch (e) { wrongRejected = !!(e && e.wrongPassword); }
	ok('a wrong password is still rejected', wrongRejected);

	// Source guard: both unlock paths must FILTER by slot kind BEFORE applying their cap, so neither kind can crowd
	// out the other. Pins the fix against a regression that reintroduces slice-before-filter.
	const src2 = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	// The caps are single-sourced as named constants (MAX_PASSPHRASE_SLOTS / MAX_MEMBER_SLOTS), used by BOTH the unlock
	// loops and the enrollment guards so the two can never drift (keyslotformatdrift.js pins that binding). Match the
	// filter-then-slice by the named constant rather than a literal number.
	ok('the passphrase unlock filters out member slots before the cap', /filter\(s => s\.kind !== 'member'\)\.slice\(0, MAX_PASSPHRASE_SLOTS\)/.test(src2));
	ok('the member unlock filters to member slots before the cap', /filter\(s => s\.kind === 'member'\)\.slice\(0, MAX_MEMBER_SLOTS\)/.test(src2));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UNLOCK-SLOT-CAP CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if (kv.includes('vdisk-slotcap-')) await vdisk.removeKnownVault(kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
