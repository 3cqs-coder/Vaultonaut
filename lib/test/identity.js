'use strict';
// lib/test/identity.js — a vault's authenticity anchors. The IDENTITY (a fingerprint of the write‑authority
// public key) is stable across edits and password changes and differs between vaults, so a user can verify
// "this is the genuine vault, not a hacker's recreation." The rollback ledger also enforces hash‑chain
// CONTINUITY: a baseline that advances the version by one must chain to the prior root (prevRoot), so a hidden
// or rewritten intermediate baseline is caught. Needs the bundled engine only for the vault parts.
//
// Run:  node lib/test/identity.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	// --- Chain-continuity (unit; no engine needed) ---
	const vid = crypto.randomBytes(16).toString('hex'); // a throwaway vault id so we don't touch a real one
	const R5 = 'a'.repeat(64), R6 = 'b'.repeat(64), R7 = 'c'.repeat(64);
	ok('first sighting of a vault is accepted', (await Integrity.observe(vid, 5, R5, null)).status === 'ok');
	ok('a consecutive baseline that chains (prevRoot === last root) is accepted', (await Integrity.observe(vid, 6, R6, R5)).status === 'ok');
	ok('a consecutive baseline with the WRONG prevRoot is a chain-break', (await Integrity.observe(vid, 7, R7, 'd'.repeat(64))).status === 'chain-break');
	// A multi-machine GAP (seq jumps by >1) must NOT false-positive as a break (its prevRoot was never recorded here).
	const vid2 = crypto.randomBytes(16).toString('hex');
	await Integrity.observe(vid2, 3, R5, null);
	ok('a version gap (seq jumps by >1) is advisory, not a chain-break', (await Integrity.observe(vid2, 8, R6, 'e'.repeat(64))).status === 'ok');

	// --- Stable identity (needs the engine) ---
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the vault-identity checks.'); }
	else {
		const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-identity-')); workspace = tmp;
		const src = path.join(tmp, 'src'); await fsp.mkdir(src);
		await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(2048));
		const v = path.join(tmp, 'A.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
		await vdisk.snapshot(v, { password: 'pw1' }); // establishes the baseline + the published public key
		const id1 = (await vdisk.fingerprint(v)).identity;
		ok('a vault has a stable identity once it has a baseline', !!id1);

		// A password change re-wraps the master but never changes the key it derives — identity must be unchanged.
		await vdisk.changePassword(v, { oldPassword: 'pw1', newPassword: 'pw2' });
		ok('the identity is unchanged by a password change', (await vdisk.fingerprint(v)).identity === id1);
		// A new snapshot changes the CONTENT fingerprint but not the identity.
		await vdisk.snapshot(v, { password: 'pw2' });
		ok('the identity is unchanged by taking another snapshot', (await vdisk.fingerprint(v)).identity === id1);

		// A DIFFERENT vault has a DIFFERENT identity (a hacker's recreation can't reproduce it).
		const v2 = path.join(tmp, 'B.vault'); await vdisk.importFolder(v2, { password: 'pw1', sourceDir: src });
		await vdisk.snapshot(v2, { password: 'pw1' });
		ok('a different vault has a different identity', (await vdisk.fingerprint(v2)).identity !== id1);

		await vdisk.removeKnownVault(v).catch(() => {}); await vdisk.removeKnownVault(v2).catch(() => {});
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL IDENTITY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-identity-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
