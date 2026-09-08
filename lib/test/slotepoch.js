'use strict';
// lib/test/slotepoch.js — passphrase-family key-slot changes carry a cross-machine compare-and-swap, the analogue
// of the membership roster epoch. The per-machine vault lock serializes writers on ONE machine, but a vault on a
// shared or removable drive can be opened from two machines with independent locks; without a backstop, two
// concurrent slot edits could each build a manifest from the same starting slots and the second would silently
// clobber the first's key change. Each add / change-password / remove now bumps a monotonic crypt.slotEpoch and
// re-reads the on-disk manifest right before writing, refusing if the epoch moved.
//
// This pins the mechanism (each slot change bumps the epoch, and the credentials still work afterward) and the
// two invariants a refactor must not break: every slot mutator routes through the CAS, and the epoch stays OUT of
// the signed seal input so an existing vault's seal never reads as tampered. (A true refusal interleave is
// single-thread-unreachable here — the module's internal readManifest can't be intercepted from outside — the same
// reason the roster-epoch guard is tested by its bump, not its refusal.)
//
// Run:  node lib/test/slotepoch.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function opens(v, pw) { return Vault.assertReadable(v, pw).then(() => true, () => false); }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-slotepoch-')); workspace = tmp;
	const v = path.join(tmp, 'Slot.vault');
	await vdisk.create(v, { password: 'pw' });
	const epochOf = () => Number((JSON.parse(fs.readFileSync(path.join(v, 'vault.json'), 'utf8')).crypt || {}).slotEpoch) || 0;

	// --- the epoch advances by exactly one on each kind of slot change, and the vault stays openable ---
	const e0 = epochOf();
	await vdisk.addKey(v, { password: 'pw', newPassword: 'pw2', label: 'Second' });
	ok('adding a key bumps the slot epoch by one', epochOf() === e0 + 1);
	ok('both keys open the vault after the add', (await opens(v, 'pw')) && (await opens(v, 'pw2')));

	const e1 = epochOf();
	await vdisk.changePassword(v, { oldPassword: 'pw2', newPassword: 'pw3' });
	ok('changing a password bumps the slot epoch by one', epochOf() === e1 + 1);
	ok('the changed password opens the vault and the old one does not', (await opens(v, 'pw3')) && !(await opens(v, 'pw2')));

	const e2 = epochOf();
	const keys = await vdisk.listKeys(v); // slots[0] is the original 'pw' slot; remove it while unlocking with the other key
	await vdisk.removeKey(v, { password: 'pw3', slotId: keys.slots[0].id });
	ok('removing a key bumps the slot epoch by one', epochOf() === e2 + 1);
	ok('the removed key no longer opens the vault, the kept one still does', !(await opens(v, 'pw')) && (await opens(v, 'pw3')));

	// --- invariants a refactor must preserve ---
	const vault = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	for (const fn of ['changePassword', 'addKeyInternal', 'removeKey']) {
		const at = vault.indexOf('function ' + fn + '(');
		const body = at >= 0 ? vault.slice(at, at + 2500) : '';
		ok(fn + ' persists its slot change through the CAS helper', /persistSlotChange\(/.test(body));
	}
	ok('persistSlotChange runs the epoch CAS before persisting', /assertManifestEpochs\(abs, manifest\)[\s\S]{0,120}persistManifest\(/.test(vault));
	// The CAS guards BOTH counters, so a key-slot change and a membership change racing across machines cannot
	// clobber each other by carrying the other's now-stale section forward in the whole-manifest write.
	const casFn = (vault.match(/function assertManifestEpochs\([\s\S]*?\n\}/) || [''])[0];
	ok('the manifest CAS checks the slot epoch', !!casFn && /slotOf\(cur\) !== slotOf\(manifest\)/.test(casFn));
	ok('the manifest CAS also checks the roster epoch (cross-class protection)', !!casFn && /rosterOf\(cur\) !== rosterOf\(manifest\)/.test(casFn));
	const commitAt = vault.indexOf('async function commitMembership(');
	ok('commitMembership runs the same whole-manifest CAS', commitAt >= 0 && /assertManifestEpochs\(abs, manifest\)[\s\S]{0,120}persistManifest\(/.test(vault.slice(commitAt, commitAt + 900)));
	// The epoch must NOT be part of the signed seal input, or every existing vault's seal would read as tampered.
	const sealFn = (vault.match(/function manifestSealInput\([\s\S]*?\n\}/) || [''])[0];
	ok('the slot epoch is kept out of the signed manifest seal input (existing seals stay valid)', !!sealFn && !/slotEpoch/.test(sealFn));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SLOT-EPOCH CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-slotepoch-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
