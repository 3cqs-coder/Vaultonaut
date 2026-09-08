'use strict';
// lib/test/slotepochrefuse.js — the REFUSAL half of the key-slot cross-machine compare-and-swap. slotepoch.js
// proves the epoch bumps; this proves the guard actually refuses a write when the on-disk epoch moved between the
// mutator's read and its write — the case a second machine editing the same shared-drive vault creates, which
// without the CAS would silently clobber one machine's key change.
//
// A same-process test cannot truly interleave two writers (the vault lock serializes them), so the concurrent
// bump is injected the way the lease-fence test injects a stolen lease: wrap Common.readFileCapped and, on the
// SECOND read of the manifest (the assertSlotEpoch re-read — the first is the mutator's own initial read), return a
// copy whose crypt.slotEpoch is higher, as if another machine had written in between. Only the returned bytes are
// changed, never the file, so the vault is left intact. The assertion is self-validating: it passes only if the
// operation actually rejected and left the slots untouched.
//
// Run:  node lib/test/slotepochrefuse.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function opens(v, pw) { return Vault.assertReadable(v, pw).then(() => true, () => false); }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-slotrefuse-')); workspace = tmp;
	const v = path.join(tmp, 'R.vault');
	await vdisk.create(v, { password: 'pw' });
	await vdisk.addKey(v, { password: 'pw', newPassword: 'pw2', label: 'Second' }); // slotEpoch -> 1

	// Arm the injection: on the SECOND manifest read during the next op (the assertSlotEpoch re-read), hand back a
	// copy with a higher slotEpoch, simulating another machine's concurrent write. The file itself is untouched.
	const realRFC = Common.readFileCapped;
	let manifestReads = 0, armed = false;
	Common.readFileCapped = async function (p, max, enc) {
		const txt = await realRFC(p, max, enc);
		if (armed && String(p).endsWith('vault.json')) {
			manifestReads++;
			if (manifestReads >= 2) { try { const m = JSON.parse(txt); m.crypt.slotEpoch = (Number(m.crypt.slotEpoch) || 0) + 5; return JSON.stringify(m); } catch (_) {} }
		}
		return txt;
	};

	let refused = false;
	try {
		armed = true;
		await vdisk.changePassword(v, { oldPassword: 'pw', newPassword: 'pw-NEW' });
	} catch (e) { refused = /at the same time|Reload the vault/i.test(e && e.message || ''); }
	finally { armed = false; Common.readFileCapped = realRFC; }

	ok('a slot change is REFUSED when the on-disk slot epoch moved mid-operation', refused);
	// The refusal must have left the slots exactly as they were: the original password still opens the vault, and
	// the would-be new password does not.
	ok('the original password still opens the vault (the change did not persist)', await opens(v, 'pw'));
	ok('the would-be new password does not open the vault', !(await opens(v, 'pw-NEW')));
	// And a normal change with no interference still succeeds (the guard is not stuck on).
	await vdisk.changePassword(v, { oldPassword: 'pw', newPassword: 'pw-OK' });
	ok('a normal slot change still succeeds once the interference is gone', (await opens(v, 'pw-OK')) && !(await opens(v, 'pw')));

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SLOT-EPOCH-REFUSE CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
