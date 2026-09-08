'use strict';
// lib/test/recoveryanchor.js — the self-heal rollback anchor's reset behavior. The anchor (recoverySigned[vaultId]
// in the local ledger) advances monotonically so a stripped/older recovery-index signature is caught as a
// downgrade. But when recovery data is LEGITIMATELY destroyed with write authority (an explicit unprotect, or a key
// rotation that invalidates the old-key parity), a later re-protect restarts the index at version 1 — so the anchor
// MUST be reset, or heal (and scheduled auto-heal) would falsely refuse the fresh data as a downgrade and silently
// stop repairing after a benign action. This locks clearRecoverySigned: it resets the anchor, is a safe no-op when
// none is set, and never disturbs a DIFFERENT vault's anchor. Runs against the isolated .test-data ledger.
//
// Run:  node -r ./lib/test/_setup.js lib/test/recoveryanchor.js

const crypto = require('crypto');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const vid = () => crypto.randomBytes(16).toString('hex');

async function main() {
	const a = vid(), b = vid();

	// Advances monotonically as the index is (re-)signed.
	await Integrity.noteRecoverySigned(a, 1);
	await Integrity.noteRecoverySigned(a, 4);
	await Integrity.noteRecoverySigned(a, 2); // a lower version never moves it backward
	ok('anchor advances monotonically to the highest signed version', (await Integrity.recoverySignedVersion(a)) === 4);

	// A second vault's anchor is independent.
	await Integrity.noteRecoverySigned(b, 7);

	// clearRecoverySigned resets ONLY the named vault's anchor (models a credentialed unprotect / rekey).
	await Integrity.clearRecoverySigned(a);
	ok('clearRecoverySigned resets the anchor to zero', (await Integrity.recoverySignedVersion(a)) === 0);
	ok('clearRecoverySigned leaves a different vault untouched', (await Integrity.recoverySignedVersion(b)) === 7);

	// After the reset, a fresh re-protect that starts at version 1 is NOT below the anchor, so heal's downgrade gate
	// (expectedVer > 0 && ...) would not falsely refuse it: the anchor is 0 until the rebuilt data is signed again.
	ok('a re-protect at version 1 is not a downgrade after a reset (anchor 0)', (await Integrity.recoverySignedVersion(a)) === 0);
	await Integrity.noteRecoverySigned(a, 1); // the signed rebuild re-anchors from the new baseline
	ok('the signed rebuild re-anchors from the new baseline', (await Integrity.recoverySignedVersion(a)) === 1);

	// Clearing an anchor that was never set is a safe no-op.
	let threw = false;
	try { await Integrity.clearRecoverySigned(vid()); } catch (_) { threw = true; }
	ok('clearRecoverySigned on an unknown vault is a safe no-op', !threw);
	// A null id is tolerated (best-effort call sites pass whatever vaultId() returns).
	try { await Integrity.clearRecoverySigned(null); } catch (_) { failures++; }
	ok('clearRecoverySigned tolerates a null id', true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-ANCHOR CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
