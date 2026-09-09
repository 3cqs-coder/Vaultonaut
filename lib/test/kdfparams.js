'use strict';
// lib/test/kdfparams.js — the KDF parameters travel INSIDE a shareable vault, so they are UNTRUSTED and are bounded
// tightly before they reach the hasher. This pins two consistency rules the bounds must enforce, so a self-
// inconsistent set fails with the module's clean "refused" message instead of a raw crypto/hasher error deep inside:
//   - hashLen is pinned to 32, the only length AES-256-GCM (wrapSecret/unwrapSecret) can consume;
//   - memKiB must be at least 8x parallelism, which Argon2 itself requires.
// The refusal cases throw before the hasher runs, so they are fast; one tiny valid set confirms a good set still works.
//
// Run:  node lib/test/kdfparams.js

const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const base = { algo: 'argon2id', v: 1, memKiB: 64, iterations: 1, parallelism: 1, hashLen: 32, salt: Buffer.alloc(16).toString('base64') };
async function refused(params) {
	try { await Kdf.deriveKey('pw', params); return false; }
	catch (e) { return /invalid or out-of-range password-protection parameters/.test(e.message); }
}

async function main() {
	ok('a valid minimal parameter set derives a 32-byte key', (await Kdf.deriveKey('pw', base)).length === 32);
	ok('every shipped level passes validation and derives', (await Kdf.deriveKey('pw', Kdf.defaultParams('standard'))).length === 32);

	ok('hashLen other than 32 is refused (AES-256-GCM needs a 32-byte key)', await refused({ ...base, hashLen: 16 }) && await refused({ ...base, hashLen: 64 }));
	ok('memKiB below 8x parallelism is refused (Argon2 requires m >= 8p)', await refused({ ...base, memKiB: 16, parallelism: 4 }));
	ok('a consistent memKiB/parallelism pair is accepted', (await Kdf.deriveKey('pw', { ...base, memKiB: 32, parallelism: 4 })).length === 32);
	ok('an out-of-range memKiB is still refused', await refused({ ...base, memKiB: 4 }));
	ok('an out-of-range parallelism is still refused', await refused({ ...base, memKiB: 64, parallelism: 99 }));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KDF-PARAM CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
