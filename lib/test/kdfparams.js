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

	// The cost bounds are DERIVED from the shipped LEVELS (single-sourced) so the validator can never drift from the
	// presets it bounds: a vault may present at most the strongest preset's cost, never more. This pins that a set
	// just past the strongest preset (iterations 5 / parallelism 5, both above the 4/4 ceiling) is refused, closing an
	// earlier gap where the bound (iterations up to 6, parallelism up to 8) was looser than the code comment claimed.
	ok('the cost bounds equal the strongest shipped level (no drift)', Kdf.KDF_MAX.memKiB === 524288 && Kdf.KDF_MAX.iterations === 4 && Kdf.KDF_MAX.parallelism === 4);
	ok('iterations above the strongest preset are refused', await refused({ ...base, iterations: 5 }) && await refused({ ...base, iterations: 6 }));
	ok('parallelism above the strongest preset is refused', await refused({ ...base, memKiB: 64, parallelism: 5 }) && await refused({ ...base, memKiB: 64, parallelism: 8 }));
	ok('the strongest shipped level (max) is still accepted', (await Kdf.deriveKey('pw', Kdf.defaultParams('max'))).length === 32);

	// The salt must DECODE to at least a few bytes. Buffer.from(x, 'base64') silently drops non-base64 characters, so a
	// hostile/corrupt manifest could otherwise present a salt that decodes to zero or a couple of bytes; that must be
	// refused HERE (deterministically, coded KDF_PARAMS) rather than fail-closing later through the worker fallback.
	ok('an empty salt is refused (decodes to 0 bytes)', await refused({ ...base, salt: '' }));
	ok('a too-short salt is refused (3 decoded bytes, under the 8-byte floor)', await refused({ ...base, salt: 'AAAA' }));
	ok('a non-base64-junk salt is refused (its characters drop to 0 bytes)', await refused({ ...base, salt: '!!!!' }));
	ok('a genuine salt of at least 8 bytes is accepted', (await Kdf.deriveKey('pw', { ...base, salt: Buffer.alloc(8).toString('base64') })).length === 32);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KDF-PARAM CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
