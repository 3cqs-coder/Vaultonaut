'use strict';
// lib/test/kdfkat.js — a known-answer test (KAT) for the password key-derivation function. The vault's master key
// is wrapped by an Argon2id-derived key (lib/Kdf.js, via the hash-wasm dependency, whose exact version floats within
// its caret range because no lockfile is committed). If a future hash-wasm release ever changed Argon2id's output
// bytes for the same inputs — a bug, or an intentional change — every existing vault would stop unlocking, and every
// round-trip test would still pass because it wraps and unwraps with the same new code. This KAT fixes the derivation
// to a frozen expected value so any such change fails LOUDLY in CI instead of silently in the field, protecting the
// backward-compatibility promise that a 1.0.0 vault keeps opening.
//
// The parameters here are minimal (fast) and are NOT a shipped security preset — they exist only to pin the algorithm
// output cheaply. The frozen hex was computed once from the current, correct implementation.
//
// Run:  node lib/test/kdfkat.js

const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Frozen inputs and the expected 32-byte key. Change these ONLY with a deliberate, reviewed migration — a change to
// the expected value means the derivation output moved, which is exactly the regression this guard exists to catch.
const PARAMS = { algo: 'argon2id', v: 1, memKiB: 8, iterations: 1, parallelism: 1, hashLen: 32, salt: Buffer.from('vaultonaut-kat-salt-0001', 'utf8').toString('base64') };
const PASSPHRASE = 'correct horse battery staple';
const EXPECTED_HEX = '90093bb68a32bfd4b13f52399da611076b3a71a41721aa5af6183226b1ed57ba';

async function main() {
	const key = await Kdf.deriveKey(PASSPHRASE, PARAMS);
	ok('deriveKey returns a 32-byte Buffer', Buffer.isBuffer(key) && key.length === 32);
	ok('Argon2id derivation matches the frozen known answer (hash-wasm output is unchanged)', Buffer.from(key).toString('hex') === EXPECTED_HEX);

	// The derivation actually depends on its inputs (not a constant): a changed passphrase or salt yields a different
	// key. This keeps the KAT honest — a broken deriveKey that returned a fixed buffer would still fail above, and a
	// salt/passphrase that was silently ignored would fail here.
	const other = await Kdf.deriveKey(PASSPHRASE + '!', PARAMS);
	ok('a different passphrase derives a different key', Buffer.from(other).toString('hex') !== EXPECTED_HEX);
	const otherSalt = await Kdf.deriveKey(PASSPHRASE, { ...PARAMS, salt: Buffer.from('vaultonaut-kat-salt-0002', 'utf8').toString('base64') });
	ok('a different salt derives a different key', Buffer.from(otherSalt).toString('hex') !== EXPECTED_HEX);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KDF-KAT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
