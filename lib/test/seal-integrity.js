'use strict';
// lib/test/seal-integrity.js — the SEAL state (and the deep flag) must be bound to the baseline signature.
// A read-only credential holder (a read-only password or a read link) can decrypt and re-encrypt the vault's
// blobs and recompute the HMAC, but cannot produce the Ed25519 signature — that needs the write key. Before
// this fix the signature did not cover `sealed`, so such a holder could flip a vault from sealed to unsealed
// and the record still verified, silently defeating the tripwire, undetectable even to the owner. From
// baseline version 4 the seal state and deep flag are part of the signed input (Integrity.signingInput), so
// any change to them — or a version downgrade to dodge the binding — breaks verification. This proves that
// property directly against the write keypair, and confirms v3 records still verify (backward compatible).
// Needs no engine.
//
// Run:  node lib/test/seal-integrity.js

const crypto = require('crypto');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const seed = crypto.randomBytes(32).toString('base64');
	const { priv, pub } = Integrity.signKeysFromSeed(seed);
	const base = { scheme: Integrity.SCHEME, root: 'a'.repeat(64), seq: 3, prevRoot: 'b'.repeat(64), count: 5, createdAt: '2026-01-02T03:04:05.000Z' };

	// A version-4 SEALED, DEEP baseline as writeSnapshot would sign it.
	const v4 = { ...base, version: 4, sealed: true, deep: true };
	const sig4 = Integrity.sign(priv, Integrity.signingInput(v4));
	ok('a v4 sealed/deep signature verifies against its own input', Integrity.verify(pub, Integrity.signingInput(v4), sig4));

	// The attack: a read-key holder flips a bound flag but cannot re-sign. Verification must fail.
	ok('stripping the seal (sealed:true->false) breaks the v4 signature', !Integrity.verify(pub, Integrity.signingInput({ ...v4, sealed: false }), sig4));
	ok('downgrading the deep flag (deep:true->false) breaks the v4 signature', !Integrity.verify(pub, Integrity.signingInput({ ...v4, deep: false }), sig4));

	// Dodging the binding by claiming the record is v3 must also fail, because the signature was made over the
	// v4 input (which includes the flags) — the v3 input differs, so it will not verify.
	ok('downgrading the version to v3 to dodge the binding breaks the signature', !Integrity.verify(pub, Integrity.signingInput({ ...v4, version: 3 }), sig4));

	// Backward compatibility: an existing v3 baseline still verifies. (v3 deliberately does NOT bind the seal —
	// that is exactly the gap v4 closes — so a v3 record upgrades to v4 the next time it is (re)written.)
	const v3 = { ...base, version: 3, sealed: true, deep: true };
	const sig3 = Integrity.sign(priv, Integrity.signingInput(v3));
	ok('a legacy v3 signature still verifies (no false tamper after upgrade)', Integrity.verify(pub, Integrity.signingInput(v3), sig3));
	ok('v3 does not bind the seal (documents why v4 is needed)', Integrity.verify(pub, Integrity.signingInput({ ...v3, sealed: false }), sig3));

	// A wrong key must never verify a genuine signature (sanity on the primitive itself).
	const other = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	ok('a different key does not verify the signature', !Integrity.verify(other.pub, Integrity.signingInput(v4), sig4));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SEAL-INTEGRITY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
