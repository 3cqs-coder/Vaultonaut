'use strict';
// lib/test/pqsign.js — the post-quantum companion signature. Vaultonaut signs every baseline, seal, and recovery
// index with BOTH Ed25519 (classical) and ML-DSA-65 (FIPS 204, post-quantum), an AND-signature: a record is authentic
// only if both verify, so it stays trustworthy as long as EITHER scheme is unbroken. The ML-DSA key is derived
// DETERMINISTICALLY from the same write seed as the Ed25519 key, so the write-cap alone reproduces both and no extra
// key material is stored. This pins that contract: derivation is deterministic and seed-bound, sign/verify roundtrips,
// a wrong key or tampered payload is rejected, and the whole thing runs on native OpenSSL (no dependency, no worker).
// Pure — no engine, no browser.
//
// Run:  node lib/test/pqsign.js

const crypto = require('crypto');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const seed = crypto.randomBytes(32).toString('base64');
const other = crypto.randomBytes(32).toString('base64');

// --- derivation: deterministic, seed-bound, and independent of the Ed25519 key ---
const a = Integrity.signKeysFromSeed(seed);
const b = Integrity.signKeysFromSeed(seed);
ok('the ML-DSA public key derives deterministically from the write seed', typeof a.pqPub === 'string' && a.pqPub.length > 0 && a.pqPub === b.pqPub);
ok('a different seed yields a different ML-DSA key', Integrity.signKeysFromSeed(other).pqPub !== a.pqPub);
ok('the ML-DSA public key is distinct from the Ed25519 public key', a.pqPub !== a.pub);
ok('the Ed25519 public key is still the 32-byte hex it always was', /^[0-9a-f]{64}$/.test(a.pub));

// --- sign / verify roundtrip (AND-combiner building blocks) ---
const msg = 'vault-manifest-seal-v4\nroot\n7\nprev\n42\n2026-09-13';
const edSig = Integrity.sign(a.priv, msg);
const pqSig = Integrity.signPq(a.pqPriv, msg);
ok('Ed25519 signature verifies', Integrity.verify(a.pub, msg, edSig));
ok('ML-DSA signature verifies against the derived public key', Integrity.verifyPq(a.pqPub, msg, pqSig));
ok('the write-cap re-derives the same ML-DSA key and verifies (no stored key needed)', Integrity.verifyPq(b.pqPub, msg, pqSig));

// --- rejection: wrong key, tampered payload, malformed input all fail closed ---
ok('ML-DSA verify rejects a signature from a different key', !Integrity.verifyPq(Integrity.signKeysFromSeed(other).pqPub, msg, pqSig));
ok('ML-DSA verify rejects a tampered payload', !Integrity.verifyPq(a.pqPub, msg + 'x', pqSig));
ok('ML-DSA verify fails closed on a null/garbage public key', !Integrity.verifyPq(null, msg, pqSig) && !Integrity.verifyPq('not-base64!!', msg, pqSig));
ok('ML-DSA verify fails closed on a null/garbage signature', !Integrity.verifyPq(a.pqPub, msg, null) && !Integrity.verifyPq(a.pqPub, msg, 'xyz'));

// --- an AND-combiner: a full hybrid check passes only when BOTH sides verify ---
const bothOk = Integrity.verify(a.pub, msg, edSig) && Integrity.verifyPq(a.pqPub, msg, pqSig);
ok('the hybrid AND-check passes when both signatures are valid', bothOk === true);
const strippedPq = Integrity.verify(a.pub, msg, edSig) && Integrity.verifyPq(a.pqPub, msg, 'AAAA');
ok('the hybrid AND-check fails if the post-quantum half is stripped or forged', strippedPq === false);

// --- the shared signHybrid/verifyHybrid helpers (the single choke point every signed artifact routes through) ---
const h = Integrity.signHybrid(a.priv, a.pqPriv, msg);
ok('signHybrid produces both signatures over the same input', h.sig === edSig && Integrity.verifyPq(a.pqPub, msg, h.sigPq));
ok('verifyHybrid accepts a genuine pair', Integrity.verifyHybrid(a.pub, a.pqPub, msg, h.sig, h.sigPq) === true);
ok('verifyHybrid rejects a stripped post-quantum half', Integrity.verifyHybrid(a.pub, a.pqPub, msg, h.sig, null) === false);
ok('verifyHybrid rejects a stripped classical half', Integrity.verifyHybrid(a.pub, a.pqPub, msg, null, h.sigPq) === false);
ok('verifyHybrid rejects a tampered payload', Integrity.verifyHybrid(a.pub, a.pqPub, msg + '!', h.sig, h.sigPq) === false);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PQ-SIGN CHECKS PASSED'));
process.exit(failures ? 1 : 0);
