'use strict';
// lib/test/integritykat.js — a KNOWN-ANSWER (golden-vector) test for the deterministic key/identity derivation. The
// Ed25519 and ML-DSA signing keys, the read key, and the human identity are all derived from a write seed through
// fixed constants: the PKCS8 / ML-DSA-seed DER prefixes, the HKDF info strings ('vdisk-mldsa-sign-v1',
// 'vdisk-read-key-v1'), and the identity domain ('vault-identity-v1'). Every other crypto test is a round-trip or a
// cross-implementation parity check, so a silent edit to any of these constants would still pass them (it would just
// change every derived value in lockstep) — while breaking every EXISTING vault: its baseline and identity would read
// TAMPERED and its slots would no longer unlock. This test freezes a fixed seed to its exact derived outputs, so any
// such change fails immediately and must be made here on purpose. A wrong constant fails closed (a mismatch, never a
// forgery), so this guards compatibility and false-tamper, not confidentiality.
//
// Run:  node lib/test/integritykat.js

const crypto = require('crypto');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Fixed, deterministic inputs (not secret — a test vector).
const SEED = Buffer.alloc(32, 7).toString('base64');
const SALT = Buffer.alloc(16, 3).toString('base64');

// Golden outputs, committed. If a derivation constant changes these must be updated ON PURPOSE (and every existing
// vault would then need re-derivation), which is exactly the deliberate step this test forces.
const GOLD = {
	pub: 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c',
	pqPubSha256: '0dd6771fb3d7cb390e94a7c9a39b2c4c2337c617fe3fa5b377c20b682649fa98',
	pqPubLen: 2632,
	readKey: 'BD1SVtpnIRahUO7xNf4hoPxjGgyBsMKSqAa2/6FoUsM=',
	identity: 'BPK8-9H5V-4B0V-22ZX-TW61-9VVX-MW',
};

const k = Integrity.signKeysFromSeed(SEED);
ok('the Ed25519 public key matches the golden vector (PKCS8 prefix + seed derivation unchanged)', k.pub === GOLD.pub);
ok('the ML-DSA public key matches the golden vector (ML-DSA seed prefix + HKDF info unchanged)', k.pqPub.length === GOLD.pqPubLen && crypto.createHash('sha256').update(k.pqPub).digest('hex') === GOLD.pqPubSha256);
ok('the read key matches the golden vector (read-key HKDF domain + salt binding unchanged)', Integrity.readKeyFromSeed(SEED, SALT) === GOLD.readKey);
ok('the human identity matches the golden vector (identity domain unchanged)', Integrity.identity(k.pub) === GOLD.identity);

// Determinism sanity: a second derivation from the same seed yields the same values (the vectors are reproducible).
const k2 = Integrity.signKeysFromSeed(SEED);
ok('derivation is deterministic (same seed -> same keys)', k2.pub === k.pub && k2.pqPub === k.pqPub);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL INTEGRITY-KAT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
