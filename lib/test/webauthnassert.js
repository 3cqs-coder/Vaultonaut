'use strict';
// lib/test/webauthnassert.js — the server-side WebAuthn assertion verifier (lib/WebAuthn.js) that backs the strong,
// replay-resistant passwordless web sign-in. Generates real keys, crafts a spec-shaped assertion, and checks that a
// genuine one verifies for ES256 / RS256 / EdDSA, while every tampered field (challenge, origin, RP id, signature,
// flags, counter, type, algorithm) fails closed. Pure and fast — Node crypto only, no engine, no network.
//
// Run:  node lib/test/webauthnassert.js

const crypto = require('crypto');
const WebAuthn = require('../WebAuthn');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const rpId = '127.0.0.1';
const origin = 'http://127.0.0.1:7420';
const challenge = crypto.randomBytes(32).toString('base64url');

// authenticatorData: SHA-256(rpId) || flags || signCount(4 BE). flags 0x05 = user present (0x01) + user verified (0x04).
function authData(rp, flags, count) {
	const b = Buffer.alloc(37);
	crypto.createHash('sha256').update(rp).digest().copy(b, 0);
	b[32] = flags; b.writeUInt32BE(count, 33);
	return b;
}
function clientData(type, chal, orig) { return Buffer.from(JSON.stringify({ type, challenge: chal, origin: orig, crossOrigin: false }), 'utf8'); }
function signedBytes(ad, cd) { return Buffer.concat([ad, crypto.createHash('sha256').update(cd).digest()]); }
const u = (b) => Buffer.from(b).toString('base64url');

// --- ES256 (the common platform-authenticator algorithm) ---
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ecSpki = ec.publicKey.export({ format: 'der', type: 'spki' });
const ad = authData(rpId, 0x05, 1);
const cd = clientData('webauthn.get', challenge, origin);
const ecSig = crypto.sign('sha256', signedBytes(ad, cd), { key: ec.privateKey, dsaEncoding: 'der' });
const base = { pubKeySpki: u(ecSpki), alg: -7, authenticatorData: u(ad), clientDataJSON: u(cd), signature: u(ecSig), expectedChallenge: challenge, expectedOrigin: origin, expectedRpId: rpId, prevSignCount: 0 };

const good = WebAuthn.verifyAssertion(base);
ok('a valid ES256 assertion verifies', good.ok === true);
ok('it returns the authenticator signature counter', good.signCount === 1);

ok('a wrong challenge fails closed', WebAuthn.verifyAssertion({ ...base, expectedChallenge: crypto.randomBytes(32).toString('base64url') }).ok === false);
ok('a wrong origin fails closed', WebAuthn.verifyAssertion({ ...base, expectedOrigin: 'http://evil.example' }).ok === false);
ok('a wrong RP id fails closed', WebAuthn.verifyAssertion({ ...base, expectedRpId: 'evil.example' }).ok === false);
ok('an unsupported algorithm fails closed', WebAuthn.verifyAssertion({ ...base, alg: -999 }).ok === false);

const badSig = Buffer.from(ecSig); badSig[10] ^= 0x01;
ok('a tampered signature fails closed', WebAuthn.verifyAssertion({ ...base, signature: u(badSig) }).ok === false);

const adNoUv = authData(rpId, 0x01, 1); // user present but NOT verified
const sigNoUv = crypto.sign('sha256', signedBytes(adNoUv, cd), { key: ec.privateKey, dsaEncoding: 'der' });
ok('a user-not-verified assertion fails closed', WebAuthn.verifyAssertion({ ...base, authenticatorData: u(adNoUv), signature: u(sigNoUv) }).ok === false);

const adNoUp = authData(rpId, 0x04, 1); // verified flag set but user-present bit clear (malformed)
const sigNoUp = crypto.sign('sha256', signedBytes(adNoUp, cd), { key: ec.privateKey, dsaEncoding: 'der' });
ok('a user-not-present assertion fails closed', WebAuthn.verifyAssertion({ ...base, authenticatorData: u(adNoUp), signature: u(sigNoUp) }).ok === false);

ok('a non-advancing counter fails closed (clone/replay detection)', WebAuthn.verifyAssertion({ ...base, prevSignCount: 1 }).ok === false);

const cdCreate = clientData('webauthn.create', challenge, origin);
const sigCreate = crypto.sign('sha256', signedBytes(ad, cdCreate), { key: ec.privateKey, dsaEncoding: 'der' });
ok('a create-type clientData fails closed (must be webauthn.get)', WebAuthn.verifyAssertion({ ...base, clientDataJSON: u(cdCreate), signature: u(sigCreate) }).ok === false);

const ad0 = authData(rpId, 0x05, 0); // an authenticator that does not implement a counter reports 0
const sig0 = crypto.sign('sha256', signedBytes(ad0, cd), { key: ec.privateKey, dsaEncoding: 'der' });
ok('a 0/0 counter (authenticator without a counter) is allowed', WebAuthn.verifyAssertion({ ...base, authenticatorData: u(ad0), signature: u(sig0), prevSignCount: 0 }).ok === true);

ok('garbage inputs fail closed without throwing', WebAuthn.verifyAssertion({ pubKeySpki: 'xx', alg: -7, authenticatorData: 'yy', clientDataJSON: 'zz', signature: 'ww', expectedChallenge: 'c', expectedOrigin: origin, expectedRpId: rpId }).ok === false);

// --- RS256 (RSA security keys) ---
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaSpki = rsa.publicKey.export({ format: 'der', type: 'spki' });
const rsaSig = crypto.sign('sha256', signedBytes(ad, cd), { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
ok('a valid RS256 assertion verifies', WebAuthn.verifyAssertion({ ...base, pubKeySpki: u(rsaSpki), alg: -257, signature: u(rsaSig) }).ok === true);

// --- EdDSA (Ed25519) ---
const ed = crypto.generateKeyPairSync('ed25519');
const edSpki = ed.publicKey.export({ format: 'der', type: 'spki' });
const edSig = crypto.sign(null, signedBytes(ad, cd), ed.privateKey);
ok('a valid EdDSA assertion verifies', WebAuthn.verifyAssertion({ ...base, pubKeySpki: u(edSpki), alg: -8, signature: u(edSig) }).ok === true);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WEBAUTHN-ASSERTION CHECKS PASSED'));
process.exit(failures ? 1 : 0);
