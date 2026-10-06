'use strict';
// lib/WebAuthn.js — server-side verification of a WebAuthn assertion (a navigator.credentials.get() result), for
// passwordless web-interface sign-in. This is the REAL ceremony: the authenticator signs a single-use, server-issued
// challenge, and we verify that signature against the credential's public key — so a captured sign-in value is
// worthless (unlike a static secret). It is deliberately dependency-free and uses only Node's built-in crypto: the
// browser hands us the public key already as SPKI DER (AuthenticatorAttestationResponse.getPublicKey()), so there is
// no COSE/CBOR or attestation parsing to get wrong. Pure and synchronous (one signature verify per sign-in is fast),
// cross-platform, and NEVER throws — a malformed or hostile assertion is a clean `{ ok: false }`, never a crash.
//
// Supported algorithms are the three WebAuthn mandates plus EdDSA: ES256 (ECDSA P-256), RS256 (RSA PKCS1-v1.5), and
// EdDSA (Ed25519). These cover every common platform authenticator and roaming security key; an unknown algorithm
// fails closed. The signer includes authenticatorData || SHA-256(clientDataJSON), per the spec.

const crypto = require('crypto');

function b64uToBuf(s) { try { return Buffer.from(String(s || ''), 'base64url'); } catch (_) { return Buffer.alloc(0); } }
// Constant-time string compare that never leaks length via early return beyond the unavoidable length check.
function timingEqualStr(a, b) {
	const ba = Buffer.from(String(a == null ? '' : a), 'utf8');
	const bb = Buffer.from(String(b == null ? '' : b), 'utf8');
	if (ba.length !== bb.length) return false;
	try { return crypto.timingSafeEqual(ba, bb); } catch (_) { return false; }
}

// COSE algorithm identifiers the client reports via getPublicKeyAlgorithm(). Map each to how Node verifies it.
const ALG = {
	'-7': 'es256',    // ECDSA w/ SHA-256 on P-256 — WebAuthn signatures are ASN.1 DER (Node's EC default)
	'-257': 'rs256',  // RSASSA-PKCS1-v1_5 w/ SHA-256
	'-8': 'eddsa',    // Ed25519 — null digest, raw 64-byte signature
};

// Verify one assertion. All inputs are base64url strings (or Buffers). Returns { ok, signCount } on success so the
// caller can persist the new monotonic counter, or { ok: false }. Checks, in order: clientDataJSON shape + challenge +
// origin; authenticatorData rpIdHash + user-present + user-verified flags; the signature over authData||hash(clientData)
// against the stored public key; and the signature counter (monotonic, unless the authenticator never sets one).
function verifyAssertion(opts = {}) {
	try {
		const spki = Buffer.isBuffer(opts.pubKeySpki) ? opts.pubKeySpki : b64uToBuf(opts.pubKeySpki);
		const authData = Buffer.isBuffer(opts.authenticatorData) ? opts.authenticatorData : b64uToBuf(opts.authenticatorData);
		const clientData = Buffer.isBuffer(opts.clientDataJSON) ? opts.clientDataJSON : b64uToBuf(opts.clientDataJSON);
		const sig = Buffer.isBuffer(opts.signature) ? opts.signature : b64uToBuf(opts.signature);
		if (spki.length < 16 || authData.length < 37 || clientData.length < 2 || sig.length < 1) return { ok: false };

		// 1) clientDataJSON: must be a get() ceremony bound to OUR challenge and origin.
		let cd; try { cd = JSON.parse(clientData.toString('utf8')); } catch (_) { return { ok: false }; }
		if (!cd || cd.type !== 'webauthn.get') return { ok: false };
		if (typeof cd.challenge !== 'string' || !timingEqualStr(cd.challenge, opts.expectedChallenge)) return { ok: false };
		if (typeof cd.origin !== 'string' || cd.origin !== String(opts.expectedOrigin || '')) return { ok: false };

		// 2) authenticatorData: the RP id hash must match our host, and the user must have been present AND verified.
		const rpIdHash = authData.subarray(0, 32);
		const wantRp = crypto.createHash('sha256').update(String(opts.expectedRpId || ''), 'utf8').digest();
		if (rpIdHash.length !== wantRp.length || !crypto.timingSafeEqual(rpIdHash, wantRp)) return { ok: false };
		const flags = authData[32];
		if (!(flags & 0x01)) return { ok: false }; // UP — user present
		if (!(flags & 0x04)) return { ok: false }; // UV — user verified (enrollment requires userVerification)
		const signCount = authData.readUInt32BE(33);

		// 3) The signature covers authenticatorData concatenated with SHA-256(clientDataJSON).
		const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
		const kind = ALG[String(opts.alg)];
		if (!kind) return { ok: false };
		let key; try { key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }); } catch (_) { return { ok: false }; }
		let good = false;
		try {
			if (kind === 'eddsa') good = crypto.verify(null, signed, key, sig);
			else if (kind === 'rs256') good = crypto.verify('sha256', signed, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
			else good = crypto.verify('sha256', signed, { key, dsaEncoding: 'der' }, sig); // ES256: WebAuthn sig is DER-encoded
		} catch (_) { good = false; }
		if (!good) return { ok: false };

		// 4) Counter: must advance, so a cloned authenticator replaying an old assertion is caught. An authenticator
		// that does not implement a counter reports 0 every time, which is allowed only when the stored count is also 0.
		const prev = Number(opts.prevSignCount) || 0;
		if (!(signCount === 0 && prev === 0) && !(signCount > prev)) return { ok: false };
		return { ok: true, signCount };
	} catch (_) { return { ok: false }; }
}

module.exports = { verifyAssertion, SUPPORTED_ALGS: Object.keys(ALG).map(Number) };
