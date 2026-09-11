'use strict';
// lib/test/attestforgery.js — the attestation verifier's most important property, tested OFFLINE: a self-minted
// timestamp token must NOT verify as genuine. verifyToken does full RFC 3161 / CMS verification and the ONLY thing
// standing between a forged token and "genuine" is that its certificate chain must reach a TRUSTED root. This mints
// a real, structurally-complete, correctly-signed token from a self-issued timestamping certificate (see _tsa.js)
// and asserts:
//   • with no extra trust, it is rejected as 'untrusted-chain' (a self-minted token cannot forge a proof);
//   • it passes EVERY earlier check (content-type, message-digest, ESSCertID, signature, critical timestamping EKU,
//     genTime) — proven by the fact that the reason is exactly 'untrusted-chain', not an earlier failure;
//   • supplying its own root as a trust anchor makes it verify (ok:true) and bind to our digest — confirming the
//     verifier really does the whole check and the trust anchor is the decisive gate;
//   • tampering the timestamped content after signing breaks it (message-digest-mismatch);
//   • a signer whose timestamping EKU is not marked critical is rejected (RFC 3161 §2.3).
// Deterministic and network-free, so a regression that weakened verifyToken (e.g. accepting an unverified chain)
// fails here on any offline runner.
//
// Run:  node lib/test/attestforgery.js   (no engine, no network)

const crypto = require('crypto');
const Attest = require('../Attest');
const { mintToken } = require('./_tsa');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const digest = crypto.createHash('sha256').update('the thing being timestamped').digest();

	// A fully-formed, correctly-signed, self-minted token.
	const t = mintToken({ digest });

	// 1. Without trusting its root, it is rejected — and rejected at the CHAIN, meaning every earlier anti-forgery
	//    check passed. If a check like the signature or the ESSCertID binding were broken, the reason would differ.
	const r1 = Attest.verifyToken(t.tokenDer, { digest });
	ok('a self-minted token is not genuine', r1.ok === false);
	ok('it is rejected specifically at the trust anchor (untrusted-chain), not earlier', r1.reason === 'untrusted-chain');

	// 2. Trusting its own root makes it verify and bind to our digest — so the verifier does the full check and the
	//    trust anchor is the one thing that gates it.
	const r2 = Attest.verifyToken(t.tokenDer, { digest, extraRoots: [t.certPem] });
	ok('supplying the token\'s root as a trust anchor makes it verify', r2.ok === true && r2.reason === null);
	ok('the verified token binds to the timestamped digest', (r2.imprintHex || '').toLowerCase() === digest.toString('hex'));
	ok('a mismatching digest is caught even with the root trusted', Attest.verifyToken(t.tokenDer, { digest: crypto.randomBytes(32), extraRoots: [t.certPem] }).reason === 'imprint-mismatch');

	// 3. Tampering the token after signing must break the message-digest binding.
	const tampered = Buffer.from(t.tokenDer);
	// Flip a byte inside the embedded TSTInfo content region (well past the header) — the signature no longer covers it.
	tampered[Math.floor(tampered.length / 2)] ^= 0xff;
	const r3 = Attest.verifyToken(tampered, { digest, extraRoots: [t.certPem] });
	ok('a token altered after signing does not verify', r3.ok === false);

	// 4. A signer whose timestamping EKU is present but NOT marked critical is rejected (even with its root trusted).
	const nc = mintToken({ digest, ekuCritical: false });
	const r4 = Attest.verifyToken(nc.tokenDer, { digest, extraRoots: [nc.certPem] });
	ok('a non-critical timestamping EKU is rejected', r4.ok === false && r4.reason === 'no-timestamping-eku');

	// 5. Source pin: verifyBundle must surface the trusted "As of" time and the timestamped flag ONLY for an
	// attestation of THIS bundle's baseline — its identity, root, AND seq must match. Binding them to any verifying
	// token would let an older attestation (say seq 3) shipped with a newer baseline (seq 5) lend its earlier timestamp
	// to the newer content, overclaiming when that content came into existence in the evidence feature. Exercising this
	// behaviorally needs a real TRUSTED TSA token (a self-minted token never verifies inside verifyBundle, so the
	// timestamp is never set either way), so pin the binding statically against a refactor that silently unbinds it.
	const fs = require('fs'); const path = require('path');
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('verifyBundle binds the trusted timestamp to this baseline (identity, root, and seq)',
		/it\.seq === baseline\.seq\s*&&\s*it\.root === baseline\.merkleRoot\s*&&\s*it\.identity === identity/.test(vaultSrc)
		&& /timestamped = true; const t = v\.genTime\.toISOString\(\); if \(!asOf \|\| t < asOf\) asOf = t;/.test(vaultSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ATTEST-FORGERY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
