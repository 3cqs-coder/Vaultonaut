'use strict';
// lib/test/pqsigncomplete.js — every authenticity signature Vaultonaut writes is a HYBRID of Ed25519 and ML-DSA-65,
// produced through the single Integrity.signHybrid choke point so a record can never be persisted with only the
// classical half. The danger this guards: a future edit adds (or a refactor reintroduces) a signing site that calls
// the classical-only Integrity.sign(...) and writes an artifact with no post-quantum signature. Its verify path now
// REQUIRES the post-quantum half, so such an artifact would fail verification (a false tamper alarm or a lockout) — and
// a quantum forger could strip the missing half. This statically pins that no module signs an artifact outside the
// hybrid helper, and that the in-app and vendored bundle verifiers both check the baseline's post-quantum half.
// Pure static source analysis — no engine, fast, cross-platform.
//
// Run:  node lib/test/pqsigncomplete.js

const fs = require('fs');
const path = require('path');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const lib = path.join(__dirname, '..');
const repo = path.join(lib, '..');
const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return ''; } };
// Strip line and block comments so a `Integrity.sign(` written inside a comment (like this one) is not counted.
function stripComments(s) { return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1'); }

// --- 1. No module signs a vault artifact with the classical-only Integrity.sign(...) — every site must use signHybrid.
// signHybrid itself lives in Integrity.js and legitimately calls the bare sign(); it is the ONE allowed place, so
// Integrity.js is excluded from this scan (its own internals are checked separately below).
const SIGN_SITES = ['Vault.js', 'Recovery.js'];
for (const f of SIGN_SITES) {
	const src = stripComments(read(path.join(lib, f)));
	const bare = (src.match(/Integrity\.sign\s*\(/g) || []).length;
	ok(f + ' signs no artifact with the classical-only Integrity.sign() (must use signHybrid): ' + bare + ' found', bare === 0);
}
// ReleaseIntegrity.js is the ONE place with a deliberate classical/post-quantum split (the sign script writes .sig and
// .sig.pq from these two functions), so it is allowed a classical signer — but ONLY if the post-quantum companion also
// exists. This keeps the release path's two halves from drifting to classical-only.
const relSrc = stripComments(read(path.join(lib, 'ReleaseIntegrity.js')));
ok('ReleaseIntegrity has BOTH a classical (signManifest) and a post-quantum (signManifestPq) signer', /function signManifest\s*\(/.test(relSrc) && /function signManifestPq\s*\(/.test(relSrc));
// The root verify.js is a VERIFIER: it must not sign a release. The only signing it may contain is the throwaway
// capability probe (signing the literal 'probe' bytes to test whether this runtime can do ML-DSA at all), never a
// signature over the release manifest. Assert it holds no manifest/release signer.
{
	const vjs = stripComments(read(path.join(repo, 'verify.js')));
	ok('verify.js signs nothing but the throwaway capability probe', !/\.sign\s*\([^)]*manifest/i.test(vjs) && !/signManifest/.test(vjs));
}

// --- 2. signHybrid is the single choke point: it ALWAYS emits the classical half, and emits the post-quantum half
// whenever this runtime can do ML-DSA (pqPriv is non-null). On a runtime that genuinely lacks ML-DSA the pq half is
// omitted (sigPq: null) rather than throwing — symmetric with verifyHybrid's classical-only fallback — so no signer
// throws and none silently swallows the throw into a stale signature. A capable runtime always signs both halves.
const integ = stripComments(read(path.join(lib, 'Integrity.js')));
ok('Integrity.signHybrid emits the classical half plus the capability-gated post-quantum half', /function signHybrid\([^)]*\)\s*\{\s*return\s*\{\s*sig:\s*sign\([^)]*\),\s*sigPq:\s*pqPriv\s*\?\s*signPq\([^)]*\)\s*:\s*null\s*\}/.test(integ));
// The ML-DSA private/public key getters are capability-gated (return null, never throw, when the runtime lacks ML-DSA),
// which is what lets signHybrid omit the pq half instead of throwing deep inside a signer.
ok('the ML-DSA signing key getter is capability-gated (returns null when ML-DSA is unavailable, does not throw)', /get pqPriv\(\)\s*\{\s*return pqAvailable\(\)\s*\?\s*lazy\(\)\.priv\s*:\s*null/.test(integ));
// verifyHybrid must verify the classical half first (returning false if it fails), then the post-quantum half — with a
// capability fallback (classical-only) ONLY when the runtime cannot do ML-DSA at all. Confirm all three ingredients are
// present in the one function, so a refactor cannot quietly drop the AND-combiner or the fallback.
{
	const vh = (integ.match(/function verifyHybrid\([^)]*\)\s*\{[\s\S]*?\n\}/) || [''])[0];
	ok('Integrity.verifyHybrid verifies the classical half and fails closed on it', /if\s*\(!verify\([^)]*\)\)\s*return false/.test(vh));
	ok('Integrity.verifyHybrid requires the post-quantum half (AND-combiner)', /return verifyPq\([^)]*\)/.test(vh));
	ok('Integrity.verifyHybrid falls back to classical only when the runtime lacks ML-DSA', /if\s*\(!pqAvailable\(\)\)\s*return true/.test(vh));
}

// --- 3. Both bundle verifiers check the baseline's post-quantum half (the in-app verifyBundle once diverged from the
// vendored one — this pins them together so a baseline forgery that drops sigPq is caught by BOTH).
const vault = read(path.join(lib, 'Vault.js'));
const vb = read(path.join(lib, 'verify-bundle.js'));
ok('the in-app verifyBundle verifies the baseline with verifyHybrid (not classical-only)', /verifyHybrid\([^;]*baseline\.sig,\s*baseline\.sigPq\)/.test(vault));
ok('the vendored verify-bundle verifies the baseline with verifyHybrid', /verifyHybrid\([^;]*baseline\.sig,\s*baseline\.sigPq\)/.test(vb));
ok('the vendored verify-bundle verifies the manifest seal and roster with verifyHybrid', /verifyHybrid/.test(vb) && (vb.match(/verifyHybrid/g) || []).length >= 3);

// --- 4. Self-test: the scanner actually flags a classical-only signer, so it cannot silently pass.
ok('the scanner would flag a bare Integrity.sign() call', (stripComments('x = Integrity.sign(k, m);').match(/Integrity\.sign\s*\(/g) || []).length === 1);
ok('the scanner ignores Integrity.sign() written inside a comment', (stripComments('// Integrity.sign(k, m)\nvar y = 1;').match(/Integrity\.sign\s*\(/g) || []).length === 0);
// And the hybrid helpers really are exported and behave as an AND-combiner (belt-and-suspenders with pqsign.js).
ok('signHybrid/verifyHybrid are exported and function', typeof Integrity.signHybrid === 'function' && typeof Integrity.verifyHybrid === 'function');

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PQ-SIGN-COMPLETE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
