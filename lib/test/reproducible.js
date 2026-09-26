'use strict';
// lib/test/reproducible.js — the reproducible-build digest and its verifier. A signature proves the maintainer signed
// the manifest; the reproducible digest proves the signed manifest is EXACTLY the public source at a tag, so nothing is
// hidden. The digest must therefore be a deterministic function of the covered content ONLY — independent of the signing
// timestamp — and must change the moment any covered file, path, or the version changes. This checks those properties
// on synthetic manifests (deterministic, no packaging needed) and pins that the verifier is wired to the real checks.
//
// Run:  node lib/test/reproducible.js

const fs = require('fs');
const path = require('path');
const RI = require('../ReleaseIntegrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const base = () => ({
	schema: 'vaultonaut-release-1', product: 'Vaultonaut', version: '1.2.0', algo: 'sha256',
	generatedAt: '2026-01-01T00:00:00.000Z',
	files: [
		{ path: 'a.js', sha256: 'a'.repeat(64), size: 10 },
		{ path: 'b/c.js', sha256: 'b'.repeat(64), size: 20 },
	],
});

// 1. The digest ignores the (non-reproducible) signing timestamp — two signings of the same source must agree.
{
	const m1 = base(), m2 = base();
	m2.generatedAt = '2030-12-31T23:59:59.999Z';
	ok('the reproducible digest is identical when only generatedAt differs', RI.reproducibleDigest(m1) === RI.reproducibleDigest(m2));
	ok('reproducibleContent drops generatedAt entirely', RI.reproducibleContent(m1).generatedAt === undefined);
	ok('the same content yields a byte-identical digest (deterministic)', RI.reproducibleDigest(base()) === RI.reproducibleDigest(base()));
}

// 2. The digest is sensitive to every covered field — a changed file hash, path, size, or the version must change it.
{
	const d0 = RI.reproducibleDigest(base());
	const hashChanged = base(); hashChanged.files[0].sha256 = 'c'.repeat(64);
	ok('a changed file hash changes the digest', RI.reproducibleDigest(hashChanged) !== d0);
	const pathChanged = base(); pathChanged.files[0].path = 'a-renamed.js';
	ok('a changed file path changes the digest', RI.reproducibleDigest(pathChanged) !== d0);
	const sizeChanged = base(); sizeChanged.files[0].size = 999;
	ok('a changed file size changes the digest', RI.reproducibleDigest(sizeChanged) !== d0);
	const verChanged = base(); verChanged.version = '1.3.0';
	ok('a changed version changes the digest', RI.reproducibleDigest(verChanged) !== d0);
	const added = base(); added.files.push({ path: 'z.js', sha256: 'd'.repeat(64), size: 1 });
	ok('an added file changes the digest', RI.reproducibleDigest(added) !== d0);
}

// 2b. Every covered field moves the digest — including schema, product, and algo (not just files/version).
{
	const d0 = RI.reproducibleDigest(base());
	for (const k of ['schema', 'product', 'algo']) { const m = base(); m[k] = m[k] + '-x'; ok('a changed ' + k + ' changes the digest', RI.reproducibleDigest(m) !== d0); }
}

// 2c. Pin the EXACT field set the digest covers. If a future manifest gains a field that affects what ships (an
// executable/mode bit, a compression marker) it must be ADDED to reproducibleContent, or it could be tampered without
// moving the digest — silently defeating the "signed manifest == public source" guarantee. This forces that decision.
{
	const c = RI.reproducibleContent(base());
	ok('reproducibleContent covers exactly {schema, product, version, algo, files}', JSON.stringify(Object.keys(c).sort()) === JSON.stringify(['algo', 'files', 'product', 'schema', 'version']));
	ok('each covered file entry is exactly {path, sha256, size}', c.files.every((f) => JSON.stringify(Object.keys(f).sort()) === JSON.stringify(['path', 'sha256', 'size'])));
}

// 3. The digest is a 64-hex SHA-256.
ok('the reproducible digest is a SHA-256 hex string', /^[0-9a-f]{64}$/.test(RI.reproducibleDigest(base())));

// 4. Verifier wiring: the reproducible-build tool must compare digests AND verify the signature, resolve the published
// set from the packager, and be a dev-only script (never shipped); the signer must print the digest; npm exposes it.
const read = (p) => { try { return fs.readFileSync(path.join(__dirname, '..', '..', p), 'utf8'); } catch (_) { return ''; } };
const vb = read('lib/scripts/verify-build.js');
ok('verify-build compares the committed and rebuilt reproducible digests', /reproducibleDigest\(committed\)/.test(vb) && /reproducibleDigest\(rebuilt\)/.test(vb) && /const reproducible = digestCommitted === digestRebuilt/.test(vb));
ok('verify-build verifies the manifest signature (hybrid, key from --pubkey or embedded)', /verifyManifestSigHybrid\(committedBuf, sigB64, sigPqB64, pub, pqPub\)/.test(vb) && /arg\('--pubkey'\)/.test(vb));
ok('verify-build resolves the published set from the packaging planner (matches the signer)', /prepare-sidecar\.js/.test(vb) && /publishedFileList/.test(vb));
ok('the reproducible-build verifier is dev-only (in lib/scripts, which the package excludes)', /"!lib\/scripts"/.test(read('package.json')) && fs.existsSync(path.join(__dirname, '..', 'scripts', 'verify-build.js')));
ok('npm exposes a verify:build script', /"verify:build": "node lib\/scripts\/verify-build\.js"/.test(read('package.json')));
ok('the signer prints the reproducible digest for publishing', /reproducibleDigest\(manifest\)/.test(read('lib/scripts/sign-release.js')));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REPRODUCIBLE-BUILD CHECKS PASSED'));
process.exit(failures ? 1 : 0);
