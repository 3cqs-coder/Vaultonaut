'use strict';
// lib/test/releaseintegrity.js — the application self-integrity / release-authenticity stack. A maintainer signs a
// manifest of every shipped file's hash with an Ed25519 key; users (and the boot self-check, and the standalone
// verify.js) confirm the installed files still match, against the maintainer's public key. This pins:
//   • a signed tree verifies GENUINE, and the standalone verifier agrees;
//   • editing, adding-hash-mismatch, or deleting a file is detected as TAMPERED / a mismatch;
//   • a wrong public key fails the signature (an attacker cannot re-sign without the private key);
//   • an unsigned tree (no manifest) is INERT — never a false alarm;
//   • paths are stored POSIX-style so a manifest is cross-platform.
//
// Pure Node, no engine or network needed.
//
// Run:  node lib/test/releaseintegrity.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const RI = require('../ReleaseIntegrity');
const Integrity = require('../Integrity');
const verify = require('../../verify');
const { verifyRelease } = verify;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-relint-'));
	// A small fake install tree: a couple of nested files, plus a lib/releasePubKey.js so the standalone verifier
	// can find an embedded key, and an excluded dir that must NOT be covered.
	await fsp.mkdir(path.join(tmp, 'lib', 'sub'), { recursive: true });
	await fsp.mkdir(path.join(tmp, 'node_modules', 'x'), { recursive: true }); // excluded
	await fsp.writeFile(path.join(tmp, 'app.js'), 'console.log(1)\n');
	await fsp.writeFile(path.join(tmp, 'lib', 'a.js'), 'module.exports = 1\n');
	await fsp.writeFile(path.join(tmp, 'lib', 'sub', 'b.js'), 'module.exports = 2\n');
	await fsp.writeFile(path.join(tmp, 'node_modules', 'x', 'junk.js'), 'nope\n');

	// A maintainer keypair (32-byte seed, like the vault write-seed).
	const seed = crypto.randomBytes(32).toString('base64');
	const pub = RI.publicKeyForSeed(seed);
	// Embed the public key the way the real lib/releasePubKey.js exports it, so verify.js can read it.
	await fsp.writeFile(path.join(tmp, 'lib', 'releasePubKey.js'), "module.exports = { pubkey: '" + pub + "' };\n");

	// Build + sign.
	const manifest = await RI.buildManifest(tmp, { version: '9.9.9' });
	ok('the manifest covers the shipped files', manifest.files.some(f => f.path === 'app.js') && manifest.files.some(f => f.path === 'lib/sub/b.js'));
	ok('the manifest excludes node_modules', !manifest.files.some(f => f.path.startsWith('node_modules/')));
	ok('manifest paths are POSIX-style (cross-platform)', manifest.files.every(f => !f.path.includes('\\')));
	const buf = RI.serialize(manifest);
	const sig = RI.signManifest(buf, seed);
	await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), buf);
	await fsp.writeFile(path.join(tmp, RI.SIG_NAME), sig + '\n');

	// verifyInstall (the boot-check path) — clean tree passes.
	{
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('verifyInstall reports a clean signed tree as ok', r.present && r.signatureValid && r.ok && r.mismatches.length === 0 && r.missing.length === 0);
	}
	// The standalone verifier agrees, both with an explicit key and with the embedded one.
	ok('verify.js returns GENUINE with the maintainer key', verifyRelease(tmp, pub).verdict === 'GENUINE');
	ok('verify.js returns GENUINE using the embedded key', verifyRelease(tmp).verdict === 'GENUINE');

	// A wrong key must fail the signature — nobody can re-sign without the private key.
	{
		const otherPub = RI.publicKeyForSeed(crypto.randomBytes(32).toString('base64'));
		const r = await RI.verifyInstall(tmp, { pubHex: otherPub });
		ok('a wrong public key fails the manifest signature', r.present && r.signatureValid === false);
		ok('verify.js reports TAMPERED under a wrong key', verifyRelease(tmp, otherPub).verdict === 'TAMPERED');
	}

	// Editing a covered file is detected (its hash no longer matches; the signature still verifies).
	{
		await fsp.writeFile(path.join(tmp, 'lib', 'a.js'), 'module.exports = 999 // tampered\n');
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('an edited file is detected as a mismatch', r.signatureValid && !r.ok && r.mismatches.includes('lib/a.js'));
		ok('verify.js reports TAMPERED for an edited file', verifyRelease(tmp, pub).verdict === 'TAMPERED');
		await fsp.writeFile(path.join(tmp, 'lib', 'a.js'), 'module.exports = 1\n'); // restore
		ok('restoring the file clears the mismatch', (await RI.verifyInstall(tmp, { pubHex: pub })).ok === true);
	}

	// Deleting a covered file is detected as missing.
	{
		await fsp.rm(path.join(tmp, 'lib', 'sub', 'b.js'));
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a deleted file is detected as missing', r.signatureValid && !r.ok && r.missing.includes('lib/sub/b.js'));
		await fsp.writeFile(path.join(tmp, 'lib', 'sub', 'b.js'), 'module.exports = 2\n'); // restore
	}

	// ADDING a covered file (not in the manifest) is detected as extraneous — an attacker dropping a file in.
	{
		await fsp.writeFile(path.join(tmp, 'lib', 'evil.js'), 'require("child_process")\n');
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('an added file is detected as extraneous', r.signatureValid && !r.ok && (r.extraneous || []).includes('lib/evil.js'));
		ok('verify.js reports TAMPERED for an added file', verifyRelease(tmp, pub).verdict === 'TAMPERED');
		await fsp.rm(path.join(tmp, 'lib', 'evil.js')); // restore
		ok('removing the added file clears the extraneous finding', (await RI.verifyInstall(tmp, { pubHex: pub })).ok === true);
	}

	// A crafted manifest path that escapes the root is neutralized (defense-in-depth), not hashed outside the tree.
	{
		const evil = JSON.parse(buf.toString('utf8'));
		evil.files = [{ path: '../outside.txt', sha256: 'x'.repeat(64), size: 1 }].concat(evil.files);
		const evilBuf = RI.serialize(evil);
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), evilBuf);
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), RI.signManifest(evilBuf, seed) + '\n'); // signed with the REAL key, so only the path is the concern
		await fsp.writeFile(path.join(path.dirname(tmp), 'outside.txt'), 'secret'); // a real file just outside the root
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a manifest path escaping the root is treated as a mismatch, never hashed outside', r.signatureValid && !r.ok && r.mismatches.includes('../outside.txt'));
		await fsp.rm(path.join(path.dirname(tmp), 'outside.txt'), { force: true });
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), buf); // restore the genuine manifest
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), sig + '\n');
	}

	// The standalone verifier's exclude sets MUST match the library's, or extraneous detection would drift.
	{
		const eq = (a, b) => a.size === b.size && [...a].every(x => b.has(x));
		ok('verify.js EXCLUDE_TOP matches lib/ReleaseIntegrity.js', eq(verify.EXCLUDE_TOP, RI.EXCLUDE_TOP));
		ok('verify.js EXCLUDE_NAME matches lib/ReleaseIntegrity.js', eq(verify.EXCLUDE_NAME, RI.EXCLUDE_NAME));
	}

	// Replacing the manifest with an attacker's own (re-signed with THEIR key) is caught, because the embedded
	// public key does not match their signature.
	{
		const evilSeed = crypto.randomBytes(32).toString('base64');
		const evil = await RI.buildManifest(tmp, { version: 'evil' });
		const evilBuf = RI.serialize(evil);
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), evilBuf);
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), RI.signManifest(evilBuf, evilSeed) + '\n');
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a manifest re-signed with a different key fails against the embedded key', r.present && r.signatureValid === false);
		// restore the genuine manifest
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), buf);
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), sig + '\n');
	}

	// An UNSIGNED tree (no manifest) is inert — the boot check must say nothing (present:false).
	{
		const bare = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-relint-bare-'));
		await fsp.writeFile(path.join(bare, 'app.js'), 'x\n');
		const r = await RI.verifyInstall(bare, { pubHex: pub });
		ok('an unsigned tree is inert (no manifest → nothing to assert)', r.present === false);
		ok('verify.js reports UNVERIFIED for an unsigned tree', verifyRelease(bare, pub).verdict === 'UNVERIFIED');
		await fsp.rm(bare, { recursive: true, force: true });
	}

	// A manifest present but NO embedded key is also inert for the boot check. Simulate "no embedded key" by
	// overriding the require cache for releasePubKey to an empty key (the real one is now published, so passing a
	// null/empty pubHex would just fall back to it — this exercises the pubkey:false branch faithfully).
	{
		const pubModPath = require.resolve('../releasePubKey');
		const orig = require.cache[pubModPath];
		require.cache[pubModPath] = { id: pubModPath, filename: pubModPath, loaded: true, exports: { pubkey: '' } };
		try {
			const r = await RI.verifyInstall(tmp); // no pubHex → falls back to embeddedPubKey(), now empty
			ok('a manifest with no available public key is inert (pubkey:false)', r.present === true && r.pubkey === false);
		} finally { if (orig) require.cache[pubModPath] = orig; else delete require.cache[pubModPath]; }
	}

	// The SelfCheck wrappers (release_integrity + release_signing_pending), including the security-relevant
	// maintainer-skip guard. Uses a temp app root and overrides the embedded key in the require cache (no file
	// mutation) so the checks run against the temp signed tree exactly as they would on a real install.
	{
		const SelfCheck = require('../SelfCheck');
		const Common = require('../Common');
		const pubModPath = require.resolve('../releasePubKey');
		const origPubMod = require.cache[pubModPath];
		const origRoot = Common.root, origData = Common.dataDir, origState = Common.statePath;
		const rroot = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-relsc-'));
		const rdata = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-relsc-data-'));
		try {
			await fsp.mkdir(path.join(rroot, 'lib'), { recursive: true });
			await fsp.writeFile(path.join(rroot, 'app.js'), 'hello\n');
			await fsp.writeFile(path.join(rroot, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
			const seed2 = crypto.randomBytes(32).toString('base64');
			const pub2 = RI.publicKeyForSeed(seed2);
			await fsp.writeFile(path.join(rroot, 'lib', 'releasePubKey.js'), "module.exports = { pubkey: '" + pub2 + "' };\n");
			const doSign = async () => { const m = await RI.buildManifest(rroot); const b = RI.serialize(m); await fsp.writeFile(path.join(rroot, RI.MANIFEST_NAME), b); await fsp.writeFile(path.join(rroot, RI.SIG_NAME), RI.signManifest(b, seed2) + '\n'); };
			await doSign();
			require.cache[pubModPath] = { id: pubModPath, filename: pubModPath, loaded: true, exports: { pubkey: pub2 } };
			Common.root = () => rroot; Common.dataDir = () => rdata; Common.statePath = () => path.join(rdata, 'state.json');
			const rel = async (label) => { const r = await SelfCheck.run({ quiet: true, label }); return { integ: r.filter(f => f.check === 'release_integrity'), pend: r.filter(f => f.check === 'release_signing_pending'), expo: r.filter(f => f.check === 'release_key_exposed') }; };

			let r = await rel('c1');
			ok('SelfCheck: a clean signed end-user install is silent', r.integ.length === 0 && r.pend.length === 0);

			await fsp.writeFile(path.join(rroot, 'app.js'), 'hello tampered here\n'); // different length → cache miss
			r = await rel('c2');
			ok('SelfCheck: an edited end-user file warns "may have been modified"', r.integ.length === 1 && /may have been modified/.test(r.integ[0].message));

			// An EXTRA, unlisted file alone (not a modified or missing signed file) must NOT raise the tamper alarm — a
			// from-source install legitimately carries development files the published set omits. Restore the edited file
			// so only the extra file differs, then put the edit back so the maintainer-skip case (c3) still has its premise.
			await fsp.writeFile(path.join(rroot, 'app.js'), 'hello\n');
			await fsp.writeFile(path.join(rroot, 'extra-dev-file.js'), 'dev only\n');
			r = await rel('c2b');
			ok('SelfCheck: an extra unlisted file alone does NOT warn (no false alarm on a source install)', r.integ.length === 0);
			await fsp.rm(path.join(rroot, 'extra-dev-file.js'));
			await fsp.writeFile(path.join(rroot, 'app.js'), 'hello tampered here\n');

			await fsp.writeFile(path.join(rroot, RI.KEY_NAME), JSON.stringify({ alg: 'ed25519', seed: seed2, pub: pub2 }));
			r = await rel('c3');
			ok('SelfCheck: the end-user tamper alarm is suppressed on the maintainer machine (own edits)', r.integ.length === 0);
			await fsp.writeFile(path.join(rroot, 'app.js'), 'hello\n'); await doSign(); // clean, signed at 1.0.0

			await fsp.writeFile(path.join(rroot, 'package.json'), JSON.stringify({ name: 'x', version: '1.2.0' }));
			r = await rel('c4');
			ok('SelfCheck: a version bump reminds the maintainer to re-sign', r.pend.length === 1 && /1\.2\.0/.test(r.pend[0].message));

			// release_key_exposed: the private key is present but this temp root has no .gitignore rule for it → warn;
			// adding the rule silences it.
			r = await rel('c5');
			ok('SelfCheck: warns when the private key is present but not git-ignored', r.expo.length === 1);
			await fsp.writeFile(path.join(rroot, '.gitignore'), 'node_modules/\n' + RI.KEY_NAME + '\n');
			r = await rel('c6');
			ok('SelfCheck: silent once .gitignore lists the private key', r.expo.length === 0);
		} finally {
			Common.root = origRoot; Common.dataDir = origData; Common.statePath = origState;
			if (origPubMod) require.cache[pubModPath] = origPubMod; else delete require.cache[pubModPath];
			await fsp.rm(rroot, { recursive: true, force: true }).catch(() => {});
			await fsp.rm(rdata, { recursive: true, force: true }).catch(() => {});
		}
	}

	// The maintainer "re-sign pending" reminder, driven by the package.json version (no hooks).
	{
		// No key present in the tree yet → not the maintainer's machine → silent.
		ok('signingPending is silent with no signing key present', (await RI.signingPending(tmp)) === null);
		// Add a key file and a package.json at the tree, and a manifest at the current version → not pending.
		await fsp.writeFile(path.join(tmp, RI.KEY_NAME), JSON.stringify({ alg: 'ed25519', seed, pub }));
		await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
		const m1 = await RI.buildManifest(tmp); // version read from the tree's package.json = 1.0.0
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), RI.serialize(m1));
		ok('the manifest records the version from the tree\'s package.json', m1.version === '1.0.0');
		ok('signingPending is not pending when the signed version matches', (await RI.signingPending(tmp)).pending === false);
		// Bump the version → pending with reason version-changed (the "never forget" trigger).
		await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({ name: 'x', version: '1.1.0' }));
		const sp = await RI.signingPending(tmp);
		ok('bumping the version marks a re-sign as pending', sp.pending === true && sp.reason === 'version-changed' && sp.version === '1.1.0' && sp.signedVersion === '1.0.0');
		// Re-sign at the new version → no longer pending.
		const m2 = await RI.buildManifest(tmp);
		await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), RI.serialize(m2));
		ok('re-signing at the new version clears the pending state', (await RI.signingPending(tmp)).pending === false);
	}

	return done();
}

async function done() {
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELEASE-INTEGRITY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
