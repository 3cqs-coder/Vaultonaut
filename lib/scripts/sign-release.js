#!/usr/bin/env node
'use strict';
// lib/scripts/sign-release.js — the MAINTAINER's release-signing tool. DEV-ONLY: it is never needed at install or run
// time and is not part of the shipped application. Run it before tagging a release to (re)generate the signed
// release manifest that lets users confirm they have an authentic, unmodified copy.
//
//   node lib/scripts/sign-release.js --init [--key <path>]   Generate the signing keypair once. Writes the PUBLIC key
//                                                         into lib/releasePubKey.js and saves the PRIVATE key to
//                                                         <path> (default ./release-signing-key.json, git-ignored).
//   node lib/scripts/sign-release.js [--key <path>]           Sign: rebuild the manifest from the CURRENT files and
//                                                         write release-manifest.json + release-manifest.sig, plus
//                                                         SHA256SUMS + SHA256SUMS.sig. Run this after ANY code
//                                                         change you are about to release — it re-discovers every
//                                                         file automatically, so nothing needs manual listing.
//   node lib/scripts/sign-release.js --check                  Report whether the working tree still matches the last
//                                                         signed manifest (i.e. whether a re-sign is needed).
//
// Universal and host-independent by design: the trust root is this keypair, not any hosting platform. Keep the
// private key file private and backed up; publish the public key (printed by --init) in the README and on the
// official site so users can verify against a key they obtained independently.
//
// The manifest covers the FULL working tree minus the excluded set, so distribute the release as that same full
// tree (the folder users download and verify with verify.js). It is not meant to match an npm-published tarball,
// which .npmignore trims down — an npm install has its own integrity and provenance and is not what verify.js checks.
//
// Never-forget-to-sign, without any git or npm hooks: once the private key exists here, the application itself
// notices — every time you run it or "npm run doctor" — that the package.json version was bumped past the last
// signed release, and reminds you to run "npm run sign". So the normal act of bumping the version is the trigger;
// nothing has to be wired into git. "npm run sign:check" shows the same status on demand.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ROOT = path.resolve(__dirname, '..', '..'); // this script lives at lib/scripts/, so the app root is two levels up
const RI = require('../ReleaseIntegrity');

function arg(name, def) { const i = process.argv.indexOf(name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def; }
function has(flag) { return process.argv.includes(flag); }
const keyPath = path.resolve(arg('--key', path.join(ROOT, RI.KEY_NAME)));
// The private key must never end up committed OR hashed into the PUBLIC manifest. Only the default name
// (release-signing-key.json) is git-ignored and excluded from the manifest; a key placed anywhere else UNDER the
// repo with a different name would be both. So refuse an in-repo --key that is not the default name — keep the key at
// the default location, or outside the repo entirely.
{
	const relToRoot = path.relative(ROOT, keyPath);
	const insideRoot = relToRoot && !relToRoot.startsWith('..') && !path.isAbsolute(relToRoot);
	if (insideRoot && path.basename(keyPath) !== RI.KEY_NAME) {
		console.error('Refusing --key at ' + keyPath + ': a signing key inside the repo must be named ' + RI.KEY_NAME + ' (the only name that is git-ignored and excluded from the release manifest). Use that name, or keep the key OUTSIDE the repo.');
		process.exit(1);
	}
}

function writeEmbeddedPubKey(pubHex) {
	const p = path.join(ROOT, 'lib', 'releasePubKey.js');
	let s = fs.readFileSync(p, 'utf8');
	const line = "module.exports = { pubkey: '" + pubHex + "' };";
	if (!/module\.exports\s*=\s*\{\s*pubkey:/.test(s)) throw new Error('lib/releasePubKey.js does not have the expected export to update.');
	s = s.replace(/module\.exports\s*=\s*\{\s*pubkey:[^}]*\};/, line);
	fs.writeFileSync(p, s);
}

async function doInit() {
	if (fs.existsSync(keyPath) && !has('--force')) { console.error('A signing key already exists at ' + keyPath + '. Refusing to overwrite it (that would invalidate every prior release). Use --force only if you are certain.'); process.exit(1); }
	const seed = crypto.randomBytes(32).toString('base64');
	const pub = RI.publicKeyForSeed(seed);
	fs.writeFileSync(keyPath, JSON.stringify({ alg: 'ed25519', seed, pub, createdAt: new Date().toISOString() }, null, 2) + '\n', { mode: 0o600 });
	try { fs.chmodSync(keyPath, 0o600); } catch (_) {}
	writeEmbeddedPubKey(pub);
	console.log('Generated a release-signing keypair.');
	console.log('  Private key: ' + keyPath + '  (keep this private and backed up; it is git-ignored)');
	console.log('  Public key embedded in lib/releasePubKey.js:');
	console.log('    ' + pub);
	console.log('\nPublish that public key in the README and on your official site. Then run this tool with no');
	console.log('arguments to sign the release.');
}

function loadSeed() {
	let raw; try { raw = JSON.parse(fs.readFileSync(keyPath, 'utf8')); } catch (_) { console.error('No signing key at ' + keyPath + '. Run "node lib/scripts/sign-release.js --init" first.'); process.exit(1); }
	if (!raw || !raw.seed) { console.error('The signing key file is not in the expected format.'); process.exit(1); }
	return raw.seed;
}

async function doSign() {
	const seed = loadSeed();
	const manifest = await RI.buildManifest(ROOT);
	const buf = RI.serialize(manifest);
	fs.writeFileSync(path.join(ROOT, RI.MANIFEST_NAME), buf);
	fs.writeFileSync(path.join(ROOT, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n');
	// Also emit a plain SHA256SUMS for users who prefer the familiar `sha256sum -c` flow to confirm files are not
	// corrupted. Its AUTHENTICITY comes from verify.js / the signed manifest (which covers the same hashes), so there
	// is no separate signature file over it — an Ed25519 signature no standard tool could verify would only mislead.
	const sums = manifest.files.map(f => f.sha256 + '  ' + f.path).join('\n') + '\n';
	fs.writeFileSync(path.join(ROOT, 'SHA256SUMS'), Buffer.from(sums, 'utf8'));
	console.log('Signed the release: ' + manifest.files.length + ' file(s), version ' + (manifest.version || '?') + '.');
	console.log('  ' + RI.MANIFEST_NAME + ' + ' + RI.SIG_NAME + ' (authenticity — verify.js)');
	console.log('  SHA256SUMS (plain corruption check)');
	console.log('Public key (must match the README): ' + RI.publicKeyForSeed(seed));
}

async function doCheck() {
	// The version-based signal first (what the app reminds you about), then the thorough file-hash check.
	const sp = await RI.signingPending(ROOT);
	if (sp && sp.pending) console.log(sp.reason === 'version-changed'
		? 'Version changed: package.json is ' + (sp.version || '?') + ' but the last signed release was ' + (sp.signedVersion || '?') + '. A re-sign is due.'
		: 'A signing key is present but nothing has been signed yet.');
	const r = await RI.verifyInstall(ROOT);
	if (!r.present) { console.log('No signed manifest yet — run the signer to create one.'); process.exitCode = (sp && sp.pending) ? 1 : 0; return; }
	if (r.pubkey === false) { console.log('A manifest is present but lib/releasePubKey.js has no key — run --init.'); return; }
	if (!r.signatureValid) { console.log('The manifest signature does NOT verify against the embedded key — re-sign (or the key/manifest was changed).'); process.exitCode = 1; return; }
	if (r.ok) { console.log('Up to date: all ' + r.count + ' file(s) match the signed manifest. No re-sign needed.'); return; }
	console.log('OUT OF DATE — the working tree no longer matches the signed manifest. Re-sign before releasing.');
	if (r.mismatches.length) console.log('  Changed: ' + r.mismatches.slice(0, 50).join(', ') + (r.mismatches.length > 50 ? ', …' : ''));
	if (r.missing.length) console.log('  Missing: ' + r.missing.slice(0, 50).join(', ') + (r.missing.length > 50 ? ', …' : ''));
	process.exitCode = 1;
}

(async () => {
	try {
		if (has('--init')) await doInit();
		else if (has('--check')) await doCheck();
		else await doSign();
	} catch (e) { console.error('sign-release failed: ' + (e && e.message ? e.message : e)); process.exit(1); }
})();
