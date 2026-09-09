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
// The manifest covers the PUBLISHED application file set — the exact files the package ships and the desktop build
// stages into its bundle. Signing that set (rather than the whole working tree) is what lets ONE committed signature
// verify a source download, an npm install, AND every platform's desktop bundle: the bundled Node runtime and
// node_modules, which each platform's build supplies on its own, are outside the set. Commit release-manifest.json
// and release-manifest.sig; the desktop build embeds them without ever holding the private key.
//
// Never-forget-to-sign, enforced not just reminded: the committed manifest is checked by the fail-closed
// release-signed test the CI suite runs BEFORE any build, so a shipped file changed without a re-sign blocks the
// release. On top of that, the application still notices a version bump past the last signed release (when you run it
// or "npm run doctor") and reminds you; "npm run sign:check" shows the same status on demand; and an optional
// pre-commit hook (.githooks/pre-commit, enabled with `git config core.hooksPath .githooks`) re-signs and stages the
// manifest automatically on the maintainer's machine so it is never even a manual step.

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

// The published application file set — the exact files that ship in the package AND are staged into the desktop
// bundle. Single-sourced from the packaging planner so the signed manifest and the staged bundle can never diverge;
// signing the published set (not the whole working tree) is what lets ONE signature cover the source download, the
// npm install, and every platform's desktop bundle. The planner lives in the packaging tree, which the maintainer
// always has (it is dev-only and never shipped), so requiring it here is safe.
function publishedFileList() {
	let planner;
	try { planner = require(path.join(ROOT, 'src-tauri', 'prepare-sidecar.js')); }
	catch (e) { throw new Error('cannot resolve the published file set — the packaging planner (src-tauri/prepare-sidecar.js) did not load: ' + (e && e.message || e)); }
	return planner.publishedFileList();
}

async function doSign() {
	const seed = loadSeed();
	const manifest = await RI.buildManifestFromList(ROOT, publishedFileList());
	const buf = RI.serialize(manifest);
	fs.writeFileSync(path.join(ROOT, RI.MANIFEST_NAME), buf);
	fs.writeFileSync(path.join(ROOT, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n');
	// Also emit a plain SHA256SUMS for users who prefer the familiar `sha256sum -c` flow to confirm files are not
	// corrupted. Its AUTHENTICITY comes from verify.js / the signed manifest (which covers the same hashes), so there
	// is no separate signature file over it — an Ed25519 signature no standard tool could verify would only mislead.
	const sums = manifest.files.map(f => f.sha256 + '  ' + f.path).join('\n') + '\n';
	fs.writeFileSync(path.join(ROOT, 'SHA256SUMS'), Buffer.from(sums, 'utf8'));
	console.log('Signed the release: ' + manifest.files.length + ' file(s), version ' + (manifest.version || '?') + '.');
	console.log('  ' + RI.MANIFEST_NAME + ' + ' + RI.SIG_NAME + ' (authenticity — verify.js; committed so every build, including CI, embeds them)');
	console.log('  SHA256SUMS (plain corruption check)');
	console.log('Public key (must match the README): ' + RI.publicKeyForSeed(seed));
	console.log('Commit ' + RI.MANIFEST_NAME + ' and ' + RI.SIG_NAME + ' with your changes so the desktop bundle build can embed them.');
}

async function doCheck() {
	// The version-based signal first (what the app reminds you about), then the thorough content check: rebuild the
	// manifest from the CURRENT published files and compare it to the committed one. Comparing the published set (not a
	// full-tree walk) keeps this accurate on a working clone, where development-only files are present but not shipped.
	const sp = await RI.signingPending(ROOT);
	if (sp && sp.pending) console.log(sp.reason === 'version-changed'
		? 'Version changed: package.json is ' + (sp.version || '?') + ' but the last signed release was ' + (sp.signedVersion || '?') + '. A re-sign is due.'
		: 'A signing key is present but nothing has been signed yet.');
	const r = await RI.releaseSigningStatus(ROOT, publishedFileList());
	if (!r.present) { console.log('No signed manifest yet — run the signer to create one.'); process.exitCode = (sp && sp.pending) ? 1 : 0; return; }
	if (!r.readable) { console.log('The committed manifest is not readable JSON — re-sign.'); process.exitCode = 1; return; }
	if (!r.sigValid) { console.log('The committed manifest signature does NOT verify against the embedded key — re-sign (or the key/manifest was changed).'); process.exitCode = 1; return; }
	if (r.matches) { console.log('Up to date: all ' + r.count + ' published file(s) match the signed manifest. No re-sign needed.'); return; }
	console.log('OUT OF DATE — the published files no longer match the signed manifest. Re-sign before releasing.');
	if (r.changed.length) console.log('  Changed: ' + r.changed.slice(0, 50).join(', ') + (r.changed.length > 50 ? ', …' : ''));
	if (r.added.length) console.log('  Added: ' + r.added.slice(0, 50).join(', ') + (r.added.length > 50 ? ', …' : ''));
	if (r.removed.length) console.log('  Removed: ' + r.removed.slice(0, 50).join(', ') + (r.removed.length > 50 ? ', …' : ''));
	process.exitCode = 1;
}

(async () => {
	try {
		if (has('--init')) await doInit();
		else if (has('--check')) await doCheck();
		else await doSign();
	} catch (e) { console.error('sign-release failed: ' + (e && e.message ? e.message : e)); process.exit(1); }
})();
