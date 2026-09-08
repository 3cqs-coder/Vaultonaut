'use strict';
// lib/ReleaseIntegrity.js — verify that the INSTALLED application's own files are the authentic, unmodified
// release the maintainer signed. This generalizes the bundled engine's checksum pin to the whole program: the
// maintainer signs a manifest of every shipped file's hash with an Ed25519 key at release time
// (lib/scripts/sign-release.js), and this module rebuilds that manifest and checks it against the embedded public key.
//
// Design goals it satisfies:
//   • Universal / host-independent — the trust root is the maintainer's own key, not any hosting platform. It
//     verifies identically whether the code came from one git host, another, or a plain download.
//   • Cross-platform — pure Node (node:crypto), no spawned commands; manifest paths are stored POSIX-style so a
//     manifest signed on one operating system verifies on every other.
//   • Reuse — it uses the vault's own Ed25519 primitives (one signature implementation for the whole project) and
//     the shared SHA-256 helper.
//   • Honest limit — a self-check is code, and whoever modified the files can also patch out the check, so this
//     COMPLEMENTS verifying the download out of band against the maintainer's key; it never replaces it.
//
// The signature covers the exact bytes of the manifest file; the manifest covers every other shipped file by hash.

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const Common = require('./Common');
const Integrity = require('./Integrity');

const MANIFEST_NAME = 'release-manifest.json';
const SIG_NAME = 'release-manifest.sig';
const KEY_NAME = 'release-signing-key.json'; // the PRIVATE key, if ever placed at the root — never shipped, never hashed
const SCHEMA = 'vaultonaut-release-1';

// Top-level names that are never part of the signed application: version control, CI, dependencies (node_modules
// AND package-lock.json, which npm rewrites on install — signing it would make a legitimately-installed copy read as
// tampered), the per-user data directory (it should not live under the app root, but exclude it defensively), the
// manifest and signature themselves, the private signing key, and generated release artifacts. ONE list, shared by
// the signer and the verifier, so what is covered can never drift between them.
const EXCLUDE_TOP = new Set(['.git', '.github', '.githooks', 'node_modules', 'package-lock.json', 'data', '.test-data', MANIFEST_NAME, SIG_NAME, KEY_NAME, 'SHA256SUMS', 'SHA256SUMS.sig']);
const EXCLUDE_NAME = new Set(['.DS_Store', 'Thumbs.db', KEY_NAME]); // OS cruft (and the key) that could appear in any folder

function embeddedPubKey() { try { return require('./releasePubKey').pubkey || null; } catch (_) { return null; } }
function appVersion() { try { return require('../package.json').version || null; } catch (_) { return null; } }
// The version declared by the package.json AT a given root (not this module's own), so the manifest records — and
// the pending check compares — the version that actually ships with that copy. Falls back to this build's version.
function versionAt(root) { try { return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version || appVersion(); } catch (_) { return appVersion(); } }

// SHA-256 of a file, streamed so a file of ANY size never loads whole into memory (no size cap needed — an
// oversize shipped asset is still covered, never silently skipped). Cross-platform, no spawn.
function hashFile(abs) {
	return new Promise((resolve, reject) => {
		const h = crypto.createHash('sha256');
		const s = fs.createReadStream(abs);
		s.on('error', reject);
		s.on('data', (d) => h.update(d));
		s.on('end', () => resolve(h.digest('hex')));
	});
}

// Resolve a manifest's POSIX-relative path under `root` and confirm it does not escape it. A signed manifest never
// contains a `..` or absolute segment (the signer only emits in-scope relative paths), but a crafted one might, so
// verifying resolves safely and rejects an escape rather than hashing an out-of-root file. Returns the absolute
// path, or null when the entry escapes the root.
function resolveWithin(root, relPosix) {
	const abs = path.resolve(root, ...String(relPosix).split('/'));
	const rel = path.relative(root, abs);
	if (rel === '' || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return null;
	return abs;
}

// Walk the COVERED scope (the shipped application, minus the excluded names) and call onFile(relPosix, abs, stat)
// for every regular file. ONE walker, shared by the manifest builder and the extraneous-file check, so both cover
// exactly the same scope and can never drift. Cooperative on large trees; symlinks and non-regular files skipped.
async function walkCovered(root, onFile, { withDependencies = false } = {}) {
	// A DESKTOP bundle ships its dependencies as part of the signed artifact, so it must cover node_modules too
	// (a source release excludes it, because npm re-fetches it with its own registry integrity). Everything else in
	// EXCLUDE_TOP stays excluded in both cases. The manifest records which scope it used so the verifier matches.
	const topExcl = withDependencies ? new Set([...EXCLUDE_TOP].filter((n) => n !== 'node_modules')) : EXCLUDE_TOP;
	let seen = 0;
	async function walk(dir, relBase) {
		let entries; try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { return; }
		for (const e of entries) {
			if (EXCLUDE_NAME.has(e.name)) continue;
			if (!relBase && topExcl.has(e.name)) continue; // top-level excludes apply at the root only
			const rel = relBase ? relBase + '/' + e.name : e.name; // POSIX-style, stable across platforms
			const abs = path.join(dir, e.name);
			if (e.isSymbolicLink()) continue;
			if (e.isDirectory()) { await walk(abs, rel); continue; }
			if (!e.isFile()) continue;
			let st; try { st = await fsp.stat(abs); } catch (_) { continue; }
			await onFile(rel, abs, st);
			if (++seen % 512 === 0) await Common.yieldToLoop(); // yield on a large tree
		}
	}
	await walk(root, '');
}

// Build { schema, product, version, algo, generatedAt, files } — files is a path-sorted list of
// { path (POSIX-relative), sha256, size } for every shipped regular file.
async function buildManifest(root, { version, withDependencies = false } = {}) {
	root = path.resolve(root || Common.root());
	const files = [];
	await walkCovered(root, async (rel, abs, st) => { files.push({ path: rel, sha256: await hashFile(abs), size: st.size }); }, { withDependencies });
	files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
	const manifest = { schema: SCHEMA, product: require('./Brand').name, version: version || versionAt(root), algo: 'sha256', generatedAt: new Date().toISOString(), files };
	if (withDependencies) manifest.coversDependencies = true; // absent on a source release, so those manifests are unchanged
	return manifest;
}

// The exact bytes that are written to disk AND signed — a stable, pretty-printed form with a trailing newline, so
// the signer and every verifier agree on the byte sequence the signature covers.
function serialize(manifest) { return Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8'); }

// Sign / verify the manifest bytes with the project's own Ed25519 primitives (reused, not re-implemented). The
// private key is a 32-byte seed, base64-encoded, exactly like the vault write-seed — so the same derivation works.
function signManifest(manifestBuf, seedB64) { const { priv } = Integrity.signKeysFromSeed(seedB64); return Integrity.sign(priv, manifestBuf.toString('utf8')); }
function verifyManifestSig(manifestBuf, sigB64, pubHex) { return Integrity.verify(pubHex, manifestBuf.toString('utf8'), sigB64); }
function publicKeyForSeed(seedB64) { return Integrity.signKeysFromSeed(seedB64).pub; }

// Verify an installed copy against its signed manifest. Returns a plain result the caller (the boot self-check or
// a CLI/report) turns into words:
//   { present:false }                              — no manifest (an unsigned source checkout); nothing to assert
//   { present:true, pubkey:false }                 — a manifest but no embedded key to check it against
//   { present:true, signatureValid:false }         — the manifest's signature is missing or does not verify (tamper)
//   { present:true, signatureValid:true, ok, mismatches[], missing[], extraneous[], count, version }
// `extraneous` lists files present in the covered scope but NOT in the manifest (an addition), which the listed-file
// loop cannot see on its own. Best-effort and never throws.
async function verifyInstall(root, { pubHex } = {}) {
	root = path.resolve(root || Common.root());
	pubHex = pubHex || embeddedPubKey();
	let manifestBuf;
	try { manifestBuf = await fsp.readFile(path.join(root, MANIFEST_NAME)); } catch (_) { return { present: false }; }
	if (!pubHex) return { present: true, pubkey: false };
	let sigB64 = null; try { sigB64 = (await fsp.readFile(path.join(root, SIG_NAME), 'utf8')).trim(); } catch (_) {}
	let manifest; try { manifest = JSON.parse(manifestBuf.toString('utf8')); } catch (_) { return { present: true, signatureValid: false, reason: 'unreadable-manifest' }; }
	let signatureValid = false; try { signatureValid = !!sigB64 && verifyManifestSig(manifestBuf, sigB64, pubHex); } catch (_) { signatureValid = false; }
	if (!signatureValid) return { present: true, signatureValid: false };
	const mismatches = [], missing = [];
	const listed = new Set();
	for (const f of manifest.files || []) {
		listed.add(String(f.path));
		const abs = resolveWithin(root, f.path); // a path that escapes the root is treated as a mismatch, never hashed
		let cur = null; try { cur = abs && await hashFile(abs); } catch (_) { missing.push(f.path); continue; }
		if (!abs || cur !== f.sha256) mismatches.push(f.path);
	}
	// Extraneous-file detection: a file present in the covered scope but absent from the manifest was ADDED after
	// signing (an attacker dropping a file in). The per-entry loop above cannot see it, so walk the scope and flag it.
	const extraneous = [];
	// Match the manifest's own scope: a bundle manifest covers node_modules, so an added dependency file must be
	// flagged as extraneous too — the manifest says so via coversDependencies.
	try { await walkCovered(root, (rel) => { if (!listed.has(rel)) extraneous.push(rel); }, { withDependencies: !!manifest.coversDependencies }); } catch (_) {}
	return { present: true, signatureValid: true, ok: mismatches.length === 0 && missing.length === 0 && extraneous.length === 0, mismatches, missing, extraneous, count: (manifest.files || []).length, version: manifest.version };
}

// A cheap cache in front of verifyInstall so the periodic boot self-check does not re-hash the whole install every
// few minutes. It fingerprints the tree by path + size + mtime (a stat walk, no content hashing) and only runs the
// full verify when that fingerprint changed since the last one — the app's own files do not change while it runs, so
// repeat sweeps reuse the verdict, yet a real on-disk change still forces a re-verify. The fingerprint is keyed by
// root and public key so it can never be reused across a different install or key. A time-to-live forces a FULL
// re-verify at least periodically even on an unchanged fingerprint, which bounds the (attacker-only) window in which
// an in-place edit that preserves a file's size and resets its mtime would otherwise ride a stale verdict until the
// next restart. Best-effort; never throws. (The authoritative check is still the out-of-band verify.js, which never caches.)
const INSTALL_CACHE_TTL_MS = 30 * 60 * 1000;
let _installCache = null; // { fp, at, result }
async function verifyInstallCached(root, opts = {}) {
	root = path.resolve(root || Common.root());
	try {
		const h = crypto.createHash('sha256');
		await walkCovered(root, (rel, abs, st) => { h.update(rel + '\0' + st.size + '\0' + Math.floor(st.mtimeMs) + '\n'); });
		const fp = root + '\0' + (opts.pubHex || embeddedPubKey() || '') + '\0' + h.digest('hex');
		if (_installCache && _installCache.fp === fp && (Date.now() - _installCache.at) < INSTALL_CACHE_TTL_MS) return _installCache.result;
		const result = await verifyInstall(root, opts);
		_installCache = { fp, at: Date.now(), result };
		return result;
	} catch (_) { return verifyInstall(root, opts); } // any trouble fingerprinting → just verify directly
}

// MAINTAINER-side reminder: is a re-sign pending? This is only meaningful where the PRIVATE signing key is present
// (the maintainer's working copy) — an end-user install has no key and gets null, so this never reaches users. It
// uses the package.json VERSION as the release-intent signal: after you bump the version it reminds you to re-sign,
// without nagging on every mid-development file edit (the thorough file-hash check is `verifyInstall`, run by
// `npm run sign:check`). It looks for the key at its DEFAULT location under the app root. Returns:
//   null                                          — no signing key here (not the maintainer's machine)
//   { pending:false, version, signedVersion }     — the signed manifest's version matches package.json
//   { pending:true, reason:'unsigned', ... }      — a key exists but nothing has been signed yet
//   { pending:true, reason:'version-changed', ... } — package.json was bumped past the last signed version
async function signingPending(root) {
	root = path.resolve(root || Common.root());
	let hasKey = false; try { await fsp.access(path.join(root, KEY_NAME)); hasKey = true; } catch (_) {} // async, so the periodic self-check does no sync fs
	if (!hasKey) return null;
	let version = appVersion(); try { version = JSON.parse(await fsp.readFile(path.join(root, 'package.json'), 'utf8')).version || version; } catch (_) {}
	let manifest = null; try { manifest = JSON.parse(await fsp.readFile(path.join(root, MANIFEST_NAME), 'utf8')); } catch (_) {}
	if (!manifest) return { pending: true, reason: 'unsigned', version, signedVersion: null };
	if (manifest.version !== version) return { pending: true, reason: 'version-changed', version, signedVersion: manifest.version || null };
	return { pending: false, version, signedVersion: manifest.version || null };
}

module.exports = {
	MANIFEST_NAME, SIG_NAME, KEY_NAME, SCHEMA, EXCLUDE_TOP, EXCLUDE_NAME,
	embeddedPubKey, appVersion, hashFile, buildManifest, serialize, walkCovered, resolveWithin,
	signManifest, verifyManifestSig, publicKeyForSeed, verifyInstall, verifyInstallCached, signingPending,
};
