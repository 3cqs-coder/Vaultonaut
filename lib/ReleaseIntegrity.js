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
async function walkCovered(root, onFile) {
	const topExcl = EXCLUDE_TOP;
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
async function buildManifest(root, { version } = {}) {
	root = path.resolve(root || Common.root());
	const files = [];
	await walkCovered(root, async (rel, abs, st) => { files.push({ path: rel, sha256: await hashFile(abs), size: st.size }); });
	files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
	return { schema: SCHEMA, product: require('./Brand').name, version: version || versionAt(root), algo: 'sha256', generatedAt: new Date().toISOString(), files };
}

// Build a manifest over an EXPLICIT list of POSIX-relative paths (rather than by walking the tree). The maintainer
// signs the published application file set — the exact files that ship in the package AND are staged into the
// desktop bundle — so ONE signed manifest verifies a source download, an npm install, and a desktop bundle alike.
// The list is the authoritative published set (resolved by the packager), so the runtime interpreter and node_modules,
// which each platform's build supplies on its own, are deliberately outside it. Paths are hashed relative to `root`.
async function buildManifestFromList(root, relPaths, { version } = {}) {
	root = path.resolve(root || Common.root());
	const files = [];
	for (const rel of relPaths) {
		if (EXCLUDE_TOP.has(rel) || EXCLUDE_NAME.has(rel)) continue; // never sign the manifest/sig/key themselves
		const abs = resolveWithin(root, rel);
		if (!abs) continue; // a path escaping the root is dropped (defense-in-depth; the packager never emits one)
		let st; try { st = await fsp.lstat(abs); } catch (_) { continue; } // lstat, so a symlink is skipped rather than signed as its target's content (matches the symlink-skip in the extraneous scan)
		if (!st.isFile()) continue;
		files.push({ path: String(rel), sha256: await hashFile(abs), size: st.size });
	}
	files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
	return { schema: SCHEMA, product: require('./Brand').name, version: version || versionAt(root), algo: 'sha256', generatedAt: new Date().toISOString(), files };
}

// The exact bytes that are written to disk AND signed — a stable, pretty-printed form with a trailing newline, so
// the signer and every verifier agree on the byte sequence the signature covers.
function serialize(manifest) { return Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8'); }

// The top-level entries (first path segment) that contain a listed file at any depth. Extraneous-file detection
// descends at the ROOT only into these, then recurses FULLY within each one — so a file added anywhere inside a
// covered top-level tree is caught, including in a brand-new nested subdirectory. Whole top-level entries with no
// listed file — the bundled runtime and node_modules — are never descended, so they stay cheap and unflagged.
//
// This is scoped to what a DISTRIBUTED artifact contains. The npm package and the desktop bundle carry only the
// published `files` allowlist (development-only trees such as lib/test and lib/scripts are stripped from them), so a
// full recurse there has no stray files to flag. A raw from-source checkout DOES carry those dev trees under the
// covered lib/ tree, so verify.js run against a clone will report them — a clone is not a signed release, so that is
// expected, not a defect. The boot self-check does not treat extra files as tampering (only a modified or missing
// signed file), so a from-source install is never falsely alarmed by its own development files.
function coveredTopEntries(listedPaths) {
	const top = new Set();
	for (const p of listedPaths) { const i = String(p).indexOf('/'); if (i > 0) top.add(p.slice(0, i)); }
	return top;
}

// Files absent from the manifest but present in the covered scope (an addition after signing). Recurses fully inside
// each covered top-level tree, but at the root descends only into those covered trees — so node_modules, the bundled
// runtime, and dev-only trees are never walked. Symlinks are never followed. Shared by verifyInstall here and mirrored
// by the standalone verify.js (a parity test keeps the two in sync).
async function extraneousFiles(root, listedSet) {
	root = path.resolve(root);
	const topDirs = coveredTopEntries(listedSet);
	const out = [];
	async function scan(relDir) {
		const abs = relDir ? resolveWithin(root, relDir) : root;
		if (!abs) return;
		let entries; try { entries = await fsp.readdir(abs, { withFileTypes: true }); } catch (_) { return; }
		for (const e of entries) {
			if (EXCLUDE_NAME.has(e.name)) continue;
			if (e.isSymbolicLink()) continue; // never follow a symlink during the scan
			const rel = relDir ? relDir + '/' + e.name : e.name;
			if (e.isDirectory()) {
				if (relDir) await scan(rel);                 // inside a covered tree: recurse fully
				else if (topDirs.has(e.name)) await scan(rel); // at the root: descend only into covered top-level trees
				continue;
			}
			if (!e.isFile()) continue;
			if (!relDir && EXCLUDE_TOP.has(e.name)) continue; // a top-level control file (manifest/sig/key/SHA256SUMS) is never extraneous
			if (!listedSet.has(rel)) out.push(rel);
		}
	}
	await scan('');
	return out;
}

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
	// Extraneous-file detection: a file present in a covered directory but absent from the manifest was ADDED after
	// signing (an attacker dropping a file in). The per-entry loop above cannot see it, so scan the covered directories.
	let extraneous = [];
	try { extraneous = await extraneousFiles(root, listed); } catch (_) {}
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

// Compare the COMMITTED signed manifest against a freshly-built one over `publishedList` (the exact published file
// set, resolved by the packager and passed in — this module never shells out to npm). Reports whether a re-sign is
// due (a shipped file changed, was added, or was removed) and whether the committed signature still verifies against
// the embedded key. Comparing the file HASHES — not the raw manifest bytes — is deliberate: a rebuild carries a fresh
// generatedAt timestamp, so the bytes always differ, but the covered content is what must match. Both the maintainer's
// `sign:check` and the release-signed gate test call this, so the interactive check and the fail-closed gate can never
// disagree. Only the published files are considered, so it is accurate on a working clone (dev-only files are ignored).
async function releaseSigningStatus(root, publishedList, { pubHex } = {}) {
	root = path.resolve(root || Common.root());
	let committedBuf = null; try { committedBuf = await fsp.readFile(path.join(root, MANIFEST_NAME)); } catch (_) {}
	if (!committedBuf) return { present: false };
	let committed; try { committed = JSON.parse(committedBuf.toString('utf8')); } catch (_) { return { present: true, readable: false }; }
	let sigB64 = null; try { sigB64 = (await fsp.readFile(path.join(root, SIG_NAME), 'utf8')).trim(); } catch (_) {}
	const pub = pubHex || embeddedPubKey();
	let sigValid = false; try { sigValid = !!pub && !!sigB64 && verifyManifestSig(committedBuf, sigB64, pub); } catch (_) {}
	const fresh = await buildManifestFromList(root, publishedList);
	const committedByPath = new Map((committed.files || []).map(f => [f.path, f.sha256]));
	const freshByPath = new Map(fresh.files.map(f => [f.path, f.sha256]));
	const changed = [], added = [], removed = [];
	for (const [p, h] of freshByPath) { if (!committedByPath.has(p)) added.push(p); else if (committedByPath.get(p) !== h) changed.push(p); }
	for (const p of committedByPath.keys()) if (!freshByPath.has(p)) removed.push(p);
	const matches = changed.length === 0 && added.length === 0 && removed.length === 0;
	return { present: true, readable: true, sigValid, matches, changed, added, removed, version: committed.version, count: (committed.files || []).length };
}

module.exports = {
	MANIFEST_NAME, SIG_NAME, KEY_NAME, SCHEMA, EXCLUDE_TOP, EXCLUDE_NAME,
	embeddedPubKey, appVersion, hashFile, buildManifest, buildManifestFromList, serialize, walkCovered, resolveWithin,
	coveredTopEntries, extraneousFiles, signManifest, verifyManifestSig, publicKeyForSeed, verifyInstall, verifyInstallCached, signingPending, releaseSigningStatus,
};
