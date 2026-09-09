#!/usr/bin/env node
'use strict';
// verify.js — a SELF-CONTAINED verifier that confirms this copy of the application is the authentic, unmodified
// release the maintainer signed. It needs nothing but a stock Node.js install: no npm install, no dependencies, no
// network. Point it at an installation folder (or run it from inside one) and it re-checks the maintainer's
// signature over the release manifest and every file's hash, then prints GENUINE or TAMPERED.
//
//   node verify.js [folder] [--pubkey <hex>]
//
// The trust root is the maintainer's Ed25519 PUBLIC key. For the strongest check, pass --pubkey with the value
// published in the README or on the official site — a key you obtained independently of this download. With no
// --pubkey, it falls back to the key embedded in the copy being checked, which is convenient but only proves the
// copy is internally consistent, not that it came from the maintainer.
//
// This file is intentionally dependency-free so it can be published, mirrored, or pasted anywhere and still verify
// a release years later. It mirrors the math in lib/ReleaseIntegrity.js.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MANIFEST_NAME = 'release-manifest.json';
const SIG_NAME = 'release-manifest.sig';
const KEY_NAME = 'release-signing-key.json';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // raw Ed25519 public key -> SPKI DER

// The covered scope — MUST stay in sync with EXCLUDE_TOP / EXCLUDE_NAME in lib/ReleaseIntegrity.js (a test asserts
// they match). Used only to flag EXTRANEOUS files (present but not in the manifest); the per-file hash check keys off
// the manifest, so a drift here can only produce a fail-closed (over-cautious) result, never a false pass.
const EXCLUDE_TOP = new Set(['.git', '.github', '.githooks', 'node_modules', 'package-lock.json', 'data', '.test-data', MANIFEST_NAME, SIG_NAME, KEY_NAME, 'SHA256SUMS', 'SHA256SUMS.sig']);
const EXCLUDE_NAME = new Set(['.DS_Store', 'Thumbs.db', KEY_NAME]);

function verifySig(pubHex, payloadBuf, sigB64) {
	try { const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' }); return crypto.verify(null, payloadBuf, pub, Buffer.from(sigB64, 'base64')); }
	catch (_) { return false; }
}
// Hash a file of ANY size without loading it whole into memory (a fixed 1 MB buffer), so verifying a large asset is
// bounded. Sync, to keep verifyRelease synchronous and this file trivially portable.
function hashFile(abs) {
	const h = crypto.createHash('sha256');
	const fd = fs.openSync(abs, 'r');
	try { const buf = Buffer.allocUnsafe(1 << 20); let n; while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(n === buf.length ? buf : buf.subarray(0, n)); }
	finally { fs.closeSync(fd); }
	return h.digest('hex');
}
// Resolve a manifest path under dir and reject one that escapes it (defense-in-depth against a crafted manifest).
function resolveWithin(dir, relPosix) {
	const abs = path.resolve(dir, ...String(relPosix).split('/'));
	const rel = path.relative(dir, abs);
	if (rel === '' || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return null;
	return abs;
}
// The top-level entries (first path segment) that contain a listed file at any depth. Extraneous-file detection
// descends at the root only into these, then recurses fully within each — so a file added anywhere inside the
// application's own tree (including a new nested subdirectory) is caught, while directories that hold no listed file
// (the bundled runtime, node_modules, a source checkout's dev-only trees) are never descended. This MUST match
// coveredTopEntries / extraneousFiles in lib/ReleaseIntegrity.js (a parity test keeps the two behaviors in sync).
function coveredTopEntries(listedPaths) {
	const top = new Set();
	for (const p of listedPaths) { const i = String(p).indexOf('/'); if (i > 0) top.add(p.slice(0, i)); }
	return top;
}
// Files absent from the manifest but present in the covered scope (an addition). Recurses fully inside each covered
// top-level tree; at the root descends only into those trees, so node_modules / the runtime are never walked.
// Symlinks are never followed.
function extraneousFiles(dir, listedSet) {
	dir = path.resolve(dir);
	const topDirs = coveredTopEntries(listedSet);
	const out = [];
	(function scan(relDir) {
		const abs = relDir ? resolveWithin(dir, relDir) : dir;
		if (!abs) return;
		let entries; try { entries = fs.readdirSync(abs, { withFileTypes: true }); } catch (_) { return; }
		for (const e of entries) {
			if (EXCLUDE_NAME.has(e.name)) continue;
			if (e.isSymbolicLink()) continue;
			const rel = relDir ? relDir + '/' + e.name : e.name;
			if (e.isDirectory()) {
				if (relDir) scan(rel);
				else if (topDirs.has(e.name)) scan(rel);
				continue;
			}
			if (!e.isFile()) continue;
			if (!relDir && EXCLUDE_TOP.has(e.name)) continue; // a top-level control file is never extraneous
			if (!listedSet.has(rel)) out.push(rel);
		}
	})('');
	return out;
}
function embeddedPubKey(dir) {
	try { const m = require(path.resolve(dir, 'lib', 'releasePubKey.js')); return (m && m.pubkey) || null; } catch (_) { return null; }
}

function verifyRelease(dir, pubHexArg) {
	dir = path.resolve(dir || '.');
	const out = { checks: [] };
	const add = (name, ok, detail) => { out.checks.push({ name, ok: !!ok, detail: detail || '' }); return ok; };
	let manifestBuf;
	try { manifestBuf = fs.readFileSync(path.join(dir, MANIFEST_NAME)); } catch (_) { add('manifest-present', false, 'No ' + MANIFEST_NAME + ' here — this folder has no signed release manifest.'); return { verdict: 'UNVERIFIED', ...out }; }
	add('manifest-present', true);
	let sigB64 = null; try { sigB64 = fs.readFileSync(path.join(dir, SIG_NAME), 'utf8').trim(); } catch (_) {}
	const usedEmbedded = !pubHexArg;
	const pubHex = pubHexArg || embeddedPubKey(dir);
	if (!pubHex) { add('public-key', false, 'No public key: pass --pubkey <hex> from the README, or the copy has no embedded key.'); return { verdict: 'UNVERIFIED', ...out }; }
	add('public-key', true, usedEmbedded ? 'Using the key embedded in this copy (pass --pubkey from the README for a stronger check).' : 'Using the key you supplied.');
	const sigOk = !!sigB64 && verifySig(pubHex, manifestBuf, sigB64);
	add('manifest-signature', sigOk, sigOk ? '' : 'The manifest signature does not verify against this key.');
	if (!sigOk) return { verdict: 'TAMPERED', ...out, usedEmbedded };
	let manifest; try { manifest = JSON.parse(manifestBuf.toString('utf8')); } catch (_) { add('manifest-readable', false, 'The manifest is not readable JSON.'); return { verdict: 'TAMPERED', ...out, usedEmbedded }; }
	const mismatches = [], missing = [];
	const listed = new Set();
	for (const f of manifest.files || []) {
		listed.add(String(f.path));
		const abs = resolveWithin(dir, f.path); // a path that escapes the folder is treated as a mismatch, never read
		let cur = null; try { cur = abs && hashFile(abs); } catch (_) { missing.push(f.path); continue; }
		if (!abs || cur !== f.sha256) mismatches.push(f.path);
	}
	// A file present in a covered directory but not in the manifest was added after signing — flag it too.
	const extraneous = extraneousFiles(dir, listed);
	const filesOk = mismatches.length === 0 && missing.length === 0 && extraneous.length === 0;
	add('file-hashes', filesOk, filesOk ? (manifest.files || []).length + ' file(s) match the signed manifest.' : (mismatches.length + ' changed, ' + missing.length + ' missing, ' + extraneous.length + ' unexpected'));
	return { verdict: filesOk ? 'GENUINE' : 'TAMPERED', ...out, usedEmbedded, version: manifest.version, product: manifest.product, mismatches, missing, extraneous };
}

if (require.main === module) {
	const args = process.argv.slice(2);
	let dir = '.', pub = null;
	for (let i = 0; i < args.length; i++) { if (args[i] === '--pubkey') pub = args[++i]; else if (!args[i].startsWith('--')) dir = args[i]; }
	const r = verifyRelease(dir, pub);
	console.log('Verdict:   ' + r.verdict + (r.product ? '   (' + r.product + (r.version ? ' ' + r.version : '') + ')' : ''));
	console.log('\nChecks:');
	for (const c of r.checks) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.name + (c.detail ? '  — ' + c.detail : ''));
	if (r.mismatches && r.mismatches.length) console.log('\nChanged files:\n  ' + r.mismatches.slice(0, 50).join('\n  ') + (r.mismatches.length > 50 ? '\n  … and ' + (r.mismatches.length - 50) + ' more' : ''));
	if (r.missing && r.missing.length) console.log('\nMissing files:\n  ' + r.missing.slice(0, 50).join('\n  ') + (r.missing.length > 50 ? '\n  … and ' + (r.missing.length - 50) + ' more' : ''));
	if (r.verdict === 'GENUINE' && r.usedEmbedded) console.log('\nThis confirms the copy is internally consistent. For proof it came from the maintainer, re-run with --pubkey set to the key published in the README.');
	if (r.verdict === 'UNVERIFIED') console.log('\nNothing was verified. A signed release includes ' + MANIFEST_NAME + ' and ' + SIG_NAME + '.');
	process.exit(r.verdict === 'GENUINE' ? 0 : 1);
}

module.exports = { verifyRelease, EXCLUDE_TOP, EXCLUDE_NAME, coveredTopEntries, extraneousFiles }; // EXCLUDE_* and the scan helpers exported so a test can assert they match lib/ReleaseIntegrity.js
