#!/usr/bin/env node
'use strict';
// lib/scripts/verify-build.js — the REPRODUCIBLE-BUILD verifier. Run it against a source checkout at a release tag to
// prove that the committed, signed release manifest is EXACTLY reproducible from that public source — so the code the
// signed release describes is precisely the public code, with nothing hidden. It needs no private key and no network.
//
//   node lib/scripts/verify-build.js [--pubkey <hex>]        (or: npm run verify:build)
//
// It does two independent things and reports both:
//   1. REPRODUCIBLE — rebuild the manifest's covered content from the current source (the exact published file set,
//      resolved by the packager) and confirm its reproducible digest equals the committed manifest's. This is the
//      part that closes the trust gap the signature alone cannot: a signature proves the maintainer signed the
//      manifest, this proves the manifest is the public source.
//   2. SIGNATURE — confirm the committed manifest's Ed25519 + post-quantum signatures verify against the maintainer's
//      public key. Pass --pubkey with the value from the README (a key obtained independently) for the strongest check;
//      with none, the key embedded in this checkout is used (internal-consistency only).
//
// The single number to compare/publish is the REPRODUCIBLE DIGEST it prints — anyone regenerating it from the same
// source at the same tag gets the identical value. Chain of trust: this tool proves signed-manifest == public-source;
// verify.js proves a downloaded copy == signed-manifest; together they prove a download == public source.
//
// Dev-only (it resolves the packaging planner, which ships with the source but never with the app). Non-blocking:
// all file hashing is async. Cross-platform: paths in the manifest are POSIX-normalized by the packager, so the digest
// is identical on macOS, Windows, and Linux.

const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');
const RI = require('../ReleaseIntegrity');

function arg(name) { const i = process.argv.indexOf(name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : null; }

function publishedFileList() {
	let planner;
	try { planner = require(path.join(ROOT, 'src-tauri', 'prepare-sidecar.js')); }
	catch (e) { throw new Error('cannot resolve the published file set — the packaging planner (src-tauri/prepare-sidecar.js) did not load: ' + (e && e.message || e)); }
	return planner.publishedFileList();
}

// Compare two path-sorted file lists into { changed, added, removed } by path + sha256, so a mismatch names exactly
// what differs between the signed manifest and the source rebuild.
function diffFiles(committed, rebuilt) {
	const cm = new Map((committed || []).map((f) => [f.path, f.sha256]));
	const rm = new Map((rebuilt || []).map((f) => [f.path, f.sha256]));
	const changed = [], added = [], removed = [];
	for (const [p, h] of rm) { if (!cm.has(p)) added.push(p); else if (cm.get(p) !== h) changed.push(p); }
	for (const p of cm.keys()) { if (!rm.has(p)) removed.push(p); }
	return { changed: changed.sort(), added: added.sort(), removed: removed.sort() };
}

(async () => {
	const manifestPath = path.join(ROOT, RI.MANIFEST_NAME);
	let committedBuf; try { committedBuf = fs.readFileSync(manifestPath); } catch (_) { console.error('No ' + RI.MANIFEST_NAME + ' here — nothing to verify. Sign a release first.'); process.exit(1); }
	let committed; try { committed = JSON.parse(committedBuf.toString('utf8')); } catch (_) { console.error(RI.MANIFEST_NAME + ' is not readable JSON.'); process.exit(1); }

	// 1. Reproduce the manifest content from the current source and compare digests.
	const rebuilt = await RI.buildManifestFromList(ROOT, publishedFileList());
	const digestCommitted = RI.reproducibleDigest(committed);
	const digestRebuilt = RI.reproducibleDigest(rebuilt);
	const reproducible = digestCommitted === digestRebuilt;

	// 2. Verify the committed manifest's signatures against the maintainer's public key.
	const pubArg = arg('--pubkey');
	const pub = pubArg || RI.embeddedPubKey(ROOT);
	const pqPub = RI.embeddedPqPubKey(ROOT);
	let sigB64 = null, sigPqB64 = null;
	try { sigB64 = fs.readFileSync(path.join(ROOT, RI.SIG_NAME), 'utf8').trim(); } catch (_) {}
	try { sigPqB64 = fs.readFileSync(path.join(ROOT, RI.SIG_PQ_NAME), 'utf8').trim(); } catch (_) {}
	const sigValid = !!pub && !!sigB64 && RI.verifyManifestSigHybrid(committedBuf, sigB64, sigPqB64, pub, pqPub);

	console.log('Reproducible build check — ' + (committed.product || 'release') + ' ' + (committed.version || '?'));
	console.log('');
	console.log('  Reproducible digest (committed): ' + digestCommitted);
	console.log('  Reproducible digest (rebuilt):   ' + digestRebuilt);
	console.log('  ' + (reproducible ? 'ok  ' : 'FAIL') + '  REPRODUCIBLE — the signed manifest matches a rebuild from this source' + (reproducible ? '' : ' (they DIFFER)'));
	console.log('  ' + (sigValid ? 'ok  ' : 'FAIL') + '  SIGNATURE — the committed manifest is signed by ' + (pubArg ? 'the supplied key' : 'the embedded key') + (sigValid ? '' : ' (does NOT verify)'));
	console.log('  Public key' + (pubArg ? ' (supplied)' : ' (embedded — pass --pubkey from the README for a stronger check)') + ': ' + (pub || '(none)'));

	if (!reproducible) {
		const d = diffFiles(committed.files, rebuilt.files);
		if (d.changed.length) console.log('\n  Changed vs source: ' + d.changed.slice(0, 50).join(', ') + (d.changed.length > 50 ? ', …' : ''));
		if (d.added.length) console.log('  In source, not in manifest: ' + d.added.slice(0, 50).join(', ') + (d.added.length > 50 ? ', …' : ''));
		if (d.removed.length) console.log('  In manifest, not in source: ' + d.removed.slice(0, 50).join(', ') + (d.removed.length > 50 ? ', …' : ''));
	}

	const good = reproducible && sigValid;
	console.log('\n' + (good ? 'VERIFIED — this signed release is reproducible from the public source.' : 'NOT VERIFIED — see the failed check(s) above.'));
	process.exit(good ? 0 : 1);
})().catch((e) => { console.error('verify-build failed: ' + (e && e.message ? e.message : e)); process.exit(1); });
