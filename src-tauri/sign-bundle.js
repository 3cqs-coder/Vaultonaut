'use strict';
// sign-bundle.js — make the DESKTOP bundle host-independently verifiable, using the project's own signing key
// (the same Ed25519 trust root as a source release — no operating-system code-signing certificate, no Apple or
// Microsoft account, nothing platform-locked).
//
// The source release manifest covers the full source tree and cannot describe the trimmed runtime tree the
// desktop bundle carries. So this signs a manifest scoped to the STAGED bundle itself: it builds the manifest
// over src-tauri/app (the exact files the shell will ship), signs it with the maintainer's key, and writes
// app/release-manifest.json + app/release-manifest.sig. Because the manifest is generated over that same tree,
// the bundled verify.js and the app's boot-time self-check both confirm it cleanly — and anyone can re-check the
// installed app against the public key from the README, independent of any platform.
//
// Run AFTER prepare-sidecar.js (which stages app/) and BEFORE the Tauri build (which copies app/ into the
// installer). Best-effort by design: on a machine without the private signing key (any non-maintainer build) it
// prints a notice and exits 0, leaving an unsigned-but-fully-working bundle whose self-check stays inert.
//
//   node sign-bundle.js [--key <path-to-release-signing-key.json>]

const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..');
const APP_DIR = path.join(HERE, 'app');
const RI = require(path.join(REPO, 'lib', 'ReleaseIntegrity'));

function arg(name, def) { const i = process.argv.indexOf(name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def; }

function loadSeed(keyPath) {
	let raw;
	try { raw = JSON.parse(fs.readFileSync(keyPath, 'utf8')); } catch (_) { return null; }
	return raw && raw.seed ? raw.seed : null;
}

async function main() {
	if (!fs.existsSync(path.join(APP_DIR, 'vaultonaut.js'))) {
		console.error('Nothing staged at ' + path.relative(REPO, APP_DIR) + ' — run prepare-sidecar.js first.');
		process.exit(1);
	}

	const keyPath = path.resolve(arg('--key', path.join(REPO, RI.KEY_NAME)));
	const seed = loadSeed(keyPath);
	if (!seed) {
		// No maintainer key on this machine: leave the bundle unsigned. It still runs; its self-check stays inert
		// (no manifest to check), exactly like an unsigned source checkout. This keeps non-maintainer builds working.
		console.log('No signing key at ' + path.relative(REPO, keyPath) + ' — building an UNSIGNED bundle (the app still runs; its integrity self-check stays inert).');
		console.log('To make the desktop bundle verifiable, sign on the maintainer machine that holds ' + RI.KEY_NAME + '.');
		return;
	}

	// Cover the whole bundle, INCLUDING node_modules: unlike a source release (where npm re-fetches dependencies
	// with its own integrity), the desktop bundle SHIPS its dependencies as part of the signed artifact, so they
	// must be attested too or a tamperer could alter shipped third-party code and still pass verification.
	const manifest = await RI.buildManifest(APP_DIR, { withDependencies: true });
	const buf = RI.serialize(manifest);
	fs.writeFileSync(path.join(APP_DIR, RI.MANIFEST_NAME), buf);
	fs.writeFileSync(path.join(APP_DIR, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n');
	console.log('Signed the desktop bundle: ' + manifest.files.length + ' file(s), version ' + manifest.version + '.');
	console.log('  ' + RI.MANIFEST_NAME + ' + ' + RI.SIG_NAME + ' written into the staged bundle (verify.js / boot self-check).');
	console.log('Public key (must match the README): ' + RI.publicKeyForSeed(seed));
}

main().catch((e) => { console.error('Bundle signing failed:', e && e.message || e); process.exit(1); });
