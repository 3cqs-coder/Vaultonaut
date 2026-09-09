'use strict';
// sign-bundle.js — make the DESKTOP bundle host-independently verifiable using the project's own signing key (the
// same Ed25519 trust root as a source release — no operating-system code-signing certificate, no Apple or Microsoft
// account, nothing platform-locked).
//
// It does NOT sign here, and needs no private key: the maintainer signs the release manifest ONCE on their own
// machine (node lib/scripts/sign-release.js) and commits release-manifest.json + release-manifest.sig. Those cover
// the published application file set — the exact files prepare-sidecar stages into app/ — so this step simply COPIES
// them into the staged bundle and then verifies they match what was staged. Because the manifest is committed, every
// build embeds the maintainer's signature the same way, whether it runs on the maintainer's machine or on a hosted CI
// runner that never holds the key. The bundled Node runtime and node_modules are outside the manifest's scope (each
// platform's build supplies its own); the runtime is pinned to a fixed official version by prepare-sidecar, and
// node_modules carries npm's own provenance.
//
// Run AFTER prepare-sidecar.js (which stages app/) and BEFORE the Tauri build (which copies app/ into the installer).
//   node sign-bundle.js
//
// Fail-closed: if the committed manifest is present but does NOT match the staged files, the build stops — a stale or
// missing re-sign can never ship a bundle whose signature does not verify. If NO manifest is committed at all (a
// checkout from before signing was set up), it leaves an unsigned-but-working bundle whose self-check stays inert,
// exactly like an unsigned source checkout, so a non-maintainer build still succeeds.

const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..');
const APP_DIR = path.join(HERE, 'app');
const RI = require(path.join(REPO, 'lib', 'ReleaseIntegrity'));

async function main() {
	if (!fs.existsSync(path.join(APP_DIR, 'vaultonaut.js'))) {
		console.error('Nothing staged at ' + path.relative(REPO, APP_DIR) + ' — run prepare-sidecar.js first.');
		process.exit(1);
	}

	const manifestSrc = path.join(REPO, RI.MANIFEST_NAME);
	const sigSrc = path.join(REPO, RI.SIG_NAME);
	if (!fs.existsSync(manifestSrc) || !fs.existsSync(sigSrc)) {
		// No committed signature: leave the bundle unsigned. It still runs; its self-check stays inert (no manifest to
		// check), exactly like an unsigned source checkout. This keeps a checkout from before signing was set up working.
		console.log('No committed ' + RI.MANIFEST_NAME + ' / ' + RI.SIG_NAME + ' at the repository root — building an UNSIGNED bundle (the app still runs; its integrity self-check stays inert).');
		console.log('To make the desktop bundle verifiable, run "node lib/scripts/sign-release.js" on the maintainer machine and commit the manifest and signature.');
		return;
	}

	// Copy the committed manifest + signature into the staged bundle, then verify they match the staged files.
	fs.copyFileSync(manifestSrc, path.join(APP_DIR, RI.MANIFEST_NAME));
	fs.copyFileSync(sigSrc, path.join(APP_DIR, RI.SIG_NAME));

	const r = await RI.verifyInstall(APP_DIR, { pubHex: RI.embeddedPubKey() });
	if (!r.present) { console.error('Bundle signing failed: the manifest did not copy into ' + path.relative(REPO, APP_DIR) + '.'); process.exit(1); }
	if (r.pubkey === false) { console.error('Bundle signing failed: lib/releasePubKey.js has no public key — run "node lib/scripts/sign-release.js --init".'); process.exit(1); }
	if (!r.signatureValid) { console.error('Bundle signing failed: the committed manifest signature does not verify against the embedded public key. Re-sign with "node lib/scripts/sign-release.js".'); process.exit(1); }
	if (!r.ok) {
		console.error('Bundle signing failed: the staged bundle does not match the committed signed manifest — the release manifest is stale. Re-sign with "node lib/scripts/sign-release.js" and commit it.');
		if (r.mismatches && r.mismatches.length) console.error('  Changed: ' + r.mismatches.slice(0, 50).join(', ') + (r.mismatches.length > 50 ? ', …' : ''));
		if (r.missing && r.missing.length) console.error('  Missing: ' + r.missing.slice(0, 50).join(', ') + (r.missing.length > 50 ? ', …' : ''));
		if (r.extraneous && r.extraneous.length) console.error('  Unexpected: ' + r.extraneous.slice(0, 50).join(', ') + (r.extraneous.length > 50 ? ', …' : ''));
		process.exit(1);
	}
	console.log('Embedded the signed manifest in the desktop bundle: ' + r.count + ' file(s), version ' + (r.version || '?') + '.');
	console.log('  ' + RI.MANIFEST_NAME + ' + ' + RI.SIG_NAME + ' copied into ' + path.relative(REPO, APP_DIR) + ' and verified against the embedded public key.');
}

main().catch((e) => { console.error('Bundle signing failed:', e && e.message || e); process.exit(1); });
