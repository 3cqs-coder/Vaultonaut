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
const DEFAULT_REPO = path.resolve(HERE, '..');
const DEFAULT_APP = path.join(HERE, 'app');
const RI = require(path.join(DEFAULT_REPO, 'lib', 'ReleaseIntegrity'));

// Embed the committed, maintainer-signed manifest into the staged bundle and verify it matches the staged files.
// Returns { signed:false } when nothing is committed (a pre-signing checkout — the bundle still runs, unsigned), or
// { signed:true, count, version } on success. THROWS on any fail-closed condition — nothing staged, no public key, a
// bad signature, or a stale manifest that no longer matches the staged files — so the build stops rather than ship a
// bundle whose signature does not verify. Parameterized on appDir/repoDir/pubHex for testability; the real build uses
// the defaults (the staged app/ and the repository root) and the embedded public key.
async function embedSignedManifest({ appDir = DEFAULT_APP, repoDir = DEFAULT_REPO, pubHex } = {}) {
	if (!fs.existsSync(path.join(appDir, 'vaultonaut.js'))) throw new Error('Nothing staged at ' + appDir + ' — run prepare-sidecar.js first.');
	const manifestSrc = path.join(repoDir, RI.MANIFEST_NAME);
	const sigSrc = path.join(repoDir, RI.SIG_NAME);
	if (!fs.existsSync(manifestSrc) || !fs.existsSync(sigSrc)) return { signed: false };
	// Copy the committed manifest + signature into the staged bundle, then verify they match the staged files.
	fs.copyFileSync(manifestSrc, path.join(appDir, RI.MANIFEST_NAME));
	fs.copyFileSync(sigSrc, path.join(appDir, RI.SIG_NAME));
	const r = await RI.verifyInstall(appDir, { pubHex: pubHex || RI.embeddedPubKey() });
	if (!r.present) throw new Error('the manifest did not copy into ' + appDir + '.');
	if (r.pubkey === false) throw new Error('lib/releasePubKey.js has no public key — run "node lib/scripts/sign-release.js --init".');
	if (!r.signatureValid) throw new Error('the committed manifest signature does not verify against the embedded public key. Re-sign with "node lib/scripts/sign-release.js".');
	if (!r.ok) { const e = new Error('the staged bundle does not match the committed signed manifest — the release manifest is stale. Re-sign with "node lib/scripts/sign-release.js" and commit it.'); e.details = { mismatches: r.mismatches || [], missing: r.missing || [], extraneous: r.extraneous || [] }; throw e; }
	return { signed: true, count: r.count, version: r.version };
}

async function main() {
	let res;
	try { res = await embedSignedManifest(); }
	catch (e) {
		console.error('Bundle signing failed: ' + (e && e.message || e));
		const d = e && e.details;
		if (d) {
			if (d.mismatches.length) console.error('  Changed: ' + d.mismatches.slice(0, 50).join(', ') + (d.mismatches.length > 50 ? ', …' : ''));
			if (d.missing.length) console.error('  Missing: ' + d.missing.slice(0, 50).join(', ') + (d.missing.length > 50 ? ', …' : ''));
			if (d.extraneous.length) console.error('  Unexpected: ' + d.extraneous.slice(0, 50).join(', ') + (d.extraneous.length > 50 ? ', …' : ''));
		}
		process.exit(1);
	}
	if (!res.signed) {
		console.log('No committed ' + RI.MANIFEST_NAME + ' / ' + RI.SIG_NAME + ' at the repository root — building an UNSIGNED bundle (the app still runs; its integrity self-check stays inert).');
		console.log('To make the desktop bundle verifiable, run "node lib/scripts/sign-release.js" on the maintainer machine and commit the manifest and signature.');
		return;
	}
	console.log('Embedded the signed manifest in the desktop bundle: ' + res.count + ' file(s), version ' + (res.version || '?') + '.');
	console.log('  ' + RI.MANIFEST_NAME + ' + ' + RI.SIG_NAME + ' copied into the staged bundle and verified against the embedded public key.');
}

module.exports = { embedSignedManifest };
if (require.main === module) main().catch((e) => { console.error('Bundle signing failed:', e && e.message || e); process.exit(1); });
