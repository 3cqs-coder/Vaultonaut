'use strict';
// prepare-sidecar.js — stage everything the native desktop shell bundles, using only Node built-ins so it
// runs identically on macOS, Windows, and Linux with nothing to install. It does two things:
//
//   1. Copy the current Node runtime to runtime/node (plus .exe on Windows). The desktop shell runs the app
//      through this bundled runtime, so the end user needs no separate Node installation. It is bundled as an
//      ordinary resource (Contents/Resources/runtime on macOS) — deliberately NOT as a bundler "sidecar",
//      which would place it in Contents/MacOS where macOS would give it its own Dock tile.
//   2. Stage the application into app/ — the SAME files the published package ships, plus the production
//      dependencies. The shell launches app/vaultonaut.js from this staged copy.
//
// No-drift by construction: the set of application files is not a hand-maintained list here. It is taken from
// the package's own "files" allowlist, resolved by the package manager itself (the exact set that would be
// published), so anything added to or removed from the shipped app automatically flows into the desktop bundle
// too — the two can never silently diverge. A test asserts this staging tracks that authoritative set.
//
// Everything here uses only Node built-ins and adapts to the host (the .exe suffix on Windows, executable bits
// on POSIX), so the same script stages a bundle correctly on macOS, Windows, and Linux.

const fs = require('fs');
const path = require('path');
const { runNpm } = require('./buildutil');

const HERE = __dirname;
const REPO = path.resolve(HERE, '..');
const APP_DIR = path.join(HERE, 'app');
// The bundled runtime lives INSIDE the staged app tree so it ships with the bundle, but it is OUTSIDE the signed
// manifest's scope: the manifest covers the published application files, which are identical on every platform, so a
// single committed signature verifies all three desktop builds. The interpreter cannot be in that scope because each
// platform bundles a different Node binary; its authenticity comes instead from the fixed version pin below (every
// build must run on exactly that official Node) plus the checksum-verifying toolchain that fetched it.
const RUNTIME_DIR = path.join(APP_DIR, 'runtime');

function rimraf(p) { fs.rmSync(p, { recursive: true, force: true }); }

// The authoritative application file set: the package's own "files" allowlist, resolved by the package manager
// exactly as it would be for publishing (so the tests/packaging trees and the private signing key are already
// excluded, and any future change to what ships is reflected here for free). POSIX-relative paths.
function publishedFileList() {
	const r = runNpm(['pack', '--dry-run', '--json'], { cwd: REPO, capture: true });
	if (r.status !== 0) throw new Error('npm pack failed: ' + (r.stderr || (r.error && r.error.message) || ('exit ' + r.status)));
	const j = JSON.parse(r.stdout); // npm --json prints a clean JSON array to stdout
	return (j[0] && j[0].files || []).map(f => String(f.path).replace(/\\/g, '/')).sort();
}

// Copy the running Node executable into the bundle's runtime resource (app/runtime/node, or node.exe on
// Windows). It is a plain resource, not a bundler "sidecar", so on macOS it stays out of Contents/MacOS and
// raises no Dock tile of its own. Call AFTER stageApp (which recreates app/). It ships inside app/ but is outside
// the signed manifest's scope (see the RUNTIME_DIR note above); its version is pinned instead.
function stageRuntime() {
	fs.mkdirSync(RUNTIME_DIR, { recursive: true });
	const dest = path.join(RUNTIME_DIR, process.platform === 'win32' ? 'node.exe' : 'node');
	fs.copyFileSync(process.execPath, dest);
	if (process.platform !== 'win32') fs.chmodSync(dest, 0o755);
	return dest;
}

// Stage the runtime application: every published file, in the same layout, plus the production dependencies.
// node_modules is added on top of the published set (a fresh install resolves it separately; a self-contained
// desktop bundle must carry it). It is deliberately absent from the release manifest's covered scope, exactly
// as in a normal install, so bundling it changes nothing about verification.
function stageApp() {
	rimraf(APP_DIR);
	fs.mkdirSync(APP_DIR, { recursive: true });

	for (const rel of publishedFileList()) {
		const from = path.join(REPO, rel);
		if (!fs.existsSync(from)) continue; // a listed path that is not a regular file (should not happen) is skipped safely
		const to = path.join(APP_DIR, rel);
		fs.mkdirSync(path.dirname(to), { recursive: true });
		fs.copyFileSync(from, to);
	}

	const nmFilter = (src) => { const b = path.basename(src); return b !== '.git' && b !== '.test-data'; };
	fs.cpSync(path.join(REPO, 'node_modules'), path.join(APP_DIR, 'node_modules'), { recursive: true, filter: nmFilter });
	return APP_DIR;
}

function dirSizeMB(p) {
	let total = 0;
	const walk = (d) => {
		for (const e of fs.readdirSync(d, { withFileTypes: true })) {
			const full = path.join(d, e.name);
			if (e.isDirectory()) walk(full);
			else { try { total += fs.statSync(full).size; } catch (_) {} }
		}
	};
	try { walk(p); } catch (_) {}
	return (total / (1024 * 1024)).toFixed(1);
}

// The desktop bundle ships whatever Node runs this staging step, so its runtime version is fixed at build time.
// Two requirements drive the pin below:
//   1. Every platform's installer must bundle the SAME Node version. The macOS, Windows, and Linux builds each
//      run on their own machine, so without a pin they would drift to whatever each machine happens to have.
//   2. The compiled app must enable EVERY feature. One capability is version-gated: the post-quantum protection
//      on anything sealed to a person's public key needs Node 24.7+ (older runtimes fall back to a classical
//      method), so the pin must stay at or above 24.7.
// The pin is single-sourced here and bumped deliberately with a release (the same discipline as the encryption
// engine's pinned version). The build refuses to run on any other Node so a mismatched or feature-limited runtime
// can never be shipped.
const PINNED_NODE = '24.11.1'; // MUST be >= 24.7; every platform build must use exactly this version
function enforceRuntimeVersion() {
	if (process.versions.node !== PINNED_NODE) {
		console.error(`\nRefusing to build the desktop app on Node ${process.versions.node}. Every platform's installer must bundle`);
		console.error(`the same runtime, so this build requires exactly Node ${PINNED_NODE}. Install it (for example with nvm,`);
		console.error('fnm, or volta, or from nodejs.org) and build again. Bump PINNED_NODE in prepare-sidecar.js to move it.\n');
		process.exit(1);
	}
}

function main() {
	enforceRuntimeVersion();
	const app = stageApp();       // recreates app/ (the published files + node_modules)
	const runtime = stageRuntime(); // then drops the runtime inside it (shipped with the bundle; pinned by version, not signed)
	console.log(`Staged app:     ${path.relative(REPO, app)}  (${dirSizeMB(app)} MB)`);
	console.log(`Node runtime:   ${path.relative(REPO, runtime)}`);
	console.log('Ready to build the desktop shell (sign the bundle next, then run the Tauri build).');
}

// Exported so a drift-guard test can assert the desktop bundle tracks the published file set without running a
// full build. Requiring this module never performs any staging.
module.exports = { publishedFileList, APP_DIR, RUNTIME_DIR, REPO, PINNED_NODE };

if (require.main === module) main();
