'use strict';
// lib/test/packaging.js — a WATCHDOG over the published npm package. It must NEVER ship a secret (the release
// signing key), the test scratch tree, internal docs, or dev-only material, and it MUST include everything the app
// needs to run and to be release-verified. The package is defined by a package.json "files" ALLOWLIST — a denylist
// silently ships anything new, which once leaked the private signing key and the whole .test-data/ tree — so this
// asserts the REAL `npm pack` output stays clean. Skips gracefully where npm is not on PATH.
//
// Run:  node -r ./lib/test/_setup.js lib/test/packaging.js

const { execFileSync } = require('child_process');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function packFileList() {
	const root = path.join(__dirname, '..', '..');
	// On Windows npm is a .cmd shim and current Node refuses to spawn a .cmd without a shell (throws EINVAL), so
	// run it through the shell there. The arguments are all static, so this adds no injection surface.
	const isWin = process.platform === 'win32';
	const out = execFileSync(isWin ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, shell: isWin });
	const j = JSON.parse(out); // npm --json prints a clean JSON array to stdout
	return (j[0] && j[0].files || []).map(f => String(f.path).replace(/\\/g, '/'));
}

function main() {
	let files;
	try { files = packFileList(); }
	catch (e) { console.log('  skip  (npm pack unavailable: ' + String(e && e.message || e).split('\n')[0] + ')'); return done(); }

	ok('npm pack returned a non-empty file list', files.length > 0);

	// NEVER ship: a secret, the test tree, runtime data, internal docs, or dev-only material. The signed release
	// MANIFEST and its signature, by contrast, MUST ship (they are what the bundled verifier checks the files
	// against) — they are asserted as required below; only the private signing key must never leave the maintainer's
	// machine. SHA256SUMS is a plain corruption aid published on the releases page, not inside the package.
	const forbidden = [
		/(^|\/)release-signing-key\.json$/, /(^|\/)SHA256SUMS(\.sig)?$/,
		/(^|\/)\.test-data(\/|$)/, /(^|\/)data(\/|$)/,
		/(^|\/)docs\/BACKLOG\.md$/, /(^|\/)docs\/TEAM-VAULTS-DESIGN\.md$/, /(^|\/)docs\/SECURITY\.md$/, /(^|\/)docs\/THIRD-PARTY-LICENSES\.md$/,
		/(^|\/)lib\/test\//, /(^|\/)lib\/scripts\//, /(^|\/)\.githooks\//, /(^|\/)node_modules\//, /(^|\/)package-lock\.json$/,
			/(^|\/)src-tauri(\/|$)/ // the native desktop-packaging tree is development-only, never part of the published package
	];
	const leaked = files.filter(f => forbidden.some(re => re.test(f)));
	ok('the package ships NO secret, test tree, internal doc, or dev-only file' + (leaked.length ? ' — leaked: ' + leaked.slice(0, 6).join(', ') : ''), leaked.length === 0);

	// MUST ship: the app cannot run (or be verified) without these. The manifest and its signature are required so a
	// distributed copy can actually be verified by the bundled verifier and by the startup self-check.
	const required = ['vaultonaut.js', 'verify.js', 'release-manifest.json', 'release-manifest.sig', 'docs/README.md', 'LICENSE', 'CONTRIBUTING.md', 'lib/index.js', 'lib/Vault.js', 'lib/templates/help.txt'];
	const missing = required.filter(f => !files.includes(f));
	ok('the package includes every file the app needs to run' + (missing.length ? ' — missing: ' + missing.join(', ') : ''), missing.length === 0);
	ok('the package includes the web UI assets (lib/webserver/public)', files.some(f => f.startsWith('lib/webserver/public/')));

	return done();
}
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PACKAGING CHECKS PASSED')); process.exit(failures ? 1 : 0); }
main();
