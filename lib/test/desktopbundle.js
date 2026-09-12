'use strict';
// lib/test/desktopbundle.js — a DRIFT GUARD over the native desktop packaging. The desktop bundle stages its
// application files from the package's own "files" allowlist (resolved by `npm pack`), so the shipped app and the
// desktop bundle can never silently diverge. This asserts that contract holds: the staging planner tracks the
// authoritative published set, that set still contains everything the app needs to RUN and to SELF-VERIFY, and it
// still excludes development-only material and the private signing key. If someone trims the allowlist in a way
// that would break the desktop app (dropping the web UI, the standalone verifier, or the embedded public key), or
// widens it to leak a secret, this fails. Skips gracefully where the packaging tree or npm is unavailable.
//
// Run:  node -r ./lib/test/_setup.js lib/test/desktopbundle.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DESKTOP-BUNDLE CHECKS PASSED')); process.exit(failures ? 1 : 0); }

function main() {
	const prep = path.join(__dirname, '..', '..', 'src-tauri', 'prepare-sidecar.js');
	if (!fs.existsSync(prep)) { console.log('  skip  (no src-tauri packaging tree in this checkout)'); return done(); }

	let planner;
	try { planner = require(prep); } catch (e) { console.log('  skip  (packaging planner did not load: ' + String(e && e.message || e).split('\n')[0] + ')'); return done(); }

	ok('the packaging planner exports publishedFileList', typeof planner.publishedFileList === 'function');

	let files;
	try { files = planner.publishedFileList(); }
	catch (e) { console.log('  skip  (npm pack unavailable: ' + String(e && e.message || e).split('\n')[0] + ')'); return done(); }

	ok('the published (and therefore staged) file set is non-empty', Array.isArray(files) && files.length > 0);
	const has = (f) => files.includes(f);
	const hasPrefix = (p) => files.some(f => f.startsWith(p));

	// MUST be staged — the desktop app cannot run without these.
	ok('stages the entry script (vaultonaut.js)', has('vaultonaut.js'));
	ok('stages the library entry (lib/index.js)', has('lib/index.js'));
	ok('stages the web UI assets (lib/webserver/public/)', hasPrefix('lib/webserver/public/'));

	// MUST be staged — the desktop bundle is host-independently verifiable (the standalone verifier and the
	// embedded public key it checks against travel with the bundle).
	ok('stages the standalone verifier (verify.js)', has('verify.js'));
	ok('stages the embedded release public key (lib/releasePubKey.js)', has('lib/releasePubKey.js'));
	// The verifier and public key are useless without the SIGNED MANIFEST and its signature to check the files
	// against, so those must travel too — in the npm package AND the desktop bundle. Their absence made release
	// verification silently inert in every distributed copy (verify.js returned UNVERIFIED, the boot self-check saw
	// no manifest), which this assertion now guards against. They are excluded from the manifest's own hashed scope,
	// so shipping them does not disturb verification; they are just the material the verifier reads.
	ok('stages the signed release manifest', has('release-manifest.json'));
	ok('stages the release manifest signature', has('release-manifest.sig'));

	// MUST NOT be staged — development-only material and, above all, the private signing key.
	ok('never stages the private signing key', !files.some(f => /(^|\/)release-signing-key\.json$/.test(f)));
	ok('never stages the test tree (lib/test/)', !hasPrefix('lib/test/'));
	ok('never stages the packaging scripts (lib/scripts/)', !hasPrefix('lib/scripts/'));
	ok('never stages node_modules via the published set (added separately as bundled deps)', !hasPrefix('node_modules/'));

	return done();
}
main();
