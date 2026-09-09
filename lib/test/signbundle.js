'use strict';
// lib/test/signbundle.js — a FUNCTIONAL test of the desktop bundle-signing gate (src-tauri/sign-bundle.js). The build
// must EMBED the committed, maintainer-signed manifest by copying it into the staged bundle and then FAIL CLOSED if
// the staged files no longer match the manifest or the signature is bad — otherwise a stale re-sign would ship a
// bundle whose signature does not verify. When nothing is committed (a checkout from before signing was set up), it
// must instead leave an unsigned-but-working bundle so a non-maintainer build still succeeds. This drives the exported
// embedSignedManifest with throwaway app/ + repo directories and a synthetic key, so all four outcomes are exercised
// (not just pattern-matched). Skips cleanly when the packaging tree is not present in this checkout.
//
// Run:  node lib/test/signbundle.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const RI = require('../ReleaseIntegrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let signBundle;
try { signBundle = require('../../src-tauri/sign-bundle.js'); }
catch (e) { console.log('  skip  (no packaging tree in this checkout: ' + String(e && e.message || e).split('\n')[0] + ')'); process.exit(0); }

let tmp = null;
async function main() {
	if (typeof signBundle.embedSignedManifest !== 'function') { ok('sign-bundle exports embedSignedManifest', false); return done(); }
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vd-signbundle-'));
	const appDir = path.join(tmp, 'app'), repoDir = path.join(tmp, 'repo');
	await fsp.mkdir(path.join(appDir, 'lib'), { recursive: true });
	await fsp.mkdir(path.join(appDir, 'runtime'), { recursive: true });
	await fsp.mkdir(repoDir, { recursive: true });
	// A tiny staged bundle: the entry, a lib file, plus an out-of-scope runtime binary (not in the manifest).
	await fsp.writeFile(path.join(appDir, 'vaultonaut.js'), 'entry\n');
	await fsp.writeFile(path.join(appDir, 'lib', 'index.js'), 'module.exports = 1\n');
	await fsp.writeFile(path.join(appDir, 'runtime', 'node'), 'binary\n');
	const seed = crypto.randomBytes(32).toString('base64'), pub = RI.publicKeyForSeed(seed);
	const list = ['vaultonaut.js', 'lib/index.js'];
	const signInto = async () => { const m = await RI.buildManifestFromList(appDir, list); const buf = RI.serialize(m); await fsp.writeFile(path.join(repoDir, RI.MANIFEST_NAME), buf); await fsp.writeFile(path.join(repoDir, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n'); };

	// (a) Nothing committed → unsigned bundle, no throw.
	let res = await signBundle.embedSignedManifest({ appDir, repoDir, pubHex: pub });
	ok('no committed manifest leaves an unsigned bundle (no throw)', res && res.signed === false);

	// (b) A matching committed manifest → embedded, verified, and copied into the bundle.
	await signInto();
	res = await signBundle.embedSignedManifest({ appDir, repoDir, pubHex: pub });
	ok('a matching committed manifest embeds and verifies', res && res.signed === true && res.count === list.length);
	ok('the manifest and signature were copied into the staged bundle', fs.existsSync(path.join(appDir, RI.MANIFEST_NAME)) && fs.existsSync(path.join(appDir, RI.SIG_NAME)));

	// (c) A staged file changed after signing → stale → fail closed.
	await fsp.writeFile(path.join(appDir, 'lib', 'index.js'), 'module.exports = 999 // changed\n');
	let threw = false; try { await signBundle.embedSignedManifest({ appDir, repoDir, pubHex: pub }); } catch (_) { threw = true; }
	ok('a stale manifest (a staged file changed) fails the build closed', threw);
	await fsp.writeFile(path.join(appDir, 'lib', 'index.js'), 'module.exports = 1\n'); // restore

	// (d) A manifest signed with the wrong key → fail closed.
	await signInto();
	const buf = await fsp.readFile(path.join(repoDir, RI.MANIFEST_NAME));
	await fsp.writeFile(path.join(repoDir, RI.SIG_NAME), RI.signManifest(buf, crypto.randomBytes(32).toString('base64')) + '\n');
	threw = false; try { await signBundle.embedSignedManifest({ appDir, repoDir, pubHex: pub }); } catch (_) { threw = true; }
	ok('a manifest signed with the wrong key fails the build closed', threw);

	return done();
}

async function done() {
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SIGN-BUNDLE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
