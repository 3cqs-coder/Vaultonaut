'use strict';
// lib/test/bundlemanifest.js — a DESKTOP bundle ships its dependencies as part of the signed artifact, so the
// bundle manifest must cover node_modules and detect tampering with any shipped dependency. A source-release
// manifest deliberately does NOT cover node_modules (npm re-fetches it with its own integrity). This locks in
// both: a modified or added dependency file fails verification for a bundle manifest, in-process and through the
// standalone verify.js, while a source manifest's behavior is unchanged.
//
// Run:  node -r ./lib/test/_setup.js lib/test/bundlemanifest.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const RI = require('../ReleaseIntegrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-bundlemanifest-'));
	const M = path.join(tmp, RI.MANIFEST_NAME), S = path.join(tmp, RI.SIG_NAME);
	const dep = path.join(tmp, 'node_modules', 'dep', 'index.js');
	try {
		// A tiny staged app with a first-party file and a shipped dependency.
		fs.writeFileSync(path.join(tmp, 'vaultonaut.js'), 'entry');
		fs.mkdirSync(path.join(tmp, 'lib')); fs.writeFileSync(path.join(tmp, 'lib', 'x.js'), 'first-party');
		fs.mkdirSync(path.join(tmp, 'node_modules', 'dep'), { recursive: true }); fs.writeFileSync(dep, 'dep-v1');
		fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
		const seed = crypto.randomBytes(32).toString('base64'); const pub = RI.publicKeyForSeed(seed);
		const signWith = (m) => { const buf = RI.serialize(m); fs.writeFileSync(M, buf); fs.writeFileSync(S, RI.signManifest(buf, seed) + '\n'); };

		// BUNDLE manifest — covers node_modules.
		const bundle = await RI.buildManifest(tmp, { withDependencies: true });
		ok('bundle manifest records coversDependencies', bundle.coversDependencies === true);
		ok('bundle manifest lists the shipped dependency file', bundle.files.some((f) => f.path === 'node_modules/dep/index.js'));
		signWith(bundle);
		ok('a clean bundle verifies ok (in-process)', (await RI.verifyInstall(tmp, { pubHex: pub })).ok === true);

		fs.writeFileSync(dep, 'dep-HACKED');
		ok('a modified dependency is detected (mismatch)', (await RI.verifyInstall(tmp, { pubHex: pub })).mismatches.includes('node_modules/dep/index.js'));

		fs.writeFileSync(dep, 'dep-v1'); // restore
		fs.writeFileSync(path.join(tmp, 'node_modules', 'dep', 'evil.js'), 'evil');
		ok('an added dependency file is detected (extraneous)', (await RI.verifyInstall(tmp, { pubHex: pub })).extraneous.includes('node_modules/dep/evil.js'));
		fs.rmSync(path.join(tmp, 'node_modules', 'dep', 'evil.js'));

		// SOURCE manifest — unchanged behavior: node_modules is NOT covered.
		const source = await RI.buildManifest(tmp);
		ok('source manifest omits coversDependencies', !source.coversDependencies);
		ok('source manifest does not list any dependency file', !source.files.some((f) => f.path.startsWith('node_modules/')));
		signWith(source);
		fs.writeFileSync(dep, 'source-does-not-track-this');
		ok('a source manifest ignores node_modules changes (unchanged)', (await RI.verifyInstall(tmp, { pubHex: pub })).ok === true);

		// The standalone verify.js honors the same self-described scope, end to end.
		fs.writeFileSync(dep, 'dep-v1'); signWith(bundle);
		const vjs = path.join(__dirname, '..', '..', 'verify.js');
		const runVerify = () => { try { return execFileSync('node', [vjs, tmp, '--pubkey', pub], { encoding: 'utf8' }); } catch (e) { return (e.stdout || '') + (e.stderr || ''); } };
		ok('standalone verify.js reports GENUINE for a clean bundle', /GENUINE/.test(runVerify()));
		fs.writeFileSync(dep, 'dep-HACKED-again');
		ok('standalone verify.js reports TAMPERED for a modified dependency', /TAMPERED/.test(runVerify()));
	} finally {
		try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BUNDLE-MANIFEST CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
