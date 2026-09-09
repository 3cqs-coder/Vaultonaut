'use strict';
// lib/test/releasesigned.js — the HOST-INDEPENDENT bundle-signing path. The maintainer signs ONE manifest over the
// published application file set on their own machine and commits it; every build (including CI, which never holds the
// private key) embeds that manifest into the desktop bundle. This pins the two properties that make that safe:
//   • a bundle-shaped tree — the published files PLUS a per-platform Node runtime and node_modules that are NOT in the
//     manifest — verifies GENUINE, because extraneous-file detection is scoped to the directories the manifest covers.
//     This is what lets a single committed signature verify all three desktop builds without covering per-platform bytes;
//   • adding a file INTO a covered directory is still caught, while the out-of-scope runtime/node_modules never trip it;
//   • releaseSigningStatus (which the maintainer's `sign:check` and this gate share) detects a changed/added/removed
//     shipped file — so a code change without a re-sign cannot pass.
// It also acts as the FAIL-CLOSED gate on the real repository: if a signed manifest is committed, it must still match
// the current published files and verify against the embedded key, or this test fails (blocking a release build).
//
// Pure Node, no engine or network needed.  Run:  node lib/test/releasesigned.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const RI = require('../ReleaseIntegrity');
const verify = require('../../verify');
const { verifyRelease } = verify;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-relsigned-'));

	// A maintainer keypair, and the published application file set staged as it would be in a desktop bundle: the
	// app's own files, PLUS a Node runtime and a node_modules dependency that the platform build supplies on its own.
	const seed = crypto.randomBytes(32).toString('base64');
	const pub = RI.publicKeyForSeed(seed);
	await fsp.mkdir(path.join(tmp, 'lib', 'webserver', 'public', 'js'), { recursive: true });
	await fsp.mkdir(path.join(tmp, 'docs'), { recursive: true });
	await fsp.mkdir(path.join(tmp, 'runtime'), { recursive: true });                 // the bundled interpreter (out of scope)
	await fsp.mkdir(path.join(tmp, 'node_modules', 'dep'), { recursive: true });      // a shipped dependency (out of scope)
	await fsp.writeFile(path.join(tmp, 'vaultonaut.js'), 'console.log(1)\n');
	await fsp.writeFile(path.join(tmp, 'verify.js'), '// verifier\n');
	await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({ name: 'x', version: '3.0.0' }));
	await fsp.writeFile(path.join(tmp, 'lib', 'index.js'), 'module.exports = 1\n');
	await fsp.writeFile(path.join(tmp, 'lib', 'webserver', 'public', 'js', 'app.js'), '// ui\n');
	await fsp.writeFile(path.join(tmp, 'docs', 'README.md'), '# hi\n');
	await fsp.writeFile(path.join(tmp, 'lib', 'releasePubKey.js'), "module.exports = { pubkey: '" + pub + "' };\n");
	await fsp.writeFile(path.join(tmp, 'runtime', 'node'), 'ELF-ish binary\n');
	await fsp.writeFile(path.join(tmp, 'node_modules', 'dep', 'index.js'), 'module.exports = 2\n');

	// The published list is the app's own files only — NOT the runtime and NOT node_modules.
	const published = ['vaultonaut.js', 'verify.js', 'package.json', 'lib/index.js', 'lib/webserver/public/js/app.js', 'docs/README.md', 'lib/releasePubKey.js'];

	const manifest = await RI.buildManifestFromList(tmp, published, { version: '3.0.0' });
	ok('buildManifestFromList covers exactly the published files', manifest.files.length === published.length && published.every(p => manifest.files.some(f => f.path === p)));
	ok('the manifest excludes the bundled runtime', !manifest.files.some(f => f.path.startsWith('runtime/')));
	ok('the manifest excludes node_modules', !manifest.files.some(f => f.path.startsWith('node_modules/')));
	const buf = RI.serialize(manifest);
	await fsp.writeFile(path.join(tmp, RI.MANIFEST_NAME), buf);
	await fsp.writeFile(path.join(tmp, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n');

	// THE CRUX: a bundle-shaped tree (runtime + node_modules present but unsigned) verifies clean, because extraneous
	// detection is scoped to the covered directories. A single committed signature therefore covers every platform.
	{
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a bundle-shaped tree (runtime + node_modules present) verifies ok', r.present && r.signatureValid && r.ok, );
		ok('the out-of-scope runtime is NOT flagged as extraneous', !(r.extraneous || []).some(p => p.startsWith('runtime/')));
		ok('the out-of-scope node_modules is NOT flagged as extraneous', !(r.extraneous || []).some(p => p.startsWith('node_modules/')));
		ok('verify.js agrees the bundle-shaped tree is GENUINE', verifyRelease(tmp, pub).verdict === 'GENUINE');
	}

	// A file added INTO a covered directory is still caught.
	{
		await fsp.writeFile(path.join(tmp, 'lib', 'evil.js'), 'require("child_process")\n');
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a file added into a covered directory is detected as extraneous', !r.ok && (r.extraneous || []).includes('lib/evil.js'));
		ok('verify.js reports TAMPERED for a covered-directory addition', verifyRelease(tmp, pub).verdict === 'TAMPERED');
		await fsp.rm(path.join(tmp, 'lib', 'evil.js'));
	}

	// A file added in a BRAND-NEW nested subdirectory under a covered tree is caught too (the scan recurses fully inside
	// a covered top-level tree, not just its immediate directory). This is the case a shallow scan would miss.
	{
		await fsp.mkdir(path.join(tmp, 'lib', 'webserver', 'public', 'js', 'newsub'), { recursive: true });
		await fsp.writeFile(path.join(tmp, 'lib', 'webserver', 'public', 'js', 'newsub', 'evil.js'), 'require("child_process")\n');
		const r = await RI.verifyInstall(tmp, { pubHex: pub });
		ok('a file in a new nested subdirectory under a covered tree is detected as extraneous', !r.ok && (r.extraneous || []).includes('lib/webserver/public/js/newsub/evil.js'));
		ok('verify.js reports TAMPERED for a nested-subdirectory addition', verifyRelease(tmp, pub).verdict === 'TAMPERED');
		await fsp.rm(path.join(tmp, 'lib', 'webserver', 'public', 'js', 'newsub'), { recursive: true, force: true });
	}

	// A file added into the OUT-OF-SCOPE runtime directory does NOT trip verification (it is not in the signed scope).
	{
		await fsp.writeFile(path.join(tmp, 'runtime', 'extra.so'), 'x\n');
		ok('an addition inside the out-of-scope runtime stays GENUINE', verifyRelease(tmp, pub).verdict === 'GENUINE');
		await fsp.rm(path.join(tmp, 'runtime', 'extra.so'));
	}

	// releaseSigningStatus — the shared "is a re-sign due?" check used by sign:check AND this gate. (The synthetic key
	// is passed explicitly; on the real repository the check falls back to the embedded public key.)
	{
		let s = await RI.releaseSigningStatus(tmp, published, { pubHex: pub });
		ok('releaseSigningStatus reports a matching, validly-signed manifest', s.present && s.readable && s.sigValid && s.matches);
		await fsp.writeFile(path.join(tmp, 'lib', 'index.js'), 'module.exports = 999\n'); // change a shipped file
		s = await RI.releaseSigningStatus(tmp, published, { pubHex: pub });
		ok('a changed shipped file makes releaseSigningStatus report out of date', !s.matches && s.changed.includes('lib/index.js'));
		await fsp.writeFile(path.join(tmp, 'lib', 'index.js'), 'module.exports = 1\n'); // restore
		await fsp.writeFile(path.join(tmp, 'lib', 'new.js'), 'module.exports = 3\n'); // a shipped file present but not yet signed
		s = await RI.releaseSigningStatus(tmp, published.concat(['lib/new.js']), { pubHex: pub });
		ok('a new shipped file (not yet signed) is reported as added', !s.matches && s.added.includes('lib/new.js'));
		await fsp.rm(path.join(tmp, 'lib', 'new.js'));
	}

	// A manifest re-signed with a DIFFERENT key fails against the embedded key (nobody can re-sign without the private key).
	{
		const evilSeed = crypto.randomBytes(32).toString('base64');
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), RI.signManifest(buf, evilSeed) + '\n');
		const s = await RI.releaseSigningStatus(tmp, published, { pubHex: pub });
		ok('a manifest signed with a different key fails the signature check', s.present && s.sigValid === false);
		await fsp.writeFile(path.join(tmp, RI.SIG_NAME), RI.signManifest(buf, seed) + '\n'); // restore
	}

	// PARITY: the extraneous-scan algorithm is hand-duplicated in lib/ReleaseIntegrity.js and verify.js. Assert the two
	// produce identical results on a tricky tree (a nested unlisted file, a stray root file, and a file in an
	// out-of-scope top-level directory), so the two copies can never silently drift on the exact case that changed.
	{
		await fsp.mkdir(path.join(tmp, 'lib', 'deep', 'deeper'), { recursive: true });
		await fsp.writeFile(path.join(tmp, 'lib', 'deep', 'deeper', 'x.js'), 'x\n'); // nested under covered lib/ → extraneous
		await fsp.writeFile(path.join(tmp, 'stray-root.txt'), 'x\n');                // stray root file → extraneous
		await fsp.writeFile(path.join(tmp, 'runtime', 'lib2.so'), 'x\n');            // out-of-scope top dir → NOT extraneous
		const listedSet = new Set(published);
		const a = (await RI.extraneousFiles(tmp, listedSet)).sort();
		const b = verify.extraneousFiles(tmp, listedSet).sort();
		ok('RI.extraneousFiles and verify.extraneousFiles agree on a tricky tree', JSON.stringify(a) === JSON.stringify(b));
		ok('the scan flags the nested and root additions but not the out-of-scope runtime file', a.includes('lib/deep/deeper/x.js') && a.includes('stray-root.txt') && !a.some(p => p.startsWith('runtime/')));
		const ta = [...RI.coveredTopEntries(listedSet)].sort();
		const tb = [...verify.coveredTopEntries(listedSet)].sort();
		ok('RI.coveredTopEntries and verify.coveredTopEntries agree', JSON.stringify(ta) === JSON.stringify(tb));
		await fsp.rm(path.join(tmp, 'lib', 'deep'), { recursive: true, force: true });
		await fsp.rm(path.join(tmp, 'stray-root.txt'), { force: true });
		await fsp.rm(path.join(tmp, 'runtime', 'lib2.so'), { force: true });
	}

	await gateOnRealRepo();
	return done();
}

// FAIL-CLOSED gate on the actual repository: once a signed manifest is committed, it MUST still match the current
// published files and verify against the embedded key. If it does not, a shipped file changed without a re-sign — fail,
// so a release build (which runs the suite first) is blocked. Skips cleanly when nothing is signed yet, or when the
// packaging planner / npm is unavailable to resolve the published set (e.g. a trimmed checkout).
async function gateOnRealRepo() {
	const repo = path.resolve(__dirname, '..', '..');
	if (!fs.existsSync(path.join(repo, RI.MANIFEST_NAME))) { console.log('  skip  no signed manifest committed yet — nothing to gate'); return; }
	let planner; try { planner = require(path.join(repo, 'src-tauri', 'prepare-sidecar.js')); } catch (_) { console.log('  skip  packaging planner unavailable — cannot resolve the published set'); return; }
	let published; try { published = planner.publishedFileList(); } catch (e) { console.log('  skip  npm pack unavailable: ' + String(e && e.message || e).split('\n')[0]); return; }
	const s = await RI.releaseSigningStatus(repo, published);
	ok('committed manifest signature verifies against the embedded key', s.sigValid === true);
	ok('committed manifest still matches the current published files (re-sign if this fails)', s.matches === true);
	if (!s.matches) { if (s.changed.length) console.log('    Changed: ' + s.changed.slice(0, 20).join(', ')); if (s.added.length) console.log('    Added: ' + s.added.slice(0, 20).join(', ')); if (s.removed.length) console.log('    Removed: ' + s.removed.slice(0, 20).join(', ')); }
	const pkgVer = (() => { try { return require(path.join(repo, 'package.json')).version; } catch (_) { return null; } })();
	ok('committed manifest version matches package.json (re-sign after a version bump)', s.version === pkgVer);
}

async function done() {
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELEASE-SIGNED CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
