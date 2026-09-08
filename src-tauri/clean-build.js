'use strict';
// clean-build.js — produce a desktop build that carries NO build-machine identity, in one command, on macOS,
// Windows, or Linux. It copies the project to a NEUTRAL path (one with no username in it), installs dependencies
// fresh there, points CARGO_HOME at a neutral path too, and runs the normal build — so every path embedded in the
// binary is neutral even when you run this from your personal account. The build's own leak scan then verifies
// the result and fails if anything slipped through.
//
//   node clean-build.js [neutral-base-dir]
//
// Default neutral base per OS (all writable without elevation and free of any username):
//   macOS:   /Users/Shared/vaultonaut-build
//   Windows: %PUBLIC%\vaultonaut-build   (C:\Users\Public\vaultonaut-build)
//   Linux:   /var/tmp/vaultonaut-build
// Pass a different one if you prefer; any path with no username in it works.
//
// The base is created owner-only. The copied source never carries the private signing key or other secrets, so
// nothing sensitive is exposed there. When a signing key IS available, it is placed at the base for the build
// only — written owner-only and removed as soon as the build ends, even on failure — so the bundle is signed
// without the key ever lingering on a possibly-shared path. Signing is the default when a key is present; pass
// --no-sign to skip it, or --key <path> for a key kept outside the default location. See README.md.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { runNpm } = require('./buildutil');

const REPO = path.resolve(__dirname, '..');
const RI = require(path.join(REPO, 'lib', 'ReleaseIntegrity'));

function defaultBase() {
	if (process.platform === 'win32') return path.join(process.env.PUBLIC || 'C:\\Users\\Public', 'vaultonaut-build');
	if (process.platform === 'darwin') return '/Users/Shared/vaultonaut-build';
	return '/var/tmp/vaultonaut-build';
}

// Would building here embed a personal identity? Normalized (lower-case, forward slashes, no trailing slash) so
// it holds on case-insensitive Windows/macOS filesystems and for mixed separators. A safety net; the post-build
// scan is the real guarantee.
function looksPersonal(p) {
	const norm = (s) => String(s || '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
	const P = norm(p);
	let home = ''; try { home = norm(os.homedir()); } catch (_) {}
	let user = ''; try { user = String(os.userInfo().username || '').toLowerCase(); } catch (_) {}
	if (home && (P === home || P.startsWith(home + '/'))) return true;
	if (user && user.length >= 2 && (P.includes('/users/' + user) || P.includes('/home/' + user))) return true;
	return false;
}

// What must NOT be copied to the neutral base. Directories that are always build/dependency output are dropped
// at ANY depth; ambiguous names are anchored to their known top-level location so a future nested source folder
// of the same name is not silently lost; and secrets are dropped by exact basename anywhere. The secret names
// come from ReleaseIntegrity so the private key can never fall out of sync with the copy filter.
const ARTIFACT_SEGMENTS = new Set(['.git', 'node_modules', 'target']);
const ANCHORED_DIRS = new Set(['src-tauri/app', 'src-tauri/binaries', 'src-tauri/gen', 'src-tauri/.cargo', 'data', '.test-data']);
const SECRET_BASENAMES = new Set([RI.KEY_NAME, RI.MANIFEST_NAME, RI.SIG_NAME, 'SHA256SUMS', 'SHA256SUMS.sig', '.npmrc', '.env']);

function copyFilter(src) {
	const relPosix = path.relative(REPO, src).split(path.sep).join('/');
	if (relPosix === '' ) return true;                                   // the base dir itself
	if (relPosix.split('/').some((seg) => ARTIFACT_SEGMENTS.has(seg))) return false;
	if (ANCHORED_DIRS.has(relPosix)) return false;
	if (SECRET_BASENAMES.has(path.basename(src))) return false;
	return true;
}

function run(args, cwd, extraEnv) {
	const r = runNpm(args, { cwd, env: extraEnv });
	if (r.status !== 0) { console.error(`\nclean-build: "npm ${args.join(' ')}" failed (exit ${r.status}).`); process.exit(r.status || 1); }
}

// Parse the neutral base (a positional path) and the signing flags: --no-sign turns signing off; --key <path>
// names a signing key; --sign requires signing (fail if no key is found).
function parseArgs(argv) {
	const a = argv.slice(2);
	const ki = a.indexOf('--key');
	// A --key with no value (or immediately followed by another flag) is recorded as '' so it errors clearly,
	// rather than silently falling back to the default key.
	const keyVal = ki >= 0 ? (a[ki + 1] && !String(a[ki + 1]).startsWith('-') ? a[ki + 1] : '') : null;
	const flags = { noSign: a.includes('--no-sign'), sign: a.includes('--sign'), key: keyVal };
	flags.base = a.find((v, i) => !v.startsWith('-') && !(ki >= 0 && i === ki + 1)) || null;
	return flags;
}

// Decide whether — and with which key — to sign. Signing is the DEFAULT when a key is present, so a release from
// the maintainer's machine is signed without having to remember a flag; on a machine with no key it is skipped.
// --no-sign forces it off; --sign (or --key) makes it an error if the key is missing, for release automation.
function resolveSigningKey(flags) {
	if (flags.noSign) return { key: null };
	if (flags.key === '') return { key: null, missing: '--key needs a path' };
	const cand = flags.key ? path.resolve(flags.key) : path.join(REPO, RI.KEY_NAME);
	if (fs.existsSync(cand)) return { key: cand };
	if (flags.sign || flags.key) return { key: null, missing: cand };
	return { key: null };
}

// Place the signing key at the neutral base for the build only (owner-only), and remove it. Split out so they
// can be tested, and so the removal can be wired to run no matter how the process ends.
function placeSigningKey(base, keyPath) {
	const dest = path.join(base, RI.KEY_NAME);
	fs.copyFileSync(keyPath, dest);
	try { fs.chmodSync(dest, 0o600); } catch (_) {}
	return dest;
}
function removeSigningKey(dest) { if (dest) { try { fs.rmSync(dest, { force: true }); } catch (_) {} } }

function main() {
	const flags = parseArgs(process.argv);
	const signing = resolveSigningKey(flags);
	if (signing.missing) { console.error('\nclean-build: signing was requested but no key was found at ' + signing.missing + '.\n'); process.exit(1); }
	const BASE = path.resolve(flags.base || defaultBase());
	if (looksPersonal(BASE)) {
		console.error(`\nclean-build: refusing to build at ${BASE} — it is under your home / contains your username, which would`);
		console.error('embed your identity in the binary. Pass a neutral path (for example /var/tmp/vaultonaut-build).\n');
		process.exit(1);
	}
	console.log('Neutral build base: ' + BASE);

	// 1) Fresh copy of the source at the neutral path, created owner-only so nothing that lands there is exposed
	//    on a shared location; the copy filter drops VCS, deps, outputs, data, and — above all — secrets.
	fs.rmSync(BASE, { recursive: true, force: true });
	fs.mkdirSync(BASE, { recursive: true, mode: 0o700 });
	try { fs.chmodSync(BASE, 0o700); } catch (_) {} // enforce even if it already existed
	fs.cpSync(REPO, BASE, { recursive: true, filter: copyFilter });

	// 2) Install dependencies fresh at the neutral path (so nothing is carried from a personal node_modules): the
	//    app's runtime dependencies at the root, and the packaging tools under src-tauri.
	console.log('\nInstalling dependencies (fresh, at the neutral path)…');
	run(['install', '--no-audit', '--no-fund'], BASE);
	run(['install', '--no-audit', '--no-fund'], path.join(BASE, 'src-tauri'));

	// 3) If signing, place the key at the neutral base JUST for the build. The base is owner-only, the key is
	//    written owner-only, and it is removed immediately after the build — so it is never left on a shared
	//    location and is never part of the copied source (the copy filter excludes it). Without a key the build
	//    is unsigned by design.
	let keyAtBase = null;
	if (signing.key) {
		keyAtBase = placeSigningKey(BASE, signing.key);
		// Remove the key on ANY exit, including the immediate process.exit that a failed build triggers (which
		// would skip a finally). This guarantees the private key never lingers at the base after a build.
		process.on('exit', () => removeSigningKey(keyAtBase));
		console.log('Signing: using the key at ' + signing.key + ' (placed at the base only for this build).');
	} else {
		console.log('Signing: none (no key) — the bundle will be unsigned; pass --key <path> or place the signing key to sign.');
	}

	// 4) Build, with a neutral CARGO_HOME so the dependency cache paths are neutral too. npm run build runs the
	//    staging, the bundle signing (now that the key is in place), the Tauri build, and finally the leak scan —
	//    which fails the build if any build-machine identity remains.
	console.log('\nBuilding at the neutral path (CARGO_HOME is neutral too)…');
	try {
		run(['run', 'build'], path.join(BASE, 'src-tauri'), { CARGO_HOME: path.join(BASE, '.cargo') });
	} finally {
		removeSigningKey(keyAtBase);
	}

	console.log('\nClean build complete. Installer(s): ' + path.join(BASE, 'src-tauri', 'target', 'release', 'bundle'));
	console.log('The leak scan passed, so the artifacts contain no build-machine username, hostname, or home path.');
	console.log(keyAtBase ? 'The bundle is signed; verify it with verify.js against the public key in the README.' : 'The bundle is UNSIGNED.');
}

module.exports = { defaultBase, looksPersonal, copyFilter, parseArgs, resolveSigningKey, placeSigningKey, removeSigningKey, ARTIFACT_SEGMENTS, ANCHORED_DIRS, SECRET_BASENAMES, REPO };

if (require.main === module) main();
