'use strict';
// lib/test/cleanbuild.js — locks in the guards of the one-command identity-free build helper
// (src-tauri/clean-build.js). Two properties matter most: it must never copy the private signing key (or other
// secrets) to the neutral build base, and it must refuse to build at a personal path. Skips if the packaging
// tree is absent. Requiring the module does NOT run a build (it is guarded by require.main).
//
// Run:  node -r ./lib/test/_setup.js lib/test/cleanbuild.js

const fs = require('fs');
const os = require('os');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLEAN-BUILD CHECKS PASSED')); process.exit(failures ? 1 : 0); }

function main() {
	const mod = path.join(__dirname, '..', '..', 'src-tauri', 'clean-build.js');
	if (!fs.existsSync(mod)) { console.log('  skip  (no src-tauri packaging tree in this checkout)'); return done(); }
	const C = require(mod);
	const RI = require('../ReleaseIntegrity');
	const REPO = C.REPO;
	const at = (...p) => path.join(REPO, ...p);

	ok('exports the guards to test (looksPersonal, copyFilter, defaultBase)', typeof C.looksPersonal === 'function' && typeof C.copyFilter === 'function' && typeof C.defaultBase === 'function');

	// looksPersonal rejects paths under the real home / containing the username, and accepts neutral paths.
	ok('rejects the home directory itself', C.looksPersonal(os.homedir()) === true);
	ok('rejects a path under home', C.looksPersonal(path.join(os.homedir(), 'x', 'y')) === true);
	ok('accepts a neutral macOS shared path', C.looksPersonal('/Users/Shared/vaultonaut-build') === false);
	ok('accepts a neutral Linux path', C.looksPersonal('/var/tmp/vaultonaut-build') === false);

	// copyFilter must DROP secrets and build/dependency output, and KEEP real source.
	ok('DROPS the private signing key (never copied to the neutral base)', C.copyFilter(at(RI.KEY_NAME)) === false);
	ok('DROPS a stray .npmrc (could hold a token)', C.copyFilter(at('.npmrc')) === false);
	ok('DROPS a stray .env', C.copyFilter(at('.env')) === false);
	ok('DROPS .git', C.copyFilter(at('.git')) === false);
	ok('DROPS node_modules at any depth', C.copyFilter(at('node_modules')) === false && C.copyFilter(at('src-tauri', 'node_modules')) === false);
	ok('DROPS a nested target directory', C.copyFilter(at('src-tauri', 'target')) === false);
	ok('DROPS the staged src-tauri/app', C.copyFilter(at('src-tauri', 'app')) === false);
	ok('KEEPS the entry script', C.copyFilter(at('vaultonaut.js')) === true);
	ok('KEEPS library source', C.copyFilter(at('lib', 'Vault.js')) === true);
	// F5: a future nested source dir merely NAMED "app"/"data" is not dropped (excludes are anchored, not by basename).
	ok('KEEPS a nested source dir coincidentally named "app"', C.copyFilter(at('lib', 'webserver', 'app')) === true);

	// The default neutral base carries no username.
	let user = ''; try { user = String(os.userInfo().username || '').toLowerCase(); } catch (_) {}
	const base = C.defaultBase();
	ok('defaultBase is absolute', path.isAbsolute(base));
	ok('defaultBase contains no username', !(user && base.toLowerCase().includes(user)));

	// Argument parsing: a positional base plus the signing flags.
	ok('parseArgs reads a positional base and --no-sign', (() => { const f = C.parseArgs(['node', 'x', '/var/tmp/b', '--no-sign']); return f.base === '/var/tmp/b' && f.noSign === true; })());
	ok('parseArgs reads --key without mistaking its value for the base', (() => { const f = C.parseArgs(['node', 'x', '--key', '/k.json']); return f.key === '/k.json' && f.base === null; })());

	// Signing resolution: signs by default when a key is present (so a maintainer cannot forget), skips on
	// --no-sign, and errors when signing is explicitly requested but the key is missing.
	ok('--no-sign never signs', C.resolveSigningKey({ noSign: true }).key === null);
	ok('a present key is used (signs by default)', (() => {
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-key-')); const k = path.join(tmp, 'key.json'); fs.writeFileSync(k, '{}');
		const r = C.resolveSigningKey({ key: k }); fs.rmSync(tmp, { recursive: true, force: true }); return r.key === k;
	})());
	ok('explicit --sign with no key is an error (missing set)', !!C.resolveSigningKey({ sign: true, key: path.join(os.tmpdir(), 'definitely-absent-key.json') }).missing);
	ok('--key pointing at an absent file is an error (missing set)', !!C.resolveSigningKey({ key: path.join(os.tmpdir(), 'nope.json') }).missing);
	ok('--key with no value is an error, not a silent fallback', (() => { const f = C.parseArgs(['node', 'x', '--key']); return f.key === '' && !!C.resolveSigningKey(f).missing; })());

	// The signing key is placed owner-only for the build and removed afterward (the security-sensitive seam).
	{
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-signkey-')); const key = path.join(tmp, 'key.json'); fs.writeFileSync(key, '{"seed":"x"}');
		const base = path.join(tmp, 'base'); fs.mkdirSync(base);
		const dest = C.placeSigningKey(base, key);
		ok('placeSigningKey puts the key under the base', dest === path.join(base, RI.KEY_NAME) && fs.existsSync(dest));
		if (process.platform !== 'win32') ok('the placed key is owner-only (0600)', (fs.statSync(dest).mode & 0o777) === 0o600);
		else ok('the placed key exists (permissions are a POSIX concept)', fs.existsSync(dest));
		C.removeSigningKey(dest);
		ok('removeSigningKey deletes the key', !fs.existsSync(dest));
		C.removeSigningKey(dest); // idempotent, no throw on a missing file
		ok('removeSigningKey is idempotent', !fs.existsSync(dest));
		fs.rmSync(tmp, { recursive: true, force: true });
	}

	return done();
}
main();
