'use strict';
// lib/test/binprecedence.js — pins the full precedence contract of Common.binDir(), the resolver that decides where the
// storage engine lives. The order is: an explicit setBinDir() wins; then, ONLY in a real (non-test) process, the
// VAULTONAUT_ENGINE_DIR environment variable (the container points this at its baked /engine); then the default under
// the data dir. The test-process carve-out matters: a stray VAULTONAUT_ENGINE_DIR in a dev or CI shell must never
// steer a test run at some other engine, so a test-launched process ignores the env entirely. This guards that logic
// against a refactor that reorders the checks or drops the test carve-out.
//
// Run:  node -r ./lib/test/_setup.js lib/test/binprecedence.js

const path = require('path');
const { spawnSync } = require('child_process');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const REPO = path.join(__dirname, '..', '..');
const COMMON = path.join(REPO, 'lib', 'Common.js');

// (1) setBinDir() is the highest-precedence source and wins even inside the test process. Set it, confirm, then clear.
const savedBin = Common.binDir();
const custom = path.join(REPO, '.test-data', 'custom-engine');
Common.setBinDir(custom);
ok('an explicit setBinDir() wins over everything', path.resolve(Common.binDir()) === path.resolve(custom));
ok('setBinDir() reports a pre-installed dir as NOT env-provided (so it is still managed normally)', Common.binDirIsPreinstalled() === false);
Common.setBinDir(null); // restore default resolution for the rest of the process

// (2) This IS a test process (the runner entry is a lib/test file), so a VAULTONAUT_ENGINE_DIR in the environment must
// be IGNORED — binDir falls through to the isolated data dir's bin, and binDirIsPreinstalled() is false.
const priorEnv = process.env.VAULTONAUT_ENGINE_DIR;
process.env.VAULTONAUT_ENGINE_DIR = path.join(REPO, '.no-such-engine');
try {
	ok('a test process ignores VAULTONAUT_ENGINE_DIR (engine dir stays under the isolated data dir)',
		path.resolve(Common.binDir()) === path.resolve(path.join(Common.dataDir(), 'bin')));
	ok('a test process is not treated as having a pre-installed engine dir', Common.binDirIsPreinstalled() === false);
} finally {
	if (priorEnv === undefined) delete process.env.VAULTONAUT_ENGINE_DIR; else process.env.VAULTONAUT_ENGINE_DIR = priorEnv;
}

// (3) A REAL (non-test) process MUST honor VAULTONAUT_ENGINE_DIR. Simulate one with `node -e`: with no main module,
// require.main is undefined, so the launched-from-test guard is false and the env branch applies — exactly the
// production/container path. Assert the child reports the env dir as its engine dir AND flags it pre-installed.
const engine = path.join(REPO, '.test-data', 'preinstalled-engine');
const script = 'const C=require(' + JSON.stringify(COMMON) + ');process.stdout.write(JSON.stringify({bin:C.binDir(),pre:C.binDirIsPreinstalled()}))';
const r = spawnSync(process.execPath, ['-e', script], { cwd: REPO, encoding: 'utf8', env: { ...process.env, VAULTONAUT_ENGINE_DIR: engine } });
let child = {};
try { child = JSON.parse((r.stdout || '').trim()); } catch (_) {}
ok('a real (non-test) process honors VAULTONAUT_ENGINE_DIR as the engine dir', path.resolve(child.bin || '') === path.resolve(engine));
ok('a real process flags an env-provided engine dir as pre-installed (skips create/chmod on a read-only rootfs)', child.pre === true);

// restore (setBinDir(null) already done; binDir now resolves to the default again)
ok('after clearing the override the engine dir returns to the default', path.resolve(Common.binDir()) === path.resolve(savedBin));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BIN-PRECEDENCE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
