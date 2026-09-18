'use strict';
// lib/test/testisolation.js — proves the test suite can never scatter state into the user's REAL data directory.
// Two guarantees:
//   1. under the _setup preload (how the suite runs), the data dir is the project-local, git-ignored .test-data;
//   2. even a DIRECT run of a test file (no preload) is auto-isolated to .test-data by the fail-safe in
//      Common.dataDir (which never returns the real per-user location when the entry point is a lib/test/ file).
// This is the watchdog behind the "tests run fully isolated" contract, so a future change cannot quietly let a test
// write to the user's real vault list, locks, or ledgers.
//
// Run:  node -r ./lib/test/_setup.js lib/test/testisolation.js

const path = require('path');
const { spawnSync } = require('child_process');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const REPO = path.join(__dirname, '..', '..');
const TEST_DATA = path.resolve(path.join(REPO, '.test-data'));

// (1) This file runs under the _setup preload, which points the data dir at .test-data; confirm it is not the real dir.
ok('under the _setup preload the data dir is the project-local .test-data (not the real user dir)', path.resolve(Common.dataDir()) === TEST_DATA);

// (2) A DIRECT run of a test file, WITHOUT the preload, must still resolve to .test-data via the fail-safe. Spawn a
// tiny probe with no -r and read the data dir AND engine dir it reports. Inject a bogus VAULTONAUT_ENGINE_DIR into the
// child's environment: a real (non-test) process would honor it, but a test-launched process must IGNORE it and keep
// the engine dir under the isolated .test-data — otherwise a stray dev/CI shell variable could steer a test at some
// other engine. This directly exercises the launchedFromTest() guard in Common.binDir().
const BOGUS_ENGINE = path.join(REPO, '.no-such-engine-dir-should-be-ignored');
const r = spawnSync(process.execPath, [path.join('lib', 'test', '_isolationprobe.js')],
	{ cwd: REPO, encoding: 'utf8', env: { ...process.env, VAULTONAUT_ENGINE_DIR: BOGUS_ENGINE } });
let probe = {};
try { probe = JSON.parse((r.stdout || '').trim()); } catch (_) {}
const reportedData = path.resolve(probe.dataDir || '');
const reportedBin = path.resolve(probe.binDir || '');
ok('a direct test run (no _setup preload) is auto-isolated to .test-data, never the real user dir', reportedData === TEST_DATA);
ok('a test-launched process ignores a stray VAULTONAUT_ENGINE_DIR and keeps the engine dir under .test-data',
	reportedBin === path.join(TEST_DATA, 'bin') && reportedBin !== path.resolve(BOGUS_ENGINE));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TEST-ISOLATION CHECKS PASSED'));
process.exit(failures ? 1 : 0);
