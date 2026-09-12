'use strict';
// lib/test/_runall.js — the cross-platform test runner behind `npm run test:all`. It replaces a bash-only
// `for … case … esac` one-liner so the full suite runs the same on macOS, Linux, and Windows (cmd/PowerShell),
// which a contributor on any platform needs. Behavior is faithful to the old loop: run every lib/test/*.js in sorted
// order, skip the `_`-prefixed helpers (fixtures and this runner), preload ./lib/test/_setup.js into each, print
// "# <file>" before it, and stop at the FIRST failure with a non-zero exit. The leading `_` keeps the runner itself
// out of the globbed set it runs.
//
// Run:  node lib/test/_runall.js   (or: npm run test:all)

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// Per-test wall-clock cap. Without it, ONE hung test (a wedged serve, a deadlocked port bind, a stuck download) would
// block the whole suite — and a CI job — forever with no diagnostic. Generous, so it only ever trips a genuine hang,
// not a legitimately slow test; override with TEST_TIMEOUT_MS for a constrained runner. The child is killed on
// timeout and the runner exits non-zero, naming the file, so a hang looks like a clear failure rather than a stall.
const TEST_TIMEOUT_MS = Math.max(1000, Number(process.env.TEST_TIMEOUT_MS) || 300000);

const testDir = __dirname;
const files = fs.readdirSync(testDir)
	.filter((n) => n.endsWith('.js') && !n.startsWith('_')) // skip helpers/fixtures/this runner, matching the old `_*)` skip
	.sort(); // stable, locale-independent order so a failure is reproducible run to run

// The per-test cap uses spawnSync's `timeout` option — but on Windows that option triggers a libuv assertion during
// the child's teardown ("Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), src\\win\\async.c"), a known
// Node/libuv bug, which crashes the runner itself. So apply the watchdog only where it is reliable (macOS and Linux).
// Windows keeps running the suite without the cap; a Windows-safe async runner can restore the cap there later.
const isWin = process.platform === 'win32';

const setup = path.join('lib', 'test', '_setup.js');
for (const name of files) {
	const rel = path.join('lib', 'test', name);
	console.log('# ' + rel);
	const opts = { stdio: 'inherit' };
	if (!isWin) { opts.timeout = TEST_TIMEOUT_MS; opts.killSignal = 'SIGKILL'; }
	const r = spawnSync(process.execPath, ['-r', './' + setup.split(path.sep).join('/'), rel], opts);
	// A timeout surfaces as a kill signal (and, on some platforms, r.error.code === 'ETIMEDOUT'); make it an explicit,
	// named failure so a hang is diagnosable instead of a silent stall.
	if (r.signal || (r.error && r.error.code === 'ETIMEDOUT')) {
		console.error('\nTIMED OUT after ' + TEST_TIMEOUT_MS + 'ms: ' + rel + ' (killed with ' + (r.signal || 'SIGKILL') + ')');
		process.exit(1);
	}
	if (r.status !== 0 || r.error) { process.exit(r.status || 1); } // fail-fast, like the old `|| exit 1`
}
