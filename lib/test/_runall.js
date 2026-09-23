'use strict';
// lib/test/_runall.js — the cross-platform test runner behind `npm run test:all`. It replaces a bash-only
// `for … case … esac` one-liner so the full suite runs the same on macOS, Linux, and Windows (cmd/PowerShell),
// which a contributor on any platform needs. It runs every lib/test/*.js in sorted order, skips the `_`-prefixed
// helpers (fixtures and this runner), preloads ./lib/test/_setup.js into each, and prints "# <file>" before it. The
// leading `_` keeps the runner itself out of the globbed set it runs.
//
// It runs EVERY test even after one fails, then reports all of the failures together and exits non-zero if any failed.
// Stopping at the first failure (the old behavior) hid later regressions behind an earlier one — most sharply when the
// release-signing guard failed on a locally stale manifest and masked every source-guard test after it — so a run now
// surfaces the whole set of failures at once. Set TEST_FAILFAST=1 to stop at the first failure instead.
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

const failFast = process.env.TEST_FAILFAST === '1'; // opt back into stopping at the first failure
const setup = path.join('lib', 'test', '_setup.js');
const failures = []; // { rel, why } — collected so every failing test is reported at the end, not just the first
for (const name of files) {
	const rel = path.join('lib', 'test', name);
	console.log('# ' + rel);
	const opts = { stdio: 'inherit' };
	if (!isWin) { opts.timeout = TEST_TIMEOUT_MS; opts.killSignal = 'SIGKILL'; }
	const r = spawnSync(process.execPath, ['-r', './' + setup.split(path.sep).join('/'), rel], opts);
	// A timeout surfaces as a kill signal (and, on some platforms, r.error.code === 'ETIMEDOUT'); make it an explicit,
	// named failure so a hang is diagnosable instead of a silent stall.
	let why = null;
	if (r.signal || (r.error && r.error.code === 'ETIMEDOUT')) why = 'TIMED OUT after ' + TEST_TIMEOUT_MS + 'ms (killed with ' + (r.signal || 'SIGKILL') + ')';
	else if (r.status !== 0 || r.error) why = 'exited with ' + (r.status != null ? 'code ' + r.status : ((r.error && r.error.message) || 'an error'));
	if (why) {
		console.error('\nFAILED: ' + rel + ' — ' + why);
		failures.push({ rel, why });
		if (failFast) break; // opt-in early stop; the default continues so the whole failure set is visible in one run
	}
}
if (failures.length) {
	console.error('\n' + failures.length + ' test file(s) FAILED:');
	for (const f of failures) console.error('  - ' + f.rel + ' (' + f.why + ')');
	process.exit(1);
}
