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
const { spawn } = require('child_process');

// Per-test wall-clock cap. Without it, ONE hung test (a wedged serve, a deadlocked port bind, a stuck download) would
// block the whole suite — and a CI job — forever with no diagnostic. Generous, so it only ever trips a genuine hang,
// not a legitimately slow test; override with TEST_TIMEOUT_MS for a constrained runner. The child is killed on
// timeout and the runner exits non-zero, naming the file, so a hang looks like a clear failure rather than a stall.
const TEST_TIMEOUT_MS = Math.max(1000, Number(process.env.TEST_TIMEOUT_MS) || 300000);

const testDir = __dirname;
const files = fs.readdirSync(testDir)
	.filter((n) => n.endsWith('.js') && !n.startsWith('_')) // skip helpers/fixtures/this runner, matching the old `_*)` skip
	.sort(); // stable, locale-independent order so a failure is reproducible run to run

// On timeout we must kill the whole PROCESS TREE, not just the test process. A mount-bearing test spawns the storage
// engine (rclone + its NFS/FUSE helper) as a grandchild; killing only the direct child would orphan that helper and
// leave a LIVE mount behind — the exact leak the "never leak processes/mounts" rule forbids, and it silently degrades
// the host (and every later mount-bearing test) until it is reaped by hand. So on macOS/Linux the child is spawned as
// a process-GROUP leader (`detached`) and a timeout kills the entire group with a negative-pid signal, taking the test
// and every helper it started down together. On Windows there is no process group to signal, so a timeout instead runs
// `taskkill /PID <pid> /T /F`, which force-kills the child AND its whole tree (reaping any WinFsp/engine helper). This
// uses async `spawn` (not the old `spawnSync` whose `timeout` tripped a libuv teardown assertion), so the cap is safe on
// every platform now — a hung test becomes a named failure instead of stalling the suite (and a CI job) indefinitely.
const isWin = process.platform === 'win32';
// Kill a timed-out child and everything it spawned, per platform. Best-effort: any failure falls back to killing the
// lone child, so a hang is always interrupted.
function killTree(child) {
	if (isWin) { try { require('child_process').spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true }); } catch (_) { try { child.kill(); } catch (_) {} } }
	else { try { process.kill(-child.pid, 'SIGKILL'); } catch (_) { try { child.kill('SIGKILL'); } catch (_) {} } } // negative pid → the whole group
}

// Run one test file to completion (or until the timeout kills its whole process group). Resolves with the exit status;
// never rejects, so one child's failure is recorded and the suite moves on. The timer is unref'd and always cleared, so
// it can neither hold the runner open nor fire after the child has already exited.
function runOne(rel) {
	return new Promise((resolve) => {
		const child = spawn(process.execPath, ['-r', './' + setup.split(path.sep).join('/'), rel], { stdio: 'inherit', detached: !isWin });
		let timedOut = false;
		const timer = setTimeout(() => { timedOut = true; killTree(child); }, TEST_TIMEOUT_MS);
		if (timer.unref) timer.unref();
		child.once('error', (e) => { if (timer) clearTimeout(timer); resolve({ error: e, timedOut: timedOut }); });
		child.once('exit', (code, signal) => { if (timer) clearTimeout(timer); resolve({ status: code, signal: signal, timedOut: timedOut }); });
	});
}

const failFast = process.env.TEST_FAILFAST === '1'; // opt back into stopping at the first failure
const setup = path.join('lib', 'test', '_setup.js');
const failures = []; // { rel, why } — collected so every failing test is reported at the end, not just the first

(async () => {
	for (const name of files) {
		const rel = path.join('lib', 'test', name);
		console.log('# ' + rel);
		const r = await runOne(rel);
		// A timeout kills the child's group, surfacing as our timedOut flag (and a kill signal); make it an explicit,
		// named failure so a hang is diagnosable instead of a silent stall.
		let why = null;
		if (r.timedOut) why = 'TIMED OUT after ' + TEST_TIMEOUT_MS + 'ms (whole process group killed)';
		else if (r.error) why = 'exited with ' + (r.error.message || 'an error');
		else if (r.signal) why = 'killed with ' + r.signal;
		else if (r.status !== 0) why = 'exited with code ' + r.status;
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
})();
