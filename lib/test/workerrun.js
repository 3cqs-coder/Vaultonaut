'use strict';
// lib/test/workerrun.js — the shared worker runner's lifecycle and its progress-idle watchdog. The
// watchdog frees a caller when a worker goes silent (a wedged read on an unresponsive vault) instead of
// hanging forever, while never interrupting a worker that keeps streaming progress.
//
// Run:  node lib/test/workerrun.js

const path = require('path');
const WorkerRun = require('../WorkerRun');
const FIX = path.join(__dirname, '_workerfixture.js');
const CHILD = path.join(__dirname, '_runchildfixture.js');
const PROC = path.join(__dirname, '_runprocessfixture.js');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	console.log('[normal completion resolves]');
	const r = await WorkerRun.runWorker(FIX, { mode: 'done' }, null, { idleMs: 1000 });
	ok('a worker that finishes resolves with its result', r && r.ok === true);

	console.log('[a silent worker trips the idle watchdog]');
	let err = null;
	try { await WorkerRun.runWorker(FIX, { mode: 'hang' }, null, { idleMs: 300, idleMessage: 'A test operation' }); }
	catch (e) { err = e; }
	ok('a worker that never reports is stopped, not hung', err && /stopped responding/.test(err.message));
	ok('the timeout error names the operation', err && /A test operation/.test(err.message));

	console.log('[progress keeps the watchdog from firing, then silence trips it]');
	let progressed = 0, err2 = null;
	try { await WorkerRun.runWorker(FIX, { mode: 'progress-then-hang' }, () => { progressed++; }, { idleMs: 300 }); }
	catch (e) { err2 = e; }
	ok('progress was delivered before the stall', progressed >= 3);
	ok('the watchdog fired only after progress stopped', err2 && /stopped responding/.test(err2.message));

	console.log('[no watchdog when idleMs is unset: a normal worker still completes]');
	const r2 = await WorkerRun.runWorker(FIX, { mode: 'done' }, null);
	ok('runs fine with no watchdog configured', r2 && r2.ok === true);

	console.log('[runChild dispatches to a handler and streams its result]');
	let echoProg = 0;
	const echo = await WorkerRun.runWorker(CHILD, { op: 'echo', args: { hi: 7 } }, () => { echoProg++; });
	ok('runChild returns the handler result', echo && echo.got && echo.got.hi === 7);
	ok('runChild forwards handler progress', echoProg >= 1);

	console.log('[runChild surfaces a handler throw and an unknown op]');
	let boomErr = null;
	try { await WorkerRun.runWorker(CHILD, { op: 'boom', args: {} }, null); } catch (e) { boomErr = e; }
	ok('a throwing handler rejects with its message', boomErr && /handler failed/.test(boomErr.message));
	let unkErr = null;
	try { await WorkerRun.runWorker(CHILD, { op: 'nope', args: {} }, null); } catch (e) { unkErr = e; }
	ok('an unknown op rejects, naming the label', unkErr && /Unknown test operation: nope/.test(unkErr.message));

	console.log('[runProcess runs a job in an isolated child process and returns its result]');
	const pr = await WorkerRun.runProcess(PROC, { op: 'echo', args: { hi: 9 } }, { maxMs: 15000 });
	ok('runProcess returns the child result', pr && pr.got && pr.got.hi === 9);
	let pboom = null;
	try { await WorkerRun.runProcess(PROC, { op: 'boom', args: {} }, { maxMs: 15000 }); } catch (e) { pboom = e; }
	ok('a throwing child handler rejects with its message', pboom && /handler failed/.test(pboom.message));
	let punk = null;
	try { await WorkerRun.runProcess(PROC, { op: 'nope', args: {} }, { maxMs: 15000 }); } catch (e) { punk = e; }
	ok('an unknown child op rejects, naming the label', punk && /Unknown test operation: nope/.test(punk.message));

	console.log('[the child bounds its OWN off-heap growth (memory isolation) and the parent RSS is unaffected]');
	const rssBefore = process.memoryUsage().rss;
	let hogErr = null; const hogT0 = Date.now();
	try { await WorkerRun.runProcess(PROC, { op: 'hog', args: {}, rssLimitMb: 128 }, { maxMs: 30000, label: 'A test op' }); } catch (e) { hogErr = e; }
	ok('a child whose off-heap memory runs away is stopped (its own RSS budget), not left to OOM the app', hogErr && (Date.now() - hogT0) < 20000);
	ok('the runaway child never grew the PARENT process RSS (separate address space)', (process.memoryUsage().rss - rssBefore) < 300 * 1024 * 1024);

	console.log('[the parent time budget stops a CPU-bound child]');
	let spinErr = null; const spinT0 = Date.now();
	try { await WorkerRun.runProcess(PROC, { op: 'spin', args: {} }, { maxMs: 1500, label: 'A test op' }); } catch (e) { spinErr = e; }
	ok('a CPU-bound child is stopped by the absolute time budget', spinErr && /did not finish within/.test(spinErr.message) && (Date.now() - spinT0) < 8000);

	console.log('[the child self-timeout backstops an orphaned child whose async work never returns]');
	let sleepErr = null; const sleepT0 = Date.now();
	// No parent maxMs here; only the child's own selfTimeoutMs bounds it — the orphan case where the parent is gone.
	try { await WorkerRun.runProcess(PROC, { op: 'sleep', args: {}, selfTimeoutMs: 1000 }, { label: 'A test op' }); } catch (e) { sleepErr = e; }
	ok('a child with no parent deadline still self-exits at its own selfTimeoutMs', sleepErr && (Date.now() - sleepT0) < 8000);

	console.log('[scrubEnv gives an untrusted-input child a minimal environment, withholding ambient secrets]');
	// The document extractor parses untrusted bytes, so it is forked with scrubEnv:true and must NOT inherit ambient
	// secrets (cloud creds, API tokens, anything the shell exported). Set a stand-in secret in THIS process's env and
	// confirm the child cannot see it under scrubEnv, but CAN without it (so the mechanism is really what hides it),
	// while a benign runtime variable (PATH) is still present so the child can actually run.
	process.env.VDISK_TEST_SECRET = 'top-secret-token';
	const scrubbed = await WorkerRun.runProcess(PROC, { op: 'env', args: {} }, { maxMs: 15000, scrubEnv: true });
	ok('a scrubEnv child does NOT inherit an ambient secret from the parent', scrubbed && scrubbed.secret === null && !scrubbed.keys.includes('VDISK_TEST_SECRET'));
	ok('a scrubEnv child still has PATH so it can run', scrubbed && scrubbed.path === true);
	ok('a scrubEnv child gets only a small allowlisted environment', scrubbed && scrubbed.keys.length > 0 && scrubbed.keys.length < 40);
	const inherited = await WorkerRun.runProcess(PROC, { op: 'env', args: {} }, { maxMs: 15000 }); // no scrubEnv → full inheritance (proves the scrub is what hid it)
	ok('without scrubEnv the child DOES inherit the parent environment (the scrub is the cause)', inherited && inherited.secret === 'top-secret-token');
	delete process.env.VDISK_TEST_SECRET;

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORKER-RUN CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
