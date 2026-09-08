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

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORKER-RUN CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
