'use strict';
// lib/test/workerconcurrency.js — a DRIFT GUARD against a subtle hazard: opening several time-locked emergency grants
// CONCURRENTLY from a test. On platforms that still run the pairing in a worker thread (macOS/Linux — Timelock.js runs
// it synchronously on Windows now, precisely because concurrent worker spawn/teardown segfaulted there), wrapping
// several opens in Promise.all spawns several worker threads at the same instant, and concurrent worker-thread spawn
// and teardown is a known native-crash trigger. Production never does this — a real beneficiary opens one grant at a
// time — so a test that parallelizes opens is both unrealistic and a regression risk. This guard keeps every test's
// emergency opens sequential (defensive on every platform). A test that genuinely needs the concurrent pattern can opt
// out with a `worker-concurrency-ok` marker in the same call.
//
// Run:  node -r ./lib/test/_setup.js lib/test/workerconcurrency.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const TEST_DIR = __dirname;
// A worker-backed emergency/time-lock operation invoked from inside a Promise.all argument is the hazard. Match a
// Promise.all(...) call whose body (a generous window) invokes one of these worker-spawning operations.
const WORKER_OP = /emergencyOpen\s*\(|Timelock\.(open|seal)\s*\(/;
const PROMISE_ALL = /Promise\.all\s*\(/g;
const OPT_OUT = /worker-concurrency-ok/;

function scan(file, text) {
	let m;
	while ((m = PROMISE_ALL.exec(text)) !== null) {
		const window = text.slice(m.index, m.index + 300);
		if (!WORKER_OP.test(window)) continue;   // not a worker-backed op — no hazard
		if (OPT_OUT.test(window)) continue;      // deliberately opted out
		ok('no test opens time-locked grants concurrently (' + path.basename(file) + ' near offset ' + m.index + ')', false);
	}
}

function main() {
	const before = failures;
	for (const name of fs.readdirSync(TEST_DIR)) {
		if (!name.endsWith('.js')) continue;
		if (name === path.basename(__filename)) continue; // this guard names the tokens literally; do not scan itself
		let text = '';
		try { text = fs.readFileSync(path.join(TEST_DIR, name), 'utf8'); } catch (_) { continue; }
		scan(path.join(TEST_DIR, name), text);
	}
	ok('emergency/time-lock grants are opened sequentially in every test (one worker thread at a time)', failures === before);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORKER-CONCURRENCY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
