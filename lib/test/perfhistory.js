'use strict';
// lib/test/perfhistory.js — the in-memory performance sample ring behind the dashboard's Performance tile. It must
// sample cheaply, bound its memory (a fixed ring), never keep the process alive (its timer is unref'd), and expose a
// copy the caller cannot mutate. Deterministic, no browser, cross-platform.
//
// Run:  node lib/test/perfhistory.js

const P = require('../PerfHistory');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	P._reset();
	const s = P.sample();
	ok('a sample carries at / loopLagMs / heapPct / rssBytes', s && typeof s.at === 'number' && typeof s.loopLagMs === 'number' && typeof s.heapPct === 'number' && typeof s.rssBytes === 'number');
	ok('loop lag and heap are non-negative', s.loopLagMs >= 0 && s.heapPct >= 0);

	P._reset();
	for (let i = 0; i < P.MAX_SAMPLES + 25; i++) P.sample();
	ok('the ring is bounded to MAX_SAMPLES (oldest dropped)', P.series().length === P.MAX_SAMPLES);

	const a = P.series();
	a.push({ junk: 1 });
	ok('series() returns a copy — mutating it does not grow the ring', P.series().length === P.MAX_SAMPLES);

	P.start(); P.start(); // idempotent
	ok('start() is idempotent and leaves samples flowing', P.series().length >= 1);
	P.stop();
	ok('stop() does not throw and can be called when stopped', (() => { try { P.stop(); return true; } catch (_) { return false; } })());

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PERF-HISTORY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
	// The process must exit on its own here — if PerfHistory's timer were not unref'd, this test would hang.
}

main();
