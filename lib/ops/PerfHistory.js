'use strict';
// lib/PerfHistory.js — a tiny, in-memory ring buffer of recent performance samples for the dashboard's Performance
// tile (sparklines of event-loop lag and heap use over the last few minutes). It is deliberately NON-persistent: a
// live trend does not need to survive a restart, so there is no disk format to version and nothing an older client
// could misread. Sampling is O(1), runs on one unref'd timer off the request hot path, and uses its OWN event-loop
// delay histogram so it never disturbs the self-check's event_loop_lag reading (that reader resets on read). Everything
// is feature-probed and wrapped, so a runtime without perf_hooks/v8 simply reports an empty series.

const perfHooks = require('perf_hooks');
const v8 = require('v8');

const MAX_SAMPLES = 60;          // ~10 minutes of history at the sample interval below — plenty for a sparkline
const SAMPLE_INTERVAL_MS = 10000;

let hist = null;
try { if (typeof perfHooks.monitorEventLoopDelay === 'function') { hist = perfHooks.monitorEventLoopDelay({ resolution: 20 }); hist.enable(); } } catch (_) { hist = null; }

const ring = []; // [{ at, loopLagMs, heapPct, rssBytes }] oldest-first, capped at MAX_SAMPLES
let timer = null;

// Take one sample now. `loopLagMs` is the worst event-loop stall since the previous sample (then reset), so each point
// describes its own window rather than an all-time figure — the same shape the self-check's lag probe uses.
function sample() {
	let loopLagMs = 0;
	if (hist) { try { loopLagMs = hist.max / 1e6; hist.reset(); } catch (_) { loopLagMs = 0; } }
	if (!isFinite(loopLagMs) || loopLagMs < 0) loopLagMs = 0;
	let heapPct = 0, rssBytes = 0;
	try { const s = v8.getHeapStatistics(); if (s && s.heap_size_limit) heapPct = (s.used_heap_size / s.heap_size_limit) * 100; } catch (_) {}
	try { rssBytes = (process.memoryUsage() || {}).rss || 0; } catch (_) {}
	ring.push({ at: Date.now(), loopLagMs: Math.round(loopLagMs), heapPct: Math.round(heapPct * 10) / 10, rssBytes: rssBytes });
	while (ring.length > MAX_SAMPLES) ring.shift();
	return ring[ring.length - 1];
}

// Start periodic sampling. Idempotent. The timer is unref'd so it never keeps the process alive (a one-shot CLI that
// happens to require this module still exits normally). The web server calls this; the CLI does not.
function start() {
	if (timer) return;
	try { sample(); } catch (_) {}
	timer = setInterval(() => { try { sample(); } catch (_) {} }, SAMPLE_INTERVAL_MS);
	if (timer.unref) timer.unref();
}
function stop() { if (timer) { clearInterval(timer); timer = null; } }

// The recorded series, oldest-first (a copy so a caller cannot mutate the ring).
function series() { return ring.slice(); }

module.exports = { start, stop, sample, series, MAX_SAMPLES, SAMPLE_INTERVAL_MS, _reset: () => { ring.length = 0; } };
