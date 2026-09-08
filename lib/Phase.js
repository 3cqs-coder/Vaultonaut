'use strict';
// lib/Phase.js — a tiny cross-process "what is the service doing right now" marker, so the EXTERNAL Guardian
// can tell an intentional, healthy shutdown (a slow drain-on-stop) apart from a genuine wedge. During a clean
// shutdown the service writes phase 'stopping' and heartbeats it every second; as long as its event loop is
// alive — even through a minutes-long drain — the heartbeat stays fresh, and the Guardian DEFERS rather than
// racing the teardown (or, when escalation is enabled, killing it mid-flush). If the loop truly wedges, the
// heartbeat stops, the marker goes stale, and the Guardian proceeds.
//
// Wall-clock is used deliberately: two separate processes must share the reference, and Node's monotonic clock
// is per-process. The freshness window is short (seconds), so an occasional clock nudge is immaterial, and the
// symmetric check below treats a backward jump as "stale" (fail toward the Guardian acting, never toward it
// being blocked forever by a bogus-fresh marker).

const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Common = require('./Common');

function phasePath() { return path.join(Common.runDir(), 'phase.json'); }

async function setPhase(phase, extra) {
	try {
		await fsp.mkdir(Common.runDir(), { recursive: true, mode: 0o700 });
		await Common.writeJsonAtomic(phasePath(), Object.assign({ phase, pid: process.pid, updatedAt: new Date().toISOString() }, extra || {}), { mode: 0o600 });
	} catch (_) {} // best-effort telemetry — a failure here must never disturb the shutdown it describes
}
// Synchronous read for the Guardian's simple watch loop.
function readPhaseSync() { try { return JSON.parse(fs.readFileSync(phasePath(), 'utf8')); } catch (_) { return null; } }
async function clearPhase() { try { await fsp.rm(phasePath(), { force: true }); } catch (_) {} }

// Fresh = updated within `windowMs` (default 6s: longer than the 1s heartbeat, shorter than the Guardian's
// ~3s stale detection, so a live shutdown always reads fresh and a wedged one goes stale quickly). A marker
// timestamped in the future by more than the window is treated as stale (a clock jump must not pin the Guardian).
function isFresh(ph, windowMs = 6000) {
	if (!ph || !ph.updatedAt) return false;
	const t = Date.parse(ph.updatedAt); if (!Number.isFinite(t)) return false;
	const age = Date.now() - t;
	return age <= windowMs && age >= -windowMs;
}

module.exports = { setPhase, readPhaseSync, clearPhase, isFresh, phasePath };
