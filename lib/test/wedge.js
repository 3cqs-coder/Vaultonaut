'use strict';
// lib/test/wedge.js — the Guardian's wedge-vs-clean-shutdown decision and the phase marker behind it. The
// Guardian is a separate process that locks a dead service's vaults; the risk is that a CLEAN shutdown clears
// its own liveness nonce early, so a slow drain-on-stop looks wedged from outside. The phase marker fixes that:
// while the service heartbeats 'stopping', the Guardian DEFERS (never racing the teardown or killing mid-flush);
// a genuine wedge (no fresh marker) it either locks (default) or, with health-based restart enabled, escalates
// to a kill so the OS relaunches it. This tests the pure decision across every case and the marker's freshness.
//
// Run:  node lib/test/wedge.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-wedge-'));
	const Common = require('../Common');
	const runDir = path.join(tmp, 'run'); await fsp.mkdir(runDir, { recursive: true });
	Common.runDir = () => runDir;
	const Phase = require('../Phase');
	const Guardian = require('../Guardian');

	const PID = 4242;
	const fresh = () => ({ phase: 'stopping', pid: PID, updatedAt: new Date().toISOString() });
	const stale = () => ({ phase: 'stopping', pid: PID, updatedAt: new Date(Date.now() - 60000).toISOString() });

	// The decision matrix.
	ok('a fresh clean-shutdown heartbeat -> defer (never race a healthy teardown)', Guardian.decide({ ownerPid: PID, phase: fresh(), killEnabled: false }) === 'defer');
	ok('a fresh clean-shutdown heartbeat -> defer even with escalation enabled', Guardian.decide({ ownerPid: PID, phase: fresh(), killEnabled: true }) === 'defer');
	ok('a genuine wedge (no marker), escalation off -> lock', Guardian.decide({ ownerPid: PID, phase: null, killEnabled: false }) === 'lock');
	ok('a genuine wedge (no marker), escalation on -> escalate', Guardian.decide({ ownerPid: PID, phase: null, killEnabled: true }) === 'escalate');
	ok('a STALE stopping marker is not a clean shutdown -> not defer', Guardian.decide({ ownerPid: PID, phase: stale(), killEnabled: false }) === 'lock');
	ok('a marker from a DIFFERENT pid is ignored -> not defer', Guardian.decide({ ownerPid: PID, phase: { phase: 'stopping', pid: 9999, updatedAt: new Date().toISOString() }, killEnabled: false }) === 'lock');
	ok('a non-stopping marker is ignored -> not defer', Guardian.decide({ ownerPid: PID, phase: { phase: 'running', pid: PID, updatedAt: new Date().toISOString() }, killEnabled: true }) === 'escalate');

	// Freshness window: recent is fresh, old and far-future are not.
	ok('a recent marker is fresh', Phase.isFresh({ updatedAt: new Date(Date.now() - 1000).toISOString() }) === true);
	ok('an old marker is stale', Phase.isFresh({ updatedAt: new Date(Date.now() - 60000).toISOString() }) === false);
	ok('a far-future marker (clock jump) is treated as stale', Phase.isFresh({ updatedAt: new Date(Date.now() + 60000).toISOString() }) === false);
	ok('no marker is not fresh', Phase.isFresh(null) === false);

	// The marker round-trips through the run dir and clears.
	await Phase.setPhase('stopping');
	const read = Phase.readPhaseSync();
	ok('setPhase writes a readable stopping marker with our pid', read && read.phase === 'stopping' && read.pid === process.pid && Phase.isFresh(read));
	await Phase.clearPhase();
	ok('clearPhase removes the marker', Phase.readPhaseSync() === null);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WEDGE CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
