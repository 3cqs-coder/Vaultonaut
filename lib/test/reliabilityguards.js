'use strict';
// lib/test/reliabilityguards.js — pins the non-blocking / crash-proof guards on the health tick and the periodic
// scheduler ticks, which live in the web server's orchestration layer and in lib/Vault.js and are not otherwise
// unit-tested (their functions are not exported). These guards keep a wedged drive or a slow housekeeping pass from
// stalling the 12-second health tick that gates the systemd watchdog ping, and keep one bad mount from aborting a
// whole pass. A source-level guard (like routeguards.js) is the right, cheap level here — an end-to-end wedged-fs
// test would be flaky. If any of these regresses, the reliability property it protects is silently lost.
//
// Run:  node lib/test/reliabilityguards.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
// Slice a function body from its declaration to the start of the next top-level function, for scoped assertions.
function body(src, decl, span = 2500) { const at = src.indexOf(decl); return at >= 0 ? src.slice(at, at + span) : ''; }

function main() {
	const server = read('webserver/index.js');
	const vault = read('Vault.js');

	// 1. The housekeeping sweep must be DETACHED from the health tick (not awaited), with an overlap guard — an
	//    awaited sweep over several stale mounts (or a resumed rekey) could delay the health stamp. Scope the check
	//    to watchTick: an awaited sweep in a user-triggered request handler (e.g. /api/repair) is fine.
	const watch = body(server, 'async function watchTick(', 9000);
	ok('the health tick does not await Vault.sweep() (it is detached)', watch.length > 0 && !/await\s+Vault\.sweep\(\)/.test(watch));
	ok('the health tick guards the detached sweep against overlap (sweepRunning)', /sweepRunning/.test(watch) && /Vault\.sweep\(\)/.test(watch));

	// 1b. watchBusy must be latched INSIDE the try whose finally clears it — the whole tick body, including the
	//     sleep/clock-jump prologue, runs under that try. Otherwise a synchronous throw before the try would latch
	//     watchBusy true and silently stop the health watch (and the systemd ping it gates) forever.
	ok('watchTick opens its try immediately after latching watchBusy', /watchBusy = true;\s*try \{/.test(watch));

	// 2. The backup/scrub preflight must time-bound the manifest read, so an unmounted vault on a wedged path can
	//    never hang (and stack) the sequential schedule pass.
	ok('the scheduled-tick preflight bounds readManifest with a timeout', /withTimeout\(readManifest\(abs\)/.test(vault));

	// 3. autoLockTick must guard the WHOLE per-mount body (the activity probe can reject under fd pressure), so one
	//    bad mount cannot abort the pass and skip the rest.
	const autoLock = body(vault, 'async function autoLockTick(');
	const tryAt = autoLock.indexOf('try {'), probeAt = autoLock.indexOf('vfsActivitySig(bin, m.rcSocket)');
	ok('autoLockTick wraps the activity probe in a try (per-mount isolation)', tryAt >= 0 && probeAt > tryAt);

	// 4. cloudTokenTick must be a true in-flight mutex, not just a timestamp throttle, so a slow sweep can't overlap.
	ok('cloudTokenTick has an in-flight mutex', /_cloudTokenSweeping/.test(vault));

	// 4b. runScheduleTick must not overlap itself: each schedule tick fires detached every ~12s, and the pass awaits
	//     each vault in turn, so without a per-store in-flight guard a long op would let the next tick start another
	//     due vault, piling up unbounded concurrent operations when many vaults are due at once. A per-store guard
	//     keeps at most one pass of each tick running (due vaults are then processed serially, as one pass already is).
	const sched = body(vault, 'async function runScheduleTick(', 3000);
	ok('runScheduleTick guards against overlapping passes (per-store in-flight set)', /tickInFlight\.has\(store\)/.test(sched) && /tickInFlight\.add\(store\)/.test(sched) && /finally\s*\{\s*tickInFlight\.delete\(store\)/.test(sched));

	// 4c. Rotation must FENCE the lease BEFORE staging the commit anchor (MANIFEST_NEW). Once that anchor exists the
	//     interruption-recovery path treats the rotation as committed, so a fence placed after it could not abort a
	//     stolen-lease rotation — it would silently commit a superseded manifest over a concurrent key/member change.
	const rot = body(vault, 'async function rotate(', 20000);
	const fenceAt = rot.indexOf('assertStillHoldLease(abs)');
	const anchorAt = rot.indexOf('MANIFEST_NEW), newManifest');
	ok('rotation fences the lease before staging the commit anchor (MANIFEST_NEW)', fenceAt >= 0 && anchorAt >= 0 && fenceAt < anchorAt);

	// 5. emergencyRelease must guard its filesystem writes so a write failure never rejects out of the health tick.
	const rel = body(vault, 'async function emergencyRelease(');
	const relTry = rel.indexOf('try {'), relMkdir = rel.indexOf('fsp.mkdir(dir');
	ok('emergencyRelease wraps its writes in a try (never throws out of the tick)', relTry >= 0 && relMkdir > relTry);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELIABILITY-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
