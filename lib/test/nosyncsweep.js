'use strict';
// lib/test/nosyncsweep.js — a whole-lib WATCHDOG for the standing "never block the event loop on the shared service"
// principle. Per-module source contracts catch a *Sync inside a module that already has one, but nothing stopped a NEW
// module (or a new call in an existing one) from shipping a blocking `fs.readFileSync` / `execSync` / `inflateRawSync`
// on a hot path. This test enumerates every synchronous call across all of lib/ (excluding tests) and holds each file
// to a REVIEWED ceiling: the current, deliberate synchronous sites — CLI commands, one-time startup, worker threads,
// forked child processes, and microsecond crypto — are allowed, and any NEW synchronous call trips the test so it gets
// reviewed before it can regress responsiveness. It is a pure source scan, so it can never hang or flake.
//
// When a change legitimately adds or removes a synchronous call, update the ceiling for that file below (and note why).
//
// Run:  node lib/test/nosyncsweep.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Reviewed ceiling of synchronous calls per file, relative to lib/. A file absent here must have ZERO synchronous
// calls. Each entry is a deliberate, non-shared-service-hot-path use: CLI (Commands), install/startup one-shots
// (Launcher, RcloneSetup, TorSetup — both binary-download setup one-shots with existsSync cache checks off any hot
// path, Shortcut, Autostart), build scripts, worker threads / forked children (SearchDefs, Extract,
// Timelock, Guardian, Phase, SlotRegistry), integrity/crypto one-shots and microsecond KDFs (Integrity, Emergency,
// Net, verify-bundle, ReleaseIntegrity, Cert test-only keygen), platform detection on the mount path (Driver), the
// mobile service-worker fingerprint computed once at route registration (mobileRoutes), one-time template caches and
// HMAC-based hkdf on Vault (the notes-wrap, snapshot-HMAC, and metadata-wrap keys — each a single microsecond HMAC,
// never on the shared-service hot path), and dir hardening plus a one-time, memoized PATH probe for the desktop file/URL opener on
// Common (both off the shared-service hot path — the opener probe runs only when a user opens a page or reveals a
// folder, and caches its result for the process). Ocr.js has two existsSync sites, both off the shared-service loop: a
// one-time, main-thread language-data enable, and a fail-closed model-present guard that runs inside the forked,
// resource-capped extraction child (like Extract.js) once per document — never on the web service event loop.
const CEILING = {
	'Commands.js': 14, 'Launcher.js': 12, 'scripts/sign-release.js': 10, 'Emergency.js': 8, 'Net.js': 7,
	'verify-bundle.js': 5, 'Driver.js': 5, 'SlotRegistry.js': 4, 'Common.js': 4, 'webserver/mobileRoutes.js': 3, 'Vault.js': 4,
	'RcloneSetup.js': 3, 'TorSetup.js': 3, 'Timelock.js': 2, 'SearchDefs.js': 2, 'Phase.js': 2, 'Integrity.js': 2, 'Ocr.js': 2,
	'Shortcut.js': 1, 'ReleaseIntegrity.js': 1, 'RecoveryKit.js': 1, 'Logger.js': 1, 'Guardian.js': 1, 'Extract.js': 1, 'Cert.js': 1,
};
const SYNC = /\b[A-Za-z_$][\w$]*Sync\(/g;
const libDir = path.join(__dirname, '..');

function jsFiles(dir, out = []) {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		if (e.name === 'test' || e.name === 'node_modules' || e.name.startsWith('.')) continue;
		const p = path.join(dir, e.name);
		if (e.isDirectory()) jsFiles(p, out);
		else if (e.isFile() && e.name.endsWith('.js')) out.push(p);
	}
	return out;
}

const offenders = [];
for (const file of jsFiles(libDir)) {
	const rel = path.relative(libDir, file).split(path.sep).join('/');
	const count = (fs.readFileSync(file, 'utf8').match(SYNC) || []).length;
	const allowed = CEILING[rel] || 0;
	if (count > allowed) offenders.push(rel + ' has ' + count + ' synchronous call(s), reviewed ceiling ' + allowed);
}
ok('no lib file exceeds its reviewed ceiling of synchronous calls (a new blocking call needs review)', offenders.length === 0);
if (offenders.length) for (const o of offenders) console.log('        ' + o);

// A couple of pinned invariants that must stay at zero regardless of the ceiling table, since they are the request
// layer itself: the web route module and the P2P transport must never introduce a synchronous call.
for (const rel of ['webserver/index.js', 'HolePunch.js', 'Tunnel.js', 'Relay.js']) {
	const count = (fs.readFileSync(path.join(libDir, rel), 'utf8').match(SYNC) || []).length;
	ok(rel + ' has no synchronous calls at all (request/transport layer)', count === 0);
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NO-SYNC-SWEEP CHECKS PASSED'));
process.exit(failures ? 1 : 0);
