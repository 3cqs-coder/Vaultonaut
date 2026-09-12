'use strict';
// lib/test/leaseactive.js — the cross-machine write-lease liveness check. A lease file lives on a shared/cloud
// destination and can be written by another machine (or a hostile peer), so leaseActive must be robust against a
// peer-controlled record: a fresh lease reads active, an old one reads stale (so another machine can take over), an
// oversized ttl is clamped, an unparseable timestamp is not trusted, and — the case this guards — a `since` set in
// the FUTURE (a hostile peer, or a badly-skewed clock) must NOT read as active forever, which would block every
// other machine from ever mounting for writes.
//
// Run:  node lib/test/leaseactive.js

const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const leaseActive = Vault._leaseActive;
const iso = (ms) => new Date(Date.now() + ms).toISOString();

function main() {
	ok('no lease / no holder / no since is not active', !leaseActive(null) && !leaseActive({}) && !leaseActive({ holder: 'x' }));
	ok('a fresh lease is active', leaseActive({ holder: 'a', since: iso(-1000), ttlMs: 60 * 1000 }) === true);
	ok('a lease older than its ttl is stale (another machine can take over)', leaseActive({ holder: 'a', since: iso(-120 * 1000), ttlMs: 60 * 1000 }) === false);
	ok('an unparseable since is not active', leaseActive({ holder: 'a', since: 'not-a-date', ttlMs: 60 * 1000 }) === false);
	// A gigantic peer-supplied ttl is clamped to the default stale window, so an old lease still expires.
	ok('an oversized ttl is clamped (a 13-hour-old lease is stale despite a huge ttl)', leaseActive({ holder: 'a', since: iso(-13 * 60 * 60 * 1000), ttlMs: Number.MAX_SAFE_INTEGER }) === false);
	// The guard: a lease far in the future must not read as active forever.
	ok('a far-future since is NOT active (cannot pin the lease forever)', leaseActive({ holder: 'a', since: iso(60 * 60 * 1000), ttlMs: 60 * 1000 }) === false);
	// A small clock skew is tolerated: a lease a little in the future still reads active for a legitimate skewed peer.
	ok('a slightly-future since (within skew) is still active', leaseActive({ holder: 'a', since: iso(60 * 1000), ttlMs: 10 * 60 * 1000 }) === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LEASE-ACTIVE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
