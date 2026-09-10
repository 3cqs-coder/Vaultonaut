'use strict';
// lib/test/ramcache-budget.js — the RAM-cache aggregate memory budget (lib/RamCache.planSizeMB). On macOS and
// Windows a mount's write cache is wired in physical memory the moment it is created, one per mount, so several
// open vaults must not sum past what the machine can spare. planSizeMB decides each new cache's size from the
// request, what is already reserved, and a ceiling: the generous default still applies to the first mount on a
// well-provisioned machine, later mounts shrink to the remaining headroom, and once too little remains it returns
// 0 so the caller streams (which writes nothing to disk) instead of wiring memory the machine cannot afford. This
// pins that arithmetic so a regression cannot let the aggregate run past the ceiling or shrink the common case.
//
// Run:  node lib/test/ramcache-budget.js

const RamCache = require('../RamCache');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	console.log('[first mount on a well-provisioned machine keeps the generous default]');
	ok('a first mount (nothing reserved) gets the full 2 GB default', RamCache.planSizeMB({}, 0, 4096) === 2048);
	ok('a low ceiling caps even the first mount (never wire more than the budget)', RamCache.planSizeMB({}, 0, 1536) === 1536);

	console.log('[the aggregate across mounts is bounded]');
	ok('a second mount shrinks to the remaining headroom', RamCache.planSizeMB({}, 3072, 4096) === 1024); // 4096-3072 = 1024
	ok('a mount at the ceiling gets nothing (stream instead)', RamCache.planSizeMB({}, 4096, 4096) === 0);
	ok('headroom below the 256 MB minimum yields 0 (stream, do not wire a scrap)', RamCache.planSizeMB({}, 4000, 4096) === 0);

	console.log('[per-mount request handling and clamps]');
	ok('an explicit smaller request is honored', RamCache.planSizeMB({ cacheSizeMB: 512 }, 0, 4096) === 512);
	ok('an explicit request is still capped by the aggregate headroom', RamCache.planSizeMB({ cacheSizeMB: 4096 }, 3000, 4096) === 1096);
	ok('the per-mount maximum clamp (8 GB) still applies under a huge ceiling', RamCache.planSizeMB({ cacheSizeMB: 99999 }, 0, 999999) === 8192);
	ok('a non-positive request falls back to the default', RamCache.planSizeMB({ cacheSizeMB: 0 }, 0, 4096) === 2048 && RamCache.planSizeMB({ cacheSizeMB: -5 }, 0, 4096) === 2048);

	console.log('[the ceiling derives from real memory and is sane]');
	const ceil = RamCache.aggregateCeilingMB();
	ok('aggregateCeilingMB returns a positive number of megabytes', typeof ceil === 'number' && ceil > 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RAM-CACHE-BUDGET CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
