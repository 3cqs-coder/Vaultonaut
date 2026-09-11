'use strict';
// lib/test/recoverygeometry.js — a pure, offline unit test of the Reed-Solomon GEOMETRY algebra that the whole
// self-heal rests on: shapeFor(D, r) (how D data blocks split into S stripes of k data + m parity shards) and the
// interleaving map stripeSlotToBlock(stripe, slot, S) = slot*S + stripe. The end-to-end recovery tests exercise this
// only through mid-size vaults; this pins the invariants directly, across the boundary sizes that matter (a single
// block, exactly K_MAX, one over, the field edge, and a large vault), so a future change to the shape math cannot
// silently break the codec bounds or the canonical re-derivation readIndex depends on. No engine, no mount — runs
// everywhere.
//
// Run:  node lib/test/recoverygeometry.js

const { shapeFor, stripeSlotToBlock, K_MAX } = require('../Recovery')._geom;
const { TIERS } = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// The redundancy percentages the product actually ships (low/medium/high), plus the extremes, so the invariants are
// checked across the whole configured range, not just one tier.
const RATES = [...new Set([1, 5, 10, 15, 100, ...Object.values(TIERS)])];
// The boundary block-counts: the degenerate single block, around K_MAX, around the GF(256) field edge, and a large vault.
const SIZES = [1, 2, 127, 128, 129, 254, 255, 256, 257, 511, 512, 16384, 16385];

for (const D of SIZES) {
	for (const r of RATES) {
		const { S, k, m } = shapeFor(D, r);
		const tag = 'D=' + D + ' r=' + r + ' -> S=' + S + ' k=' + k + ' m=' + m;
		// 1. Every stripe must have at least one parity shard, or it could not repair a single loss.
		ok('m >= 1  (' + tag + ')', m >= 1);
		// 2. Data shards per stripe never exceed the cap, so k + m stays well under the 256-symbol GF(2^8) field limit
		//    and the codec (which rejects k + m > 255) always accepts the shape.
		ok('k <= K_MAX and k + m <= 255  (' + tag + ')', k <= K_MAX && k + m <= 255);
		// 3. The S stripes of k data slots must cover all D real blocks (shorter stripes are zero-padded).
		ok('S*k >= D  (covers every data block)  (' + tag + ')', S * k >= D);
		// 4. S is minimal for the K_MAX cap: one stripe when it fits, otherwise just enough to keep k <= K_MAX.
		ok('S is the minimal stripe count for the cap  (' + tag + ')', S === Math.max(1, Math.ceil(D / K_MAX)));
	}
}

// 5. The interleaving map must be a BIJECTION from (stripe, slot) onto the global block index range [0, k*S) for every
//    shape — this is what lets protect/verify/heal agree on which block sits where. A collision or a gap would make
//    heal reconstruct the wrong block. Check it exhaustively for a representative shape at each size.
for (const D of SIZES) {
	const { S, k } = shapeFor(D, 10);
	const seen = new Set();
	let inRange = true;
	for (let stripe = 0; stripe < S; stripe++) {
		for (let slot = 0; slot < k; slot++) {
			const gi = stripeSlotToBlock(stripe, slot, S);
			if (gi < 0 || gi >= k * S) inRange = false;
			seen.add(gi);
		}
	}
	ok('the interleave map is a bijection onto [0, k*S)  (D=' + D + ', k*S=' + (k * S) + ')', inRange && seen.size === k * S);
	// Every real block 0..D-1 must be reachable (the padding blocks D..k*S-1 are the only extras).
	let allReal = true;
	for (let i = 0; i < D; i++) if (!seen.has(i)) allReal = false;
	ok('every real data block 0..D-1 is placed  (D=' + D + ')', allReal);
}

// 6. The degenerate single-block vault is the S=1, k=1 "mirror" geometry with m>=1 parity — the case the end-to-end
//    tests never build. Pin it explicitly.
{
	const g = shapeFor(1, 5);
	ok('a single-block vault is the S=1, k=1 mirror geometry with parity', g.S === 1 && g.k === 1 && g.m >= 1);
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-GEOMETRY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
