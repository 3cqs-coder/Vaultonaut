'use strict';
// lib/test/reedsolomon.js — exhaustive correctness tests for the pure-JS Reed–Solomon erasure codec.
// The codec is the load-bearing part of vault self-healing, so this proves: the field math is a
// valid GF(2^8), encoding is systematic, ANY k of n shards reconstruct the data (checked
// exhaustively for small shapes and randomly for large ones), losing more than m shards fails
// cleanly, and edge shapes (m=0, m=1, large n) all hold.
//
// Run:  node lib/test/reedsolomon.js

const crypto = require('crypto');
const RS = require('../ReedSolomon');

let failures = 0;
function ok(name, cond) { if (!cond) { console.log('  FAIL ' + name); failures++; } }

// Deterministic PRNG so a failure is reproducible (no Math.random).
let seed = 0x12345678;
function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; }
function randByte() { return rnd() & 0xff; }

// Every k-subset of [0..n-1], as index arrays.
function kSubsets(n, k) {
	const out = [];
	const rec = (start, chosen) => {
		if (chosen.length === k) { out.push(chosen.slice()); return; }
		for (let i = start; i < n; i++) { chosen.push(i); rec(i + 1, chosen); chosen.pop(); }
	};
	rec(0, []);
	return out;
}

function buildShards(k, m, len) {
	const data = Array.from({ length: k }, () => { const b = Buffer.alloc(len); for (let i = 0; i < len; i++) b[i] = randByte(); return b; });
	const rs = RS.codec(k, m);
	const parity = rs.encode(data);
	return { rs, data, all: data.concat(parity) };
}

function main() {
	console.log('[GF(2^8) field]');
	// a * inv(a) == 1, and div is the inverse of mul, across all nonzero elements.
	let fieldOk = true, divOk = true;
	for (let a = 1; a < 256; a++) {
		if (RS.gfMul(a, RS.gfInv(a)) !== 1) fieldOk = false;
		for (let b = 1; b < 256; b++) if (RS.gfMul(RS.gfDiv(a, b), b) !== a) { divOk = false; break; }
	}
	ok('a * inv(a) == 1 for all nonzero a', fieldOk);
	ok('div is the inverse of mul for all pairs', divOk);
	ok('gfInv(0) throws', (() => { try { RS.gfInv(0); return false; } catch (_) { return true; } })());

	console.log('[systematic encoding]');
	{
		const { data, all } = buildShards(5, 3, 32);
		let same = true;
		for (let i = 0; i < 5; i++) if (!all[i].equals(data[i])) same = false;
		ok('the first k shards are the data unchanged', same);
	}

	console.log('[exhaustive recovery — every loss pattern of up to m shards, small shapes]');
	{
		let allRecovered = true, checks = 0;
		for (const [k, m] of [[1, 1], [2, 1], [2, 2], [3, 2], [4, 3], [5, 3], [6, 2], [3, 5]]) {
			const { rs, data, all } = buildShards(k, m, 24);
			const n = k + m;
			// Try losing every subset of size 1..m (any k survivors must rebuild the data exactly).
			for (let lose = 1; lose <= m; lose++) {
				for (const lost of kSubsets(n, lose)) {
					const shards = all.map(b => Buffer.from(b));
					const present = new Array(n).fill(true);
					for (const idx of lost) { shards[idx] = null; present[idx] = false; }
					rs.reconstruct(shards, present);
					checks++;
					for (let i = 0; i < k; i++) if (!shards[i].equals(data[i])) allRecovered = false;
					for (let i = 0; i < n; i++) if (!shards[i].equals(all[i])) allRecovered = false; // parity too
				}
			}
		}
		ok('every loss of up to m shards reconstructs exactly (' + checks + ' cases)', allRecovered);
	}

	console.log('[unrecoverable — losing m+1 shards fails cleanly]');
	{
		const { rs, all } = buildShards(4, 2, 16);
		const n = 6;
		const shards = all.map(b => Buffer.from(b));
		const present = new Array(n).fill(true);
		for (const idx of [0, 1, 2]) { shards[idx] = null; present[idx] = false; } // lose 3 > m=2
		ok('losing m+1 shards throws (not silent wrong data)', (() => { try { rs.reconstruct(shards, present); return false; } catch (_) { return true; } })());
	}

	console.log('[edge shapes]');
	{
		// m = 0 (no parity): reconstruct is a no-op when all present, throws if any lost.
		const { rs, data, all } = buildShards(4, 0, 8);
		const shards = all.map(b => Buffer.from(b));
		rs.reconstruct(shards, [true, true, true, true]);
		ok('m=0 with all present is a no-op', shards.every((b, i) => b.equals(data[i])));

		// len = 0 (empty shards): encode and reconstruct must round-trip with no out-of-bounds on the per-byte
		// loop. Callers always use a fixed block size >= 1, so this is a belt-and-suspenders guard on the codec.
		{
			const z = buildShards(3, 2, 0);
			const s = z.all.map(b => Buffer.from(b));
			const p = [true, true, true, true, true]; s[0] = null; s[4] = null; p[0] = false; p[4] = false; // lose m=2
			z.rs.reconstruct(s, p);
			ok('zero-length shards reconstruct (empty round-trip, no bounds error)', s.every((b, i) => b && b.length === 0));
		}

		// m = 1 recovers any single loss (parity-like).
		const one = buildShards(7, 1, 40);
		for (let idx = 0; idx < 8; idx++) {
			const s = one.all.map(b => Buffer.from(b));
			const p = new Array(8).fill(true); s[idx] = null; p[idx] = false;
			one.rs.reconstruct(s, p);
			ok('m=1 recovers the loss of shard ' + idx, s.every((b, i) => b.equals(one.all[i])));
		}

		// Large n near the field limit, random large loss up to m.
		const k = 200, m = 50; // n = 250 <= 256
		const big = buildShards(k, m, 64);
		const n = k + m;
		let bigOk = true;
		for (let trial = 0; trial < 5; trial++) {
			const s = big.all.map(b => Buffer.from(b));
			const p = new Array(n).fill(true);
			const lost = new Set();
			while (lost.size < m) lost.add(rnd() % n);
			for (const idx of lost) { s[idx] = null; p[idx] = false; }
			big.rs.reconstruct(s, p);
			for (let i = 0; i < k; i++) if (!s[i].equals(big.data[i])) bigOk = false;
		}
		ok('large shape k=200 m=50 recovers 50 random losses', bigOk);
	}

	console.log('[randomized fuzz — 300 random shapes and loss patterns]');
	{
		let fuzzOk = true;
		for (let t = 0; t < 300; t++) {
			const k = 1 + (rnd() % 30);
			const m = rnd() % Math.min(20, 256 - k);
			const len = 1 + (rnd() % 50);
			const { rs, data, all } = buildShards(k, m, len);
			const n = k + m;
			const s = all.map(b => Buffer.from(b));
			const p = new Array(n).fill(true);
			const lose = m ? (rnd() % (m + 1)) : 0;
			const lost = new Set();
			while (lost.size < lose) lost.add(rnd() % n);
			for (const idx of lost) { s[idx] = null; p[idx] = false; }
			rs.reconstruct(s, p);
			for (let i = 0; i < k; i++) if (!s[i].equals(data[i])) fuzzOk = false;
		}
		ok('300 random encode/lose/reconstruct round-trips recover exactly', fuzzOk);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REED–SOLOMON CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
