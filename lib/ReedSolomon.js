'use strict';
// lib/ReedSolomon.js — a small, dependency-free Reed–Solomon ERASURE codec over GF(2^8), used to
// build the optional per-vault recovery data. This is error-correction math, NOT cryptography: the
// vault's confidentiality and authentication stay entirely in the bundled encryption engine. This
// module only lets a set of data blocks survive the loss/corruption of some of them.
//
// Model (the standard "data shards + parity shards" erasure-coding model):
//   • k data shards + m parity shards = n total, all the SAME length, one byte-stream each.
//   • The code is SYSTEMATIC — the first k shards ARE the data (read directly, no decode needed) —
//     and MDS: ANY k of the n shards reconstruct the original data, so any m shards may be lost.
//   • Reed–Solomon runs independently on each byte position across the n shards, so a shard is just
//     an opaque Buffer; encode/decode is per-byte GF(2^8) linear algebra.
//
// The encoding matrix is [ I_k ; C ] where C is an m×k CAUCHY matrix. A Cauchy matrix has every
// square submatrix invertible, which makes [I; C] an MDS generator: any k surviving shards give a
// k×k submatrix that is always invertible, so reconstruction never fails while ≥ k shards remain.
//
// GF(2^8) uses the standard primitive polynomial 0x11d (x^8+x^4+x^3+x^2+1) and generator 2 — the
// field used by most Reed–Solomon implementations. n = k + m must be ≤ 256.

const FIELD = 256;
const POLY = 0x11d;

// log / exp (antilog) tables for GF(2^8) multiplication and inverse. EXP is doubled in length so a
// multiply can add logs without a modulo.
const EXP = new Uint8Array(FIELD * 2);
const LOG = new Uint8Array(FIELD);
(function buildTables() {
	let x = 1;
	for (let i = 0; i < FIELD - 1; i++) {
		EXP[i] = x;
		LOG[x] = i;
		x <<= 1;
		if (x & FIELD) x ^= POLY; // reduce modulo the primitive polynomial
	}
	for (let i = FIELD - 1; i < EXP.length; i++) EXP[i] = EXP[i - (FIELD - 1)];
})();

// Full multiply table (256 rows of 256): MUL[c][x] = c·x in GF(2^8). The per-byte encode/decode inner loops
// dominate protect/heal, and one table lookup `o[b] ^= MUL[coef][d[b]]` is markedly faster than the
// log-add-antilog `EXP[LOG[c]+LOG[x]]` with its zero-branch (MUL[c][0] and MUL[0][x] are 0, so a zero
// coefficient or byte contributes nothing without a branch). 64 KiB, built once at load from LOG/EXP.
const MUL = [];
for (let c = 0; c < FIELD; c++) {
	const row = new Uint8Array(FIELD);
	if (c !== 0) { const lc = LOG[c]; for (let x = 1; x < FIELD; x++) row[x] = EXP[lc + LOG[x]]; }
	MUL.push(row);
}

function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]]; }
function gfDiv(a, b) { if (b === 0) throw new Error('GF divide by zero'); return a === 0 ? 0 : EXP[LOG[a] + (FIELD - 1) - LOG[b]]; }
function gfInv(a) { if (a === 0) throw new Error('GF inverse of zero'); return EXP[(FIELD - 1) - LOG[a]]; }

// ── matrices over GF(2^8) (plain number[][]) ──────────────────────────────────────────────────
// Invert a square matrix via Gauss–Jordan elimination over GF(2^8). Throws if singular (which, for a
// submatrix drawn from our Cauchy-based generator, cannot happen while ≥ k shards survive).
function matInvert(src) {
	const n = src.length;
	const m = src.map((row, i) => { const r = row.slice(); for (let j = 0; j < n; j++) r.push(i === j ? 1 : 0); return r; });
	for (let col = 0; col < n; col++) {
		let piv = col;
		while (piv < n && m[piv][col] === 0) piv++;
		if (piv === n) throw new Error('matrix is singular');
		if (piv !== col) { const t = m[piv]; m[piv] = m[col]; m[col] = t; }
		const inv = gfInv(m[col][col]);
		for (let j = 0; j < 2 * n; j++) m[col][j] = gfMul(m[col][j], inv);
		for (let row = 0; row < n; row++) {
			if (row === col || m[row][col] === 0) continue;
			const factor = m[row][col];
			for (let j = 0; j < 2 * n; j++) m[row][j] ^= gfMul(factor, m[col][j]);
		}
	}
	return m.map(row => row.slice(n));
}

// The m×k Cauchy parity matrix: C[i][j] = 1 / (x_i + y_j) with the x's and y's distinct and disjoint
// (field addition is XOR). y_j = j (0..k-1), x_i = k+i (k..k+m-1), so all are distinct and x⊕y ≠ 0.
function cauchy(k, m) {
	const C = [];
	for (let i = 0; i < m; i++) {
		const row = new Array(k);
		for (let j = 0; j < k; j++) row[j] = gfInv((k + i) ^ j);
		C.push(row);
	}
	return C;
}

// A codec bound to (k, m). Reusable across all stripes with the same shape.
function codec(k, m) {
	if (k < 1 || m < 0) throw new Error('invalid shard counts');
	if (k + m > FIELD) throw new Error('k + m must be <= ' + FIELD);
	const n = k + m;
	const parity = cauchy(k, m);        // m×k
	// Encoding matrix rows for EVERY shard: identity rows for the k data shards, Cauchy rows for the
	// m parity shards. Row `s` maps the k data shards to shard s.
	const encodeRow = (s) => (s < k) ? Array.from({ length: k }, (_, j) => (j === s ? 1 : 0)) : parity[s - k];

	// Compute the m parity shards from the k data shards (all Buffers of equal length `len`).
	function encode(dataShards) {
		if (dataShards.length !== k) throw new Error('expected ' + k + ' data shards');
		const len = dataShards[0].length;
		const out = Array.from({ length: m }, () => Buffer.alloc(len));
		for (let i = 0; i < m; i++) {
			const prow = parity[i];
			const o = out[i];
			for (let j = 0; j < k; j++) {
				const coef = prow[j]; if (coef === 0) continue;
				const d = dataShards[j];
				const mrow = MUL[coef];
				for (let b = 0; b < len; b++) o[b] ^= mrow[d[b]];
			}
		}
		return out;
	}

	// Reconstruct the missing shards in place. `shards` is length-n; present entries are Buffers, lost
	// ones are null. `present[s]` is the boolean map. Fills every null with its recovered Buffer.
	// Returns the same array. Throws if fewer than k shards survive (unrecoverable).
	function reconstruct(shards, present) {
		const haveIdx = [];
		for (let s = 0; s < n && haveIdx.length < k; s++) if (present[s]) haveIdx.push(s);
		if (haveIdx.length < k) throw new Error('too much loss to recover (need ' + k + ' of ' + n + ' shards, have ' + present.filter(Boolean).length + ')');
		const len = shards[haveIdx[0]].length;
		// Every surviving shard must be the same length, or the byte-wise solve below would read past a short one
		// (undefined -> a silently wrong byte). Assert it rather than reconstruct garbage. Defense in depth: callers
		// pass shards derived from a shape-validated index, so this should never fire.
		for (const s of haveIdx) if (!shards[s] || shards[s].length !== len) throw new Error('cannot reconstruct: surviving shards have unequal lengths');

		// Recover the DATA shards first (if any are missing): take k surviving shards, form their k×k
		// encode-matrix, invert it, and multiply by those shards to solve for the original data.
		const dataMissing = [];
		for (let s = 0; s < k; s++) if (!present[s]) dataMissing.push(s);
		if (dataMissing.length) {
			const sub = haveIdx.map(s => encodeRow(s));
			const inv = matInvert(sub);
			const survivors = haveIdx.map(s => shards[s]);
			for (const s of dataMissing) {
				const row = inv[s]; // row that produces data shard s from the survivors
				const buf = Buffer.alloc(len);
				for (let t = 0; t < k; t++) {
					const coef = row[t]; if (coef === 0) continue;
					const src = survivors[t], mrow = MUL[coef];
					for (let b = 0; b < len; b++) buf[b] ^= mrow[src[b]];
				}
				shards[s] = buf; present[s] = true;
			}
		}

		// Then recompute any missing PARITY shards directly from the (now complete) data shards.
		const needParity = [];
		for (let s = k; s < n; s++) if (!present[s]) needParity.push(s);
		if (needParity.length) {
			const data = [];
			for (let s = 0; s < k; s++) data.push(shards[s]);
			for (const s of needParity) {
				const prow = parity[s - k];
				const buf = Buffer.alloc(len);
				for (let j = 0; j < k; j++) {
					const coef = prow[j]; if (coef === 0) continue;
					const d = data[j], mrow = MUL[coef];
					for (let b = 0; b < len; b++) buf[b] ^= mrow[d[b]];
				}
				shards[s] = buf; present[s] = true;
			}
		}
		return shards;
	}

	return { k, m, n, encode, reconstruct };
}

// gfMul/gfDiv/gfInv are reused by Shamir.js; matInvert is used only internally by codec().
module.exports = { codec, gfMul, gfDiv, gfInv };
