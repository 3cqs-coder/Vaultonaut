'use strict';
// lib/Shamir.js — Shamir threshold secret sharing over GF(2^8). Splits a secret into n shares such
// that ANY k of them reconstruct it and any k-1 reveal nothing. Used to disperse a vault's key across
// nodes so no single node — or a subpoena to one host — can decrypt, while k cooperating shares
// restore access.
//
// It reuses the exact GF(2^8) field the Reed–Solomon codec already ships (same primitive polynomial,
// same log/exp tables), so there is no second finite-field implementation to trust. Add is XOR;
// multiply/divide come from ReedSolomon.
//
//   split(secret, n, k) -> [shareString × n]     (2 ≤ k ≤ n ≤ 255)
//   combine([shareString ≥ k]) -> Buffer         (reconstructs the secret; refuses fewer than k)
//
// A share is a short self-describing string: "vds1.<k>.<x>.<base64(y)>", where x is the share's
// distinct evaluation point (1..n) and y is the per-byte polynomial value. k travels in the share so
// combine can enforce the threshold. The scheme is information-theoretic: fewer than k shares are
// statistically independent of the secret, so a lost or stolen minority leaks nothing.

const crypto = require('crypto');
const { gfMul, gfDiv } = require('./ReedSolomon');

const PREFIX = 'vds1'; // vault-disk share, format 1

function formatShare(k, x, y) { return PREFIX + '.' + k + '.' + x + '.' + Buffer.from(y).toString('base64'); }
// Strict decimal integer, so a mangled field ("2e1", "0x3", " 4 ") is rejected rather than silently
// reinterpreted with a different k/x.
function strictInt(s) { return /^\d+$/.test(s) ? Number(s) : NaN; }
function parseShare(s) {
	const parts = String(s || '').trim().split('.');
	if (parts.length !== 4 || parts[0] !== PREFIX) return null;
	const k = strictInt(parts[1]), x = strictInt(parts[2]);
	if (!Number.isInteger(k) || k < 2 || !Number.isInteger(x) || x < 1 || x > 255) return null;
	// Base64 decoding is lenient (it never throws and drops stray characters), so round-trip it to
	// confirm the body is exactly canonical base64 rather than a mangled string reinterpreted silently.
	const y = Buffer.from(parts[3], 'base64');
	if (y.toString('base64') !== parts[3]) return null;
	return { k, x, y };
}

// Split `secret` (a Buffer or string) into n shares with threshold k. Each byte is shared under its own
// random degree-(k-1) polynomial whose constant term is that byte, so the shares are independent per
// byte and no share reveals the secret.
function split(secret, n, k) {
	const buf = Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret), 'utf8');
	if (!Number.isInteger(k) || !Number.isInteger(n) || k < 2 || n < k || n > 255) {
		throw new Error('Invalid share parameters: need 2 ≤ k ≤ n ≤ 255 (got k=' + k + ', n=' + n + ').');
	}
	const ys = Array.from({ length: n }, () => Buffer.alloc(buf.length));
	for (let b = 0; b < buf.length; b++) {
		const coeffs = crypto.randomBytes(k - 1); // a_1 … a_{k-1}, each UNIFORM over the whole field (zero included); constant term a_0 is the secret byte
		// Every non-constant coefficient is drawn uniformly, zero included — this is exactly what gives Shamir its
		// information-theoretic secrecy: from fewer than k shares the secret is uniformly distributed and nothing
		// leaks. Forcing the top coefficient nonzero (to keep the polynomial at exactly degree k-1) would EXCLUDE one
		// candidate secret value per byte from an adversary's view, a small but real leak, so it is deliberately NOT
		// done. Reconstruction is unaffected: Lagrange through k points recovers the unique polynomial of degree ≤ k-1
		// whether or not the top coefficient happens to be zero. (When it is zero at k=2 two shares share that byte's
		// value, which is harmless — a holder of fewer than k shares cannot tell a zero coefficient from a nonzero one.)
		for (let s = 0; s < n; s++) {
			const x = s + 1; // evaluation points 1..n (never 0, which would BE the secret)
			// Horner over the polynomial a_{k-1}·x^{k-1} + … + a_1·x + secret.
			let acc = coeffs[k - 2];
			for (let c = k - 3; c >= 0; c--) acc = gfMul(acc, x) ^ coeffs[c];
			acc = gfMul(acc, x) ^ buf[b];
			ys[s][b] = acc;
		}
	}
	return ys.map((y, s) => formatShare(k, s + 1, y));
}

// Reconstruct the secret from k or more shares via Lagrange interpolation at x = 0. Refuses fewer than
// k distinct shares (the threshold is carried in each share), so an accidental under-threshold combine
// fails loudly instead of returning a wrong secret.
function combine(shareStrings) {
	const parsed = [];
	const seen = new Set();
	for (const s of shareStrings || []) {
		const p = parseShare(s);
		if (!p) throw new Error('A share is malformed or from an unrecognized format.');
		if (seen.has(p.x)) continue; // ignore an accidental duplicate of the same point
		seen.add(p.x); parsed.push(p);
	}
	if (!parsed.length) throw new Error('No valid shares were provided.');
	const k = parsed[0].k;
	if (parsed.some(p => p.k !== k)) throw new Error('The shares are from different splits (their thresholds disagree).');
	if (parsed.some(p => p.y.length !== parsed[0].y.length)) throw new Error('The shares are from different splits (their lengths disagree).');
	if (parsed.length < k) throw new Error('Not enough shares: ' + parsed.length + ' of the required ' + k + '.');
	const pts = parsed.slice(0, k); // any k suffice
	const len = pts[0].y.length;
	const out = Buffer.alloc(len);
	for (let j = 0; j < k; j++) {
		// Lagrange basis for point j evaluated at 0:  Π_{i≠j} x_i / (x_j ⊕ x_i).
		let num = 1, den = 1;
		for (let i = 0; i < k; i++) {
			if (i === j) continue;
			num = gfMul(num, pts[i].x);
			den = gfMul(den, pts[j].x ^ pts[i].x);
		}
		const basis = gfDiv(num, den);
		for (let b = 0; b < len; b++) out[b] ^= gfMul(pts[j].y[b], basis);
	}
	return out;
}

module.exports = { split, combine, parseShare, PREFIX };
