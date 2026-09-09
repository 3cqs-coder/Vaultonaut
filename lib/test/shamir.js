'use strict';
// lib/test/shamir.js — exhaustive checks for the Shamir threshold secret-sharing primitive. Any k of
// n shares must reconstruct the secret exactly; fewer than k must be refused; corrupted or mismatched
// shares must not silently pass. Combinatorial over small shapes, plus randomized fuzzing.
//
// Run:  node lib/test/shamir.js

const crypto = require('crypto');
const Shamir = require('../Shamir');

let failures = 0;
function ok(name, cond) { if (!cond) { console.log('  FAIL ' + name); failures++; } }
function eqBuf(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); }

// Every k-subset of [0..n-1].
function kSubsets(n, k) {
	const out = [];
	(function pick(start, chosen) {
		if (chosen.length === k) { out.push(chosen.slice()); return; }
		for (let i = start; i < n; i++) { chosen.push(i); pick(i + 1, chosen); chosen.pop(); }
	})(0, []);
	return out;
}

function main() {
	console.log('[exhaustive: every k-subset of small shapes reconstructs; every (k-1)-subset is refused]');
	let shapeChecks = 0;
	for (let n = 2; n <= 7; n++) {
		for (let k = 2; k <= n; k++) {
			const secret = crypto.randomBytes(1 + (n * k) % 40);
			const shares = Shamir.split(secret, n, k);
			ok('split produces n shares (n=' + n + ',k=' + k + ')', shares.length === n);
			// Any k of n reconstruct exactly.
			for (const sub of kSubsets(n, k)) {
				const got = Shamir.combine(sub.map(i => shares[i]));
				if (!eqBuf(got, secret)) { ok('k-subset {' + sub + '} reconstructs (n=' + n + ',k=' + k + ')', false); }
				shapeChecks++;
			}
			// Any k-1 are refused (threshold enforced), never a silent wrong answer.
			if (k >= 2) {
				for (const sub of kSubsets(n, k - 1)) {
					let refused = false;
					try { Shamir.combine(sub.map(i => shares[i])); } catch (_) { refused = true; }
					ok('under-threshold {' + sub + '} is refused (n=' + n + ',k=' + k + ')', refused);
				}
			}
		}
	}
	console.log('  (' + shapeChecks + ' successful k-subset reconstructions)');

	console.log('[secret sizes: empty, 1 byte, 32-byte key, large]');
	for (const len of [0, 1, 16, 32, 1000]) {
		const secret = crypto.randomBytes(len);
		const shares = Shamir.split(secret, 5, 3);
		ok('reconstructs a ' + len + '-byte secret', eqBuf(Shamir.combine([shares[4], shares[0], shares[2]]), secret));
	}

	console.log('[string secret round-trips as UTF-8]');
	{
		const shares = Shamir.split('correct horse battery staple 🔐', 4, 2);
		ok('string secret reconstructs', Shamir.combine([shares[1], shares[3]]).toString('utf8') === 'correct horse battery staple 🔐');
	}

	console.log('[order independence + extra shares]');
	{
		const secret = crypto.randomBytes(24);
		const shares = Shamir.split(secret, 6, 3);
		ok('shares combine in any order', eqBuf(Shamir.combine([shares[5], shares[1], shares[3]]), secret));
		ok('more than k shares still reconstruct', eqBuf(Shamir.combine(shares), secret));
		ok('a duplicated share does not count toward the threshold', (() => { try { Shamir.combine([shares[0], shares[0], shares[0]]); return false; } catch (_) { return true; } })());
	}

	console.log('[tamper + malformed]');
	{
		const secret = crypto.randomBytes(20);
		const shares = Shamir.split(secret, 5, 3);
		ok('a malformed share is rejected', (() => { try { Shamir.combine([shares[0], 'garbage', shares[2]]); return false; } catch (_) { return true; } })());
		ok('shares from different splits are rejected', (() => { const other = Shamir.split(secret, 5, 4); try { Shamir.combine([shares[0], shares[1], other[2]]); return false; } catch (_) { return true; } })());
		// A corrupted share within a k-set does not throw but must not yield the true secret.
		const bad = Shamir.parseShare(shares[1]); bad.y[0] ^= 0xff;
		// Rebuild the corrupted share preserving its split id, so it is still recognized as belonging to THIS split
		// (a same-split corrupted byte, not a cross-split mix) — the case this asserts is caught later by the AEAD.
		const corrupted = 'vds1.3.' + bad.x + '.' + Buffer.from(bad.y).toString('base64') + (bad.id ? '.' + bad.id : '');
		ok('a corrupted share yields a wrong secret, not the true one (caught downstream by AEAD)', !eqBuf(Shamir.combine([shares[0], corrupted, shares[2]]), secret));
	}

	console.log('[split-id binding]');
	{
		// Each split carries a random id in every share; combine rejects a mix of shares from DIFFERENT splits that
		// happen to agree on k and length, instead of silently interpolating to a wrong secret.
		const secret = crypto.randomBytes(32);
		const a = Shamir.split(secret, 5, 3), b = Shamir.split(secret, 5, 3); // same shape, two independent splits
		const idA = Shamir.parseShare(a[0]).id, idB = Shamir.parseShare(b[0]).id;
		ok('every share carries a split id', !!idA && a.every(s => Shamir.parseShare(s).id === idA));
		ok('two independent splits get different ids', !!idB && idA !== idB);
		ok('a same-split k-set still reconstructs', eqBuf(Shamir.combine([a[0], a[2], a[4]]), secret));
		ok('a cross-split mix (equal k and length) is refused, not silently wrong', (() => { try { Shamir.combine([a[0], a[1], b[2]]); return false; } catch (e) { return /different splits/i.test(e.message); } })());
		// Backward compatibility: shares written before ids existed (four fields, no id) still reconstruct.
		const legacy = a.map(s => { const p = Shamir.parseShare(s); return 'vds1.' + p.k + '.' + p.x + '.' + Buffer.from(p.y).toString('base64'); });
		ok('legacy id-less shares still reconstruct', eqBuf(Shamir.combine([legacy[0], legacy[1], legacy[2]]), secret));
		ok('mixing an id-less share with id-bearing ones is refused', (() => { try { Shamir.combine([a[0], a[1], legacy[2]]); return false; } catch (e) { return /different splits/i.test(e.message); } })());
	}

	console.log('[randomized fuzz — 400 random shapes/secrets/subsets]');
	for (let t = 0; t < 400; t++) {
		const n = 2 + (crypto.randomBytes(1)[0] % 8);
		const k = 2 + (crypto.randomBytes(1)[0] % (n - 1));
		const secret = crypto.randomBytes(crypto.randomBytes(1)[0] % 64);
		const shares = Shamir.split(secret, n, k);
		// pick a random k-subset
		const idx = [...Array(n).keys()];
		for (let i = idx.length - 1; i > 0; i--) { const j = crypto.randomBytes(1)[0] % (i + 1); [idx[i], idx[j]] = [idx[j], idx[i]]; }
		const pick = idx.slice(0, k).map(i => shares[i]);
		if (!eqBuf(Shamir.combine(pick), secret)) { ok('fuzz #' + t + ' (n=' + n + ',k=' + k + ',len=' + secret.length + ')', false); }
	}

	console.log('[strict share parsing — a mangled field is rejected, not reinterpreted]');
	{
		const shares = Shamir.split(crypto.randomBytes(16), 5, 3);
		const p = Shamir.parseShare(shares[0]);
		ok('a genuine share parses', p && p.k === 3 && p.x === 1);
		ok('scientific-notation k is rejected ("2e1")', Shamir.parseShare('vds1.2e1.5.' + p.y.toString('base64')) === null);
		ok('hex x is rejected ("0x3")', Shamir.parseShare('vds1.3.0x3.' + p.y.toString('base64')) === null);
		ok('whitespace in a field is rejected', Shamir.parseShare('vds1.3. 4 .' + p.y.toString('base64')) === null);
		ok('non-canonical base64 body is rejected', Shamir.parseShare('vds1.3.4.not*valid*base64') === null);
		// Forward compatibility: a share written by a NEWER format (a bumped family, or the current family with extra
		// fields) must be reported as "update the app," not as a corrupt/unrecognized share — otherwise a user hunts
		// for a broken share that is only newer than this build.
		const body = p.y.toString('base64');
		ok('a bumped share family is detected as newer (vds2)', Shamir.looksNewerFormat('vds2.3.1.' + body));
		ok('the current family with extra fields is detected as newer', Shamir.looksNewerFormat('vds1.3.1.' + body + '.abcdef01.extra'));
		ok('a genuine current share is NOT flagged as newer', !Shamir.looksNewerFormat('vds1.3.1.' + body + '.abcdef01'));
		ok('an unrelated string is NOT flagged as newer', !Shamir.looksNewerFormat('hello.world'));
		ok('combine reports a newer-format share as "update", not "malformed"', (() => { try { Shamir.combine(['vds2.3.1.' + body]); return false; } catch (e) { return /newer version/i.test(e.message); } })());
	}

	console.log('[same-shape cross-split is rejected outright]');
	{
		// Two splits of the same shape (n,k) but different secrets. The split id now makes a mix of their shares a
		// HARD rejection, rather than the old behavior of silently interpolating to a wrong secret that only the
		// downstream AEAD would later catch — a wrong secret is never returned in the first place.
		const s1 = crypto.randomBytes(20), s2 = crypto.randomBytes(20);
		const a = Shamir.split(s1, 5, 3), b = Shamir.split(s2, 5, 3); // same (n,k), different secrets
		ok('mixing shares from two same-shape splits is refused (never a silent wrong secret)', (() => { try { Shamir.combine([a[0], a[1], b[2]]); return false; } catch (e) { return /different splits/i.test(e.message); } })());
	}

	console.log('[non-constant coefficients are uniform — perfect secrecy, no excluded value]');
	{
		// Shamir's information-theoretic secrecy requires every non-constant coefficient to be UNIFORM over the whole
		// field, zero included. An earlier version forced the top coefficient nonzero, which excluded the secret's own
		// value from a share byte and leaked ~1 value per byte. Assert the leak is gone: over many k=2 splits a share
		// byte CAN equal the secret byte (impossible under the old reroll), share bytes span the full 0..255 range
		// (uniform, not biased away from any value), and the split still reconstructs exactly.
		const secret = Buffer.alloc(64, 0xa5); // a fixed byte value so one position's distribution is observable
		const seenEqualSecret = new Set(); const values = new Set();
		let roundTrips = true;
		for (let t = 0; t < 400; t++) {
			const shares = Shamir.split(secret, 2, 2);
			if (!Shamir.combine(shares).equals(secret)) roundTrips = false;
			for (const sh of shares) { const y = Shamir.parseShare(sh).y; for (let b = 0; b < secret.length; b++) { values.add(y[b]); if (y[b] === secret[b]) seenEqualSecret.add(b); } }
		}
		ok('k=2 split/combine still round-trips exactly', roundTrips);
		ok('a share byte can equal the secret byte (uniform coefficients — no leak-inducing exclusion)', seenEqualSecret.size > 0);
		ok('share bytes span the full field (uniform, not biased away from any value)', values.size === 256);
	}

	console.log('[the field-edge shape n=255 works]');
	{
		const secret = crypto.randomBytes(24);
		const shares = Shamir.split(secret, 255, 3);
		ok('n=255 produces 255 shares', shares.length === 255);
		ok('any 3 of 255 reconstruct the secret', eqBuf(Shamir.combine([shares[0], shares[128], shares[254]]), secret));
	}

	console.log('[parameter validation]');
	ok('k < 2 is refused', (() => { try { Shamir.split(Buffer.from('x'), 3, 1); return false; } catch (_) { return true; } })());
	ok('n < k is refused', (() => { try { Shamir.split(Buffer.from('x'), 2, 3); return false; } catch (_) { return true; } })());
	ok('n > 255 is refused', (() => { try { Shamir.split(Buffer.from('x'), 256, 2); return false; } catch (_) { return true; } })());

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SHAMIR CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
