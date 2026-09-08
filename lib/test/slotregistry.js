'use strict';
// lib/test/slotregistry.js — the deniable-storage slot primitive behind per-vault decoys and travel mode. The
// whole point is that a stored file reveals NOTHING without a key: every slot is the same size whatever it holds,
// a wrong key and a real key do the same work and both learn nothing, and the on-disk format is fixed so a
// registry written by an earlier build still opens. This checks those invariants on the crypto directly.
//
// Run:  node lib/test/slotregistry.js  (no engine needed)

const crypto = require('crypto');
const S = require('../SlotRegistry');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const K = crypto.randomBytes(32);        // a real derived key is 32 bytes; the slot crypto keys off it via HKDF
	const wrongK = crypto.randomBytes(32);

	// FORMAT STABILITY: the on-disk slot layout must not drift, or an older registry would stop opening.
	ok('the slot size is the fixed salt+iv+plaintext+tag layout', S.SLOT_LEN === 32 + 12 + S.PLAINTEXT_SIZE + 16 && S.PLAINTEXT_SIZE === 16384);

	// LENGTH UNIFORMITY: a tiny payload and a large one produce byte-identical-length slots, so the amount stored
	// (and whether a slot is real at all) cannot be inferred from size.
	const small = S.encryptSlot(K, { a: 1 });
	const big = S.encryptSlot(K, { paths: Array.from({ length: 200 }, (_, i) => '/some/vault/path/number-' + i + '.vault') });
	ok('a small payload fills a full-size slot', Buffer.isBuffer(small) && small.length === S.SLOT_LEN);
	ok('a large payload is the SAME size as a small one (length reveals nothing)', big.length === small.length);
	ok('random filler is indistinguishable from a real slot by size', S.randomSlot().length === S.SLOT_LEN);

	// CONFIDENTIALITY + NO-LEAK: the right key recovers the payload; a wrong key learns nothing and never throws.
	ok('the right key recovers the exact payload', JSON.stringify(S.tryDecryptSlot(K, small)) === JSON.stringify({ a: 1 }));
	ok('a wrong key returns null (no partial read, no throw)', S.tryDecryptSlot(wrongK, small) === null);
	ok('the right key against random filler returns null (AEAD rejects)', S.tryDecryptSlot(K, S.randomSlot()) === null);

	// NON-DETERMINISM: encrypting the same object twice yields different bytes (fresh HKDF salt + IV), so equal
	// contents across slots can't be spotted, yet both still decrypt. Defeats an "are these two the same?" oracle.
	const one = S.encryptSlot(K, { x: 'same' }), two = S.encryptSlot(K, { x: 'same' });
	ok('encrypting the same payload twice gives different bytes', !one.equals(two));
	ok('both encryptions still decrypt to the same payload', JSON.stringify(S.tryDecryptSlot(K, one)) === JSON.stringify(S.tryDecryptSlot(K, two)));

	// ROBUSTNESS: a malformed, short, or wrong-length slot returns null rather than throwing (the trial-decrypt
	// over a whole registry must never crash on a corrupt or attacker-supplied slot).
	let threw = false;
	try {
		ok('a truncated slot returns null', S.tryDecryptSlot(K, small.subarray(0, 50)) === null);
		ok('an empty buffer returns null', S.tryDecryptSlot(K, Buffer.alloc(0)) === null);
		ok('a non-buffer returns null', S.tryDecryptSlot(K, null) === null && S.tryDecryptSlot(K, 'not a slot') === null);
		ok('a full-size random blob returns null', S.tryDecryptSlot(K, crypto.randomBytes(S.SLOT_LEN)) === null);
		// A slot with the tag flipped fails authentication (integrity), not a silent wrong read.
		const tampered = Buffer.from(small); tampered[tampered.length - 1] ^= 0xff;
		ok('a tampered slot fails authentication (returns null)', S.tryDecryptSlot(K, tampered) === null);
	} catch (_) { threw = true; }
	ok('trial-decrypt never throws on bad input', threw === false);

	// A payload too large to fit one slot is refused up front (not silently truncated).
	let tooBig = false;
	try { S.encryptSlot(K, { blob: 'x'.repeat(S.PLAINTEXT_SIZE) }); } catch (_) { tooBig = true; }
	ok('an over-size payload is refused, never truncated', tooBig);

	// The real derive path works end to end: a key derived from a credential encrypts and decrypts a slot, and a
	// different credential does not open it.
	const params = S.newKdfParams();
	const dk = await S.deriveK('a-credential', params);
	const dkWrong = await S.deriveK('a-different-credential', params);
	const dslot = S.encryptSlot(dk, { real: true });
	ok('a slot opens with the credential-derived key', S.tryDecryptSlot(dk, dslot) && S.tryDecryptSlot(dk, dslot).real === true);
	ok('a different credential does not open it', S.tryDecryptSlot(dkWrong, dslot) === null);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SLOT-REGISTRY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
