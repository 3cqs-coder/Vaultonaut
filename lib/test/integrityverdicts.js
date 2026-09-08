'use strict';
// lib/test/integrityverdicts.js — the two things the anti-rollback machinery rests on, tested as units:
//   1. observe() must return the right verdict for a REPLAY (seq goes backward), a FORK (same seq, different
//      contents), and a hidden-history CHAIN-BREAK (next seq, but the chain no longer links) — not just "ok".
//   2. the baseline signing input must bind EVERY security-relevant field, so flipping any one of them (root,
//      seq, prevRoot, count, timestamp, scheme, seal state, deep flag) breaks the signature. If a field were
//      silently dropped from the signed message, that field could be forged and every other test would still pass.
//
// Run:  node lib/test/integrityverdicts.js  (no engine needed)

const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-verdicts-'));
	const Common = require('../Common');
	Common.dataDir = () => tmp; // keep the rollback ledger in a throwaway dir; never touch real state
	fs.mkdirSync(tmp, { recursive: true });
	const Integrity = require('../Integrity');

	// --- observe() verdicts ---
	const vid = crypto.randomBytes(16).toString('hex');
	const rootA = 'a'.repeat(64), rootB = 'b'.repeat(64), rootC = 'c'.repeat(64);

	console.log('[observe verdicts]');
	ok('first sighting is ok', (await Integrity.observe(vid, 1, rootA, null, 'id1')).status === 'ok');
	ok('advancing the counter with a linked root is ok', (await Integrity.observe(vid, 2, rootB, rootA, 'id1')).status === 'ok');
	ok('re-observing the same seq and root is ok (idempotent)', (await Integrity.observe(vid, 2, rootB, rootA, 'id1')).status === 'ok');
	// ROLLBACK: a lower counter than we last saw — an older, still-valid state swapped in.
	ok('a lower seq than last seen is a rollback', (await Integrity.observe(vid, 1, rootA, null, 'id1')).status === 'rollback');
	// FORK: the SAME counter but different contents — the history was rewritten at that point.
	ok('the same seq with a different root is a fork', (await Integrity.observe(vid, 2, rootC, rootA, 'id1')).status === 'fork');
	// CHAIN-BREAK: the next counter, but its prevRoot does not link to the root we last recorded — a baseline in
	// between was hidden, or the chain re-forged, even though the number moved forward. Use a fresh vault so the
	// last-seen root is unambiguous.
	const vid2 = crypto.randomBytes(16).toString('hex');
	await Integrity.observe(vid2, 5, rootA, null, 'id1');
	ok('the next seq whose prevRoot does not link to the last root is a chain-break', (await Integrity.observe(vid2, 6, rootB, rootC /* prevRoot != rootA */, 'id1')).status === 'chain-break');
	ok('the ledger records the highest seq seen', (await Integrity.lastSeen(vid)).seq === 2);

	// --- signing-input field binding ---
	console.log('[signing input binds every field]');
	const kp = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	const base = { scheme: Integrity.SCHEME, root: 'd'.repeat(64), seq: 7, prevRoot: 'e'.repeat(64), count: 42, createdAt: '2026-01-02T03:04:05.000Z', version: 4, sealed: true, deep: true };
	const sig = Integrity.sign(kp.priv, Integrity.signingInput(base));
	ok('the unmodified baseline verifies', Integrity.verify(kp.pub, Integrity.signingInput(base), sig) === true);
	const flips = {
		root: 'f'.repeat(64), seq: 8, prevRoot: '0'.repeat(64), count: 43,
		createdAt: '2026-01-02T03:04:05.001Z', scheme: 'vdisk-integrity-2', sealed: false, deep: false,
	};
	for (const [field, val] of Object.entries(flips)) {
		const mutated = { ...base, [field]: val };
		ok('flipping ' + field + ' breaks the signature', Integrity.verify(kp.pub, Integrity.signingInput(mutated), sig) === false);
	}
	// A version downgrade (v4 -> v3) drops the sealed/deep fields from the input, so it also fails — a downgrade
	// to dodge the seal binding is caught the same way.
	ok('downgrading the record version breaks the signature', Integrity.verify(kp.pub, Integrity.signingInput({ ...base, version: 3 }), sig) === false);

	// merkleRoot is cooperative-async (it yields to the event loop for large file sets so the mount/audit/snapshot
	// paths never freeze). Pin that the yielding form is DETERMINISTIC and ORDER-INDEPENDENT, and that a set large
	// enough to cross several yield points still produces the same root as the same files in a different order —
	// a regression here would mean the loop restructuring changed the hash a signature is bound to.
	const mkFiles = (n) => Array.from({ length: n }, (_, i) => ({ path: 'dir/file-' + i + '.dat', size: (i * 7) % 1000, hash: 'h' + i }));
	const bigSet = mkFiles(20000);           // well past YIELD_EVERY (4096), several reduction levels
	const mkRootA = await Integrity.merkleRoot(bigSet);
	const mkRootB = await Integrity.merkleRoot(bigSet.slice().reverse()); // shuffled input -> same sorted root
	ok('merkleRoot is stable across repeated calls', (await Integrity.merkleRoot(bigSet)) === mkRootA);
	ok('merkleRoot is order-independent for a large set', mkRootA === mkRootB);
	ok('merkleRoot of a large set is a 64-hex-char digest', /^[0-9a-f]{64}$/.test(mkRootA));
	ok('the empty set has a fixed non-empty root', /^[0-9a-f]{64}$/.test(await Integrity.merkleRoot([])));
	ok('a single-file change moves the root', (await Integrity.merkleRoot([{ path: 'a', size: 1 }])) !== (await Integrity.merkleRoot([{ path: 'a', size: 2 }])));

	try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL INTEGRITY-VERDICT CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
