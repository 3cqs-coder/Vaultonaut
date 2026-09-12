'use strict';
// lib/test/timelock.js — the time-lock primitive (lib/Timelock.js): drand-beacon identity-based encryption used to
// seal a payload so it only opens after a chosen moment, with no server we run. Two halves, both OFFLINE (no network,
// so it is deterministic in CI):
//   1. Correctness with a stand-in beacon key: round math, a full seal→sign→open round-trip, and fail-closed on a
//      wrong signature or altered data.
//   2. A COMMITTED real drand vector: round 1,000,000's actual published signature must verify against the PINNED
//      quicknet public key, and a payload sealed to that round with the pinned key must open with it. This proves our
//      IBE interoperates with real drand output byte-for-byte, without depending on the live network.
//
// Run:  node lib/test/timelock.js

const T = require('../Timelock');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// A real quicknet beacon: round 1,000,000 and its published 48-byte compressed-G1 signature (fetched from the drand
// API and frozen here as an interop vector). If our pinned key, DST, round hashing, or pairing ever drift, this fails.
const REAL_ROUND = 1000000;
const REAL_SIG = '83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72';

async function main() {
	// ── pinned parameters are well-formed ───────────────────────────────────────────────────────────────────────
	ok('the pinned chain hash is 32 bytes of hex', /^[0-9a-f]{64}$/.test(T.QUICKNET.chainHash));
	ok('the pinned public key is a 96-byte (G2) compressed point', /^[0-9a-f]{192}$/.test(T.QUICKNET.publicKey));
	ok('the signing DST is the exact drand RFC 9380 tag (ends with NUL_)', T.QUICKNET.dst === 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_');
	ok('several independent beacon gateways are pinned', Array.isArray(T.ENDPOINTS) && T.ENDPOINTS.length >= 2);

	// ── round math ──────────────────────────────────────────────────────────────────────────────────────────────
	const now = Date.now();
	const rNow = T.roundAt(now);
	ok('roundAt returns a positive round for now', Number.isInteger(rNow) && rNow > 1);
	ok('a later time never maps to an earlier round', T.roundAt(now + 3000) >= rNow);
	ok('timeOfRoundMs inverts roundAt to within one period', Math.abs(T.timeOfRoundMs(rNow) - now) <= T.QUICKNET.period * 1000);
	ok('roundForDelay(+30 days) is well past the current round', T.roundForDelay(30 * 86400000, now) > rNow);
	ok('a zero/negative delay still targets the future, never the past', T.roundForDelay(0, now) > rNow && T.roundForDelay(-1000, now) > rNow);
	ok('a target before genesis is refused', (() => { try { T.roundAt(0); return false; } catch (_) { return true; } })());
	ok('a round in the future is not yet due; a past round is', T.isRoundDue(1, now) === true && T.isRoundDue(T.roundForDelay(86400000, now), now) === false);

	// ── correctness with a stand-in beacon key (offline) ────────────────────────────────────────────────────────
	const beacon = T._test.genKey(); // sk + its G2 public key, mimicking a drand chain we control
	const round = 12345678;
	const payload = Buffer.from('read-cap:inheritance-token — café ☃', 'utf8');
	const blob = T.sealToRound(round, payload, { publicKey: beacon.publicKey });
	ok('a sealed blob records the round it is locked to', T.blobRound(blob) === round);
	const sig = T._test.signRound(beacon.sk, round); // the signature the beacon would publish at that round
	ok('the beacon signature verifies against its own public key', T.verifyBeacon(round, sig, { publicKey: beacon.publicKey }) === true);
	ok('the blob opens with the round signature and recovers the exact payload', T.openWithSignature(blob, sig).equals(payload));

	// fail-closed: a signature from a DIFFERENT beacon key cannot open the blob
	const other = T._test.genKey();
	const otherSig = T._test.signRound(other.sk, round);
	ok('a wrong beacon signature does not open the blob (fail-closed)', (() => { try { T.openWithSignature(blob, otherSig); return false; } catch (_) { return true; } })());
	ok('verifyBeacon rejects a signature from the wrong key', T.verifyBeacon(round, otherSig, { publicKey: beacon.publicKey }) === false);
	// fail-closed: altering the ciphertext body breaks the AEAD tag
	const torn = JSON.parse(blob); const ctBuf = Buffer.from(torn.ct, 'base64'); ctBuf[0] ^= 0xff; torn.ct = ctBuf.toString('base64');
	ok('an altered ciphertext body fails to open (AEAD tag)', (() => { try { T.openWithSignature(JSON.stringify(torn), sig); return false; } catch (_) { return true; } })());
	// fail-closed: swapping the claimed round in the header breaks the AEAD (the round is bound as additional data)
	const swapped = JSON.parse(blob); swapped.round = round + 1;
	ok('swapping the blob\'s claimed round is rejected (round is AEAD-bound)', (() => { try { T.openWithSignature(JSON.stringify(swapped), sig); return false; } catch (_) { return true; } })());
	// a blob from a newer/different scheme is refused with a clear message, not misread
	const alien = JSON.parse(blob); alien.s = 'some-future-beacon';
	ok('a blob from a different scheme is refused', (() => { try { T.openWithSignature(JSON.stringify(alien), sig); return false; } catch (e) { return /different or newer/.test(e.message); } })());

	// empty and larger payloads round-trip too (the DEM is a stream cipher, not fixed-size)
	ok('an empty payload round-trips', T.openWithSignature(T.sealToRound(round, Buffer.alloc(0), { publicKey: beacon.publicKey }), sig).length === 0);
	const big = require('crypto').randomBytes(200000);
	ok('a 200 KB payload round-trips byte-for-byte', T.openWithSignature(T.sealToRound(round, big, { publicKey: beacon.publicKey }), sig).equals(big));

	// ── committed real drand vector (interop, offline) ──────────────────────────────────────────────────────────
	const realSig = Buffer.from(REAL_SIG, 'hex');
	ok('a REAL drand signature verifies against the PINNED quicknet key', T.verifyBeacon(REAL_ROUND, realSig) === true);
	const realBlob = T.sealToRound(REAL_ROUND, payload); // sealed with the pinned production key (no override)
	ok('a payload sealed with the pinned key opens with the real drand signature', T.openWithSignature(realBlob, realSig).equals(payload));
	ok('the real signature does NOT verify for a different round (identity is round-bound)', T.verifyBeacon(REAL_ROUND + 1, realSig) === false);

	// ── non-blocking worker path (offload) ──────────────────────────────────────────────────────────────────────
	// The async seal/open run the pairing math in a worker thread so the caller's event loop is never blocked. Prove
	// the offloaded path produces an interchangeable result: a worker-sealed blob opens with the inline core and a
	// worker-open recovers an inline-sealed blob, so the two paths are byte-compatible.
	const wblob = await T.seal(round, payload, { publicKey: beacon.publicKey });
	ok('the worker seal produces a blob that the inline core opens', T.openWithSignature(wblob, sig).equals(payload));
	ok('the worker open recovers a payload sealed inline', (await T.open(blob, sig)).equals(payload));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TIME-LOCK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
