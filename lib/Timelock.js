'use strict';
// lib/Timelock.js — TIME-LOCK encryption: seal a payload so it can only be opened AFTER a chosen moment, with no
// server we run and no key we hold. It rides the drand distributed randomness beacon (the "League of Entropy", a
// coalition of independent operators). drand publishes a threshold BLS signature over each round number on a fixed
// cadence; because the signature for a FUTURE round is unpredictable until the network produces it, that signature
// works as the decryption key for identity-based encryption whose "identity" is the round. So we encrypt to a round
// that corresponds to a target time; when the beacon reaches it, anyone can fetch the signature and decrypt — fully
// offline, no custodian. This is the tlock construction (Gailly–Melissaris–Romailler); we implement only the small
// interop-critical core (round→curve hashing, the pairing, the IBE) on the standard, audited @noble/curves BLS12-381
// primitive, and wrap the payload with Node's built-in AEAD. Nothing here is home-rolled curve math.
//
// This is a DELAY gate only. It does not know whether anyone is alive; it releases on a schedule. In the vault it is
// layered UNDER the post-quantum seal to a beneficiary (Emergency.seal) and, for reliability, beside a trustee
// quorum — so a captured blob is useless without the beneficiary's key, and a beacon outage never strands access.
//
// Cross-platform: pure JavaScript (@noble/curves) plus Node's built-in crypto — no native build, identical on
// macOS, Linux, and Windows. Non-blocking: the pairing math is tens of milliseconds, so the heavy core is meant to
// run through a worker (see Vault's use of WorkerRun); this module keeps the crypto pure and synchronous so it is
// directly testable, and lazy-loads @noble so merely reading a round number never pulls the curve into the caller.

const crypto = require('crypto');
const path = require('path');

// ── Pinned beacon parameters (drand "quicknet") ──────────────────────────────────────────────────────────────
// Single-sourced here the way the engine version is pinned: a blob is bound to THIS chain and public key, so these
// must never drift. quicknet uses the "unchained on G1" scheme — the signature (and the hashed round identity) live
// in G1 (48 bytes), the public key in G2 (96 bytes). The DST is the exact RFC 9380 tag drand signs with; it MUST
// match byte for byte (including the trailing "NUL_") or the pairing identity fails and nothing decrypts.
const QUICKNET = {
	chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
	publicKey: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
	genesisTime: 1692803367, // unix seconds
	period: 3,               // seconds between rounds
	scheme: 'bls-unchained-g1-rfc9380',
	dst: 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_',
};
// Several independent public gateways serve the same chain (addressed by its hash), tried in order so one being
// down or slow never blocks a release. They only ever return a PUBLIC signature, which we verify against the pinned
// key before trusting it (fetchSignature), so a hostile or wrong endpoint can never feed us a bad decryption key.
const ENDPOINTS = ['https://api.drand.sh', 'https://api2.drand.sh', 'https://api3.drand.sh', 'https://drand.cloudflare.com'];
// The scheme id stored in every blob, so a future beacon or construction can be added without misreading old blobs.
const SCHEME_ID = 'drand-quicknet-g1';
const BLOB_VERSION = 1;

// ── round math ───────────────────────────────────────────────────────────────────────────────────────────────
// The round whose signature will exist at or after a given time. Rounds are 1-indexed from genesis. A time before
// genesis has no round (throws) — callers only ever target the future, so this is a guard, not a real case.
function roundAt(unixMs) {
	const genMs = QUICKNET.genesisTime * 1000, perMs = QUICKNET.period * 1000;
	if (unixMs < genMs) throw new Error('A time-lock target cannot be before the beacon genesis.');
	return Math.floor((unixMs - genMs) / perMs) + 1;
}
// The wall-clock time (ms) at which a round is produced — used to show a countdown and to sanity-check a target.
function timeOfRoundMs(round) { return (QUICKNET.genesisTime + (Math.max(1, round) - 1) * QUICKNET.period) * 1000; }
// The round for "now + windowMs", clamped to at least the next round so a zero/negative window never targets the past.
function roundForDelay(windowMs, now = Date.now()) { return Math.max(roundAt(now) + 1, roundAt(now + Math.max(0, windowMs))); }

// ── identity-based encryption core (interop-critical) ────────────────────────────────────────────────────────
let _bls = null;
function bls() { if (!_bls) _bls = require('@noble/curves/bls12-381.js').bls12_381; return _bls; } // lazy: keep the curve out of processes that only need round math
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();
const xor = (a, b) => { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };
// The round encoded exactly as drand signs it: the 8-byte big-endian round number, hashed with SHA-256. That digest
// is the IBE identity; drand's signature on this same value is the matching private key.
function roundIdentity(round) { const rb = Buffer.alloc(8); rb.writeBigUInt64BE(BigInt(round)); return sha256(rb); }
function qidPoint(round) { return bls().G1.hashToCurve(roundIdentity(round), { DST: QUICKNET.dst }); } // hash the identity onto G1 with drand's DST

// The three IBE hash functions, domain-separated. H2 masks a GT (pairing output) element down to the 16-byte key;
// H3 derives the encryption randomness from (sigma, message) so decryption can re-derive and self-check (Fujisaki–
// Okamoto), making the scheme non-malleable; H4 masks the message. Their exact byte layout only has to be
// self-consistent between our encrypt and decrypt (we never interoperate with age-format tlock files — only with
// drand's round SIGNATURES, which the pinned DST + G1 hashing above make exact).
const IBE_KEY_BYTES = 16;
function h2(gtBytes) { return sha256(Buffer.concat([Buffer.from('IBE-H2'), gtBytes])).subarray(0, IBE_KEY_BYTES); }
function h4(sigma) { return sha256(Buffer.concat([Buffer.from('IBE-H4'), sigma])).subarray(0, IBE_KEY_BYTES); }
function h3Scalar(sigma, msg) {
	const ORDER = bls().fields.Fr.ORDER;
	for (let ctr = 0; ctr < 65536; ctr++) { // rejection-sample a nonzero scalar; a collision to zero is astronomically unlikely, so this all but always runs once
		const c = Buffer.alloc(4); c.writeUInt32BE(ctr);
		const n = BigInt('0x' + sha256(Buffer.concat([Buffer.from('IBE-H3'), sigma, msg, c])).toString('hex')) % ORDER;
		if (n !== 0n) return n;
	}
	throw new Error('Could not derive a time-lock scalar.'); // unreachable in practice
}

// Encrypt a 16-byte value to a round. Returns the three ciphertext components as bytes: U (a G2 point), V, W.
// `publicKey` overrides the pinned beacon key — used only by the offline test, which stands up its own key so the
// suite never depends on the live network.
function ibeEncrypt(round, msg16, { publicKey = QUICKNET.publicKey } = {}) {
	const b = bls();
	if (!Buffer.isBuffer(msg16) || msg16.length !== IBE_KEY_BYTES) throw new Error('Time-lock payload key must be 16 bytes.');
	const pk = b.G2.Point.fromHex(publicKey);
	const sigma = crypto.randomBytes(IBE_KEY_BYTES);
	const r = h3Scalar(sigma, msg16);
	const U = b.G2.Point.BASE.multiply(r);
	const gidR = b.fields.Fp12.pow(b.pairing(qidPoint(round), pk), r); // e(Qid, pk)^r  ==  e(sig, U) at decryption time
	const V = xor(sigma, h2(b.fields.Fp12.toBytes(gidR)));
	const W = xor(msg16, h4(sigma));
	return { U: Buffer.from(U.toBytes(true)), V, W };
}
// Decrypt with the round's beacon signature (48-byte compressed G1). Recovers the 16-byte value, or throws if the
// signature is wrong or the ciphertext was altered (the Fujisaki–Okamoto re-derivation check fails closed).
function ibeDecrypt(sigBytes, ct) {
	const b = bls();
	const sig = b.G1.Point.fromHex(Buffer.from(sigBytes).toString('hex'));
	const U = b.G2.Point.fromHex(Buffer.from(ct.U).toString('hex'));
	const gidR = b.pairing(sig, U); // e(s·Qid, r·G2) = e(Qid, pk)^r
	const sigma = xor(ct.V, h2(b.fields.Fp12.toBytes(gidR)));
	const msg = xor(ct.W, h4(sigma));
	const rCheck = U.equals(b.G2.Point.BASE.multiply(h3Scalar(sigma, msg)));
	if (!rCheck) throw new Error('This time-locked data did not open (wrong beacon signature or altered data).');
	return msg;
}
// Verify a fetched beacon signature really is drand's signature for this round, against the PINNED public key —
// e(sig, G2) == e(Qid, pk). This is what lets us fetch from any public gateway without trusting it: a wrong or
// hostile signature is rejected here, before it is ever used as a decryption key.
function verifyBeacon(round, sigBytes, { publicKey = QUICKNET.publicKey } = {}) {
	const b = bls();
	try {
		const sig = b.G1.Point.fromHex(Buffer.from(sigBytes).toString('hex'));
		const pk = b.G2.Point.fromHex(publicKey);
		return b.fields.Fp12.eql(b.pairing(sig, b.G2.Point.BASE), b.pairing(qidPoint(round), pk));
	} catch (_) { return false; }
}

// ── payload sealing (IBE key + AEAD data) ────────────────────────────────────────────────────────────────────
// Seal an arbitrary payload to a round: a random 16-byte file key is time-locked with the IBE, and the payload is
// encrypted under it with ChaCha20-Poly1305 (Node built-in). The header (version, scheme, round) is the AEAD's
// additional data, so the round a blob claims cannot be swapped without breaking the tag. Returns a compact JSON
// string (a versioned, self-describing container that future schemes can extend).
function sealToRound(round, payload, { publicKey } = {}) {
	const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
	const fileKey = crypto.randomBytes(IBE_KEY_BYTES);
	const ct = ibeEncrypt(round, fileKey, { publicKey });
	const salt = crypto.randomBytes(16), nonce = crypto.randomBytes(12);
	const header = { v: BLOB_VERSION, s: SCHEME_ID, round };
	const aad = Buffer.from(JSON.stringify(header));
	const key = Buffer.from(crypto.hkdfSync('sha256', fileKey, salt, Buffer.from('vault:timelock:dem:v1'), 32));
	const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
	c.setAAD(aad);
	const body = Buffer.concat([c.update(data), c.final()]);
	return JSON.stringify({ ...header, U: ct.U.toString('base64'), V: ct.V.toString('base64'), W: ct.W.toString('base64'),
		salt: salt.toString('base64'), nonce: nonce.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: body.toString('base64') });
}
// Open a sealed blob given the round's beacon signature. Returns the original payload buffer, or throws (fail-closed).
function openWithSignature(blobStr, sigBytes) {
	let o; try { o = JSON.parse(String(blobStr)); } catch (_) { throw new Error('This time-locked data is not in a readable format.'); }
	if (!o || o.v !== BLOB_VERSION || o.s !== SCHEME_ID) throw new Error('This time-locked data was made by a different or newer version.');
	// A version/scheme-tagged blob that is still missing a field must fail with the clean domain error, not a raw
	// TypeError from decoding an undefined below.
	for (const f of ['round', 'U', 'V', 'W', 'salt', 'nonce', 'tag', 'ct']) if (o[f] == null || (f !== 'round' && typeof o[f] !== 'string')) throw new Error('This time-locked data is not in a readable format.');
	const fileKey = ibeDecrypt(sigBytes, { U: Buffer.from(o.U, 'base64'), V: Buffer.from(o.V, 'base64'), W: Buffer.from(o.W, 'base64') });
	const aad = Buffer.from(JSON.stringify({ v: o.v, s: o.s, round: o.round }));
	const key = Buffer.from(crypto.hkdfSync('sha256', fileKey, Buffer.from(o.salt, 'base64'), Buffer.from('vault:timelock:dem:v1'), 32));
	const d = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.from(o.nonce, 'base64'), { authTagLength: 16 });
	d.setAAD(aad); d.setAuthTag(Buffer.from(o.tag, 'base64'));
	return Buffer.concat([d.update(Buffer.from(o.ct, 'base64')), d.final()]);
}
// The round a blob is locked to, and when it matures — read without any crypto, for status/countdown display.
function blobRound(blobStr) { try { const o = JSON.parse(String(blobStr)); return (o && o.v === BLOB_VERSION) ? o.round : null; } catch (_) { return null; } }

// ── beacon fetch ─────────────────────────────────────────────────────────────────────────────────────────────
// Fetch the signature for a round from the public gateways, trying each in turn and VERIFYING it against the pinned
// key before returning, so a wrong/hostile gateway is rejected rather than trusted. Returns the 48-byte signature,
// or null if the round is not available yet or no gateway served a valid one. Bounded and non-blocking (Net.getText
// caps size and time), so a slow or dead gateway can never wedge the caller.
async function fetchSignature(round, { Net } = {}) {
	const net = Net || require('./Net');
	for (const base of ENDPOINTS) {
		let body; try { body = await net.getText(base + '/' + QUICKNET.chainHash + '/public/' + round); } catch (_) { continue; }
		let j; try { j = JSON.parse(body); } catch (_) { continue; }
		const sigHex = j && typeof j.signature === 'string' ? j.signature.trim() : '';
		if (!/^[0-9a-f]{96}$/i.test(sigHex)) continue; // a 48-byte compressed G1 point is 96 hex chars
		const sig = Buffer.from(sigHex, 'hex');
		if (verifyBeacon(round, sig)) return sig; // only a signature that verifies against the pinned key is trusted
	}
	return null;
}
// Is a round mature yet (its time has arrived)? A cheap wall-clock check to decide whether to even attempt a fetch.
function isRoundDue(round, now = Date.now()) { return now >= timeOfRoundMs(round); }

// ── non-blocking wrappers ────────────────────────────────────────────────────────────────────────────────────
// Async seal/open that run the pairing-heavy core in a WORKER thread, so a caller on the service event loop is
// never blocked while the curve math runs. If a worker cannot be started (a constrained or packaged environment
// where the worker file is missing), they fall through to the synchronous core — correct, just briefly blocking —
// so the feature never simply fails for lack of a worker. maxMs bounds a genuinely stuck worker (these ops post no
// progress, so the idle watchdog cannot). A real crypto failure (wrong signature, altered data) propagates.
async function seal(round, payload, { publicKey } = {}) {
	const data = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
	let result;
	try { result = await require('./WorkerRun').runWorker(path.join(__dirname, 'TimelockWorker.js'),
		{ op: 'seal', args: { round, payloadB64: data.toString('base64'), publicKey } }, null, { maxMs: 120000, idleMessage: 'Time-locking the grant' }); }
	catch (_) { return sealToRound(round, data, { publicKey }); } // worker could not start/run — do it inline
	if (result && result.ok) return result.blob;
	throw new Error((result && result.error) || 'Could not time-lock the grant.'); // a real failure — do not re-run inline
}
async function open(blob, sigBytes) {
	const sigHex = Buffer.from(sigBytes).toString('hex');
	let result;
	try { result = await require('./WorkerRun').runWorker(path.join(__dirname, 'TimelockWorker.js'),
		{ op: 'open', args: { blob, sigHex } }, null, { maxMs: 120000, idleMessage: 'Opening the time-locked grant' }); }
	catch (_) { return openWithSignature(blob, sigBytes); } // worker could not start/run — do it inline
	if (result && result.ok) return Buffer.from(result.payloadB64, 'base64');
	throw new Error((result && result.error) || 'This time-locked data did not open.'); // a real crypto failure — do not re-run the pairing inline
}

// Test-only seam: stand up a beacon-like keypair and produce the signature a beacon would for a round
// (sig = sk·Qid(round)), so the offline suite can prove the full seal/open round-trip without the live network.
// Never used in production — the real key is pinned above.
const _test = {
	genKey() { const b = bls(); const sk = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % b.fields.Fr.ORDER; return { sk, publicKey: Buffer.from(b.G2.Point.BASE.multiply(sk).toBytes(true)).toString('hex') }; },
	signRound(sk, round) { const b = bls(); return Buffer.from(qidPoint(round).multiply(sk).toBytes(true)); },
};

module.exports = {
	QUICKNET, ENDPOINTS, SCHEME_ID, BLOB_VERSION,
	roundAt, timeOfRoundMs, roundForDelay, isRoundDue, blobRound,
	verifyBeacon, sealToRound, openWithSignature, fetchSignature, seal, open, _test,
};
