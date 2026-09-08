'use strict';
// lib/Kdf.js — a strong, memory-hard key-derivation stage placed IN FRONT of the
// encryption engine. The engine derives its own key from whatever password it is
// given, but with a modest fixed cost. To protect ordinary (human) passwords we
// first stretch the user's passphrase with Argon2id — the current best-practice
// password hash — and hand the engine the high-entropy result instead of the raw
// passphrase. Brute-forcing the passphrase then has to pay Argon2id's memory-hard
// cost, which is far higher than the engine's own stage.
//
// Argon2id runs in WebAssembly, so there is no native module to compile and the
// tool stays easy to install. The parameters and the random salt are stored, in
// the clear, in the vault manifest; they are not secret — they only need to be
// reproducible so the same passphrase derives the same secret on any machine.

const crypto = require('crypto');
const path = require('path');
const { argon2id } = require('hash-wasm');
const WorkerRun = require('./WorkerRun');

// Named security levels — the memory/iteration cost of the Argon2id stage. Higher levels raise the
// cost of brute-forcing the passphrase (more memory and time per guess) at the price of a slightly
// longer unlock and more RAM needed to open the vault. The level is chosen per vault and, like all
// KDF parameters, stored (non-secret) in the manifest so any machine reproduces the same derivation.
//   • standard — 64 MiB / 3 passes: RFC 9106's memory-constrained recommendation; opens fast on any
//                machine. The right default.
//   • high     — 256 MiB / 4 passes: noticeably costlier to attack; a brief pause to unlock.
//   • max      — 512 MiB / 4 passes: strongest; needs ~½ GiB free to open, so avoid on low-RAM devices.
const LEVELS = {
	standard: { memKiB: 65536, iterations: 3, parallelism: 4 },
	high: { memKiB: 262144, iterations: 4, parallelism: 4 },
	max: { memKiB: 524288, iterations: 4, parallelism: 4 }
};

// Build fresh KDF parameters for a chosen security level (default 'standard'), with a new random
// salt. An unknown level falls back to 'standard' rather than failing — the level is a convenience
// label; the concrete numbers are what actually govern derivation.
function defaultParams(level) {
	const preset = LEVELS[level] || LEVELS.standard;
	return {
		algo: 'argon2id',
		v: 1,
		memKiB: preset.memKiB,
		iterations: preset.iterations,
		parallelism: preset.parallelism,
		hashLen: 32,
		level: LEVELS[level] ? level : 'standard',
		salt: crypto.randomBytes(16).toString('base64')
	};
}

// A tamper tag over ALL of a slot's derivation-governing KDF fields — the cost parameters AND the salt, hash
// length, algorithm, and version. The manifest seal folds each slot to this, so a folder-write attacker cannot
// alter a slot's salt or hashLen (both change the derived key) while the seal still verifies as authentic — the
// gap that levelOf() alone (cost parameters only) left open, which would surface as a mysterious "wrong password"
// lockout on a manifest that reads as genuine. Field order is fixed; `level` is excluded (a display label only).
function sealTag(p) {
	p = p || {};
	const parts = ['kdf1', String(p.algo || 'argon2id'), String(p.v || 1), String(p.memKiB || ''), String(p.iterations || ''), String(p.parallelism || ''), String(p.hashLen || ''), String(p.salt || '')];
	return crypto.createHash('sha256').update(parts.join('\x1f')).digest('hex');
}
// The security-level name for a set of KDF params, matched by the CONCRETE cost parameters — never by the `level`
// label alone. The manifest seal folds each slot down to this name, so if it trusted the label, an attacker with
// write access to the vault folder could keep level:'max' while lowering memKiB/iterations: the seal would still
// verify as authentic, yet unlock would derive a different key and fail (a mysterious "wrong password" lockout that
// looks like the manifest is genuine). Matching by the real numbers makes such a mutation resolve to 'custom',
// which no longer equals the sealed label, so the tamper is caught. This is backward-compatible: the presets have
// never changed, so every legitimately-created slot's numbers match its preset and this returns the same label the
// old code did — only a mutated slot becomes 'custom'. Used for the seal, to preserve the level across a password
// change, and to show it in the UI.
function levelOf(params) {
	if (!params) return 'standard';
	for (const name of Object.keys(LEVELS)) {
		const p = LEVELS[name];
		if (p.memKiB === params.memKiB && p.iterations === params.iterations && p.parallelism === params.parallelism) return name;
	}
	return 'custom';
}

// Derive the high-entropy secret (base64) OFF the main thread. A high/max-level Argon2id runs for a
// noticeable time over ~½ GiB of memory; doing it inline would freeze the event loop (and the mounted-drive
// health checks that share it) during every mount and every web login. Run it in a short-lived worker
// instead. If a worker cannot be started (a constrained runtime), fall back to in-thread derivation so
// unlocking is never made impossible — only, in that rare case, blocking. A parameter/validation error is
// raised inside the worker and re-raised deterministically by the raw fallback, so it still surfaces.
// The passphrase is passed as worker data, which stays in this process's memory (thread-to-thread, never
// to disk or another process), preserving the no-plaintext-on-disk invariant.
// Cap how many Argon2id derivations run at once. Each one allocates up to ~½ GiB in its own worker thread, so
// an unbounded number of simultaneous password-bearing operations (mount, add-key, change-password, snapshot,
// seal, rotate — and every web login) would let a runaway script, or an authenticated client on an exposed
// bind, drive the host to out-of-memory. This bounds total KDF memory to the cap times the per-hash cost no
// matter how many callers arrive together; callers past the cap wait for a slot rather than being refused, so
// nothing is dropped — it is throttled, not failed. The login route keeps its own per-IP failure backoff on
// top for the online-guessing case; this is the process-wide memory bound underneath every KDF caller.
const KDF_MAX_CONCURRENT = 4;
let kdfInFlight = 0;
const kdfWaiters = [];
function acquireKdfSlot() {
	if (kdfInFlight < KDF_MAX_CONCURRENT) { kdfInFlight++; return Promise.resolve(); }
	return new Promise((resolve) => kdfWaiters.push(resolve));
}
function releaseKdfSlot() {
	const next = kdfWaiters.shift();
	if (next) next(); else kdfInFlight = Math.max(0, kdfInFlight - 1); // a waiter inherits the slot; otherwise free it
}

async function deriveSecret(passphrase, params) {
	await acquireKdfSlot();
	try {
		return await WorkerRun.runWorker(path.join(__dirname, 'KdfWorker.js'), { op: 'derive', args: { passphrase, params } }, null, {});
	} catch (_) {
		return await deriveSecretRaw(passphrase, params); // worker unavailable: still bounded by the slot we hold
	} finally {
		releaseKdfSlot();
	}
}

// The in-thread derivation itself (also the worker's body). Deterministic for a given passphrase + params.
// Fails closed on an unrecognized algorithm/version rather than silently deriving the wrong key.
async function deriveSecretRaw(passphrase, params) {
	if (!params || params.algo !== 'argon2id' || (params.v != null && params.v !== 1)) {
		throw new Error('Unsupported key-derivation settings in this vault (algo=' + (params && params.algo) + ', v=' + (params && params.v) + '). A newer version of the tool may be required.');
	}
	// SECURITY: the KDF parameters travel INSIDE a shareable vault, so they are UNTRUSTED. A crafted memKiB or
	// iterations would let a hostile vault OOM or CPU-hang the victim the instant they type a password. Bound
	// them TIGHTLY to the tool's own levels (its max is 512 MiB / 4 passes) so a hostile manifest cannot amplify
	// the unlock cost: memKiB never exceeds the shipped max (so it cannot use MORE memory than a real vault),
	// and iterations/parallelism get only a little headroom. This caps a hostile unlock at ~the legitimate
	// worst case (half a gigabyte, a couple of seconds), not the ~1 GiB / 15 s a looser bound would allow.
	const p = params, okInt = (n, lo, hi) => Number.isInteger(n) && n >= lo && n <= hi;
	if (!(okInt(p.memKiB, 8, 524288) && okInt(p.iterations, 1, 6) && okInt(p.parallelism, 1, 8) && okInt(p.hashLen, 16, 64) && typeof p.salt === 'string' && p.salt.length <= 4096)) {
		throw new Error('This vault has invalid or out-of-range password-protection parameters and was refused.');
	}
	const raw = await argon2id({
		password: passphrase,
		salt: Buffer.from(params.salt, 'base64'),
		parallelism: params.parallelism,
		iterations: params.iterations,
		memorySize: params.memKiB,
		hashLength: params.hashLen,
		outputType: 'binary'
	});
	return Buffer.from(raw).toString('base64');
}

// Derive a raw 32-byte key from a passphrase, used to WRAP the vault's master secret.
async function deriveKey(passphrase, params) {
	return Buffer.from(await deriveSecret(passphrase, params), 'base64');
}

// Wrap (encrypt) the vault's master secret with a password-derived key using
// authenticated AES-256-GCM. The result is base64 of iv(12) || ciphertext || tag(16).
// Because the engine's data key comes from the master secret — not the password — a
// password change only re-wraps this small blob, so NO file is ever re-encrypted.
function wrapSecret(secret, keyRaw) {
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', keyRaw, iv);
	const ct = Buffer.concat([cipher.update(Buffer.from(secret, 'utf8')), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([iv, ct, tag]).toString('base64');
}

// Unwrap the master secret. Throws if the key is wrong (the GCM tag fails to verify),
// which is exactly how a wrong password is detected — fail-closed, never silent.
function unwrapSecret(wrapped, keyRaw) {
	const buf = Buffer.from(wrapped, 'base64');
	if (buf.length < 12 + 16 + 1) throw new Error('stored key data is malformed (truncated or corrupt)');
	const iv = buf.subarray(0, 12);
	const tag = buf.subarray(buf.length - 16);
	const ct = buf.subarray(12, buf.length - 16);
	const decipher = crypto.createDecipheriv('aes-256-gcm', keyRaw, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

module.exports = { LEVELS, defaultParams, levelOf, sealTag, deriveSecret, deriveSecretRaw, deriveKey, wrapSecret, unwrapSecret };
