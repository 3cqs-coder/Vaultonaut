'use strict';
// lib/Integrity.js — the cryptographic building blocks and the local rollback ledger for
// vault tamper detection. All pure/computed (cross-platform, fast), and versioned by a
// SCHEME string so the algorithm suite can evolve without breaking older vaults.
//
//   • merkleRoot   — one root hash over the whole file set (Tier 2). Detects any change with a
//                    single value; RFC 6962-style domain separation guards against
//                    second-preimage tricks. The root is the vault's canonical fingerprint.
//   • fingerprint  — a short, human-transcribable form of the root (Tier 1) a user can record
//                    out of band and later eyeball to confirm the vault is the version they left.
//   • Ed25519      — an asymmetric signature over each baseline (Tier 3), and the vault's WRITE
//                    AUTHORITY. The keypair is derived from an independent write seed (NOT from the read
//                    key), and the public key is published in the manifest. A WRITE holder re-derives that
//                    public key from the seed and verifies the baseline against that independent anchor, so
//                    it cannot be fooled by a swapped manifest key — this is what separates read access from
//                    write authority. Two caveats on the reader side, since the crypt engine is symmetric (a
//                    read holder has the data key and can write files): a read-LINK (cap) holder is still
//                    protected because the write public key is pinned in the link token, but a read-only
//                    PASSWORD holder has no independent anchor (it trusts the manifest's key) and could forge
//                    a baseline that OTHER read-only-password holders accept. The write owner always detects
//                    it, and the out-of-band fingerprint catches it regardless — record it.
//   • ledger       — a small local record of the highest (seq, root) ever seen per vault
//                    (Tier 1). A vault presenting a LOWER counter than we have seen is a
//                    rollback; the same counter with a different root is a rewritten history.

const crypto = require('crypto');
const path = require('path');
const Common = require('./Common');
const FileLock = require('./FileLock'); // cross-process lock so the CLI and the service can't clobber each other's ledger writes

// The algorithm suite. Bump this (and add a branch where it is read) to migrate hash/signature
// choices later; an older build treats an unknown scheme as "can't check", never as tampering.
const SCHEME = 'vdisk-integrity-1';
const HASH = 'sha256';

// ---------------------------------------------------------------------------
// Merkle root over the file set
// ---------------------------------------------------------------------------
function h(...bufs) { return crypto.createHash(HASH).update(Buffer.concat(bufs)).digest(); }
const LEAF = Buffer.from([0x00]); // domain-separation tags (RFC 6962): leaves and internal
const NODE = Buffer.from([0x01]); // nodes are hashed under different prefixes

// Canonical bytes for one file entry — path, size, and (when present) content hash.
function fileLeaf(f) { return h(LEAF, Buffer.from(f.path + '\0' + (f.size == null ? '' : f.size) + '\0' + (f.hash || ''), 'utf8')); }

// The Merkle root as hex. Sorting by path makes it order-independent; an empty set has a fixed
// root so a wiped vault still produces a stable, verifiable value.
//
// Async and cooperative: a vault with hundreds of thousands of files makes 2N-1 sha256 hashes, which
// as one synchronous burst would freeze the event loop (and so every other request and the health
// watch) on the mount, audit, and snapshot paths — a promise timeout cannot interrupt synchronous
// CPU, so bounding the surrounding call is not enough. This yields to the loop every YIELD_EVERY
// hashes so a large set is computed without a stall. The result is byte-identical to a straight
// computation; small sets (below the yield step) never await, so a normal vault pays nothing. The
// vendored verify-bundle.js keeps its own self-contained synchronous copy on purpose.
const YIELD_EVERY = 4096;
const yieldToLoop = Common.yieldToLoop; // one shared cooperative-yield helper (the vendored verify-bundle.js keeps its own synchronous copy on purpose)
const SORT_CHUNK = 8192;
const comparePath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
// Merge two path-sorted runs, preferring the left run on a tie so the result stays stable.
function mergeRuns(a, b) {
	const out = new Array(a.length + b.length);
	let i = 0, j = 0, k = 0;
	while (i < a.length && j < b.length) out[k++] = comparePath(a[i], b[j]) <= 0 ? a[i++] : b[j++];
	while (i < a.length) out[k++] = a[i++];
	while (j < b.length) out[k++] = b[j++];
	return out;
}
// Sort the file list by path WITHOUT freezing the loop. A single Array.sort over hundreds of thousands of files is
// one uninterruptible O(n log n) burst that stalls every request and the health watch — the same reason the hashing
// below yields. Small sets take one native sort and never await; larger sets sort native-sized chunks, then merge the
// runs pairwise, yielding between merges. The comparison is identical to a single sort, so the order (and the Merkle
// root computed from it) is byte-identical.
async function sortFilesByPath(files) {
	const arr = files.slice();
	if (arr.length <= SORT_CHUNK) return arr.sort(comparePath);
	let runs = [];
	for (let i = 0; i < arr.length; i += SORT_CHUNK) runs.push(arr.slice(i, i + SORT_CHUNK).sort(comparePath));
	let merges = 0;
	while (runs.length > 1) {
		const next = [];
		for (let i = 0; i < runs.length; i += 2) {
			if (i + 1 < runs.length) { next.push(mergeRuns(runs[i], runs[i + 1])); if (++merges % 8 === 0) await yieldToLoop(); }
			else next.push(runs[i]);
		}
		runs = next;
	}
	return runs[0] || [];
}
async function merkleRoot(files) {
	if (!files || !files.length) return h(LEAF).toString('hex');
	const sorted = await sortFilesByPath(files);
	let level = new Array(sorted.length);
	for (let i = 0; i < sorted.length; i++) { level[i] = fileLeaf(sorted[i]); if (i > 0 && i % YIELD_EVERY === 0) await yieldToLoop(); }
	while (level.length > 1) {
		const next = [];
		for (let i = 0; i < level.length; i += 2) { next.push(i + 1 < level.length ? h(NODE, level[i], level[i + 1]) : level[i]); if (i > 0 && i % (YIELD_EVERY * 2) === 0) await yieldToLoop(); }
		level = next;
	}
	return level[0].toString('hex');
}

// ---------------------------------------------------------------------------
// Human-recordable fingerprint (first 128 bits of the root, Crockford base32)
// ---------------------------------------------------------------------------
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // no I, L, O, U — unambiguous to transcribe
// The truncation length, in bytes, for the vault identity and content fingerprint. 16 bytes = 128 bits of
// second-preimage strength — the modern norm — for the origin anchor a third party checks against. One constant
// so the identity and the fingerprint always match, and the vendored verify-bundle.js mirrors this exact value.
const ANCHOR_BYTES = 16;
// Crockford base32 of a buffer, grouped in fours (e.g. K7Q2-9F3M-8XZ1-4W2P). Used for both the
// short vault fingerprint and, over more bytes, a strong human-transcribable recovery key.
function groupB32(buf) {
	let bits = 0, val = 0, out = '';
	for (const byte of buf) { val = (val << 8) | byte; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
	if (bits > 0) out += B32[(val << (5 - bits)) & 31];
	return (out.match(/.{1,4}/g) || []).join('-'); // '' for an empty input, rather than throwing on a null match
}
function fingerprint(rootHex) { return groupB32(Buffer.from(rootHex, 'hex').subarray(0, ANCHOR_BYTES)); }

// A vault's stable cryptographic IDENTITY — a short fingerprint of its write-authority PUBLIC key. Unlike the
// content fingerprint above (which changes with every edit), the identity NEVER changes: the keypair is
// derived from the vault's master secret and survives edits, snapshots, and password changes. It is the
// durable answer to "is this the genuine vault, or a hacker's recreation?" — a recreation carries a DIFFERENT
// key (one an attacker cannot reproduce without the write seed) and cannot sign genuine changes for it. So an
// identity that matches the value you recorded once, on a vault whose signed baseline still verifies, proves
// the vault is authentically yours. Domain-separated so it can never collide with a content fingerprint.
function identity(pubHex) {
	if (!pubHex) return null;
	return groupB32(crypto.createHash(HASH).update('vault-identity-v1').update(String(pubHex)).digest().subarray(0, ANCHOR_BYTES));
}

// ---------------------------------------------------------------------------
// Ed25519 keypair derived deterministically from the master secret
// ---------------------------------------------------------------------------
// PKCS#8 / SPKI DER prefixes for a raw Ed25519 seed / public key, so a 32-byte value can be
// imported by Node's crypto without any encoding library.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// The Ed25519 write keypair, derived deterministically from the 32-byte WRITE SEED (the write-cap).
// The seed is independent random material — NOT derived from the read key — so a read-only holder,
// who has the read key but not the seed, cannot reconstruct the signing key and therefore cannot
// produce an authentic write. This is the capability separation (modeled on the read-cap/write-cap
// design proven by capability filesystems): write-cap -> read-key -> verify-cap, each one-way.
function signKeysFromSeed(seedB64) {
	const seed = Buffer.from(String(seedB64), 'base64').subarray(0, 32);
	const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
	const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
	return { priv, pub: spki.subarray(spki.length - 32).toString('hex') };
}
// The read key (what the engine uses to encrypt/decrypt) derived by ONE-WAY hashing the write seed,
// so a write holder can reproduce the read key but a read holder can never climb back to the write
// seed. Salted with the vault's stable engine salt so it is unique per vault.
function readKeyFromSeed(seedB64, salt) {
	return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(seedB64), 'base64'), Buffer.from(String(salt), 'utf8'), Buffer.from('vdisk-read-key-v1'), 32)).toString('base64');
}
function sign(priv, payload) { return crypto.sign(null, Buffer.from(payload, 'utf8'), priv).toString('base64'); }
function verify(pubHex, payload, sigB64) {
	try {
		const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' });
		return crypto.verify(null, Buffer.from(payload, 'utf8'), pub, Buffer.from(sigB64, 'base64'));
	} catch (_) { return false; }
}

// The exact bytes an HMAC and the Ed25519 signature both cover: the scheme, the file-set root,
// the monotonic counter, the previous root (hash chain), the count, and the timestamp. The root
// already commits to every file, so the whole vault state is bound by these few fields.
// From record version 4 the SEAL state and the deep flag are bound too, so a read-key holder — who
// can decrypt and re-encrypt the record and recompute the HMAC, but cannot produce the Ed25519
// signature (that needs the write key) — can no longer strip a seal or downgrade a deep baseline
// without breaking the signature. Version 3 records keep the original input so they still verify;
// tampering that flips the version to dodge this also breaks the signature (it was signed over the
// v4 input), so a downgrade is detected too. New baselines are always written at version 4.
function signingInput({ scheme, root, seq, prevRoot, count, createdAt, version, sealed, deep }) {
	const fields = [scheme, root, seq, prevRoot || '', count, createdAt];
	if (version >= 4) fields.push('sealed=' + (sealed ? 1 : 0), 'deep=' + (deep ? 1 : 0));
	return fields.join('\n');
}

// Constant-time hex-string compare — the shared, length-guarded, never-throwing primitive (a non-string or a
// length mismatch returns false), so every constant-time comparison in the tool goes through one audited place.
function equalHex(a, b) { return (typeof a === 'string' && typeof b === 'string') ? Common.timingSafeEqual(a, b) : false; }

// ---------------------------------------------------------------------------
// Local rollback ledger: highest (seq, root) ever seen per vault
// ---------------------------------------------------------------------------
// A stable, non-secret id for a vault, from its (obscured) salt — unique per vault, the same
// across machines and password changes, and revealing nothing decryptable.
function vaultId(manifest) {
	return crypto.createHash(HASH).update(String(manifest && manifest.crypt && manifest.crypt.salt)).digest('hex').slice(0, 32);
}
// The published Ed25519 verify key for a vault (or null). One place that knows where the key lives in the
// manifest, so every caller extracts it the same way. Safe to expose — it cannot decrypt or forge.
function pubkeyOf(manifest) { return (manifest && manifest.integrity && manifest.integrity.pubkey) || null; }

function ledgerPath() { return path.join(Common.dataDir(), 'integrity.json'); }
// A corrupt ledger is moved aside (not silently reset to {}) so the rollback history isn't quietly lost — but
// ONLY when the caller holds withLedgerLock (repair:true), never from an unlocked reader.
async function readLedger(repair = false) { return (await Common.readJsonCorruptAside(ledgerPath(), { repair, label: 'tamper/rollback ledger' })) || {}; }

// Serialize ledger read-modify-writes IN-PROCESS (the queue) AND across processes (a shared file lock on the
// ledger), so a CLI command and the background service can never clobber each other's whole-file writes to
// integrity.json / tamper-log.json — which could otherwise leave the ledger anchor ahead of the tamper log (a FALSE
// "truncated" tamper alarm) or drop an anti-rollback epoch bump. Both ledger files are guarded by this one lock, so
// their two-file update is atomic across processes too. Mirrors how settings.json is serialized.
const _ledgerQueue = Common.serialQueue();
function withLedgerLock(fn) { return _ledgerQueue(() => FileLock.withLock(FileLock.lockPathFor('integrity-ledger'), fn)); }

// Observe a vault's current (seq, root). Returns { status, seen } where status is:
//   'ok'       — first sighting, or the counter advanced (the ledger is updated to it);
//   'rollback' — the counter went BACKWARDS versus the highest we have seen (older vault);
//   'fork'     — the same counter with a different root (its history was rewritten).
// The ledger only ever moves forward (monotonic max), so a rollback can never lower it. On a
// machine that has never seen the vault, the first sighting is 'ok' — cross-machine rollback
// detection relies on the recordable fingerprint instead.
// `identity` (optional) records the committed vault identity alongside the version, so a later audit can tell a
// legitimate rotation (identity changed WITH a signed succession) from an identity substitution. The recorded
// identity is STICKY: it is set on first sighting, but a DIFFERENT identity is accepted only when the caller is
// authorized (identityAuthorized — the post-rotation observe, whose change is backed by a signed succession).
// An unauthorized path (a routine mount or snapshot) can never overwrite a known-good identity with a different
// one, so it can never launder a substituted key past the audit's succession check. The seq/root still advance
// regardless; only the identity field is held sticky.
// `sealed` records whether the observed baseline is a SEAL (the strict, never-auto-refreshed tripwire). It is
// stored with the highest-seq entry, so it is a local, attacker-inaccessible anchor of the last trusted seal
// state: because the entry only ever moves to a HIGHER seq, restoring an older still-validly-signed UNSEALED
// record cannot lower it, and a legitimate unseal (which writes an unsealed baseline at a higher seq) updates
// it forward. Callers that do not know the seal state pass undefined, which records `false`.
function observe(vid, seq, root, prevRoot, identity, identityAuthorized = false, sealed = undefined) {
	return withLedgerLock(async () => {
		const l = await readLedger(true); // under the lock: repair a corrupt ledger by moving it aside
		const cur = l[vid];
		let status = 'ok';
		if (cur) {
			if (seq < cur.seq) status = 'rollback';
			else if (seq === cur.seq && root !== cur.root) status = 'fork';
			// Hash-chain continuity: a baseline that advances the counter by exactly one MUST chain to the root
			// we last saw (its prevRoot === our last root). A mismatch means a baseline in between was hidden or
			// the history re-forged, even though the counter moved forward. Only assert on the CONSECUTIVE case —
			// a legitimate multi-machine gap (seq jumps by >1) has a prevRoot this ledger never recorded, so it
			// is advisory, not tampering.
			else if (seq === cur.seq + 1 && prevRoot != null && cur.root != null && prevRoot !== cur.root) status = 'chain-break';
		}
		if (!cur || seq > cur.seq) {
			// Re-read immediately before writing and take the per-vault max. This whole read-modify-write already runs
			// under withLedgerLock, which holds a CROSS-PROCESS advisory lock (FileLock) — so the CLI and the service
			// serialize their ledger writes and normally cannot clobber each other. This re-read-and-max is kept as
			// defense-in-depth: the advisory lock is reclaimed after a TTL if a holder dies mid-write, and in that rare
			// window this merge still prevents a stale writer from lowering another process's newer entry.
			const disk = await readLedger();
			const d = disk[vid];
			// Entries are keyed by 32-hex vault id, so a top-level schemaVersion never collides with one.
			if (!d || seq > d.seq) {
				const prior = (d && d.identity) || null;
				// Sticky identity: keep the known-good one unless this is the first sighting, the same identity, or
				// an authorized (succession-backed) change.
				const nextIdentity = prior == null ? (identity != null ? identity : null)
					: (identity == null || identity === prior || !identityAuthorized) ? prior
					: identity;
				// Spread the existing entry first so a field written by a FUTURE build (this per-entry object has grown
				// before — `identity` and `sealed` were both added after the fact) is preserved, not silently dropped
				// when an older build advances the seq. Matches the "preserve unknown fields" contract State/settings honor.
				disk[vid] = { ...(d || {}), seq, root, at: new Date().toISOString(), identity: nextIdentity, sealed: !!sealed };
				disk.schemaVersion = Common.schemaVersionFor('rollback ledger', disk);
				await Common.writeJsonAtomic(ledgerPath(), disk, { fsync: true });
			}
		} else if (sealed === true && cur && seq === cur.seq && root === cur.root && !cur.sealed) {
			// STICKY-TRUE seal anchor backfill. A sealed baseline never advances its seq (it is never auto-refreshed),
			// so the branch above — which writes only on a higher seq — can never record its seal state. Two cases need
			// this: a vault sealed by an OLDER build (its ledger entry predates the `sealed` field), and the very first
			// mount after this build is installed. `sealed === true` here comes only from an AUTHENTIC sealed record
			// (readSnapshot verified it before rollbackWarning calls observe), so this cannot be forged. It only ever
			// raises the anchor to true at the SAME (seq, root); a legitimate unseal writes a HIGHER seq with sealed:false
			// and wins through the branch above, so the anchor still follows a real unseal downward.
			const disk = await readLedger();
			const d = disk[vid];
			if (d && d.seq === seq && d.root === root && !d.sealed) { d.sealed = true; disk.schemaVersion = Common.schemaVersionFor('rollback ledger', disk); await Common.writeJsonAtomic(ledgerPath(), disk, { fsync: true }); }
		}
		return { status, seen: cur || null };
	});
}
async function lastSeen(vid) { return (await readLedger())[vid] || null; }

// ── Monotonic per-vault anti-rollback anchors ────────────────────────────────────────────────────────────────
// Several on-disk structures are signed but can still be ROLLED BACK by someone who can write the vault folder:
// restoring an older, still-validly-signed copy (an earlier recovery index, share roster, manifest, or a stale
// settings file) is not tampering the signature can catch. The defense is a local, sticky high-water mark: the
// highest VALUE this machine has seen for a vault, kept in a NAMED bucket of the rollback ledger (a named key never
// collides with a 32-hex vault-id entry). It only ever moves forward, so a restored older state reads as lower than
// the anchor and is flagged. Local-only; the in-vault signed state stays the cross-machine backstop. One shared
// read/write pair backs every specific anchor below, so they can never drift in their locking or monotonic rule.
function noteMonotonic(bucket, vid, value) {
	if (vid == null || !Number.isInteger(value)) return Promise.resolve();
	return withLedgerLock(async () => {
		const led = await readLedger();
		led[bucket] = led[bucket] || {};
		if (!(led[bucket][vid] >= value)) { // `!(x >= v)` advances on a missing/NaN prior too, and never lowers it
			led[bucket][vid] = value;
			led.schemaVersion = Common.schemaVersionFor('rollback ledger', led);
			await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true });
		}
	});
}
async function monotonicSeen(bucket, vid) { return ((await readLedger())[bucket] || {})[vid] || 0; }

// The highest recovery-index version this app has seen SIGNED for a vault. It lets the password-less recovery
// verify/heal path flag a DOWNGRADE: a recovery index that arrives unsigned, or at a lower version than one already
// seen signed, is exactly what an attacker who STRIPS the signature (to force the weaker "unsigned" path) would leave.
function noteRecoverySigned(vid, version) { return noteMonotonic('recoverySigned', vid, version); }
async function recoverySignedVersion(vid) { return monotonicSeen('recoverySigned', vid); }
// Reset the rollback anchor when a vault's recovery data is LEGITIMATELY destroyed with write authority (an
// explicit unprotect, or a key rotation that invalidates the old-key parity). Rebuilding recovery data afterward
// restarts the index at version 1, so a stale high anchor would make the downgrade gate falsely refuse a heal
// (and silently stop scheduled auto-heal) after a benign action. Clearing it here is safe: the anchor guards a
// folder-level attacker who lacks the credential, and both callers already require write authority — that is
// outside the anchor's threat model. A later signed rebuild re-establishes the anchor from the new baseline.
function clearRecoverySigned(vid) {
	if (vid == null) return Promise.resolve();
	return withLedgerLock(async () => {
		const led = await readLedger();
		if (led.recoverySigned && led.recoverySigned[vid] != null) { delete led.recoverySigned[vid]; led.schemaVersion = Common.schemaVersionFor('rollback ledger', led); await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true }); }
	});
}

// The highest share-roster EPOCH seen — the anti-rollback anchor for the signed list of who has access, so a
// restored older (pre-revocation) roster is detected even though its signature is genuine.
function noteSharesEpoch(vid, epoch) { return noteMonotonic('sharesEpoch', vid, epoch); }
async function sharesEpochSeen(vid) { return monotonicSeen('sharesEpoch', vid); }

// The anti-rollback anchor for a TEAM vault's MEMBER roster epoch (which lives inside the signed manifest), so a
// restored older manifest that re-lists a removed member's slot is detected.
function noteMembersEpoch(vid, epoch) { return noteMonotonic('membersEpoch', vid, epoch); }
async function membersEpochSeen(vid) { return monotonicSeen('membersEpoch', vid); }

// The anti-rollback anchor for a vault's KEY-SLOT set (crypt.slotEpoch), so a restored older manifest that re-lists
// a removed extra password, keyfile, or read-only slot is detected.
function noteSlotEpoch(vid, epoch) { return noteMonotonic('slotEpoch', vid, epoch); }
async function slotEpochSeen(vid) { return monotonicSeen('slotEpoch', vid); }

// The anti-rollback anchor for the dead-man's-switch CHECK-IN time (epoch milliseconds). The check-in lives in the
// settings file, which is not signed, so restoring an older settings file would move the last check-in backward and
// could make the inactivity window appear elapsed — releasing the emergency read grant early. Anchoring the latest
// check-in time here (monotonic) lets the emergency evaluation use max(stored, anchor), so a rolled-back settings
// file can never shorten the window. The dead-man switch is a single, global timer, so the caller keys this with a
// fixed name rather than a vault id; the named key never collides with a 32-hex vault-id entry either way.
function noteCheckInAt(key, atMs) { return noteMonotonic('emergencyCheckIn', key, atMs); }
async function checkInAtSeen(key) { return monotonicSeen('emergencyCheckIn', key); }

// A local reminder that a rotation removed this vault's recovery credential (a recovery key or owner recovery) and
// it has not been restored since. A rotation invalidates every non-rotating credential, so the owner can be left
// with no forgot-password safety net without noticing. Set on rotation (best-effort) and cleared when a recovery
// key or owner recovery is next added. Local and per vault; records only a timestamp, never key material.
function noteRecoveryDropped(vid) {
	if (vid == null) return Promise.resolve();
	return withLedgerLock(async () => {
		const led = await readLedger();
		led.recoveryDropped = led.recoveryDropped || {}; // a named key (not 32-hex) never collides with a vault-id entry
		if (!led.recoveryDropped[vid]) { led.recoveryDropped[vid] = new Date().toISOString(); led.schemaVersion = Common.schemaVersionFor('rollback ledger', led); await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true }); }
	});
}
function clearRecoveryDropped(vid) {
	if (vid == null) return Promise.resolve();
	return withLedgerLock(async () => {
		const led = await readLedger();
		if (led.recoveryDropped && led.recoveryDropped[vid]) { delete led.recoveryDropped[vid]; led.schemaVersion = Common.schemaVersionFor('rollback ledger', led); await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true }); }
	});
}
async function recoveryDroppedAt(vid) { return ((await readLedger()).recoveryDropped || {})[vid] || null; }

// ---------------------------------------------------------------------------
// Tamper event log: a persistent, local, append-only diagnostic history per vault
// ---------------------------------------------------------------------------
// Kept locally (not in the vault) so a record of detection survives even if the vault itself is
// rolled back or the in-vault baseline is deleted. Newest first, capped per vault.
const MAX_TAMPER_EVENTS = 200;
function tamperLogPath() { return path.join(Common.dataDir(), 'tamper-log.json'); }
async function readTamperLog(repair = false) { return (await Common.readJsonCorruptAside(tamperLogPath(), { repair, label: 'tamper log' })) || {}; }

// Canonical JSON for hashing: recursively sort object keys so the digest is independent of the key
// order the JSON happened to be written in, and stable across builds/round-trips. Arrays keep their
// order (it is meaningful). Deterministic and future-proof — a later field addition does not disturb
// the hash of records that omit it. (Only used to hash small records, never for storage.)
function canonicalJson(v) {
	if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
	// Skip keys whose value is undefined, exactly as JSON.stringify does — so canonicalizing an in-memory object
	// yields the same bytes as canonicalizing what a JSON round-trip (write-then-read) leaves on disk.
	if (v && typeof v === 'object') return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
	// string / number / boolean / null — JSON.stringify escapes unicode consistently. Note: the tamper-event
	// fields hashed through here are strings and integers only; keep them so — a non-integer float would couple
	// the chain hash to the engine's float-to-string formatting, which is not guaranteed stable across versions.
	return JSON.stringify(v);
}
// Normalize a value the way persisting it does (drop undefined-valued keys, apply any toJSON), so a hash taken
// at write time reproduces exactly when recomputed from the reloaded-from-disk copy. Guards the tamper chain
// against a divergence where an in-memory event carries own keys with undefined values (the Vault wrapper builds
// e.added = cap(undefined) etc.) that JSON.stringify silently drops on disk.
function jsonNormalize(v) { return JSON.parse(JSON.stringify(v === undefined ? null : v)); }

// Each tamper-log entry commits to the previous one, forming a hash chain (a blockchain-style linkage):
// editing or reordering any entry breaks the chain, RFC 6962-style domain separation guards the hash, and
// the FIRST entry commits to a genesis value bound to the vault identity so a fresh chain cannot be passed
// off as another vault's. In the SEPARATE rollback-ledger file we anchor BOTH ends of the retained window —
// the HEAD (newest n + hash), so removing recent entries is caught, and an EVICTION watermark (the highest
// n legitimately aged out of the cap), so deleting the OLDEST retained entries is distinguishable from
// normal cap-eviction. Appends stay keyless and fast; separately, a read-write session stamps the head with the
// write-authority key (a signed checkpoint via signTamperHead) — something a later full-file-rewrite
// attacker cannot forge, lifting tamper-EVIDENCE toward tamper-RESISTANCE. (Everything up to the last signed
// checkpoint is then unforgeable; the in-vault signed baseline remains the primary detector.)
// These domains are the versioned scheme of the tamper chain. The tamper log and its ledger anchor are LOCAL,
// rebuildable files (not carried in the shared vault), so if a future build must change how entries are hashed
// it bumps the version here AND resets the local chain (start a fresh genesis) as a migration — do not verify
// old entries under a new domain, which would false-alarm. A read-write snapshot re-establishes the chain.
const TAMPER_CHAIN_DOMAIN = 'vdisk-tamper-chain-v1';
const TAMPER_HEAD_DOMAIN = 'vdisk-tamper-head-v1'; // a DISTINCT domain so a head signature can't be replayed as a chain hash
function tamperGenesis(vid) { return crypto.createHash(HASH).update(TAMPER_CHAIN_DOMAIN).update('\ngenesis\n').update(String(vid)).digest('hex'); }
function tamperChainHash(prevHash, core) {
	// Hash the PERSISTED shape of the entry-core (undefined-valued keys dropped) so a recompute from disk matches.
	return crypto.createHash(HASH).update(TAMPER_CHAIN_DOMAIN).update('\n').update(String(prevHash || '')).update('\n').update(canonicalJson(jsonNormalize(core))).digest('hex');
}
function tamperHeadMessage(vid, n, hash) { return TAMPER_HEAD_DOMAIN + '\n' + vid + '\n' + n + '\n' + hash; }
function logTamper(vid, event) {
	return withLedgerLock(async () => {
		const l = await readTamperLog(true); // under the lock: repair a corrupt tamper log by moving it aside
		const prev = (l[vid] && l[vid][0]) || null; // the newest existing entry, or null for a fresh chain
		const prevHash = (prev && prev.hash) || tamperGenesis(vid); // the first entry commits to the vault-bound genesis
		const n = (prev && Number.isInteger(prev.n) ? prev.n : 0) + 1; // monotonic; survives cap-eviction of old entries
		const core = { at: new Date().toISOString(), n, ...event };
		const entry = { ...core, prevHash, hash: tamperChainHash(prevHash, core) };
		const full = [entry, ...(l[vid] || [])];
		l[vid] = full.slice(0, MAX_TAMPER_EVENTS);
		const dropped = full.slice(MAX_TAMPER_EVENTS); // entries aged out of the retained window (highest n first)
		l.schemaVersion = Common.schemaVersionFor('tamper log', l); // vault ids are 32-hex, so this key never collides
		await Common.writeJsonAtomic(tamperLogPath(), l, { fsync: true });
		// Anchor both ends (and carry/refresh the signed checkpoint) in the ledger, under the lock we already hold.
		const led = await readLedger();
		led.tamperHeads = led.tamperHeads || {}; // a named key (not 32-hex) never collides with a vault-id entry
		const cur = led.tamperHeads[vid] || {};
		// Spread cur first so the signed checkpoint (and any field a future build adds to the head entry) is carried
		// forward rather than dropped; the head fields below then overwrite n/hash/evicted with the new values.
		const nextHead = { ...cur, n, hash: entry.hash, evicted: dropped.length ? Math.max(cur.evicted || 0, dropped[0].n) : (cur.evicted || 0) };
		led.tamperHeads[vid] = nextHead;
		led.schemaVersion = Common.schemaVersionFor('rollback ledger', led);
		await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true });
	});
}
async function tamperLog(vid) { return (await readTamperLog())[vid] || []; }

// Sign the current tamper-log head with a write-authority key WITHOUT appending an event — used to stamp a
// signed checkpoint opportunistically when a read-write session is active (e.g. after a mount-time scan), so
// the unforgeable checkpoint keeps up with the head even across read-only or password-less appends.
function signTamperHead(vid, signPriv) {
	return withLedgerLock(async () => {
		const head = ((await readTamperLog())[vid] || [])[0];
		if (!head || !head.hash || !signPriv) return;
		const led = await readLedger();
		led.tamperHeads = led.tamperHeads || {};
		const cur = led.tamperHeads[vid] || { n: head.n, hash: head.hash, evicted: 0 };
		cur.checkpoint = { n: head.n, hash: head.hash, sig: sign(signPriv, tamperHeadMessage(vid, head.n, head.hash)) };
		led.tamperHeads[vid] = cur;
		led.schemaVersion = Common.schemaVersionFor('rollback ledger', led);
		await Common.writeJsonAtomic(ledgerPath(), led, { fsync: true });
	});
}

// Verify the local tamper history. Recompute each entry's chain hash and its link to the older entry, check
// the genesis anchor at the tail, and reconcile both ends against the ledger anchor (head + eviction
// watermark) and any signed checkpoint. Returns { ok, verdict, reason?, signed?, empty?, legacy?, unverified? };
// `verdict` (one of 'empty' / 'unverified' / 'altered' / 'signed' / 'chained') is what callers key on. A hard
// failure (ok:false) is a
// reliable contradiction: an entry edited or reordered, a bad genesis, the newest entries removed, the oldest
// retained entries deleted, or a signed checkpoint that fails to verify / sits ahead of the head (a rollback).
// A missing anchor or a pre-chain legacy tail is reported as unverified (best-effort), never as tampering.
async function verifyTamperLog(vid, pub) {
	const entries = (await readTamperLog())[vid] || [];
	if (!entries.length) return { ok: true, empty: true, verdict: 'empty' };
	const head = entries[0];
	if (!head.hash) return { ok: true, legacy: true, verdict: 'unverified' }; // written before chaining began — nothing to check yet
	for (let i = 0; i < entries.length; i++) {
		const e = entries[i];
		if (!e.hash) break; // reached the pre-chain legacy tail; older links cannot be checked
		const { hash, prevHash, ...core } = e;
		if (hash !== tamperChainHash(prevHash || '', core)) return { ok: false, reason: 'edited', verdict: 'altered' };
		const older = entries[i + 1];
		if (older && older.hash && (prevHash || '') !== older.hash) return { ok: false, reason: 'reordered', verdict: 'altered' };
	}
	const anchor = ((await readLedger()).tamperHeads || {})[vid] || null;
	if (!anchor) return { ok: true, unverified: true, reason: 'no-anchor', verdict: 'unverified' }; // ledger reset/repaired — cannot check the ends
	// A crash BETWEEN the tamper-log write and the ledger-anchor write leaves the anchor exactly one entry behind a
	// head that is correctly chained onto the anchored entry (head.n === anchor.n + 1, head.prevHash === anchor.hash).
	// That is a benign interrupted append, not tampering — the head EXTENDS the anchor rather than diverging from it,
	// and the next append re-syncs the anchor. The SAME interrupted append, once the log has reached its eviction
	// cap, ALSO evicts one entry the anchor's watermark does not yet reflect, so both ends can lag by one at once.
	// Tolerate exactly that one-step lag at both ends, and only that.
	const benignLag = head.n === anchor.n + 1 && (head.prevHash || '') === anchor.hash;
	if (anchor.n !== head.n || anchor.hash !== head.hash) {
		if (!benignLag) return { ok: false, reason: 'truncated', verdict: 'altered' }; // a head BEHIND the anchor (newest removed) or one that does not link to the anchored hash
	}
	const tail = entries[entries.length - 1];
	if (tail.hash) { // reconcile the OLDEST retained entry with what was legitimately evicted
		if (tail.n === 1) { if ((tail.prevHash || '') !== tamperGenesis(vid)) return { ok: false, reason: 'bad-genesis', verdict: 'altered' }; }
		else {
			const evBase = (anchor.evicted || 0) + 1;
			// Under a benign interrupted append at the cap, the extra eviction not yet in the watermark means the
			// oldest retained entry can legitimately be one further along than the watermark predicts.
			if (tail.n !== evBase && !(benignLag && tail.n === evBase + 1)) return { ok: false, reason: 'oldest-removed', verdict: 'altered' };
		}
	}
	const cp = anchor.checkpoint;
	if (cp && cp.sig) { // a signed checkpoint must verify and cannot sit ahead of the current head
		if (!pub || !verify(pub, tamperHeadMessage(vid, cp.n, cp.hash), cp.sig)) return { ok: false, reason: 'checkpoint-forged', verdict: 'altered' };
		if (cp.n > head.n) return { ok: false, reason: 'rolled-back', verdict: 'altered' }; // history once reached cp.n; a lower head is a rollback
		const inWindow = entries.find(e => e.n === cp.n);
		if (inWindow && inWindow.hash !== cp.hash) return { ok: false, reason: 'checkpoint-mismatch', verdict: 'altered' };
	}
	// Only claim the retained window is SIGNED when the checkpoint actually anchors it — i.e. it covers the oldest
	// retained entry (cp.n >= tail.n). Once enough keyless appends push the checkpoint below the retained window
	// (cp.n < tail.n), the signature no longer constrains any retained entry, so the window is merely hash-chained,
	// not signed — reporting it as signed would overstate the guarantee. Take a fresh read-write snapshot to
	// re-checkpoint the current head.
	const signed = !!(cp && cp.sig && cp.n >= tail.n);
	return { ok: true, signed, verdict: signed ? 'signed' : 'chained' };
}

module.exports = {
	SCHEME, HASH,
	merkleRoot, sortFilesByPath, fingerprint, identity, groupB32,
	signKeysFromSeed, readKeyFromSeed, sign, verify, signingInput, equalHex,
	vaultId, pubkeyOf, observe, lastSeen, noteRecoverySigned, recoverySignedVersion, clearRecoverySigned, noteSharesEpoch, sharesEpochSeen, noteMembersEpoch, membersEpochSeen, noteSlotEpoch, slotEpochSeen, noteCheckInAt, checkInAtSeen, noteRecoveryDropped, clearRecoveryDropped, recoveryDroppedAt, logTamper, tamperLog, verifyTamperLog, signTamperHead
};
