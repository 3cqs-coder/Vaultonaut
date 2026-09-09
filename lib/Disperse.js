'use strict';
// lib/Disperse.js — split one blob of bytes into n shards such that ANY k of them rebuild it. This
// promotes the vault's own Reed–Solomon codec from on-disk parity to INTER-NODE dispersal: pack a
// vault into one archive, shard the archive across nodes, and later gather any k nodes to reconstruct
// it. No new coding theory — the codec is the same one the self-healing feature already ships and tests.
//
//   encodeShards(buf, n, k) -> [Buffer × n]   (each a framed shard; 1 ≤ k ≤ n ≤ 255)
//   decodeShards([Buffer ≥ k]) -> Buffer      (rebuilds the original; tolerates loss and bit-rot)
//
// SECRECY: this is erasure coding for DURABILITY, not a secret-sharing scheme. The Reed–Solomon code
// is SYSTEMATIC, so the k data shards are literal slices of the input — one data shard exposes 1/k of
// the input bytes. Dispersal therefore provides NO confidentiality on its own and must only ever be
// applied to already-encrypted data. (The vault dispersal above packs the fully-encrypted vault first,
// so each shard is a slice of ciphertext; and the vault KEY is split with Shamir, which IS
// information-theoretic. Do not use Disperse to "hide" a secret — use Shamir for that.)
//
// INTEGRITY: each shard carries a self-describing header — the geometry (k, m), its index, the original
// length, and a random per-DISPERSAL id — and a SHA-256 that covers BOTH the header identity fields AND the
// payload. Covering the header matters: a bit-flip in the index byte would otherwise pass a payload-only hash
// and silently place the shard in the wrong slot (wrong bytes on rebuild); and the per-dispersal id keeps two
// separate dispersals of coincidentally equal length from being combined into a blended, corrupt rebuild. The
// hash is UNKEYED, so it detects accidental corruption or bit-rot (decode then skips the bad shard and rebuilds
// from the good ones) but does NOT authenticate against a malicious node that forges a shard with a matching
// hash. Adversarial tampering is caught downstream instead, by the reconstructed payload's own authenticated
// encryption (the vault fails to decrypt tampered ciphertext).

const crypto = require('crypto');
const fsp = require('fs/promises');
const RS = require('./ReedSolomon');

const MAGIC = Buffer.from('VDSH', 'ascii'); // vault-disk shard
const VERSION = 2; // v2 adds the per-dispersal id and extends the hash to cover the identity header; v1 (payload-only hash, no id) is still read
// Accept any shard-format version from 1 up to the one we write, so a future build with a newer VERSION can still
// read shards dispersed by an older one (a plain `=== VERSION` would strand old dispersed sets after a bump). New
// shards are always written at the current VERSION; when the format actually changes, the reader branches on `ver`.
function versionSupported(ver) { return ver >= 1 && ver <= VERSION; }
// The identity fields (offsets 4..PRE) are common to both versions; the hash and, in v2, the dispersal id follow.
const PRE = 4 + 1 + 1 + 1 + 1 + 8 + 4;   // magic + ver + k + m + idx + origLen(8) + shardLen(4) = 20 (through shardLen, before the version-specific tail)
const ID_LEN = 16;                       // v2 per-dispersal random id
const HEADER_V1 = PRE + 32;              // v1: …shardLen + sha256(payload)                 = 52
const HEADER_V2 = PRE + ID_LEN + 32;     // v2: …shardLen + id(16) + sha256(identity+payload) = 68
const HEADER = HEADER_V2;                // the size this build WRITES (and a safe upper bound for read allocation)
function headerSizeFor(ver) { return ver >= 2 ? HEADER_V2 : HEADER_V1; }
// The largest archive dispersal will encode, and a hard bound on any single shard's payload (a shard can never
// exceed a whole archive, so this also bounds a per-shard read). NOTE: encoding is not single-buffer — it holds the
// whole archive plus all n framed shards at once, so peak memory is about (1 + n/k)x the archive (roughly 2-3x for a
// sane n≈2k geometry, more for a lopsided one). The dispersal runs in a worker, so an over-budget geometry OOMs that
// worker and fails loudly rather than affecting the main process. Vault re-exports this value as its own cap.
const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;

// Build a v2 shard: the identity header (through shardLen) + the 16-byte dispersal id, then a SHA-256 that
// covers the identity fields (offsets 4..PRE+ID_LEN) AND the payload, then the payload.
function frame(k, m, idx, origLen, y, id) {
	const head = Buffer.alloc(HEADER_V2);
	MAGIC.copy(head, 0);
	head.writeUInt8(VERSION, 4);
	head.writeUInt8(k, 5);
	head.writeUInt8(m, 6);
	head.writeUInt8(idx, 7);
	head.writeBigUInt64BE(BigInt(origLen), 8);
	head.writeUInt32BE(y.length, 16);
	id.copy(head, PRE); // dispersal id at offset PRE (20)
	// Hash the identity bytes (ver..id) together with the payload, so a flipped index/geometry/id byte is caught
	// rather than accepted onto a payload-only hash and silently misplaced.
	crypto.createHash('sha256').update(head.subarray(4, PRE + ID_LEN)).update(y).digest().copy(head, PRE + ID_LEN);
	return Buffer.concat([head, y]);
}
// Build a v1 shard (payload-only hash, no dispersal id). New dispersals are always v2; this exists ONLY so that
// REPAIRING an old v1 dispersal can produce rebuilt shards in the SAME (v1) framing as the survivors, so they
// group and rebuild together instead of splitting the set. Kept byte-compatible with the v1 reader above.
function frameV1(k, m, idx, origLen, y) {
	const head = Buffer.alloc(HEADER_V1);
	MAGIC.copy(head, 0);
	head.writeUInt8(1, 4);
	head.writeUInt8(k, 5);
	head.writeUInt8(m, 6);
	head.writeUInt8(idx, 7);
	head.writeBigUInt64BE(BigInt(origLen), 8);
	head.writeUInt32BE(y.length, 16);
	crypto.createHash('sha256').update(y).digest().copy(head, PRE); // v1: payload-only hash
	return Buffer.concat([head, y]);
}
function unframe(buf) {
	if (!Buffer.isBuffer(buf) || buf.length < HEADER_V1) return null;
	if (!buf.subarray(0, 4).equals(MAGIC)) return null;
	const ver = buf.readUInt8(4);
	if (!versionSupported(ver)) return null;
	const hs = headerSizeFor(ver);
	if (buf.length < hs) return null;
	const k = buf.readUInt8(5), m = buf.readUInt8(6), idx = buf.readUInt8(7);
	// Reject nonsensical shard geometry from a crafted/corrupt header before it reaches the codec, so a
	// malformed shard reads as "not a valid shard" rather than leaking a raw internal codec error.
	if (k < 1 || k + m > 256 || idx >= k + m) return null;
	const origLen = Number(buf.readBigUInt64BE(8)), shardLen = buf.readUInt32BE(16);
	const y = buf.subarray(hs, hs + shardLen);
	if (y.length !== shardLen) return null;
	let good, id = null;
	if (ver >= 2) {
		id = buf.subarray(PRE, PRE + ID_LEN).toString('hex');
		const hash = buf.subarray(PRE + ID_LEN, hs);
		good = crypto.createHash('sha256').update(buf.subarray(4, PRE + ID_LEN)).update(y).digest().equals(hash); // identity + payload
	} else {
		const hash = buf.subarray(PRE, hs); // v1: payload-only hash, no id
		good = crypto.createHash('sha256').update(y).digest().equals(hash);
	}
	return { ver, k, m, idx, origLen, shardLen, id, y, good };
}

// Split `buf` into n = k + m shards. The archive is cut into k equal data shards (zero-padded), and the
// codec computes m parity shards; any k of the n rebuild the original.
function encodeShards(buf, n, k, { id = null, version = VERSION } = {}) {
	if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k || n > 255) {
		throw new Error('Invalid shard parameters: need 1 ≤ k ≤ n ≤ 255 (got k=' + k + ', n=' + n + ').');
	}
	const m = n - k;
	const shardLen = Math.max(1, Math.ceil(buf.length / k));
	const data = [];
	for (let i = 0; i < k; i++) {
		const s = Buffer.alloc(shardLen); // zero-padded; a shard past the blob's end stays all zeros
		const start = Math.min(i * shardLen, buf.length);
		const end = Math.min((i + 1) * shardLen, buf.length);
		if (start < end) buf.copy(s, 0, start, end);
		data.push(s);
	}
	const all = m > 0 ? data.concat(RS.codec(k, m).encode(data)) : data;
	// v1 framing is used ONLY when repairing an old v1 dispersal, so rebuilt shards match the survivors' framing.
	if (version === 1) return all.map((y, idx) => frameV1(k, m, idx, buf.length, y));
	// Preserve a caller-supplied dispersal id (used by repair, so rebuilt shards REJOIN the survivors' group rather
	// than forming a new group that would silently reduce recoverability); otherwise mint one random id for THIS
	// dispersal, so its shards never merge with another dispersal's.
	const useId = (Buffer.isBuffer(id) && id.length === ID_LEN) ? id : crypto.randomBytes(ID_LEN);
	return all.map((y, idx) => frame(k, m, idx, buf.length, y, useId));
}

// Rebuild the original blob from k or more shards (any indices). A shard that fails its hash is treated
// as absent, so corruption is survived like loss. Throws if fewer than k good shards remain.
// Parse and keep only the good (hash-verifying) shards.
function parseGoodShards(shardBuffers) {
	const parsed = [];
	for (const b of shardBuffers || []) { const p = unframe(b); if (p && p.good) parsed.push(p); }
	return parsed;
}
// Group good shards by DISPERSAL id (v2) + geometry, so two different dispersals of coincidentally equal length can
// never be combined into a blended rebuild (v1 shards carry no id; they group by geometry). Return the LARGEST
// group as a Map(idx -> shard): a few divergent shards (bit-rot that still hashes, or a shard planted from a
// different dispersal) must not block an otherwise-recoverable set, so we pick the majority and ignore the rest.
function largestGroup(parsed) {
	const groups = new Map();
	for (const p of parsed) {
		const key = (p.id || 'v1') + ':' + p.k + ':' + p.m + ':' + p.origLen + ':' + p.shardLen;
		let g = groups.get(key); if (!g) { g = new Map(); groups.set(key, g); }
		if (!g.has(p.idx)) g.set(p.idx, p);
	}
	let group = null;
	for (const g of groups.values()) if (!group || g.size > group.size) group = g;
	return group;
}
// The framing of the largest good group — its dispersal id (hex, or null for v1) and version — so a repair can
// rebuild missing shards in the SAME framing and they rejoin the group. Null when there are no good shards.
function dominantGroup(shardBuffers) {
	const group = largestGroup(parseGoodShards(shardBuffers));
	if (!group) return null;
	const p = group.values().next().value;
	return { id: p.id || null, version: p.id ? 2 : 1, k: p.k, m: p.m, origLen: p.origLen, shardLen: p.shardLen };
}
// Does a raw buffer carry our shard magic but a version NEWER than this build writes? Used to give a clear
// "update the app" error instead of a misleading "these shards are unreadable/corrupt" when a future build's shards
// are handed to an older one. Peeks only the fixed magic+version prefix, so it never throws on a short/garbage buffer.
function newerShardVersion(buf) {
	if (!Buffer.isBuffer(buf) || buf.length < 5 || !buf.subarray(0, 4).equals(MAGIC)) return 0;
	const ver = buf.readUInt8(4);
	return ver > VERSION ? ver : 0;
}
function decodeShards(shardBuffers) {
	const parsed = parseGoodShards(shardBuffers);
	if (!parsed.length) {
		// Distinguish "made by a newer version" from "unreadable/corrupt": if a shard carries our magic but a higher
		// version, the shards are fine — this build is too old to read them. Say so, rather than "no readable shards."
		if ((shardBuffers || []).some(b => newerShardVersion(b) > 0)) throw new Error('These shards were made by a newer version of the app — update to reconstruct them.');
		throw new Error('No readable shards were provided.');
	}
	const group = largestGroup(parsed);
	const usable = [...group.values()];
	const { k, m, origLen, shardLen } = usable[0];
	const n = k + m;
	const slots = new Array(n).fill(null), present = new Array(n).fill(false);
	for (const p of usable) { if (p.idx < n && !present[p.idx]) { slots[p.idx] = Buffer.from(p.y); present[p.idx] = true; } }
	const have = present.filter(Boolean).length;
	if (have < k) throw new Error('Not enough shards to rebuild: ' + have + ' of the required ' + k + '.');
	if (m > 0) RS.codec(k, m).reconstruct(slots, present);
	return Buffer.concat(slots.slice(0, k)).subarray(0, origLen);
}

// Read a shard's header without its payload — for listing/verifying a set of shards cheaply.
function shardInfo(buf) { const p = unframe(buf); return p ? { k: p.k, m: p.m, idx: p.idx, origLen: p.origLen, shardLen: p.shardLen, id: p.id, good: p.good } : null; }

// Read a shard file into memory SAFELY, from an untrusted/removable location. A shard file's real length is
// HEADER + the payload length it declares in its own header; anything past that is padding a hostile node
// could have appended to OOM whoever reads it. So read the fixed header first, learn the declared payload
// length, refuse a declaration larger than a whole archive, then read EXACTLY that many payload bytes and
// ignore the rest. Returns the framed buffer (header + payload, ready for unframe/shardInfo/decodeShards), or
// null if the file is too short, mis-declared, or unreadable — callers already treat null as "shard absent".
async function readShard(p) {
	let fh = null;
	try {
		fh = await fsp.open(p, 'r');
		// Read the COMMON prefix first (magic..shardLen, identical in both versions), so we learn the version and
		// the declared payload length before allocating — and so a v1 shard (smaller header) is not over-read.
		const pre = Buffer.alloc(PRE);
		if ((await fh.read(pre, 0, PRE, 0)).bytesRead < PRE) return null; // too short to be a shard
		const ver = pre.readUInt8(4);
		if (!pre.subarray(0, 4).equals(MAGIC) || !versionSupported(ver)) return null; // not a shard header — refuse BEFORE allocating its declared payload, so a junk file can't force a huge alloc
		const hs = headerSizeFor(ver);
		const shardLen = pre.readUInt32BE(16); // payload length declared in the header
		if (shardLen > MAX_ARCHIVE_BYTES) return null; // a shard can't be larger than the whole archive — refuse
		// Confirm the file actually HOLDS the declared payload before allocating it: a 20-byte junk file could declare
		// a shardLen just under the ceiling (~2 GiB) and force a multi-GiB allocation that OOMs a phone or small VPS,
		// only to fail the truncated-read check below. Bound the allocation to the real file size instead.
		const st = await fh.stat();
		if (st.size < hs + shardLen) return null; // truncated or mis-declared — refuse before allocating
		const buf = Buffer.allocUnsafe(hs + shardLen);
		pre.copy(buf, 0);
		if (hs > PRE && (await fh.read(buf, PRE, hs - PRE, PRE)).bytesRead < hs - PRE) return null; // rest of the header (id + hash)
		if (shardLen > 0 && (await fh.read(buf, hs, shardLen, hs)).bytesRead < shardLen) return null; // truncated
		return buf;
	} catch (_) { return null; }
	finally { if (fh) { try { await fh.close(); } catch (_) {} } }
}

// The shard index and total-n encoded in a shard's FILENAME (…​.<idx>of<n>.vdshard) — the fallback identity
// for a shard too corrupt to read its own header. The pattern is end-anchored, so it works on a full path.
function shardIdxFromName(nameOrPath) { const m = /\.(\d+)of(\d+)\.vdshard$/.exec(String(nameOrPath || '')); return m ? { idx: Number(m[1]), n: Number(m[2]) } : null; }

module.exports = { encodeShards, decodeShards, dominantGroup, shardInfo, readShard, shardIdxFromName, newerShardVersion, MAGIC, HEADER, VERSION, MAX_ARCHIVE_BYTES };
