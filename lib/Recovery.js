'use strict';
// lib/Recovery.js — OPTIONAL per-vault self-healing (bit-rot / corruption recovery). It builds an
// erasure-coding parity sidecar OVER THE CIPHERTEXT of a vault, so a repair needs no password and can
// never expose plaintext: parity is pure error-correction math (Reed–Solomon) over the encrypted
// bytes, and a successful repair re-verifies itself against the engine's authentication on the next
// read. This complements — never replaces — backups: it survives random corruption of a bounded
// fraction of the data, not deletion, a lost key, or whole-vault loss.
//
// Layout — a `.recovery/` folder at the VAULT ROOT (a sibling of `data/`, so it is outside the
// encrypted store and never seen by the mount/tamper layers):
//   • index.json (+ .bak / .bak2 copies — critical-set replication): the block size, the tier and
//     RS shape, and per-block CRC32s for every data and parity block, plus a self-integrity hash.
//   • parity.bin: the Reed–Solomon parity blocks (stripe-major).
//
// Blocks are fixed BLOCK_SIZE slices of the raw encrypted files under data/. Blocks are assigned to
// stripes by INTERLEAVING (block i -> stripe i mod S), so a contiguous burst of damage is spread
// across many stripes and stays within each stripe's repair budget. Each stripe is an independent
// Reed–Solomon(k, m) group; any m damaged/lost blocks per stripe are recoverable.
//
// The CPU-heavy work (Reed–Solomon math over every block) runs in a WORKER THREAD so it never
// blocks the event loop — the local web server keeps answering, mount health checks keep firing —
// and the parity encode holds only a single stripe in memory at a time, so the encode pass stays
// within a small, bounded footprint regardless of vault size. (The index itself carries one small CRC
// record per block, so it scales with the vault's data — modest for typical vaults.) Progress is
// reported back as it goes so a long operation always visibly shows it is working (never mistaken
// for a freeze).

const fsp = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { isMainThread } = require('worker_threads');
const WorkerRun = require('./WorkerRun');
const RS = require('./ReedSolomon');
const Common = require('./Common');
const Brand = require('./Brand');
const Integrity = require('./Integrity'); // for signing/verifying the recovery index against the vault's write-authority key

const BLOCK_SIZE = 65536;   // 64 KiB data/parity blocks
// Upper bound on an index replica read into memory. The index travels inside a shareable vault and is only
// self-hashed (unkeyed), so a hostile replica could be arbitrarily large; refuse an oversized one before
// reading it rather than spiking memory to hash-check a file that will be rejected anyway. A legitimate index
// is a tiny fraction of the vault's size (~30 bytes per 64 KiB block), so 512 MiB covers vaults into the
// terabytes — and a larger JSON string cannot be parsed by the engine regardless, so this adds no real limit.
const MAX_RECOVERY_INDEX_BYTES = 512 * 1024 * 1024;
const K_MAX = 128;          // cap on data shards per stripe (keeps k + m well under the 256 field limit)
const INDEX_COPIES = 3;     // the recovery index is tiny and critical -> keep this many copies
const RECOVERY_DIR = '.recovery';
// Version of the recovery format itself (the parity layout + index shape), independent of the
// sidecar-store schema version. A build must never repair from an index whose format it does not
// understand, so reading a newer one fails closed rather than guessing at an unknown layout.
const RECOVERY_SCHEMA = 1;
// Redundancy tiers: parity as a percentage of each stripe's data. Users pick per vault.
const TIERS = { low: 5, medium: 10, high: 15 };

function recoveryDir(vaultDir) { return path.join(path.resolve(vaultDir), RECOVERY_DIR); }
// The encrypted store for a vault (a `data/` sibling of `.recovery/`); callers may override it.
function cipherOf(vaultDir, cipherDir) { return cipherDir || path.join(path.resolve(vaultDir), 'data'); }
function parityPath(vaultDir) { return path.join(recoveryDir(vaultDir), 'parity.bin'); }
// Build the INDEX_COPIES replica paths for a recovery sidecar from its base filename set (index or signature),
// so the two replicated files stay in lockstep on the copy count without a second implementation.
function replicaPaths(vaultDir, names) {
	const d = recoveryDir(vaultDir);
	return names.slice(0, INDEX_COPIES).map(n => path.join(d, n));
}
function indexPaths(vaultDir) { return replicaPaths(vaultDir, ['index.json', 'index.bak.json', 'index.bak2.json']); }

// ── recovery-index authenticity sidecar ────────────────────────────────────────────────────────
// A detached Ed25519 signature over the index's content hash, made with the vault's WRITE-AUTHORITY key
// and verified by the password-less repair path against the vault's PUBLISHED public key. Because a
// read-only holder has the read key but NOT the signing key, they cannot forge a recovery index that
// verifies against that published key. The anchor here is the manifest's public key: a full-filesystem
// attacker could swap that key and re-sign a forged index — but that same swap breaks the in-vault signed
// baseline the moment any credential (or read-cap) holder touches the vault, and the out-of-band vault
// identity catches a recreation, so this signature is a strong LOCAL authenticity signal layered on those,
// not a standalone proof against an attacker who already controls the vault folder. Kept in its own small,
// replicated file (not inside the large index) so a refresh can add or clear it cheaply. Versioned and
// alg-tagged so the scheme can evolve without breaking older sidecars. It is tamper-EVIDENCE layered on the
// structural validation in readIndex (path containment, shape, sizes) and the signed baseline — not a
// replacement for either.
const SIG_DOMAIN = 'vdisk-recovery-index-v1';
const SIG_ALG = 'ed25519', SIG_VERSION = 1; // the sidecar's algorithm + format; the read side branches on these so a future swap is clean
function sigPaths(vaultDir) { return replicaPaths(vaultDir, ['index.sig.json', 'index.sig.bak.json', 'index.sig.bak2.json']); }
// The signed payload is a domain-separated STRUCT, never a bare hash: signing an unqualified hash value is a
// known forgery footgun, and binding the vaultId + monotonic version blocks transplanting a valid signed index
// into another vault and replaying an older signed index. Fixed field order (all scalars) — no canonical-JSON
// ambiguity. The indexHash already covers the whole index (version included), so it stands in for the content.
function sigMessage(vaultId, version, indexHash) { return SIG_DOMAIN + '\n' + String(vaultId) + '\n' + String(version) + '\n' + indexHash; }
async function writeIndexSig(vaultDir, { vaultId, version, indexHash }, signPriv) {
	const rec = { v: SIG_VERSION, alg: SIG_ALG, vaultId, version, indexHash, sig: Integrity.sign(signPriv, sigMessage(vaultId, version, indexHash)) };
	for (const p of sigPaths(vaultDir)) await Common.writeJsonAtomic(p, rec, { fsync: true }); // durable like the other signed sidecars
}
// Every readable signature replica (there are a few). authenticity() must consider them ALL, not just the first
// that parses: if one replica's signature bit-rots, another intact replica should still verify — replication
// must actually rescue a corrupt sidecar rather than let it deny repair.
async function readIndexSigs(vaultDir) {
	const out = [];
	for (const p of sigPaths(vaultDir)) {
		try { const s = JSON.parse(await Common.readFileCapped(p, 64 * 1024, 'utf8')); if (s && s.indexHash && s.sig) out.push(s); } catch (_) {}
	}
	return out;
}
async function readIndexSig(vaultDir) { return (await readIndexSigs(vaultDir))[0] || null; } // first readable replica (for the idempotency check)
async function removeIndexSig(vaultDir) {
	for (const p of sigPaths(vaultDir)) { try { await fsp.rm(p, { force: true }); } catch (_) {} }
}
// Establish whether the recovery index is authentic against the vault's published public key:
//   { signed:false }                 no signature for this index (a password-less build/refresh) — weaker trust
//   { signed:true, verified:true, version }   signature present and valid — from a write-authority holder
//   { signed:true, tampered:true }   signature present but does NOT verify — the index was altered after signing
// A signature left over for a DIFFERENT indexHash counts as "not signed for this index" (signed:false), so a
// legitimate unsigned refresh over a previously-signed index is never mistaken for tampering.
async function authenticity(vaultDir, { vaultId, version, indexHash }, pubkey) {
	// Consider every replica whose signature is FOR the current index AND uses a format/algorithm this build
	// understands. An unknown v/alg (a NEWER build's sidecar) is treated as "not signed for us" (signed:false,
	// repair still allowed, backstopped by the signed baseline) rather than a forgery — so a future signature
	// scheme never makes an older build refuse to repair a healthy vault. Signed-but-unverifiable is reported as
	// tampering only when NO known-scheme replica verifies, so a single bit-rotten sidecar is skipped in favor of
	// an intact one and never denies repair, while a genuine forgery (all replicas fail the published key) is caught.
	const known = s => (s.alg === undefined || s.alg === SIG_ALG) && (s.v === undefined || s.v === SIG_VERSION);
	const matching = (await readIndexSigs(vaultDir)).filter(s => s.indexHash === indexHash && known(s));
	if (!matching.length) return { signed: false };
	if (!pubkey) return { signed: true, verified: false, reason: 'no-pubkey', version };
	const msg = sigMessage(vaultId, version, indexHash);
	return matching.some(s => Integrity.verify(pubkey, msg, s.sig))
		? { signed: true, verified: true, version }
		: { signed: true, verified: false, tampered: true, version };
}
// Sign the EXISTING index in place (no rebuild) — used to add a signature to an already-current index when a
// write-authority key becomes available (e.g. a trusted read-write unmount whose contents did not change).
async function signIndexInPlace(vaultDir, { signPriv, vaultId }) {
	if (!signPriv || vaultId == null) return null;
	const idx = await readIndex(vaultDir);
	if (!idx || !idx.indexHash) return null;
	const existing = await readIndexSig(vaultDir); // idempotent: skip the write if already signed for this exact index
	if (existing && existing.indexHash === idx.indexHash && existing.vaultId === vaultId) return { signed: true, signedVersion: idx.version, already: true };
	await writeIndexSig(vaultDir, { vaultId, version: idx.version, indexHash: idx.indexHash }, signPriv);
	return { signed: true, signedVersion: idx.version };
}
// Clear leftover write-temp files in .recovery/ — the parity temp and the unique index temps (see
// writeJsonAtomic) that an interrupted run could strand. Only STALE temps are removed (older than the
// threshold): within one process, operations on a vault's .recovery are serialized so no live temp is
// ever swept, but a second OS process (a CLI run beside the service) might have a live temp in the same
// folder, and an age gate makes the sweep safe across processes too — a live temp is always fresh.
const TEMP_STALE_MS = 10 * 60 * 1000;
async function sweepRecoveryTemps(vaultDir) {
	const dir = recoveryDir(vaultDir);
	let names; try { names = await fsp.readdir(dir); } catch (_) { return; }
	const now = Date.now();
	for (const n of names) if (n.endsWith('.tmp')) {
		const p = path.join(dir, n);
		try { const st = await fsp.stat(p); if (now - st.mtimeMs >= TEMP_STALE_MS) await fsp.rm(p, { force: true }); } catch (_) {}
	}
}

// ── CRC32 (IEEE), table-based, pure JS — fast per-block corruption detection ───────────────────
const CRC_TABLE = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; }
	return t;
})();
function crc32(buf, len) {
	let c = 0xffffffff;
	const n = len == null ? buf.length : len;
	for (let i = 0; i < n; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

// ── enumerate the raw encrypted files under data/, in a stable order ───────────────────────────
// Lists the ciphertext blobs to protect. `exclude` is a set/array of encrypted relPaths to skip — the
// tool's own metadata blobs (the tamper snapshot, the session marker, the canary). Those change on
// their own schedule and are individually self-protecting or re-creatable, so covering them with the
// erasure parity would make a heal REVERT them to a stale version and break the tamper baseline.
async function listCipherFiles(cipherDir, exclude, tick) {
	const skip = exclude instanceof Set ? exclude : new Set(exclude || []);
	const out = [];
	async function walk(dir, rel) {
		let entries = [];
		try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { return; }
		entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)); // deterministic order
		for (const e of entries) {
			if (tick) tick(); // keep the worker idle-watchdog fed while enumerating a huge tree before the main loop starts
			const relPath = rel ? rel + '/' + e.name : e.name;
			if (e.isDirectory()) await walk(path.join(dir, e.name), relPath);
			// Exclude by BASENAME: the exclude list holds encrypted filename SEGMENTS (the vault's own metadata
			// files and fixed-name OS junk like .DS_Store), and rclone crypt encrypts each segment
			// deterministically, so one encrypted basename matches that file in EVERY folder. This keeps a
			// per-folder .DS_Store from making the vault look stale and rebuilding on every unmount.
			// Capture each file's metadata (mtime, mode, owner) alongside its size, so a heal can restore
			// it after a repair — even when the file was fully deleted and has to be recreated from parity.
			else if (e.isFile() && !skip.has(e.name)) { const st = await fsp.stat(path.join(dir, e.name)); out.push({ path: relPath, size: st.size, mtimeMs: st.mtimeMs, mode: st.mode, uid: st.uid, gid: st.gid }); }
		}
	}
	await walk(cipherDir, '');
	return out;
}

// The RS shape for D data blocks at redundancy r%: S stripes (each <= K_MAX data shards), a uniform
// per-stripe data count k (stripes shorter than k are zero-padded), and m parity shards per stripe.
function shapeFor(D, r) {
	const S = Math.max(1, Math.ceil(D / K_MAX));
	const k = Math.max(1, Math.ceil(D / S));
	let m = Math.max(1, Math.round(k * r / 100));
	if (k + m > 255) m = 255 - k;
	return { S, k, m };
}
// The global data-block index at a given stripe and slot (interleaving: block i -> stripe i mod S).
function stripeSlotToBlock(stripe, slot, S) { return slot * S + stripe; }

// Read `len` bytes at `offset` from a file into a full BLOCK_SIZE buffer (zero-padded past `len`, as the
// RS math and crc32(buf, len) both rely on), or null if the file is missing or too short (a lost block).
// A bounded pool of open READ handles so a multi-block file (and the single parity file) is opened ONCE and
// its blocks are read from the same handle, instead of re-opening per block. Block reads dominate protect /
// verify / heal, and re-opening per block is ~18x slower than reusing a handle — the single biggest speedup
// for a self-heal over many files, and it matters most on a slow or nearly-full disk where each open is
// costly. Reads are positional (pread with an explicit offset), so they never disturb a shared handle. The
// least-recently-used handle is closed when the pool is full (well under the OS descriptor limit), and
// closeAll() releases the rest when the operation ends.
function makeReadPool(cap = 96) {
	const map = new Map(); // absPath -> FileHandle; Map iteration order is insertion order → oldest first
	return {
		async open(absPath) {
			let fh = map.get(absPath);
			if (fh) { map.delete(absPath); map.set(absPath, fh); return fh; } // touch → most-recently-used
			fh = await fsp.open(absPath, 'r');
			map.set(absPath, fh);
			if (map.size > cap) { const oldest = map.keys().next().value; const old = map.get(oldest); map.delete(oldest); try { await old.close(); } catch (_) {} }
			return fh;
		},
		async closeAll() { for (const fh of map.values()) { try { await fh.close(); } catch (_) {} } map.clear(); }
	};
}

async function readBlock(absPath, offset, len, pool) {
	const buf = Buffer.alloc(BLOCK_SIZE);
	let fh = null, owned = false;
	try { if (pool) fh = await pool.open(absPath); else { fh = await fsp.open(absPath, 'r'); owned = true; } }
	catch (_) { return null; } // missing / unopenable -> treat as a lost block
	try {
		const { bytesRead } = await fh.read(buf, 0, len, offset);
		if (bytesRead < len) return null; // truncated/missing -> treat as a lost block
		return buf;
	} catch (_) { return null; }
	finally { if (owned) await fh.close().catch(() => {}); } // pooled handles are closed by closeAll()
}
// One data block (global index i): `flat[i]` gives its file + offset + real length. One parity block gp:
// fixed BLOCK_SIZE at its offset in the single parity file. Both are the same read, differing only in where.
async function readDataBlock(cipherDir, flat, i, pool) { const info = flat[i]; return readBlock(path.join(cipherDir, info.file), info.offset, info.len, pool); }
async function readParityBlock(vaultDir, gp, pool) { return readBlock(parityPath(vaultDir), gp * BLOCK_SIZE, BLOCK_SIZE, pool); }

// Build the flat block list (one entry per data block, in global order) from the file list.
function flattenBlocks(files) {
	const flat = [];
	for (const f of files) {
		const nBlocks = f.size === 0 ? 0 : Math.ceil(f.size / BLOCK_SIZE);
		for (let b = 0; b < nBlocks; b++) {
			const offset = b * BLOCK_SIZE;
			const len = Math.min(BLOCK_SIZE, f.size - offset);
			flat.push({ file: f.path, offset, len });
		}
	}
	return flat;
}

// A self-hash of the index for bit-rot detection (NOT authenticity — that is the separate signed sidecar).
// Plain JSON.stringify is deliberate and sufficient: the index is a fixed object we build with a stable key
// order, so a parse→stringify round-trip reproduces the same bytes; a canonical form would only add cost and
// would change every existing indexHash. (One latent note: mtimeMs is a float here; a future change to the
// engine's float-to-string formatting would recompute a different indexHash and read as bit-rot — fails safe.)
function hashIndex(index) {
	const copy = { ...index }; delete copy.indexHash;
	return Common.sha256Hex(JSON.stringify(copy)); // shared helper — same bytes as an inline sha256 hex digest
}

// A throttled progress reporter: calls onProgress({ percent, label }) when the whole-number percentage
// advances, so a huge vault never floods the channel with near-identical updates — AND at least every
// PROGRESS_HEARTBEAT_MS while it keeps being called, even at the same percent. The heartbeat matters
// because the worker's idle watchdog is fed by these messages: on a large vault over slow bulk storage,
// one percent can span far more than the watchdog window of steady reads, so a time-based tick (not just a
// percent change, whose granularity is coupled to vault size) keeps slow-but-working from looking wedged.
// A genuinely stuck read stops calling report() entirely, so the watchdog still fires on a real hang.
const PROGRESS_HEARTBEAT_MS = 15000;
function progressReporter(total, onProgress) {
	let last = -1, lastEmit = 0;
	return (done, label) => {
		if (!onProgress) return;
		const pct = total > 0 ? Math.min(99, Math.floor((done / total) * 100)) : 0;
		const now = Date.now();
		if (pct !== last || now - lastEmit >= PROGRESS_HEARTBEAT_MS) { last = pct; lastEmit = now; onProgress({ percent: pct, label }); }
	};
}

// A bare heartbeat for the PRE-loop scan phases (containment check, oversize scan). Those iterate every file
// BEFORE the main per-stripe report starts ticking, so on a very large vault they could go silent past the
// worker's idle watchdog and false-fail a perfectly healthy operation. Calling this each iteration keeps the
// watchdog fed (time-gated, so it costs nothing) without inventing a percentage for a pre-scan. No-op without
// an onProgress sink (e.g. a direct in-process call).
function heartbeat(onProgress, label) {
	let lastEmit = 0;
	return () => { if (!onProgress) return; const now = Date.now(); if (now - lastEmit >= PROGRESS_HEARTBEAT_MS) { lastEmit = now; onProgress({ percent: 0, label }); } };
}

// ── protect: (re)generate the recovery data for a vault ────────────────────────────────────────
// Bounded working memory: block CRCs are computed one block at a time, then parity is built one stripe
// at a time (each stripe re-reads only its own k blocks), so peak memory for the encode is a single
// stripe regardless of vault size. (The resulting index holds one small CRC record per block, so its
// own size scales with the vault's data.)
async function protectCore({ vaultDir, tier = 'medium', cipherDir, thorough = false, exclude }, onProgress) {
	const r = TIERS[tier] || TIERS.medium;
	const cdir = cipherOf(vaultDir, cipherDir);
	const files = await listCipherFiles(cdir, exclude, heartbeat(onProgress, 'Scanning files'));
	const flat = flattenBlocks(files);
	const D = flat.length;
	if (D === 0) throw new Error('The vault has no data to protect yet.');
	const { S, k, m } = shapeFor(D, r);
	const rs = RS.codec(k, m);
	const report = progressReporter(D, onProgress); // ONE pass: each data block is read once, then both CRC'd and RS-encoded
	let ops = 0;
	const pool = makeReadPool(); // reuse open handles across a file's blocks
	const parityCrcs = [];
	const fileBlocks = new Map(files.map(f => [f.path, []]));
	const blockCrc = new Array(D); // { crc, len } per global block index; assembled into per-file lists (file order) after the pass
	let parityTmp; // the temp parity file, renamed into place after the encode (below the pool scope)
	try {
		// Single pass: read each data block ONCE and use that same read for BOTH its CRC and its RS-encode. The old
		// code read the whole vault twice — once for CRCs in file order, once for the encode in stripe order —
		// doubling the disk I/O, which dominates on a large or slow-drive vault. The stripe walk covers every data
		// block gi < D exactly once (gi = slot*S + stripe is a bijection over [0, k*S), and D <= k*S), so each
		// block's CRC is taken here keyed by gi; the per-file block lists, which need file order, are assembled from
		// blockCrc[] afterward — flat[] is file-ordered, so pushing in ascending gi order reproduces the old output.
		await fsp.mkdir(recoveryDir(vaultDir), { recursive: true });
		await sweepRecoveryTemps(vaultDir); // clear any leftovers (parity + index temps) from an interrupted run
		// A per-run unique temp name so a second OS process protecting the same vault never collides on it.
		parityTmp = Common.uniqueTempPath(parityPath(vaultDir));
		const parityFh = await fsp.open(parityTmp, 'w');
		try {
			for (let s = 0; s < S; s++) {
				const shards = new Array(k);
				for (let slot = 0; slot < k; slot++) {
					const gi = stripeSlotToBlock(s, slot, S);
					if (gi < D) {
						const b = await readDataBlock(cdir, flat, gi, pool);
						if (!b) throw new Error('Could not read the vault data to protect it (a file may be open or unreadable).');
						shards[slot] = b;
						blockCrc[gi] = { crc: crc32(b, flat[gi].len), len: flat[gi].len }; // CRC from the same read the encode uses
						report(++ops, 'Building recovery data');
					} else shards[slot] = Buffer.alloc(BLOCK_SIZE); // zero-pad short stripes
				}
				const parity = rs.encode(shards);
				for (let p = 0; p < m; p++) {
					await parityFh.write(parity[p], 0, BLOCK_SIZE, (s * m + p) * BLOCK_SIZE);
					parityCrcs.push(crc32(parity[p]));
				}
			}
		} finally { try { await parityFh.sync(); } catch (e) { try { Common.warn('Recovery parity could not be flushed to disk durably (' + (e && e.message || e) + '); it is still rebuildable from the fsync-durable index and the vault data.'); } catch (_) {} } await parityFh.close(); } // flush the parity to disk before it is renamed into place, so a power loss can't leave torn parity
		// Assemble the per-file block CRC lists in FILE order (flat[] is file-ordered), matching the old first pass.
		for (let gi = 0; gi < D; gi++) fileBlocks.get(flat[gi].file).push(blockCrc[gi]);
	} finally { await pool.closeAll(); }

	// A monotonic version so a signature over an OLD index can never be replayed as the current one — the
	// signed payload binds it (see sigMessage). It steps past any prior index's version; if the prior index is
	// unreadable it restarts at 1, and the local "signed as of vN" note (kept outside the vault) still guards
	// against a rollback to a lower version.
	let priorVersion = 0;
	// Refuse to rebuild OVER a newer-format recovery index rather than silently overwriting it and resetting the
	// monotonic version to 1 — the same fail-closed stance the read/verify/heal paths take. Any other read error
	// (a genuinely absent or corrupt index) is fine to rebuild past.
	try { const prev = await readIndex(vaultDir); if (prev && Number.isInteger(prev.version)) priorVersion = prev.version; }
	catch (e) { if (e && e.code === 'RECOVERY_NEWER') throw e; }
	const index = {
		schemaVersion: RECOVERY_SCHEMA, tool: Brand.slug, createdAt: new Date().toISOString(), version: priorVersion + 1,
		tier, redundancyPercent: r, blockSize: BLOCK_SIZE, rs: { k, m }, stripes: S, dataBlocks: D,
		platform: process.platform, // OS that captured the per-file mode/owner below; a heal only restores those in place
		thorough: !!thorough, // when set, staleness re-checks block contents (catches same-size in-place edits)
		exclude: Array.isArray(exclude) ? exclude : [...(exclude || [])], // encrypted blobs left out of the parity (tool metadata) — used by the staleness check to compare the same file set
		// path + size is the cheap fingerprint used later to tell whether the vault's contents changed
		// since this recovery data was built (so it can be refreshed automatically). Modification time
		// is deliberately NOT used FOR STALENESS: the vault's own tamper baseline rewrites a small metadata
		// file on every unmount, which would bump mtimes and trigger endless needless refreshes; the
		// encrypted size of that file is stable, so comparing the set and sizes ignores that housekeeping.
		// The mtime/mode/owner captured here are stored only so a heal can RESTORE a repaired file's
		// original metadata — vital when a file was deleted outright and has to be recreated from parity,
		// since there is then no surviving copy on disk to read the original metadata from.
		files: files.map(f => ({ path: f.path, size: f.size, blocks: fileBlocks.get(f.path), mtimeMs: f.mtimeMs, mode: f.mode, uid: f.uid, gid: f.gid })),
		parityCrcs
	};
	index.indexHash = hashIndex(index);
	// Replicated critical index. A heartbeat before each write keeps the worker's idle watchdog fed while a
	// large index is being written (the one phase between the last per-block progress and completion).
	for (const p of indexPaths(vaultDir)) { if (onProgress) onProgress({ percent: 99, label: 'Saving recovery index' }); await Common.writeJsonAtomic(p, index, { fsync: true }); } // durable before the parity is published, so the index-before-parity ordering below holds across a power loss
	// Publish the new parity ONLY after the index that describes it is on disk. If the process dies in this
	// window, the survivor is new-index + old-parity, which verify reports as parity-only damage and heal
	// rebuilds from the intact data on the next run — instead of new-parity + old-index, which would look
	// like every changed stripe is unrecoverably damaged (a false alarm). The leftover .tmp is swept next run.
	await Common.renameWithRetry(parityTmp, parityPath(vaultDir)); // retry a transient Windows lock (antivirus/indexer) instead of failing the publish
	if (onProgress) onProgress({ percent: 100, label: 'Done' });
	return { vault: path.resolve(vaultDir), tier, redundancyPercent: r, dataBlocks: D, parityBlocks: S * m, stripes: S, indexHash: index.indexHash, version: index.version };
}

// Read the recovery index, trying each replica; verifies each copy's self-integrity hash so a
// corrupt index copy is skipped in favor of an intact one.
async function readIndex(vaultDir) {
	let found = null;
	for (const p of indexPaths(vaultDir)) {
		try {
			const idx = JSON.parse(await Common.readFileCapped(p, MAX_RECOVERY_INDEX_BYTES, 'utf8'));
			if (idx && idx.indexHash && idx.indexHash === hashIndex(idx)) { found = idx; break; }
		} catch (_) {}
	}
	// Fail closed on a format this build does not understand rather than misreading an unknown layout. Coerce and
	// integer-check the version (matching the manifest/sidecar readers) so a non-numeric schemaVersion cannot slip
	// the guard via loose comparison. The error is tagged so a rebuild can refuse to overwrite a newer index.
	if (found) {
		const sv = Number(found.schemaVersion);
		if (!Number.isInteger(sv) || sv > RECOVERY_SCHEMA) {
			const e = new Error('This vault\'s recovery data was created by a newer version of ' + Brand.name + ' (recovery format v' + found.schemaVersion + '; this build understands v' + RECOVERY_SCHEMA + '). Update ' + Brand.name + ' to check or repair it.');
			e.code = 'RECOVERY_NEWER';
			throw e;
		}
	}
	// SECURITY: the recovery index travels INSIDE a shareable vault, so its file paths are UNTRUSTED — the
	// indexHash is only an unkeyed bit-rot check, NOT authenticity. Every path must be a plain relative path
	// that stays within the cipher directory; reject an absolute path, a Windows drive path, or one with a
	// '..' segment. Without this, a crafted index could steer heal's block writes, file/directory creation,
	// truncation, and chown/chmod/utimes to an arbitrary path OUTSIDE the vault — a no-password arbitrary
	// file write (heal needs no password), which for a shared/synced vault is effectively code execution.
	if (found && Array.isArray(found.files)) {
		for (const f of found.files) {
			const rel = f && f.path;
			if (typeof rel !== 'string' || path.posix.isAbsolute(rel) || path.win32.isAbsolute(rel) || rel.split(/[\\/]/).some(seg => seg === '..')) {
				throw new Error('The recovery data references an unsafe file path and was refused — the vault\'s recovery folder may have been tampered with.');
			}
		}
	}
	// SECURITY: validate the numeric SHAPE too — same untrusted-index reasoning. A crafted `stripes`/`rs`/
	// `blockSize` would otherwise drive huge allocations, an effectively-infinite loop, and unbounded parity
	// writes in verify/heal (an unauthenticated DoS / disk-exhaustion on a shared vault). The whole geometry
	// is DETERMINED by the data-block count and the redundancy, so recompute the canonical shape and require
	// the stored values to match exactly. The block count is itself bounded by the size of the shipped index.
	if (found) {
		const files = Array.isArray(found.files) ? found.files : [];
		let D = 0, wellFormed = files.length > 0;
		for (const f of files) {
			if (!f || !Array.isArray(f.blocks)) { wellFormed = false; break; }
			// Validate every block record too: heal writes exactly `len` bytes of a reconstructed block back at
			// its offset, so a crafted len (negative, non-integer, or larger than a block) could otherwise steer
			// a wrong-length write. `len` must be within one block; `crc` must be a plain integer.
			let fileBytes = 0;
			const nb = f.blocks.length;
			for (let bi = 0; bi < nb; bi++) {
				const b = f.blocks[bi];
				// Every block is a fixed 64 KiB chunk except the LAST, which holds the 1..BLOCK_SIZE-byte remainder
				// (an empty file has no blocks). Enforcing this — no zero-length or undersized interior blocks —
				// pins the block COUNT to ceil(size / BLOCK_SIZE), so a crafted index can't declare millions of tiny
				// blocks to drive verify/heal into an effectively unbounded loop while progress keeps the worker
				// watchdog from tripping. The existing f.size === sum(len) check then bounds the whole geometry.
				const minLen = bi === nb - 1 ? 1 : BLOCK_SIZE;
				if (!b || !Number.isInteger(b.len) || b.len < minLen || b.len > BLOCK_SIZE || !Number.isInteger(b.crc)) { wellFormed = false; break; }
				fileBytes += b.len;
			}
			if (!wellFormed) break;
			// Validate the recorded blob SIZE against the block lengths. heal truncates a blob whose on-disk size
			// exceeds f.size (see oversizeBlobs), so a crafted, unvalidated f.size in a shared/synced vault's index
			// could truncate a perfectly healthy blob down to a bogus length — data destruction that heal performs
			// with no password. The blocks partition the file exactly, so f.size MUST equal the sum of block lengths.
			if (!Number.isInteger(f.size) || f.size < 0 || f.size !== fileBytes) { wellFormed = false; break; }
			// SANITIZE the untrusted metadata that heal restores onto ciphertext blobs (chmod/chown/utimes): a
			// crafted mode/uid/gid must not be applied. Keep only in-range non-negative integers (mode masked to
			// the permission bits); drop anything else so the restore simply skips it.
			f.mode = Number.isInteger(f.mode) && f.mode >= 0 ? (f.mode & 0o7777) : undefined;
			f.uid = Number.isInteger(f.uid) && f.uid >= 0 ? f.uid : undefined;
			f.gid = Number.isInteger(f.gid) && f.gid >= 0 ? f.gid : undefined;
			f.mtimeMs = typeof f.mtimeMs === 'number' && isFinite(f.mtimeMs) && f.mtimeMs >= 0 ? f.mtimeMs : undefined;
			D += f.blocks.length;
		}
		const rs = found.rs || {}, rp = found.redundancyPercent;
		let ok = wellFormed && D >= 1 && found.blockSize === BLOCK_SIZE
			&& Number.isInteger(rp) && rp >= 1 && rp <= 90
			&& Number.isInteger(rs.k) && Number.isInteger(rs.m) && Number.isInteger(found.stripes)
			&& Array.isArray(found.parityCrcs) && found.parityCrcs.every(c => Number.isInteger(c));
		if (ok) {
			const canon = shapeFor(D, rp);
			ok = canon.S === found.stripes && canon.k === rs.k && canon.m === rs.m && found.parityCrcs.length === found.stripes * rs.m;
		}
		if (!ok) throw new Error('The recovery data has an invalid or inconsistent structure and was refused — the vault\'s recovery folder may have been tampered with.');
	}
	return found;
}

// Lightweight status for the UI's frequent polling: just the tier/counts/flags a status badge needs,
// WITHOUT re-parsing and re-hashing the whole (per-block-CRC-laden) index on every poll — which would
// stall the event loop for a large vault. Cached per vault and keyed on the primary index file's stat:
// writeJsonAtomic changes both mtime and size on every rewrite, and protect/heal/unprotect all rewrite or
// remove the index, so the cache refreshes exactly when the index changes and is otherwise a cheap stat.
const metaCache = new Map(); // primary index path -> { mtimeMs, size, meta }
async function readIndexMeta(vaultDir) {
	const primary = indexPaths(vaultDir)[0];
	let st = null; try { st = await fsp.stat(primary); } catch (_) {}
	if (st) { const c = metaCache.get(primary); if (c && c.mtimeMs === st.mtimeMs && c.size === st.size) return c.meta; }
	else metaCache.delete(primary); // primary index gone (unprotected, removed, or the vault deleted) — drop the stale cache entry so this map can't grow one dead entry per distinct vault path over the life of the service (readIndex below still checks the backup replicas)
	// Full read + hash-verify only when the index actually changed. Route it through the recovery worker (dispatch is a
	// no-op wrapper when already inside the worker), so a large per-block-CRC index is parsed and SHA-256'd OFF the
	// event loop — the poll that calls this must never freeze the loop, matching how heal reads its index meta.
	const m = await dispatch('indexmeta', { vaultDir });
	const meta = (m && m.protected)
		? { protected: true, tier: m.tier, redundancyPercent: m.redundancyPercent, createdAt: m.createdAt, dataBlocks: m.dataBlocks, thorough: !!m.thorough }
		: { protected: false };
	if (st) metaCache.set(primary, { mtimeMs: st.mtimeMs, size: st.size, meta });
	return meta;
}

// A boolean probe: recovery data that exists but is too new to read still counts as present. Routed through
// readIndexMeta so it uses the stat-keyed cache instead of re-parsing and re-hashing the whole (possibly
// multi-MB) index on every call — the full parse runs only when the index has actually changed.
async function hasRecovery(vaultDir) { try { return (await readIndexMeta(vaultDir)).protected; } catch (_) { return true; } }

// Rebuild the flat block list from a stored index (its file order is authoritative).
function flattenFromIndex(index) {
	const flat = [];
	for (const f of index.files) {
		let off = 0;
		for (const b of f.blocks) { flat.push({ file: f.path, offset: off, len: b.len, crc: b.crc }); off += index.blockSize; }
	}
	return flat;
}

// Blobs grown LARGER than their recorded ciphertext carry trailing bytes the block-CRC pass cannot see
// (it only reads each block's recorded length). One detector, so verify (which counts them) and heal
// (which truncates them) always agree on the same damage. Compares the live size to the RECORDED size,
// which is why it can't reuse listCipherFiles (that reports current on-disk sizes). Returns the index
// entries that are over-long; a missing/unreadable file is skipped (its loss is a block-level erasure).
async function oversizeBlobs(cipherDir, files, tick) {
	const out = [];
	for (const f of files) {
		if (tick) tick(); // keep the worker idle-watchdog fed on a very large vault (time-gated no-op otherwise)
		if (f.size == null) continue;
		let st; try { st = await fsp.stat(path.join(cipherDir, f.path)); } catch (_) { continue; }
		if (st.size > f.size) out.push(f);
	}
	return out;
}

// SECURITY (symlink containment): readIndex rejects '..'/absolute path STRINGS, but a hostile vault can also
// ship a SYMLINK inside data/ (e.g. data/x -> /outside) plus a '..'-free relative path that follows it OUT of
// the vault at write time. Resolve each indexed file's REAL location (following any symlink in its existing
// ancestry) and require it to stay physically within the real cipher dir; throw on any escape. This is the
// Node equivalent of the realpath / *at-syscall containment that established encrypting filesystems use
// against exactly this attack. A legitimate cipher dir has no symlinks (listCipherFiles records only files).
async function assertContained(cipherDir, files, tick) {
	let realRoot; try { realRoot = await fsp.realpath(cipherDir); } catch (_) { realRoot = path.resolve(cipherDir); }
	for (const f of (files || [])) {
		if (tick) tick(); // keep the worker idle-watchdog fed while realpath-checking every file on a huge vault
		const resolved = await Common.resolveThroughSymlinks(path.resolve(cipherDir, f.path));
		if (resolved === null || (resolved !== realRoot && !Common.pathWithin(resolved, realRoot))) {
			throw new Error('The recovery data references a file that resolves outside the vault (a symlink in the vault folder) and was refused.');
		}
	}
}

// ── verify: report which blocks are intact / damaged, and whether each stripe is still repairable ─
async function verifyCore({ vaultDir, cipherDir }, onProgress) {
	const index = await readIndex(vaultDir);
	if (!index) return { protected: false };
	const cdir = cipherOf(vaultDir, cipherDir);
	await assertContained(cdir, index.files, heartbeat(onProgress, 'Checking vault safety')); // refuse a hostile vault that symlinks a blob path out of the vault
	const flat = flattenFromIndex(index);
	const { m } = index.rs, S = index.stripes, D = flat.length; // verify does no reconstruction, so k is unused
	const stripeLoss = new Array(S).fill(0);
	const damagedFiles = new Set();
	let damagedData = 0, damagedParity = 0;
	const report = progressReporter(D + S * m, onProgress);
	let ops = 0;
	const pool = makeReadPool(); // reuse open handles across each file's blocks (data reads are file-sequential)
	try {
		for (let i = 0; i < D; i++) {
			const buf = await readDataBlock(cdir, flat, i, pool);
			const good = buf && crc32(buf, flat[i].len) === flat[i].crc;
			if (!good) { damagedData++; stripeLoss[i % S]++; damagedFiles.add(flat[i].file); }
			report(++ops, 'Checking files');
		}
		for (let s = 0; s < S; s++) {
			for (let p = 0; p < m; p++) {
				const gp = s * m + p;
				const buf = await readParityBlock(vaultDir, gp, pool);
				const good = buf && crc32(buf) === index.parityCrcs[gp];
				if (!good) { damagedParity++; stripeLoss[s]++; }
				report(++ops, 'Checking files');
			}
		}
	} finally { await pool.closeAll(); }
	let unrecoverableStripes = 0, repairableStripes = 0;
	for (let s = 0; s < S; s++) { if (stripeLoss[s] === 0) continue; if (stripeLoss[s] <= m) repairableStripes++; else unrecoverableStripes++; }
	// A blob LARGER than its recorded ciphertext has trailing bytes the parity does not cover — the block
	// CRC pass above cannot see them. Catch that by size (shared detector with heal) so verify agrees with
	// a heal, which trims them back, and with the tamper check, which flags the size change.
	const over = await oversizeBlobs(cdir, index.files, heartbeat(onProgress, 'Checking file sizes'));
	const oversizeFiles = over.length;
	for (const f of over) damagedFiles.add(f.path);
	const clean = damagedData === 0 && damagedParity === 0 && oversizeFiles === 0;
	// No terminal 100% here on purpose: a check is always followed by either the repair phase (which
	// continues the same bar) or the result, so ending it at "Done" would flash prematurely.
	return {
		protected: true, tier: index.tier, redundancyPercent: index.redundancyPercent, clean,
		damagedData, damagedParity, oversizeFiles, damagedFiles: [...damagedFiles],
		repairableStripes, unrecoverableStripes, perStripeBudget: m,
		fullyRecoverable: unrecoverableStripes === 0,
		indexHash: index.indexHash, version: index.version // for the authenticity check in the wrapper
	};
}

// ── heal: reconstruct damaged blocks from parity and write them back ──────────────────────────
async function healCore({ vaultDir, cipherDir, expectIndexHash, force }, onProgress) {
	const index = await readIndex(vaultDir);
	if (!index) return { protected: false };
	// Bind the repair to the index the caller's authenticity gate approved: if the on-disk index changed
	// underneath us (a concurrent cross-process writer swapping it between the gate and here), abort rather than
	// repair from an index that was never checked. The caller can re-run once the vault settles.
	if (expectIndexHash && index.indexHash !== expectIndexHash) throw new Error('The recovery index changed while a repair was starting — nothing was written. Make sure nothing else is touching this vault, then run the repair again.');
	const cdir = cipherOf(vaultDir, cipherDir);
	await assertContained(cdir, index.files, heartbeat(onProgress, 'Checking vault safety')); // refuse a hostile vault that symlinks a blob path out of the vault
	const flat = flattenFromIndex(index);
	const { k, m } = index.rs, S = index.stripes, D = flat.length;
	const rs = RS.codec(k, m);
	// Drive progress over TOTAL blocks (not just stripes) and tick per block, matching verifyCore: a single
	// stripe reads k+m blocks and, if damaged, writes some back, so on slow storage one stripe can exceed the
	// worker idle-watchdog window — ticking per block keeps the watchdog fed so a healthy-but-slow heal is
	// never false-killed.
	const report = progressReporter(S * (k + m), onProgress);
	let blkOps = 0;

	// Which blocks in each stripe are present/damaged (data slots 0..k-1, parity slots k..k+m-1).
	// writeErrors counts blocks that were successfully RECONSTRUCTED but could not be written back (a
	// permission/space/lock failure) — those stay damaged, but one bad blob must never abort the whole heal.
	let repairedData = 0, repairedParity = 0, unrecoverableStripes = 0, writeErrors = 0;
	// The set of encrypted files that had at least one data block rewritten. Recovery works over the
	// ciphertext and cannot name the plaintext files inside, but reporting the encrypted file paths (and
	// their count) still tells the user how localized the damage was and which blobs were touched.
	const repairedFiles = new Set();
	// The index snapshot taken at protect time is the authoritative record of each file's original metadata
	// (size, mtime, mode, owner); the metadata-restore pass below reads it straight from index.files. It is
	// the only way to recover the metadata of a file deleted outright, since no surviving copy remains.

	// DATA SAFETY: a user EDIT and silent bit-rot both surface as a block that no longer matches the protect-time
	// index — but they are opposites. Bit-rot is damage to repair; an edit is new data to preserve. Reconstructing
	// an edited file's block from the stale parity would REVERT the edit, and trimming a file the user grew would
	// DELETE appended data — both silent losses. Distinguish them the same way the staleness check does: by SIZE.
	// Silent decay flips bytes in place and leaves a file's length unchanged, while the common edits (adding,
	// removing, appending, rewriting to a new length) change it — so a file whose current size differs from the
	// index was written since protect and is left exactly as it is, and reported so the user can update protection.
	// (A false "edited" reading only ever SKIPS a repair — it can never revert or truncate — so it fails safe.)
	// mtime is deliberately not used: the tamper baseline and cloud/mount housekeeping rewrite blobs and bump
	// mtimes without changing content, so it is not a reliable "written" signal here (see isStale). The one
	// residual gap — a same-length in-place edit — matches the staleness check's own documented limit and is
	// resolved by updating protection.
	const idxByFile = new Map((index.files || []).map(f => [f.path, f]));
	const editedFiles = new Set();       // files left untouched because they were written since protect
	const editCache = new Map();
	async function editedSinceProtect(encPath) {
		if (editCache.has(encPath)) return editCache.get(encPath);
		const meta = idxByFile.get(encPath); let edited = false;
		if (meta) {
			try { edited = (await fsp.stat(path.join(cdir, encPath))).size !== meta.size; } // a changed length means the file was written since protect
			catch (_) { edited = false; } // missing/unreadable is a LOSS to restore, not an edit — let heal rebuild it
		}
		editCache.set(encPath, edited); return edited;
	}

	// Open a ciphertext blob to write a reconstructed block into it. 'r+' handles an existing blob (an
	// in-place bit-rot rewrite). If it is gone — a deleted file, or a file whose parent directory was also
	// removed — recreate the directory tree and the file; every one of its blocks then reads as an erasure
	// and is written into the fresh file, fully rebuilding it from parity.
	async function openForRepair(abs) {
		return fsp.open(abs, 'r+').catch(async (e) => {
			// Only a genuinely MISSING blob (deleted file / vanished dir) should be recreated. Any OTHER r+
			// failure — a permission or lock error on a blob that DOES exist — must NOT fall through to 'w',
			// which would truncate the existing blob and throw away its still-healthy blocks. Rethrow so the
			// caller counts a write error and leaves the file intact.
			if (e && e.code !== 'ENOENT') throw e;
			await fsp.mkdir(path.dirname(abs), { recursive: true });
			return fsp.open(abs, 'w');
		});
	}

	// The parity file itself may have been deleted or truncated; ensure it exists so per-stripe repairs can
	// write reconstructed parity blocks back into it. Missing parity is just another erasure — every stripe
	// finds its parity slots absent and rebuilds them from the surviving data blocks.
	await fsp.mkdir(recoveryDir(vaultDir), { recursive: true }).catch(() => {});
	try { await fsp.access(parityPath(vaultDir)); } catch (_) { try { const fh = await fsp.open(parityPath(vaultDir), 'w'); await fh.close(); } catch (_) {} } // if it can't be created, the per-stripe parity writes below just fail and are counted

	const pool = makeReadPool(); // reuse open handles across a file's blocks during the repair scan
	try {
	for (let s = 0; s < S; s++) {
		const shards = new Array(k + m).fill(null);
		const present = new Array(k + m).fill(false);
		const dataGlobal = new Array(k).fill(-1); // slot -> global data index (or -1 for zero-pad)
		let loss = 0;
		// data slots
		for (let slot = 0; slot < k; slot++) {
			report(++blkOps, 'Repairing'); // per-block tick (feeds the idle watchdog and shows steady progress)
			const gi = stripeSlotToBlock(s, slot, S);
			if (gi >= D) { shards[slot] = Buffer.alloc(BLOCK_SIZE); present[slot] = true; continue; } // virtual zero
			dataGlobal[slot] = gi;
			const buf = await readDataBlock(cdir, flat, gi, pool);
			if (buf && crc32(buf, flat[gi].len) === flat[gi].crc) { shards[slot] = buf; present[slot] = true; }
			else loss++;
		}
		// parity slots
		for (let p = 0; p < m; p++) {
			report(++blkOps, 'Repairing'); // per-block tick
			const gp = s * m + p;
			const buf = await readParityBlock(vaultDir, gp, pool);
			if (buf && crc32(buf) === index.parityCrcs[gp]) { shards[k + p] = buf; present[k + p] = true; }
			else loss++;
		}
		if (loss === 0) continue;
		if (loss > m) { unrecoverableStripes++; continue; } // beyond this stripe's repair budget

		rs.reconstruct(shards, present);

		// Write back any repaired data blocks (only their real bytes) and parity blocks.
		for (let slot = 0; slot < k; slot++) {
			report(blkOps, 'Repairing'); // heartbeat during a damaged stripe's re-read + write-back
			const gi = dataGlobal[slot];
			if (gi < 0) continue;
			const good = shards[slot];
			// Re-read to see if this slot was actually damaged (avoid needless writes).
			const cur = await readDataBlock(cdir, flat, gi, pool);
			if (cur && crc32(cur, flat[gi].len) === flat[gi].crc) continue;
			// Written since protect -> new data, never revert. This must NOT be gated on `cur`: when the user TRIMMED
			// the file, its tail block now reads short and readDataBlock returns null (cur === null), so a `cur &&`
			// guard here would skip this check and rebuild the removed block from stale parity — re-growing the file
			// and resurrecting the deleted data. editedSinceProtect is size-based and fails safe: a file that still
			// exists at a different size is left alone (edit/trim preserved), while a genuinely deleted file (stat
			// fails -> false) still gets rebuilt from parity. This mirrors the grow/oversize path below.
			if (!force && await editedSinceProtect(flat[gi].file)) { editedFiles.add(flat[gi].file); continue; }
			// Verify the RECONSTRUCTED block reproduces its own recorded CRC before overwriting the file. Survivors were
			// admitted into the solve on a CRC32 match, which has a tiny false-positive rate; a poisoned survivor sharing
			// this stripe with a real loss would make the linear solve produce WRONG bytes. If the result does not match
			// the recorded CRC, leave the block as unresolved damage (a later verify surfaces it honestly) rather than
			// writing wrong bytes and certifying them as a clean repair — never corrupt good data during a repair.
			if (crc32(good, flat[gi].len) !== flat[gi].crc) { writeErrors++; continue; }
			let fh;
			// A single blob that can't be written (permissions, no space, a Windows lock) must not abort the
			// whole heal — count it and press on so every other repairable stripe is still fixed.
			try { fh = await openForRepair(path.join(cdir, flat[gi].file)); await fh.write(good, 0, flat[gi].len, flat[gi].offset); repairedData++; repairedFiles.add(flat[gi].file); }
			catch (_) { writeErrors++; }
			finally { if (fh) await fh.close().catch(() => {}); }
		}
		for (let p = 0; p < m; p++) {
			report(blkOps, 'Repairing'); // heartbeat during parity write-back
			const gp = s * m + p;
			const cur = await readParityBlock(vaultDir, gp, pool);
			if (cur && crc32(cur) === index.parityCrcs[gp]) continue;
			// Verify the RECONSTRUCTED parity block reproduces its recorded CRC before overwriting — the same defense
			// the data write-back applies above. A poisoned survivor sharing this stripe with a real loss could make
			// the solve produce wrong bytes; leave a mismatch as unresolved damage (a later verify re-flags it) rather
			// than write it and certify a clean repair for a block we cannot vouch for.
			if (crc32(shards[k + p]) !== index.parityCrcs[gp]) { writeErrors++; continue; }
			let fh;
			try { fh = await fsp.open(parityPath(vaultDir), 'r+'); await fh.write(shards[k + p], 0, BLOCK_SIZE, gp * BLOCK_SIZE); repairedParity++; }
			catch (_) { writeErrors++; }
			finally { if (fh) await fh.close().catch(() => {}); }
		}
	}
	} finally { await pool.closeAll(); }
	// A blob that grew LARGER than its recorded ciphertext has trailing bytes the parity does not cover
	// and that are not part of the real data (a stray write extended the file, filesystem corruption merged
	// two files, etc.). The block-CRC pass above cannot see bytes past the last real block, so detect these
	// by size (shared detector with verify) and truncate them back. It makes "the file got longer" a
	// recovered case too. Cheap next to the block reads heal already does.
	let repairedSize = 0;
	for (const f of await oversizeBlobs(cdir, index.files, heartbeat(onProgress, 'Checking file sizes'))) {
		if (!force && await editedSinceProtect(f.path)) { editedFiles.add(f.path); continue; } // the user grew this file — never truncate away appended data
		try { await fsp.truncate(path.join(cdir, f.path), f.size); repairedFiles.add(f.path); repairedSize++; } catch (_) { writeErrors++; }
	}
	// Restore the metadata of every file this heal actually repaired (a block rewritten, a blob recreated,
	// or an over-long blob trimmed) back to the index snapshot, so a repair leaves no trace on the file. It
	// is deliberately scoped to repairedFiles, NOT every file: a repair always changes the mod-time (a
	// rewrite bumps it; recreating a deleted file stamps it "now"), so restoring is both necessary and
	// unconditional for these — while a file the repair never touched must be left alone, since the staleness
	// check ignores mtime by design (so the index's stored mtime is intentionally stale for edited files, and
	// reverting a healthy file's newer mod-time to it would be a surprising, wrong mutation). Owner and
	// permissions are OS-specific and restored only when healing on the same platform that captured them
	// (applying a Windows-captured 0o666 as a POSIX mode would make the encrypted blob world-writable; a
	// Windows uid/gid of 0 would chown it to root) — a missing/unknown platform is treated as foreign and
	// skipped. The modification time is portable and always restored — it is the one the encryption engine
	// surfaces on the mounted drive. Order matters: chown BEFORE chmod (chown can clear setuid/setgid),
	// utimes LAST so nothing re-stamps the mod-time.
	const isWin = process.platform === 'win32';
	const samePlatform = index.platform != null && index.platform === process.platform;
	for (const f of index.files) {
		if (!repairedFiles.has(f.path)) continue;
		const p = path.join(cdir, f.path);
		if (samePlatform && !isWin && f.uid != null && f.gid != null) { try { await fsp.chown(p, f.uid, f.gid); } catch (_) {} }
		if (samePlatform && f.mode != null) { try { await fsp.chmod(p, f.mode); } catch (_) {} }
		if (f.mtimeMs != null) { const t = new Date(f.mtimeMs); try { await fsp.utimes(p, t, t); } catch (_) {} }
	}
	if (onProgress) onProgress({ percent: 100, label: 'Done' });
	return { protected: true, repairedData, repairedParity, repairedSize, writeErrors, unrecoverableStripes, healed: repairedData + repairedParity + repairedSize, repairedFiles: [...repairedFiles], changedSkipped: editedFiles.size, indexHash: index.indexHash, version: index.version };
}

// Remove a vault's recovery data (e.g. before regenerating from scratch, or on user request). Serialized
// on the same per-vault queue as protect/verify/heal so it can't race a background refresh mid-write —
// which could otherwise recreate .recovery/ (writeJsonAtomic re-mkdirs it) right after this removes it,
// resurrecting protection the user just removed or leaving the folder half-written.
async function removeRecovery(vaultDir) {
	const abs = path.resolve(vaultDir);
	return serialize(abs, async () => { try { await fsp.rm(recoveryDir(abs), { recursive: true, force: true }); } catch (_) {} });
}

// ── staleness: has the vault's ciphertext changed since its recovery data was built? ───────────
// A cheap check — it stats the cipher files and compares the set and sizes to the fingerprint stored
// in the index (no block reads). Returns true when a refresh is warranted. Modification time is
// intentionally not compared (see the note where the fingerprint is written): it would flip to stale
// on every unmount because of the tamper baseline's housekeeping. The trade-off is that an in-place
// edit that keeps a file's exact byte length is not auto-detected (rare — most edits add, remove, or
// resize files); such a vault can still be refreshed by hand with a protect.
async function isStale(vaultDir, { cipherDir, deep = false, onProgress } = {}) {
	let index;
	try { index = await readIndex(vaultDir); } catch (_) { return false; } // unreadable/newer format: not ours to refresh
	if (!index) return false; // not protected -> nothing to refresh
	const cdir = cipherOf(vaultDir, cipherDir);
	const now = await listCipherFiles(cdir, index.exclude, heartbeat(onProgress, 'Scanning files')); // same exclusion the parity was built with
	if (now.length !== index.files.length) return true;
	const prev = new Map(index.files.map(f => [f.path, f.size]));
	for (const f of now) {
		if (!prev.has(f.path)) return true;
		if (prev.get(f.path) !== f.size) return true;
	}
	if (!deep) return false; // cheap default: same set of files, same sizes -> up to date
	await assertContained(cdir, index.files, heartbeat(onProgress, 'Checking vault safety')); // the deep path READS blocks via the indexed paths — same containment
	// Thorough (opt-in): a same-size in-place edit changes a block's content but not the file's length,
	// so re-read each data block and compare its CRC to the one recorded at protect time. This reads the
	// whole vault, so it runs only inside the worker (via the 'stale' core) and never on the event loop.
	const flat = flattenFromIndex(index);
	const report = progressReporter(flat.length, onProgress); // also feeds the worker's idle watchdog
	const pool = makeReadPool(); // reuse open handles across each file's blocks (reads are file-sequential)
	try {
		for (let i = 0; i < flat.length; i++) {
			const buf = await readDataBlock(cdir, flat, i, pool);
			if (!buf || crc32(buf, flat[i].len) !== flat[i].crc) return true;
			report(i + 1, 'Checking for changes');
		}
		return false;
	} finally { await pool.closeAll(); }
}
// DATA SAFETY: is any file the recovery index PROTECTS now MISSING from the vault? This is the signal of LOSS
// (a deleted / moved-out file, or corruption that removed a blob) as opposed to a benign change (a file added
// or edited). The auto-refresh MUST consult this before it rebuilds: re-protecting over a loss would bake the
// missing file into the new parity and permanently destroy heal's ability to restore it. Returns the count of
// missing protected files (0 = nothing lost, safe to refresh).
// Does any recovery index replica exist on disk? A stat-only existence probe (no parse), used to tell a vault
// that HAS recovery data (whose index merely won't read) apart from one that was never protected.
async function anyIndexReplicaExists(vaultDir) {
	for (const p of indexPaths(vaultDir)) { try { await fsp.stat(p); return true; } catch (_) {} }
	return false;
}
// The number of PROTECTED files now missing from the vault (0 = nothing lost). This is the LOSS guard the
// destructive auto-refresh and one-way backup consult first, so it must FAIL SAFE: when it cannot tell (the
// recovery data exists but its index will not read — a newer format, tampering, or corruption), it THROWS an
// `indeterminate` error so the caller BLOCKS rather than treating "unknown" as "nothing lost" and rebuilding or
// mirror-deleting over a real loss. A genuinely UNPROTECTED vault (no index replicas at all) returns 0 — there
// is nothing to guard — so unprotected vaults are never blocked.
function indeterminate(msg) { return Object.assign(new Error('Loss check indeterminate: ' + msg), { indeterminate: true }); }
async function missingProtectedCount(vaultDir, { cipherDir } = {}) {
	let index;
	try { index = await readIndex(vaultDir); }
	catch (e) { throw indeterminate('the recovery index could not be read (' + (e && e.message || e) + ').'); }
	if (!index || !Array.isArray(index.files)) {
		// No readable, verified index. If replicas are present on disk, the index is corrupt/unreadable — that is
		// indeterminate, so fail safe. If none are present, the vault is simply not protected: nothing to guard.
		if (await anyIndexReplicaExists(vaultDir)) throw indeterminate('recovery data is present but its index could not be read or failed its integrity check.');
		return 0;
	}
	const cdir = cipherOf(vaultDir, cipherDir);
	const present = new Set((await listCipherFiles(cdir, index.exclude)).map(f => f.path));
	let missing = 0;
	for (const f of index.files) if (!present.has(f.path)) missing++;
	return missing;
}

// Worker core for the thorough staleness check (see isStale's deep path) — kept off the event loop.
async function staleCore({ vaultDir, cipherDir }, onProgress) { return { stale: await isStale(vaultDir, { cipherDir, deep: true, onProgress }) }; }
// Public thorough check: runs the deep comparison in the worker and returns a boolean. Serialized per
// vault like the other recovery operations, so it never reads a half-written index mid-refresh.
async function staleCheck(vaultDir, { cipherDir } = {}) {
	const abs = path.resolve(vaultDir);
	const r = await serialize(abs, () => dispatch('stale', { vaultDir: abs, cipherDir }));
	return !!(r && r.stale);
}

// ── worker offload ─────────────────────────────────────────────────────────────────────────────
// The heavy cores run in a worker thread so the calling process's event loop stays responsive; the
// worker streams { percent, label } progress back, which is forwarded to onProgress. The public
// protect/verify/heal below are the only entry points callers use.
// Read just the index's identity fields (its version and self-hash), off the main thread. heal()'s
// authenticity gate needs these before it repairs, and the index can be large (it scales with vault size), so
// parsing and hashing it must never run on the event loop. Returns quickly, well within the worker watchdog.
async function indexMetaCore({ vaultDir }) {
	// Returns every lightweight field a caller needs WITHOUT the caller re-reading the index: the rollback/verify
	// fields (version, indexHash) AND the status-badge fields (tier, counts, flags) readIndexMeta surfaces to the UI.
	// One worker-side read serves both, so a large index is parsed and hashed off the event loop exactly once.
	const idx = await readIndex(vaultDir);
	return idx
		? { protected: true, version: idx.version, indexHash: idx.indexHash, tier: idx.tier, redundancyPercent: idx.redundancyPercent, createdAt: idx.createdAt, dataBlocks: idx.dataBlocks, thorough: !!idx.thorough }
		: { protected: false };
}
const CORES = { protect: protectCore, verify: verifyCore, heal: healCore, stale: staleCore, indexmeta: indexMetaCore };
// A recovery core streams progress per block/stripe, so more than this long with no progress means a read
// has wedged (an unresponsive network-backed vault). The watchdog then frees the caller instead of hanging
// forever. Generous, so a legitimately slow phase (writing a large index) never trips it.
const WORKER_IDLE_MS = 120000;
// Run a core either directly (already inside the worker) or by spawning the shared worker (main thread).
function dispatch(op, args, onProgress) {
	return isMainThread
		? WorkerRun.runWorker(path.join(__dirname, 'RecoveryWorker.js'), { op, args }, onProgress, { idleMs: WORKER_IDLE_MS, idleMessage: 'A recovery operation' })
		: CORES[op](args, onProgress);
}

// Serialize every operation that touches a vault's .recovery folder, per vault, so they never overlap
// — a manual run and a background auto-refresh can't write it at once, and a check never reads a
// half-written index/parity mid-refresh (which would report false damage). Each vault keeps a promise
// chain; the next operation waits for the previous to settle. The map holds one entry per distinct
// vault (negligible), so it is never cleaned up.
const serializeQueue = Common.serialQueueByKey(); // one serial queue per vault (shared contract)
// Key the per-vault queue on the CASE-FOLDED path so two spellings of the same vault path on Windows (which is
// case-insensitive) map to the same queue — otherwise two differently-cased requests for one vault would run
// concurrently and could read a half-written index. A no-op on case-sensitive platforms.
const serialize = (key, fn) => serializeQueue(Common.foldPath(path.resolve(String(key))), fn);

// The signing key (signPriv) and vaultId are used ONLY here in the main thread — never passed into a worker —
// so the write-authority secret never leaves this process boundary. When a signer is present the freshly-built
// index is signed; otherwise any prior signature is cleared so a stale one is never checked against a new index.
// Signing is best-effort: a hiccup must never fail the parity build (the recovery data itself is the priority).
async function protect(vaultDir, { tier, cipherDir, thorough, exclude, signPriv, vaultId, onProgress } = {}) {
	// A redundancy tier is optional (absent = the default 'medium'), but an explicitly chosen one MUST be known.
	// An unknown value used to fall through to 'medium' silently inside the worker — a hidden downgrade of the
	// protection level the user asked for. Fail closed here, on the main thread, so a typo or a drifted UI option
	// is rejected up front with a clear message rather than quietly changing the redundancy that gets written.
	if (tier != null && tier !== '' && !TIERS[tier]) throw new Error('Unknown protection level "' + tier + '". Choose one of: ' + Object.keys(TIERS).join(', ') + '.');
	const abs = path.resolve(vaultDir);
	return serialize(abs, async () => {
		const res = await dispatch('protect', { vaultDir: abs, tier, cipherDir, thorough, exclude }, onProgress);
		try {
			if (signPriv && vaultId != null && res && res.indexHash) { await writeIndexSig(abs, { vaultId, version: res.version, indexHash: res.indexHash }, signPriv); res.signed = true; res.signedVersion = res.version; }
			else { await removeIndexSig(abs); }
		} catch (_) {}
		return res;
	});
}
// Add a signature to an already-current index without rebuilding parity (a trusted read-write unmount whose
// contents did not change). Serialized on the same per-vault queue so it never races a concurrent protect.
async function signIndex(vaultDir, { signPriv, vaultId } = {}) {
	const abs = path.resolve(vaultDir);
	return serialize(abs, () => signIndexInPlace(abs, { signPriv, vaultId }).catch(() => null));
}
async function verify(vaultDir, { cipherDir, pubkey, vaultId, onProgress } = {}) {
	const abs = path.resolve(vaultDir);
	const res = await serialize(abs, () => dispatch('verify', { vaultDir: abs, cipherDir }, onProgress));
	if (res && res.protected && res.indexHash) res.authenticity = await authenticity(abs, { vaultId, version: res.version, indexHash: res.indexHash }, pubkey);
	return res;
}
async function heal(vaultDir, { cipherDir, pubkey, vaultId, allowUnverified, force, onProgress } = {}) {
	const abs = path.resolve(vaultDir);
	return serialize(abs, async () => {
		// Authenticity gate BEFORE any reconstruction: a signature that is present but does NOT verify means the
		// index may have been forged, and repairing from a forged index could corrupt files — so refuse by default.
		// Unsigned or bit-rotten-signature indexes are NOT refused (a legitimate password-less refresh cannot sign,
		// and a corrupt sidecar must never become a denial of repair); the post-repair signed baseline is the backstop.
		// Read the index's version + self-hash in the WORKER (the index can be large, so parsing/hashing it must
		// stay off the event loop); the small signed sidecar and its verify stay here (cheap). healCore re-reads
		// and re-validates the index under expectIndexHash, so a bit-rotten or swapped index is still caught there.
		let auth = { signed: false }, expectIndexHash = null;
		try { const m = await dispatch('indexmeta', { vaultDir: abs }); if (m && m.indexHash) { expectIndexHash = m.indexHash; auth = await authenticity(abs, { vaultId, version: m.version, indexHash: m.indexHash }, pubkey); } } catch (_) {}
		// allowUnverified is the user's explicit "repair anyway" escape hatch: it guarantees a rare multi-fault
		// (real block damage AND the only surviving signature replica bit-rotten) can never leave a vault
		// permanently unrepairable — default stays fail-closed, but the user is never stuck.
		if (auth.tampered && !allowUnverified) { const e = new Error('Repair refused: the recovery data\'s authenticity signature did not verify, so the recovery index may have been forged (repairing from it could corrupt your files). Re-create the recovery data from a trusted read-write session, delete the .recovery folder and rebuild it, or choose to repair anyway if you trust this vault.'); e.authenticity = auth; e.code = 'AUTH_REFUSED'; throw e; }
		// A DOWNGRADE: this computer's ledger recorded that the recovery data was signed at some version, but the
		// index now presents unsigned or older — exactly what stripping the signature to force the weaker, no-password
		// repair path looks like. Refuse by default (a repair could rewrite blocks from an attacker-supplied index),
		// with allowUnverified as the same escape hatch. A never-signed vault (anchor 0) is untouched, so a legitimate
		// cold, password-less protect is unaffected; only a vault that WAS signed here and now is not trips this.
		let expectedVer = 0; try { expectedVer = await Integrity.recoverySignedVersion(vaultId); } catch (_) {}
		if (!auth.tampered && expectedVer > 0 && !(auth.signed && auth.verified && (auth.version || 0) >= expectedVer) && !allowUnverified) {
			const e = new Error('Repair refused: this vault\'s recovery data was signed before but now arrives unsigned or older than this computer last saw (expected version ' + expectedVer + '), which is what removing its signature to force an unverified repair looks like. If you just rebuilt the recovery data without unlocking the vault, open and close the vault once to re-sign it, then heal. Otherwise re-create it from a trusted read-write session, or repair anyway if you trust this vault.');
			e.authenticity = auth; e.downgrade = true; e.code = 'AUTH_REFUSED'; throw e;
		}
		// Bind the repair to the index the gate just approved (TOCTOU): healCore aborts if a concurrent writer
		// swapped the on-disk index underneath, so an unchecked index can never be repaired from.
		const res = await dispatch('heal', { vaultDir: abs, cipherDir, expectIndexHash, force: !!force }, onProgress);
		if (res && res.protected && res.indexHash) { res.authenticity = await authenticity(abs, { vaultId, version: res.version, indexHash: res.indexHash }, pubkey); if (auth.tampered && allowUnverified) res.repairedUnverified = true; }
		return res;
	});
}

module.exports = { protect, signIndex, verify, heal, readIndex, readIndexMeta, hasRecovery, removeRecovery, isStale, staleCheck, missingProtectedCount, recoveryDir, CORES, TIERS };
