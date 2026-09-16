'use strict';
// lib/Zip.js — the ONE place all ZIP reading and writing lives, so the app has a single, consistent, hardened
// implementation instead of per-feature copies. Everything here is non-blocking (streaming, async I/O, async
// decompression on the libuv threadpool) and crash-proof against hostile input (entry-count caps, zip-slip guards,
// bounded inflation so a "zip bomb" throws instead of exhausting memory or disk, and cleanup of partial output on any
// failure). It uses pure-JavaScript readers/writers — no system `unzip`/`zip`/PowerShell — so it behaves identically
// on macOS, Windows, and Linux.
//
// Three entry points cover every need in the app:
//   * unzip(zipPath, destDir)          — stream-extract a whole archive from a FILE to a directory (the .vdisk
//                                        container; the downloaded engine). Handles archives of any size in constant
//                                        memory, and treats the archive as attacker-supplied.
//   * zipDir(srcDir, outFile)          — stream-pack a directory tree into a single file, written atomically.
//   * readEntry(buffer, name)          — read ONE named entry from an in-memory Buffer (a small, possibly untrusted
//                                        upload such as a 1Password .1pux). Bounded so a bomb entry cannot OOM.
// The heavy stream reader/writer (unzipper / archiver) are required LAZILY inside unzip()/zipDir(), so importing this
// module stays cheap for the common paths that never touch a file archive.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const zlib = require('zlib');
const { promisify } = require('util');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream');
const Common = require('./Common');

const inflateRaw = promisify(zlib.inflateRaw); // async: decompression runs on the libuv threadpool, never blocking the loop

// --- shared limits (kept here so every zip path enforces the same crash-proof bounds) ---
const MAX_UNZIP_RATIO = 100;                     // an entry (and the whole archive) may inflate at most this many times the archive's REAL on-disk size…
const UNZIP_BOMB_FLOOR = 64 * 1024 * 1024;       // …with this per-entry floor so a small entry is never nuisance-rejected
const UNZIP_ABS_FLOOR = 512 * 1024 * 1024;       // cumulative floor: a small archive may expand up to this even when it is tiny; a larger archive is bounded to MAX_UNZIP_RATIO x the archive file's ACTUAL size on disk (which an attacker cannot inflate by lying in the central directory), so a real (incompressible) vault of ANY size passes while a bomb cannot inflate unbounded to disk
const MAX_ZIP_ENTRIES = 100000;                  // an archive with far more entries than any real vault is refused, so a bomb of millions of tiny entries can't exhaust inodes/handles
const MAX_ENTRY_INFLATED_BYTES = 128 * 1024 * 1024; // ceiling on ONE in-memory entry read (readEntry), so a bomb entry makes zlib throw instead of exhausting memory

// The number of entries a zip DECLARES in its End-Of-Central-Directory record, without parsing the entries. The
// classic EOCD (signature 0x06054b50) sits within the last 22+65535 bytes; its total-records count is a UInt16LE at
// offset 10. When an archive is ZIP64 (which archiver emits once the data before the central directory passes 4 GB,
// NOT only when there are >65534 entries) that field is the 0xFFFF sentinel and the REAL count lives in the ZIP64
// EOCD record — so resolve it there rather than mistaking a big-but-few-entry vault for a many-entry bomb. Returns
// the real declared count, or null if it cannot be determined (then the caller falls back to the post-open count).
function zipDeclaredEntryCount(buf) {
	const SIG = 0x06054b50;
	const lo = Math.max(0, buf.length - (22 + 65535));
	for (let i = buf.length - 22; i >= lo; i--) {
		if (buf.readUInt32LE(i) !== SIG) continue;
		const classic = buf.readUInt16LE(i + 10);
		return classic === 0xFFFF ? zip64EntryCount(buf) : classic; // 0xFFFF -> ZIP64: read the true 64-bit count
	}
	return null;
}
// The true entry count from the ZIP64 End-Of-Central-Directory record (signature 0x06064b50), which sits just before
// the ZIP64 locator and the classic EOCD — so it is within the same tail we already read. Total-entries is an 8-byte
// LE field at record offset 32. Returns the count (Infinity if it exceeds the safe-integer range — treated as over
// any limit), or null if the record is not found in the tail.
function zip64EntryCount(buf) {
	const SIG = 0x06064b50;
	for (let i = buf.length - 56; i >= 0; i--) { // the ZIP64 EOCD record is at least 56 bytes
		if (buf.readUInt32LE(i) !== SIG) continue;
		try { const n = buf.readBigUInt64LE(i + 32); return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : Infinity; } catch (_) { return null; }
	}
	return null;
}

// Read the entry count a zip DECLARES without loading the whole archive: read only the tail where the classic EOCD,
// the ZIP64 locator, and the ZIP64 EOCD record all live (22 + up to 65535 comment bytes). Lets a many-entry bomb be
// refused before the central directory is opened. Returns the real declared count (ZIP64-aware) or null.
async function declaredEntryCountFromFile(zipPath) {
	try {
		const st = await fsp.stat(zipPath);
		const tailLen = Math.min(st.size, 22 + 65535);
		if (tailLen < 22) return null;
		const fh = await fsp.open(zipPath, 'r');
		try { const buf = Buffer.allocUnsafe(tailLen); await fh.read(buf, 0, tailLen, st.size - tailLen); return zipDeclaredEntryCount(buf); }
		finally { await fh.close(); }
	} catch (_) { return null; }
}

// Extract a zip archive to destDir using pure JavaScript — no dependency on a system `unzip` or PowerShell, so it
// behaves identically on every platform. Guards against zip-slip (entries that would write outside destDir) and
// preserves the Unix executable bit when the archive records one. Returns the list of top-level entry names (so a
// caller can find the folder it extracted).
async function unzip(zipPath, destDir, { onProgress } = {}) {
	// The archive can be an attacker-supplied packed container (imported/unpacked without a password), so keep the
	// same defenses the buffered reader had — a many-entry bomb, zip-slip, and inflation bombs — but STREAM so an
	// archive of ANY size opens and extracts in constant memory. First refuse a many-entry bomb from the EOCD count
	// (read from the tail only), before the central directory is materialized into one object per entry.
	const unzipper = require('unzipper'); // streaming zip READER, loaded on first use (see the note at the top of this module)
	const declared = await declaredEntryCountFromFile(zipPath);
	if (declared != null && declared > MAX_ZIP_ENTRIES) throw new Error('the archive declares too many entries (over the ' + MAX_ZIP_ENTRIES + ' limit) and was rejected.');
	// Open reads the central directory by random access — it never pulls the whole archive into memory. Each entry
	// is then streamed out one at a time below, so peak memory is one chunk regardless of the vault's size.
	const directory = await unzipper.Open.file(zipPath);
	const entries = (directory.files || []).filter(e => e.type === 'File' || e.type === 'Directory');
	if (entries.length > MAX_ZIP_ENTRIES) throw new Error('the archive has too many entries (' + entries.length + ', over the ' + MAX_ZIP_ENTRIES + ' limit) and was rejected.');
	const root = path.resolve(destDir);
	const tops = new Set();
	let done = 0;
	const total = entries.length || 1;
	// The cumulative inflation backstop: the total bytes we WRITE across the whole archive may not exceed a generous
	// multiple of the archive's REAL on-disk size (with a floor for small archives). It is keyed off the actual file
	// size on disk — which an attacker cannot inflate by lying in the central directory — and the ACTUAL streamed
	// bytes, NOT the declared per-entry compressed sizes (which the central directory lets an attacker OVER-declare to
	// raise a per-entry ceiling). So a real, incompressible vault of any size passes, while a hostile archive (an
	// under-declared entry, an over-declared entry, or a swarm of small highly-compressible ones) cannot inflate
	// unbounded to disk: the total output is bounded by the archive's real bytes times the ratio.
	const archiveBytes = await fsp.stat(zipPath).then((s) => s.size, () => 0);
	const totalCap = Math.max(UNZIP_ABS_FLOOR, archiveBytes * MAX_UNZIP_RATIO);
	let totalGot = 0;
	for (const entry of entries) {
		const name = entry.path;
		const outPath = path.resolve(root, name);
		// Zip-slip guard via the shared boundary check (case-folded on Windows, so a differently-cased
		// path can't escape the destination there either).
		if (outPath !== root && !Common.pathWithin(outPath, root)) throw new Error('unsafe zip entry: ' + name);
		tops.add(name.split('/')[0]);
		if (entry.type === 'Directory') { await fsp.mkdir(outPath, { recursive: true }); done++; continue; }
		await fsp.mkdir(path.dirname(outPath), { recursive: true });
		const csz = Number(entry.compressedSize || 0), usz = Number(entry.uncompressedSize || 0);
		// Fast reject of an HONESTLY-declared bomb before a byte is written.
		if (usz > UNZIP_BOMB_FLOOR && csz > 0 && usz / csz > MAX_UNZIP_RATIO) throw new Error('the archive entry "' + name + '" inflates ' + Math.round(usz / csz) + '× (a suspected zip bomb) and was rejected.');
		// STREAM the entry to disk under two backstops enforced on the ACTUAL output bytes (so a size the attacker
		// mis-declares — 0, or an over-large value — cannot bypass them): this entry may not exceed a multiple of its
		// declared compressed size (an early per-entry reject), AND — the real guarantee — the running archive total may
		// not exceed the cumulative cap keyed off the archive's real on-disk size. The per-entry ceiling is itself
		// clamped to that total cap, so a single OVER-declared entry can never raise its own limit past the real bound.
		// Never hold more than one chunk. On any failure the partial output file is removed.
		const entryCap = Math.min(totalCap, Math.max(UNZIP_BOMB_FLOOR, csz * MAX_UNZIP_RATIO));
		let got = 0;
		const counter = new Transform({
			transform(chunk, _enc, cb) {
				got += chunk.length; totalGot += chunk.length;
				if (got > entryCap || totalGot > totalCap) return cb(new Error('the archive entry "' + name + '" expands far beyond its compressed size (a suspected zip bomb) and was rejected.'));
				cb(null, chunk);
			}
		});
		try {
			await pipeline(entry.stream(), counter, fs.createWriteStream(outPath));
		} catch (e) {
			try { await fsp.unlink(outPath); } catch (_) {}
			throw e;
		}
		// Preserve the Unix executable bit when the archive records one (the high 16 bits of the external attributes
		// are the st_mode); POSIX only, and best-effort — a container of encrypted blobs rarely carries one.
		if (process.platform !== 'win32' && entry.externalFileAttributes) { const mode = (entry.externalFileAttributes >>> 16) & 0o777; if (mode) { try { await fsp.chmod(outPath, mode); } catch (_) {} } }
		done++;
		if (onProgress && (done === total || done % 4 === 0)) { try { onProgress({ percent: Math.round(done / total * 100), label: 'Importing' }); } catch (_) {} }
	}
	return [...tops].filter(Boolean);
}

// Normalize a value to something archiver accepts as an input source. A Buffer sent across a worker boundary
// arrives as a plain Uint8Array (structured clone drops the Buffer subclass), which archiver rejects — copy it into
// a Buffer. Strings and Buffers pass through unchanged.
const asAppendable = (v) => (Buffer.isBuffer(v) || typeof v === 'string') ? v : Buffer.from(v);

// Zip a directory tree into a single file using pure JavaScript. Entries are stored under `prefix` so the folder is
// recreated on extraction; empty directories are preserved and symlinks are skipped (not followed). `extra` adds
// top-level entries (e.g. a container marker). Output is streamed and written atomically (temp + rename) so an
// interrupted pack never leaves a truncated file that looks valid. Reads are ASYNC (fsp) so the walk yields the event
// loop between files — packing a large vault from the web server never blocks the loop. `override` maps a RELATIVE
// path inside the tree (e.g. 'vault.json') to a Buffer that is zipped IN PLACE of the real file's bytes.
async function zipDir(srcDir, outFile, { prefix = '', extra = {}, override = {}, onProgress } = {}) {
	const tick = (p) => { if (onProgress) { try { onProgress(p); } catch (_) {} } };
	const root = path.resolve(srcDir);
	const tmp = Common.uniqueTempPath(outFile); // unique (pid+random) so two concurrent packs never share a temp path; the '.tmp' suffix is still what the stale-temp sweep recognizes
	const out = fs.createWriteStream(tmp);
	const { ZipArchive } = require('archiver'); // streaming zip WRITER, loaded on first use (see the note at the top of this module)
	const archive = new ZipArchive({ zlib: { level: 6 } });
	// Progress heartbeat, time-gated so a huge tree doesn't flood messages. archiver's 'progress' fires per ENTRY, so
	// it alone would go silent while a single very large file is read+deflated — long enough on slow storage to trip
	// the worker idle-watchdog and false-fail a healthy pack. So ALSO heartbeat as compressed BYTES flow through a
	// meter between the archive and the output, which keeps ticking mid-file. Both feed the same time gate.
	let lastTick = 0;
	const beat = () => { const now = Date.now(); if (now - lastTick > 500) { lastTick = now; tick({ indeterminate: true, label: 'Packing' }); } };
	archive.on('progress', beat);
	const meter = new Transform({ transform(chunk, _e, cb) { beat(); cb(null, chunk); } });
	// A file that vanishes or can't be read mid-pack must FAIL the pack, never be silently skipped — this archive is
	// often a safety copy made just before the original is destroyed, so a dropped file would be silent data loss.
	// So reject on any archiver warning (e.g. a stat/ENOENT), not just on a hard error.
	const done = new Promise((resolve, reject) => {
		out.on('error', reject);
		out.on('close', resolve);
		meter.on('error', reject);
		archive.on('warning', reject);
		archive.on('error', reject);
	});
	archive.pipe(meter).pipe(out);
	// Walk the tree and QUEUE each entry — archiver reads a queued file's bytes only when it reaches it in the output
	// stream, so at most one file is open at a time and the whole tree is never buffered (a vault of any size packs in
	// constant memory). A file with an override buffer is queued from the buffer in place of its on-disk bytes; empty
	// directories are queued explicitly so they survive the round-trip; symlinks are skipped (not followed).
	const queue = async (dir, rel) => {
		const entries = await fsp.readdir(dir, { withFileTypes: true });
		if (entries.length === 0 && rel) { archive.append(Buffer.alloc(0), { name: (prefix ? prefix + '/' + rel : rel) + '/' }); return; }
		for (const e of entries) {
			const abs = path.join(dir, e.name);
			const r = rel ? rel + '/' + e.name : e.name;
			if (e.isSymbolicLink()) continue;
			if (e.isDirectory()) { await queue(abs, r); continue; }
			if (!e.isFile()) continue;
			const name = prefix ? prefix + '/' + r : r;
			if (Object.prototype.hasOwnProperty.call(override, r)) archive.append(asAppendable(override[r]), { name });
			else archive.file(abs, { name }); // lazy, sequential read during output — O(1) open files
		}
	};
	tick({ indeterminate: true, label: 'Packing' });
	try {
		await queue(root, '');
		for (const [name, content] of Object.entries(extra)) archive.append(asAppendable(content), { name });
		archive.finalize().catch(() => {}); // begins draining the queue into `out`; any error surfaces via the 'error' event wired above, so swallow the returned promise to avoid a duplicate unhandled rejection. Completion is the write stream's 'close' (awaited via `done`)
		await done;
	} catch (e) {
		try { archive.destroy(); } catch (_) {}
		try { meter.destroy(); } catch (_) {}
		try { out.destroy(); } catch (_) {}
		try { await fsp.rm(tmp, { force: true }); } catch (_) {} // never leave a torn temp behind on failure
		throw e;
	}
	// Flush the packed bytes to disk BEFORE the rename, so a power loss right after this returns can never leave a
	// zero-length or torn archive — this file is often a safety copy (secure-remove --keep) made just before the
	// original is destroyed, so its durability is not optional. Then flush the directory entry too (POSIX; the
	// directory open is a harmless no-op on Windows).
	try { const fh = await fsp.open(tmp, 'r+'); try { await fh.sync(); } finally { await fh.close(); } } catch (_) {}
	await Common.renameWithRetry(tmp, outFile); // retry a transient Windows lock rather than failing the pack
	try { const dh = await fsp.open(path.dirname(outFile), 'r'); try { await dh.sync(); } finally { await dh.close(); } } catch (_) {}
	return outFile;
}

// --- in-memory single-entry read (for a small, possibly untrusted upload held as a Buffer) ---
// Walk a Buffer's central directory and return each entry's metadata WITHOUT inflating anything — cheap, and used
// both to find an entry and to let a caller enumerate an archive. Returns [] on anything that is not a readable ZIP.
function entries(buffer) {
	const out = [];
	if (!Buffer.isBuffer(buffer) || buffer.length < 22) return out;
	const maxBack = Math.min(buffer.length, 22 + 65535);
	let eocd = -1;
	for (let i = buffer.length - 22; i >= buffer.length - maxBack && i >= 0; i--) { if (buffer.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
	if (eocd < 0) return out;
	const cdCount = buffer.readUInt16LE(eocd + 10);
	let off = buffer.readUInt32LE(eocd + 16);
	for (let n = 0; n < cdCount && n < MAX_ZIP_ENTRIES; n++) {
		if (off + 46 > buffer.length || buffer.readUInt32LE(off) !== 0x02014b50) break; // central-directory file header
		const method = buffer.readUInt16LE(off + 10);
		const compSize = buffer.readUInt32LE(off + 20);
		const uncompSize = buffer.readUInt32LE(off + 24);
		const nameLen = buffer.readUInt16LE(off + 28);
		const extraLen = buffer.readUInt16LE(off + 30);
		const commentLen = buffer.readUInt16LE(off + 32);
		const localOffset = buffer.readUInt32LE(off + 42);
		const name = buffer.toString('utf8', off + 46, off + 46 + nameLen);
		out.push({ name, method, compSize, uncompSize, localOffset });
		off += 46 + nameLen + extraLen + commentLen;
	}
	return out;
}
// Read ONE named entry from an in-memory Buffer, matching the exact path OR the basename (so "export.data" is found
// whether or not it sits under a folder). Async so the deflate runs on the threadpool (non-blocking), and bounded by
// maxBytes so a bomb entry makes zlib throw rather than exhausting memory. Returns the entry's Buffer, or null if no
// entry matches. Throws a clear Error on a corrupt/oversized/unsupported archive — never crashes the caller.
async function readEntry(buffer, name, { maxBytes = MAX_ENTRY_INFLATED_BYTES } = {}) {
	if (!Buffer.isBuffer(buffer) || buffer.length < 22) throw new Error('Not a valid ZIP archive.');
	const meta = entries(buffer).find((e) => e.name === name || e.name.replace(/^.*\//, '') === name);
	if (!meta) return null;
	const lo = meta.localOffset;
	if (lo + 30 > buffer.length || buffer.readUInt32LE(lo) !== 0x04034b50) throw new Error('The ZIP archive has a corrupt local header.');
	const dataStart = lo + 30 + buffer.readUInt16LE(lo + 26) + buffer.readUInt16LE(lo + 28);
	const comp = buffer.slice(dataStart, dataStart + meta.compSize);
	if (meta.method === 0) { if (comp.length > maxBytes) throw new Error('The ZIP entry is too large.'); return comp; } // stored
	if (meta.method === 8) return await inflateRaw(comp, { maxOutputLength: maxBytes }); // deflate, off the event loop, bounded so a bomb throws
	throw new Error('The ZIP archive uses an unsupported compression method (' + meta.method + ').');
}

// The marker file written into a packed container and recognized on unpack. A single name-independent constant so
// pack (writes it) and unpack (allows it past the stray-file check) can never drift apart.
const CONTAINER_MARKER = 'vdisk-format.json';

module.exports = { unzip, zipDir, readEntry, entries, CONTAINER_MARKER, MAX_ZIP_ENTRIES };
