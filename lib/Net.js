'use strict';
// lib/Net.js — one small, shared networking helper used by both the engine
// downloader and the driver installer, so the download / verify / unzip logic
// lives in exactly one place. It follows redirects, streams to disk with a
// progress line, verifies SHA-256 (deleting the file on mismatch), reads small
// JSON/text bodies, and resolves the latest release asset (with its published
// SHA-256 digest) from a GitHub repository.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream');
const { ZipArchive } = require('archiver'); // streaming zip WRITER (archiver v8 exports named classes): queues entries and reads each file only when it reaches it, so a vault of ANY size packs in constant memory with at most one open file at a time
const unzipper = require('unzipper');       // streaming zip READER: opens the central directory by random access without loading the whole archive, then streams each entry one at a time
const Common = require('./Common');
const Brand = require('./Brand');

const UA = Brand.slug + '-setup';
const IDLE_TIMEOUT_MS = 30000; // abort a connection that opens then stalls with no data
const MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024;   // 1 GiB — the engine/installer downloads are tens of MB; this stops a runaway or hostile server filling the disk BEFORE the checksum can reject it
// A zip BOMB is a tiny compressed entry that inflates enormously. Encrypted vault data is incompressible, so a
// genuine vault's entries have a compression ratio near 1:1 — bound the RATIO (above a size floor, below which a
// small entry is never judged) instead of an absolute size, so a vault of ANY size unpacks while a bomb is refused.
const MAX_UNZIP_RATIO = 100;                     // an entry (and the whole archive) may inflate at most this many times its COMPRESSED size…
const UNZIP_BOMB_FLOOR = 64 * 1024 * 1024;       // …with this per-entry floor so a small entry is never nuisance-rejected
const UNZIP_ABS_FLOOR = 512 * 1024 * 1024;       // cumulative floor: a small archive may expand up to this even if its compressed size is tiny; a larger archive is bounded to MAX_UNZIP_RATIO x its own total compressed size, so a real (incompressible) vault of ANY size passes while a bomb cannot inflate unbounded to disk
const MAX_BODY_BYTES = 16 * 1024 * 1024;         // 16 MiB — in-memory JSON/checksum bodies are tiny (KB); this bounds a hostile/MITM'd endpoint or redirect target streaming unbounded data into memory
const BODY_DEADLINE_MS = 60 * 1000;              // absolute cap for a small in-memory fetch — a drip server that trickles bytes just under the idle window can't hold the connection open forever
const DOWNLOAD_DEADLINE_MS = 20 * 60 * 1000;     // absolute cap for a streamed download (the real ones are tens of MB; this only trips a deliberately-slow/drip source)
const MAX_ZIP_ENTRIES = 100000;                  // an archive with far more entries than any real vault is refused, so a bomb of millions of tiny entries can't exhaust inodes/handles

// Resolve one redirect hop's Location against the current URL.
function resolveRedirect(current, location) {
	if (location.startsWith('http')) return location;
	if (location.startsWith('/')) { const u = new URL(current); return u.protocol + '//' + u.host + location; }
	return current.replace(/[^/]+$/, '') + location;
}

// Refuse a redirect that downgrades HTTPS to plain HTTP. Following one would let a network attacker (or a
// hostile endpoint) strip transport security mid-fetch — dangerous for the release-metadata/checksum fetches,
// whose integrity would otherwise be trusted. An http→http or https→https(→http is blocked) redirect is fine.
function assertNoDowngrade(from, to) {
	if (from.startsWith('https:') && to.startsWith('http://')) throw new Error('refusing to follow a redirect that downgrades HTTPS to plain HTTP: ' + to);
}

// Attach timeouts to a request. The IDLE timeout aborts a connection that opens then stalls with no data
// (resets on activity, so a slow-but-progressing transfer is not cut off). The ABSOLUTE deadline (when > 0)
// bounds the TOTAL time, so a drip source that trickles a byte just inside every idle window can't hold the
// connection open indefinitely. Both destroy the request, which rejects the promise.
function armTimeout(req, reject, deadlineMs = 0) {
	req.setTimeout(IDLE_TIMEOUT_MS, () => req.destroy(new Error('network idle timeout')));
	if (deadlineMs > 0) {
		const t = setTimeout(() => req.destroy(new Error('network deadline exceeded (' + Math.round(deadlineMs / 1000) + 's)')), deadlineMs);
		if (t.unref) t.unref();
		req.on('close', () => clearTimeout(t));
	}
	req.on('error', reject);
}

// GET a small body into memory (follows redirects). For JSON/checksum files only.
function getBuffer(url, redirectsLeft = 6, endBy = Date.now() + BODY_DEADLINE_MS) {
	return new Promise((resolve, reject) => {
		const mod = url.startsWith('https') ? https : http;
		const req = mod.get(url, { headers: { 'User-Agent': UA, 'Accept': 'application/vnd.github+json, text/plain, */*' } }, (res) => {
			if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
				if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
				let next; try { next = resolveRedirect(url, res.headers.location); assertNoDowngrade(url, next); } catch (e) { res.resume(); return reject(e); }
				res.resume();
				return getBuffer(next, redirectsLeft - 1, endBy).then(resolve).catch(reject); // share the absolute deadline across hops
			}
			if (res.statusCode !== 200) { res.resume(); return reject(new Error('The download server returned HTTP ' + res.statusCode + ' for ' + url + '. Check your internet connection and try again; if it persists, the source may be temporarily unavailable.')); }
			const chunks = [];
			let got = 0;
			res.on('data', c => { got += c.length; if (got > MAX_BODY_BYTES) { try { req.destroy(); } catch (_) {} return reject(new Error('response body exceeded the size limit for ' + url)); } chunks.push(c); });
			res.on('end', () => resolve(Buffer.concat(chunks)));
			res.on('error', reject);
		});
		armTimeout(req, reject, Math.max(1, endBy - Date.now())); // absolute deadline: the REMAINING budget on this hop, so redirects don't reset it
	});
}

async function getText(url) { return (await getBuffer(url)).toString('utf8'); }
async function getJson(url) { return JSON.parse(await getText(url)); }

function sha256File(p) {
	return new Promise((resolve, reject) => {
		const h = crypto.createHash('sha256');
		const s = fs.createReadStream(p);
		s.on('data', d => h.update(d));
		s.on('end', () => resolve(h.digest('hex')));
		s.on('error', reject);
	});
}

// Download `url` to `dest`, verifying expectedSha256 if given. Writes to a TEMP sibling and moves it into place
// only on full success, so a failed, rejected, or checksum-mismatched download NEVER truncates or removes an
// existing file at `dest`. This makes the helper safe for ANY caller, not only ones that already pass a throwaway
// temp path — a future caller can point `dest` at a live "last good" file without risking it.
async function download(url, dest, opts = {}) {
	const tmp = dest + '.part-' + process.pid + '-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex'); // random suffix so two concurrent downloads to the same dest never share a temp
	try { await downloadTo(url, tmp, opts); await Common.renameWithRetry(tmp, dest); return dest; } // renameWithRetry rides out a transient Windows lock on an existing dest, so this is genuinely safe for any caller's dest
	catch (e) { try { await fsp.unlink(tmp); } catch (_) {} throw e; }
}

// Stream a download to dest (follows redirects), printing a progress line. If
// expectedSha256 is given, verify after download and DELETE the file on mismatch —
// so a tampered or corrupted binary is never used. `label` names the file in the
// progress line. Internal: callers use download() above, which routes through a temp.
function downloadTo(url, dest, opts = {}, redirectsLeft = 6, endBy = Date.now() + DOWNLOAD_DEADLINE_MS) {
	const { label = 'file' } = opts;
	return new Promise((resolve, reject) => {
		const file = fs.createWriteStream(dest);
		const mod = url.startsWith('https') ? https : http;
		const req = mod.get(url, { headers: { 'User-Agent': UA } }, (res) => {
			if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
				file.close(); try { fs.unlinkSync(dest); } catch (_) {}
				if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
				let next; try { next = resolveRedirect(url, res.headers.location); assertNoDowngrade(url, next); } catch (e) { res.resume(); return reject(e); }
				res.resume();
				return downloadTo(next, dest, opts, redirectsLeft - 1, endBy).then(resolve).catch(reject); // share the absolute deadline across hops
			}
			if (res.statusCode !== 200) { file.close(); try { fs.unlinkSync(dest); } catch (_) {} res.resume(); return reject(new Error('The download server returned HTTP ' + res.statusCode + ' while downloading ' + label + '. Check your internet connection and try again; if it persists, the source may be temporarily unavailable.')); }
			const total = parseInt(res.headers['content-length'] || '0', 10);
			if (total > MAX_DOWNLOAD_BYTES) { file.close(); try { fs.unlinkSync(dest); } catch (_) {} res.resume(); return reject(new Error('refusing to download ' + label + ': it declares ' + Math.round(total / 1e6) + ' MB, over the ' + Math.round(MAX_DOWNLOAD_BYTES / 1e6) + ' MB limit.')); }
			let got = 0, lastPct = -1;
			res.on('data', (c) => {
				got += c.length;
				if (got > MAX_DOWNLOAD_BYTES) { try { req.destroy(); } catch (_) {} try { file.close(); } catch (_) {} try { fs.unlinkSync(dest); } catch (_) {} return reject(new Error('download of ' + label + ' exceeded the ' + Math.round(MAX_DOWNLOAD_BYTES / 1e6) + ' MB size limit and was stopped.')); }
				if (total > 0) {
					const pct = Math.floor(got / total * 100);
					if (pct !== lastPct && pct % 10 === 0) { lastPct = pct; try { process.stdout.write('\r  Downloading ' + label + '… ' + pct + '%'); } catch (_) {} }
				}
			});
			// A mid-body response-stream error (network drop, reset) isn't always mirrored onto `req`, so
			// handle it here too: drop the partial file and reject rather than leave the promise hanging.
			res.on('error', (e) => { try { file.close(); } catch (_) {} try { fs.unlinkSync(dest); } catch (_) {} reject(e); });
			res.pipe(file);
			file.on('finish', async () => {
				file.close();
				try { process.stdout.write('\n'); } catch (_) {}
				if (opts.expectedSha256) {
					try {
						const actual = await sha256File(dest);
						if (actual.toLowerCase() !== opts.expectedSha256.toLowerCase()) {
							try { fs.unlinkSync(dest); } catch (_) {}
							return reject(new Error('checksum mismatch for ' + label + ' (expected ' + opts.expectedSha256.slice(0, 12) + '…, got ' + actual.slice(0, 12) + '…)'));
						}
					} catch (e) { return reject(e); }
				}
				resolve(dest);
			});
			// A write-stream error (a full or failing disk) must tear down the transfer like the other error paths —
			// otherwise res keeps draining into a dead file until a size/deadline limit trips, wasting bandwidth.
			file.on('error', (e) => { try { req.destroy(); } catch (_) {} try { file.close(); } catch (_) {} try { fs.unlinkSync(dest); } catch (_) {} reject(e); });
		});
		armTimeout(req, reject, Math.max(1, endBy - Date.now())); // absolute deadline: remaining budget on this hop, so redirects don't reset it
	});
}

// Pick a matching asset from a GitHub release object → { name, url, sha256, tag }.
// GitHub publishes each asset's SHA-256 in the `digest` field, which we use to
// verify the download without a separate checksum file. sha256 is null if the
// field is absent (callers decide whether that is acceptable).
function pickAsset(rel, matchFn, where) {
	const asset = (rel.assets || []).find(matchFn);
	if (!asset) { const e = new Error('No matching download was found for this system in ' + where + '. This operating system or processor architecture may not have a prebuilt engine available; see the README for how to install one manually.'); e.code = 'NO_ASSET'; throw e; }
	return { name: asset.name, url: asset.browser_download_url, sha256: (asset.digest || '').replace(/^sha256:/, '') || null, tag: rel.tag_name };
}

// Resolve an asset from a repo's LATEST release.
async function githubLatestAsset(repo, matchFn) {
	return pickAsset(await getJson('https://api.github.com/repos/' + repo + '/releases/latest'), matchFn, repo + '@latest');
}

// Resolve an asset from a repo's SPECIFIC tagged release (used to pin a known-good
// version instead of blindly tracking latest).
async function githubAssetForTag(repo, tag, matchFn) {
	return pickAsset(await getJson('https://api.github.com/repos/' + repo + '/releases/tags/' + tag), matchFn, repo + '@' + tag);
}

// Extract a zip archive to destDir using pure JavaScript — no dependency on a
// system `unzip` or PowerShell, so it behaves identically on every platform.
// Guards against zip-slip (entries that would write outside destDir) and preserves
// the Unix executable bit when the archive records one. Returns the list of
// top-level entry names (so a caller can find the folder it extracted).
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

async function unzip(zipPath, destDir, { onProgress } = {}) {
	// The archive can be an attacker-supplied packed container (imported/unpacked without a password), so keep the
	// same defenses the buffered reader had — a many-entry bomb, zip-slip, and inflation bombs — but STREAM so an
	// archive of ANY size opens and extracts in constant memory. First refuse a many-entry bomb from the EOCD count
	// (read from the tail only), before the central directory is materialized into one object per entry.
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
	// The cumulative inflation backstop: the total bytes we WRITE across the whole archive may exceed a generous
	// multiple of the archive's own total COMPRESSED size (with a floor for small archives). It is keyed off the
	// real compressed size and the ACTUAL streamed bytes, never a declared size an attacker controls — so a real,
	// incompressible vault of any size passes, while a hostile archive (one under-declared entry, or a swarm of
	// small highly-compressible ones) cannot inflate unbounded to disk.
	const sumCsz = entries.reduce((s, e) => s + Number(e.compressedSize || 0), 0);
	const totalCap = Math.max(UNZIP_ABS_FLOOR, sumCsz * MAX_UNZIP_RATIO);
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
		// STREAM the entry to disk under two backstops enforced on the ACTUAL bytes (so a size the attacker
		// under-declares — even 0 — cannot bypass them): this entry may not exceed a multiple of its real compressed
		// size (with the per-entry floor), and the running archive total may not exceed the cumulative cap. Never hold
		// more than one chunk. On any failure the partial output file is removed.
		const entryCap = Math.max(UNZIP_BOMB_FLOOR, csz * MAX_UNZIP_RATIO);
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

// Measure a directory tree's total file size (bytes). Used by dispersal to reserve staging space up front. ASYNC
// (fsp, not sync fs) so it never blocks the event loop — it can be driven from the long-running web server, where a
// blocked loop would stall the mounted-drive health checks.
async function treeSize(dir) {
	let total = 0;
	for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
		const abs = path.join(dir, e.name);
		if (e.isSymbolicLink()) continue;
		if (e.isDirectory()) total += await treeSize(abs);
		else if (e.isFile()) total += (await fsp.stat(abs)).size;
	}
	return total;
}

// Zip a directory tree into a single file using pure JavaScript. Entries are stored
// under `prefix` so the folder is recreated on extraction; empty directories are
// preserved and symlinks are skipped (not followed). `extra` adds top-level entries
// (e.g. a container marker). Output is streamed and written atomically (temp +
// rename) so an interrupted pack never leaves a truncated file that looks valid.
// Reads are ASYNC (fsp) so the walk yields the event loop between files — packing a large vault from the
// web server never blocks the loop (and thus never stalls the mounted-drive health checks).
// `override` maps a RELATIVE path inside the tree (e.g. 'vault.json') to a Buffer that is zipped IN PLACE of
// the real file's bytes — used to share a vault with only selected key slots by substituting a filtered
// manifest, without copying the whole vault.
// Normalize a value to something archiver accepts as an input source. A Buffer sent across a worker boundary
// arrives as a plain Uint8Array (structured clone drops the Buffer subclass), which archiver rejects — copy it into
// a Buffer. Strings and Buffers pass through unchanged.
const asAppendable = (v) => (Buffer.isBuffer(v) || typeof v === 'string') ? v : Buffer.from(v);

async function zipDir(srcDir, outFile, { prefix = '', extra = {}, override = {}, onProgress } = {}) {
	const tick = (p) => { if (onProgress) { try { onProgress(p); } catch (_) {} } };
	const root = path.resolve(srcDir);
	const tmp = Common.uniqueTempPath(outFile); // unique (pid+random) so two concurrent packs never share a temp path; the '.tmp' suffix is still what the stale-temp sweep recognizes
	const out = fs.createWriteStream(tmp);
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

// The marker file written into a packed container and recognized on unpack. A single name-independent
// constant so pack (writes it) and unpack (allows it past the stray-file check) can never drift apart.
const CONTAINER_MARKER = 'vdisk-format.json';

module.exports = { getText, download, sha256File, treeSize, githubLatestAsset, githubAssetForTag, unzip, zipDir, CONTAINER_MARKER };
