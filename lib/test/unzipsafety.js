'use strict';
// lib/test/unzipsafety.js — the zip extractor (Net.unzip) is fed attacker-supplied archives (an imported or
// unpacked .vdisk container is a zip that arrives WITHOUT a password), so a crafted entry name must never write
// outside the destination folder. This builds real malicious archives — a "../" traversal entry and an absolute
// path entry — and asserts unzip refuses them and writes nothing outside the destination, while a normal archive
// still extracts. It locks the primary path-escape (zip-slip) defense with no network and no engine.
//
// Run:  node lib/test/unzipsafety.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const zlib = require('zlib');
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const exists = (p) => { try { fs.statSync(p); return true; } catch (_) { return false; } };

// A minimal, dependency-free ZIP writer (no ZIP64, no data descriptor) so this security test can craft archives
// with EXACT, adversarial entry names — a real zip library sanitizes names like "../x" or "/abs", which would
// silently defeat the zip-slip test. Supports STORE and raw-DEFLATE entries; returns the archive as a Buffer.
// entries: [{ name, data, method: 'store'|'deflate', fakeUsz, fakeCsz }]. `fakeUsz`/`fakeCsz`, if set, are written as
// the DECLARED uncompressed / compressed sizes in place of the real ones — so a test can forge an entry that lies about
// its size (under- OR over-declaring) to probe the inflation backstop. CRC-32 uses Node's native zlib.crc32.
function buildZip(entries, opts = {}) {
	const local = [], central = [];
	let offset = 0;
	for (const e of entries) {
		const nameBuf = Buffer.from(e.name, 'utf8');
		const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data);
		const method = e.method === 'deflate' ? 8 : 0;
		const body = method === 8 ? zlib.deflateRawSync(raw) : raw;
		const crc = zlib.crc32(raw) >>> 0;
		const usz = (e.fakeUsz != null) ? e.fakeUsz : raw.length; // declared uncompressed size (may be a forged lie)
		const csz = (e.fakeCsz != null) ? e.fakeCsz : body.length; // declared COMPRESSED size (may be a forged over-declaration)
		const lh = Buffer.alloc(30);
		lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6); lh.writeUInt16LE(method, 8);
		lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(csz, 18); lh.writeUInt32LE(usz, 22);
		lh.writeUInt16LE(nameBuf.length, 26); lh.writeUInt16LE(0, 28);
		local.push(lh, nameBuf, body);
		const cd = Buffer.alloc(46);
		cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(method, 10);
		cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(csz, 20); cd.writeUInt32LE(usz, 24);
		cd.writeUInt16LE(nameBuf.length, 28); cd.writeUInt32LE(offset, 42);
		central.push(cd, nameBuf);
		offset += lh.length + nameBuf.length + body.length;
	}
	const cdBuf = Buffer.concat(central), files = Buffer.concat(local);
	// Optional ZIP64 end-of-central-directory record + locator, so a test can forge the 64-bit entry count a
	// genuinely-large (or maliciously many-entry) archive carries. When present, the classic EOCD count field holds
	// the 0xFFFF sentinel and the real count lives in the ZIP64 record's total-entries field (offset 32).
	let z64 = Buffer.alloc(0);
	if (opts.zip64Count != null) {
		const rec = Buffer.alloc(56);
		rec.writeUInt32LE(0x06064b50, 0); rec.writeBigUInt64LE(44n, 4); rec.writeUInt16LE(45, 12); rec.writeUInt16LE(45, 14);
		rec.writeBigUInt64LE(BigInt(entries.length), 24); rec.writeBigUInt64LE(BigInt(opts.zip64Count), 32); // total-entries — what zip64EntryCount reads
		rec.writeBigUInt64LE(BigInt(cdBuf.length), 40); rec.writeBigUInt64LE(BigInt(files.length), 48);
		const loc = Buffer.alloc(20);
		loc.writeUInt32LE(0x07064b50, 0); loc.writeBigUInt64LE(BigInt(files.length + cdBuf.length), 8); loc.writeUInt32LE(1, 16);
		z64 = Buffer.concat([rec, loc]);
	}
	const eocd = Buffer.alloc(22);
	const classicCount = opts.zip64Count != null ? 0xFFFF : (opts.fakeEocdCount != null ? (opts.fakeEocdCount & 0xFFFF) : entries.length);
	eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(classicCount, 8); eocd.writeUInt16LE(classicCount, 10);
	eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(files.length, 16);
	return Buffer.concat([files, cdBuf, z64, eocd]);
}
async function writeZip(zipPath, entries) {
	await fsp.writeFile(zipPath, buildZip(entries.map(([name, content]) => ({ name, data: content, method: 'store' }))));
}

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-unzip-'));
	const dest = path.join(tmp, 'out'); // extraction target
	const sentinel = path.join(tmp, 'ESCAPED.txt'); // a "../ESCAPED.txt" entry would land here, OUTSIDE dest

	// 1. A traversal entry must be refused, and must NOT write outside the destination.
	const zipSlip = path.join(tmp, 'slip.zip');
	await writeZip(zipSlip, [['a.txt', 'ok'], ['../ESCAPED.txt', 'pwned']]);
	let slipRejected = false;
	try { await Net.unzip(zipSlip, dest); } catch (_) { slipRejected = true; }
	ok('a "../" traversal entry is rejected', slipRejected);
	ok('nothing was written outside the destination', !exists(sentinel));

	// 2. An absolute-path entry must not escape either.
	const zipAbs = path.join(tmp, 'abs.zip');
	const absTarget = path.join(tmp, 'ABS_ESCAPED.txt');
	await writeZip(zipAbs, [['b.txt', 'ok'], [absTarget.replace(/^\/+/, '/'), 'pwned']]);
	let absRejected = false;
	try { await Net.unzip(zipAbs, path.join(tmp, 'out2')); } catch (_) { absRejected = true; }
	ok('an absolute-path entry is rejected or contained', absRejected || !exists(absTarget));

	// 3. Control: a normal archive extracts fine (the guard is not over-broad).
	const zipOk = path.join(tmp, 'ok.zip');
	await writeZip(zipOk, [['hello.txt', 'hi'], ['sub/deep.txt', 'deep']]);
	const cleanDest = path.join(tmp, 'clean');
	let cleanOk = true;
	try { await Net.unzip(zipOk, cleanDest); } catch (_) { cleanOk = false; }
	ok('a normal archive still extracts', cleanOk && exists(path.join(cleanDest, 'hello.txt')) && exists(path.join(cleanDest, 'sub', 'deep.txt')));

	// 4. A zip BOMB — a tiny compressed entry that inflates far beyond any plausible ratio — must be refused before a
	//    byte is written. The guard is RATIO-based (encrypted vault data is incompressible, ~1:1), not an absolute
	//    size cap, so a vault of any size still extracts while a bomb is caught. Build a 70 MiB run of zeros (past the
	//    64 MiB floor) that DEFLATEs to a few KB — a ratio of hundreds of times.
	const zipBomb = path.join(tmp, 'bomb.zip');
	await fsp.writeFile(zipBomb, buildZip([{ name: 'big.bin', data: Buffer.alloc(70 * 1024 * 1024), method: 'deflate' }]));
	let bombRejected = false;
	try { await Net.unzip(zipBomb, path.join(tmp, 'out3')); } catch (_) { bombRejected = true; }
	ok('a high-ratio zip bomb is rejected before extraction (ratio-based, any-size-safe)', bombRejected && !exists(path.join(tmp, 'out3', 'big.bin')));

	// 5. Control for the bomb guard: a large but INCOMPRESSIBLE entry (ratio ~1:1, like real encrypted vault bytes)
	//    past the floor must still extract — the guard rejects explosive ratios, never large size alone.
	const zipBig = path.join(tmp, 'big.zip');
	await fsp.writeFile(zipBig, buildZip([{ name: 'rand.bin', data: crypto.randomBytes(70 * 1024 * 1024), method: 'store' }])); // 70 MiB of random bytes, STORE: ratio ~1:1
	const bigDest = path.join(tmp, 'out4');
	let bigOk = true;
	try { await Net.unzip(zipBig, bigDest); } catch (_) { bigOk = false; }
	ok('a large incompressible entry past the floor still extracts (no absolute size cap)', bigOk && exists(path.join(bigDest, 'rand.bin')));

	// 6. A bomb that LIES about (or zeroes) its declared uncompressed size must still be caught — the inflation
	//    backstop is enforced on the ACTUAL streamed bytes and the real compressed size, not the declared size. Build
	//    120 MiB of zeros that DEFLATE tiny, but declare the uncompressed size as 0 so a size-trusting guard would be
	//    bypassed.
	const zipLiar = path.join(tmp, 'liar.zip');
	await fsp.writeFile(zipLiar, buildZip([{ name: 'liar.bin', data: Buffer.alloc(120 * 1024 * 1024), method: 'deflate', fakeUsz: 0 }]));
	let liarRejected = false;
	try { await Net.unzip(zipLiar, path.join(tmp, 'out5')); } catch (_) { liarRejected = true; }
	ok('an entry that under-declares its uncompressed size to 0 is still caught by the inflation backstop', liarRejected && !exists(path.join(tmp, 'out5', 'liar.bin')));

	// 7. Regression for the ZIP64 unpack bug: a genuinely-large archive is written in ZIP64 form, whose classic
	//    end-of-central-directory record carries the 0xFFFF entry-count sentinel. That must NOT be mistaken for a
	//    many-entry bomb — a real (few-entry) ZIP64 container must extract. Build one with the app's own zip writer
	//    forced into ZIP64 mode, so this does not need multi-gigabyte input.
	const { ZipArchive } = require('archiver');
	const zip64 = path.join(tmp, 'z64.zip');
	await new Promise((resolve, reject) => {
		const a = new ZipArchive({ zlib: { level: 0 }, forceZip64: true });
		const out = fs.createWriteStream(zip64);
		a.on('error', reject); out.on('error', reject); out.on('close', resolve);
		a.pipe(out); a.append('hello', { name: 'a.txt' }); a.append('world', { name: 'b.txt' });
		a.finalize().catch(() => {});
	});
	const z64Dest = path.join(tmp, 'out6');
	let z64Ok = true;
	try { await Net.unzip(zip64, z64Dest); } catch (_) { z64Ok = false; }
	ok('a large (ZIP64) archive with the 0xFFFF entry-count sentinel still extracts', z64Ok && exists(path.join(z64Dest, 'a.txt')));

	// 8. A many-entry bomb must be refused from the entry count BEFORE the central directory is opened into one
	//    object per entry (inode/handle exhaustion). Because the classic 16-bit EOCD count maxes out below the limit,
	//    a genuine many-entry archive is ZIP64 — so the real defense reads the 64-bit count from the ZIP64 record.
	//    Forge exactly that: two real entries, but a ZIP64 total-entries far over the limit; it must be rejected and
	//    write nothing. This exercises the fiddly ZIP64 tail parsing that test 7 only runs on its happy path.
	const zipManyZ64 = path.join(tmp, 'many-z64.zip');
	await fsp.writeFile(zipManyZ64, buildZip([['a.txt', 'x'], ['b.txt', 'y']].map(([name, content]) => ({ name, data: content, method: 'store' })), { zip64Count: 200000 }));
	let manyRejected = false;
	try { await Net.unzip(zipManyZ64, path.join(tmp, 'out7')); } catch (_) { manyRejected = true; }
	ok('a ZIP64 archive declaring too many entries is rejected before extraction', manyRejected && !exists(path.join(tmp, 'out7', 'a.txt')));

	// 9. An entry that OVER-declares its COMPRESSED size must not get a raised inflation ceiling. The per-entry cap once
	//    trusted the central-directory compressed size, so declaring it large would let a high-ratio entry inflate about
	//    an order of magnitude past the intended bound. The cap is now keyed off the archive's REAL on-disk size (which
	//    an attacker cannot inflate by lying in the central directory), so this is caught. Build 120 MiB of zeros that
	//    deflate tiny, but declare a 2 MiB compressed size — enough to raise the OLD (declared-size) ceiling well past
	//    120 MiB, while the real archive is only ~120 KiB.
	const zipOverCsz = path.join(tmp, 'overcsz.zip');
	await fsp.writeFile(zipOverCsz, buildZip([{ name: 'over.bin', data: Buffer.alloc(120 * 1024 * 1024), method: 'deflate', fakeCsz: 2 * 1024 * 1024 }]));
	let overRejected = false;
	try { await Net.unzip(zipOverCsz, path.join(tmp, 'out8')); } catch (_) { overRejected = true; }
	ok('an entry that OVER-declares its compressed size is still capped (cap keyed off the real archive bytes)', overRejected && !exists(path.join(tmp, 'out8', 'over.bin')));

	try { await fsp.rm(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UNZIP-SAFETY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
