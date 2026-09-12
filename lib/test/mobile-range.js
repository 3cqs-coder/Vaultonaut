'use strict';
// lib/test/mobile-range.js — the streaming RANGE decryptor that lets the mobile client play large media without
// decrypting the whole file. It creates a real MULTI-BLOCK vault file, then, for several byte ranges (start,
// mid spanning a block boundary, end, a single byte, the whole file), maps the range to the ciphertext it needs
// (rangeToBlocks), decrypts only those blocks (decryptBlocks), slices to the exact range, and asserts it matches
// both the original bytes and the whole-file decrypt. This is the core the service-worker media path relies on.
//
// Run:  node lib/test/mobile-range.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function walk(root, rel = '') {
	const out = [];
	for (const e of await fsp.readdir(path.join(root, rel), { withFileTypes: true })) {
		const r = rel ? rel + '/' + e.name : e.name;
		if (e.isDirectory()) out.push(...await walk(root, r)); else out.push(r);
	}
	return out;
}

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-mrange-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir; Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const reader = require('../webserver/public/mobile/crypt-reader.js');

	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// A ~4.5-block file (each plaintext block is 64 KiB) of deterministic but non-repeating bytes.
	const N = 64 * 1024 * 4 + 5000;
	const original = Buffer.alloc(N);
	for (let i = 0; i < N; i++) original[i] = (i * 2654435761) & 0xff; // Knuth multiplicative -> varied bytes
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'movie.bin'), original);
	const v = path.join(tmp, 'Media.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	const cap = JSON.parse(Buffer.from((await vdisk.makeWebReadCap(v, { password: 'pw1' })).token.split('.')[1], 'base64url').toString('utf8'));
	const keys = reader.deriveKeys(cap.key, cap.salt);

	// Find the encrypted file on disk and read its ciphertext.
	const cipherRoot = path.join(v, 'data');
	let cipherPath = null;
	for (const encRel of await walk(cipherRoot)) { try { if (reader.decryptPath(keys.nameKey, keys.nameTweak, encRel, cap.dn) === 'movie.bin') cipherPath = path.join(cipherRoot, encRel); } catch (_) {} }
	ok('the multi-block media file is found in the store', !!cipherPath);
	const cipher = new Uint8Array(await fsp.readFile(cipherPath));

	// Whole-file decrypt matches the original, and the size math is right.
	const whole = Buffer.from(reader.decryptContent(keys.dataKey, cipher));
	ok('the whole file decrypts to the original', whole.equals(original));
	ok('decryptedSize predicts the plaintext length', reader.decryptedSize(cipher.length) === N);

	// The range decryptor, over several ranges, matches the original slice — decrypting only the needed blocks.
	const B = reader.BLOCK_DATA_SIZE;
	const ranges = [
		[0, 100],                       // very start
		[B - 50, B + 50],               // spans the block-0/block-1 boundary
		[B * 2 + 123, B * 3 + 456],     // an interior span across a boundary
		[N - 200, N],                   // the tail (short last block)
		[B * 3, B * 3 + 1],             // a single byte deep in the file
		[0, N],                         // the whole file via the range path
	];
	let allMatch = true, fetchedWholeFileForASmallRange = false;
	for (const [start, end] of ranges) {
		const r = reader.rangeToBlocks(start, end, cipher.length);
		const headerNonce = reader.parseHeaderNonce(cipher.subarray(0, reader.HEADER_SIZE));
		const cipherSlice = cipher.subarray(r.cipherStart, r.cipherEnd);
		const blocksPlain = reader.decryptBlocks(keys.dataKey, headerNonce, cipherSlice, r.firstBlock);
		const got = Buffer.from(blocksPlain.subarray(r.sliceStart, r.sliceEnd));
		if (!got.equals(original.subarray(start, end))) { allMatch = false; console.log('     (range ' + start + '-' + end + ' mismatch)'); }
		// A small range must NOT have fetched the whole file's ciphertext (that would defeat streaming).
		if (end - start <= 200 && cipherSlice.length >= cipher.length - reader.HEADER_SIZE) fetchedWholeFileForASmallRange = true;
	}
	ok('every byte range decrypts to exactly the original bytes', allMatch);
	ok('a small range fetches only a few blocks, not the whole file (true streaming)', !fetchedWholeFileForASmallRange);

	// A flipped ciphertext byte in a fetched block is rejected, never silently wrong.
	const r = reader.rangeToBlocks(0, 100, cipher.length);
	const bad = cipher.slice(r.cipherStart, r.cipherEnd); bad[bad.length - 1] ^= 0xff;
	let rejected = false; try { reader.decryptBlocks(keys.dataKey, reader.parseHeaderNonce(cipher.subarray(0, reader.HEADER_SIZE)), bad, r.firstBlock); } catch (_) { rejected = true; }
	ok('a tampered media block is rejected', rejected);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-RANGE CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
