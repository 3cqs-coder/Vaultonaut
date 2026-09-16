'use strict';
// lib/test/zip.js — the shared zip module's in-memory single-entry reader (Zip.readEntry / Zip.entries) reads a real
// archive, is bounded against a bomb, and fails closed on bad input. The file-to-directory unzip and the directory
// packer (Zip.unzip / Zip.zipDir, also surfaced as Net.unzip / Net.zipDir) are covered by packroundtrip.js and
// unzipsafety.js. Pure and fast: no engine, mount driver, or network — so it runs on every platform.
//
// Run:  node lib/test/zip.js

const Zip = require('../Zip');
const zlib = require('zlib');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function rejects(p, re) { try { await p; return false; } catch (e) { return re.test(e.message); } }

// Build a real single-entry ZIP (method: 8 deflate, or 0 stored) so the reader is exercised against genuine bytes.
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n >>> 0); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
function makeZip(name, content, stored) {
	const nameBuf = Buffer.from(name, 'utf8');
	const data = stored ? content : zlib.deflateRawSync(content);
	const method = stored ? 0 : 8, comp = data.length, uncomp = content.length;
	const local = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(method), u16(0), u16(0), u32(0), u32(comp), u32(uncomp), u16(nameBuf.length), u16(0), nameBuf, data]);
	const central = Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(method), u16(0), u16(0), u32(0), u32(comp), u32(uncomp), u16(nameBuf.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(0), nameBuf]);
	const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(central.length), u32(local.length), u16(0)]);
	return Buffer.concat([local, central, eocd]);
}

async function main() {
	const zip = makeZip('folder/hello.txt', Buffer.from('hello world', 'utf8'));

	// --- entries(): lists the central directory without inflating ---
	const list = Zip.entries(zip);
	ok('entries lists the archive entry', list.length === 1 && list[0].name === 'folder/hello.txt');
	ok('entries reports the uncompressed size', list[0].uncompSize === 'hello world'.length);
	ok('entries on a non-ZIP returns empty', Zip.entries(Buffer.from('not a zip')).length === 0);

	// --- readEntry(): finds by exact path or basename, inflates correctly ---
	ok('readEntry finds an entry by exact path', (await Zip.readEntry(zip, 'folder/hello.txt')).toString('utf8') === 'hello world');
	ok('readEntry finds an entry by basename', (await Zip.readEntry(zip, 'hello.txt')).toString('utf8') === 'hello world');
	ok('readEntry returns null for a missing entry', (await Zip.readEntry(zip, 'nope.txt')) === null);

	// --- a STORED (uncompressed) entry is read too ---
	const stored = makeZip('s.txt', Buffer.from('stored bytes', 'utf8'), true);
	ok('readEntry reads a stored entry', (await Zip.readEntry(stored, 's.txt')).toString('utf8') === 'stored bytes');

	// --- bounded: a deflate entry larger than maxBytes makes zlib throw rather than exhausting memory ---
	const big = makeZip('big.txt', Buffer.alloc(50000, 0x61)); // 50 KB of 'a' compresses tiny but inflates to 50 KB
	ok('readEntry rejects an entry over the maxBytes ceiling', await rejects(Zip.readEntry(big, 'big.txt', { maxBytes: 1024 }), /./));
	ok('readEntry accepts the same entry under a generous ceiling', (await Zip.readEntry(big, 'big.txt', { maxBytes: 1 << 20 })).length === 50000);

	// --- fails closed on bad input ---
	ok('readEntry refuses a non-ZIP buffer', await rejects(Zip.readEntry(Buffer.from('nope'), 'x'), /valid ZIP/));

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL ZIP CHECKS PASSED');
}
main().catch((e) => { console.error(e); process.exit(1); });
