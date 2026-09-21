'use strict';
// lib/test/contentsearch.js — the CONTENT-search index (search inside files). It drives the real indexing
// worker and the real query path against a directory that stands in for a mounted vault (the worker and the
// query only ever see a filesystem path — the encryption is the mount's job, exercised elsewhere). It checks:
// a first build indexes every text file and finds words inside them; a second build is INCREMENTAL (only
// added/changed/removed files move) and its results reflect edits and deletions; binaries and oversized files
// are skipped; and the persisted index is a compact gzipped envelope that reloads under the same options.
//
// Run:  node lib/test/contentsearch.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const MiniSearch = require('minisearch');
const WorkerRun = require('../WorkerRun');
const D = require('../SearchDefs');
const { ZipArchive } = require('archiver'); // the same streaming zip writer the app uses — build the .docx fixture with it, no separate zip library
const zlib = require('zlib'); // to craft a "lying" deflate stream (small declared size, large real inflation) for the bomb guard

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Build a small in-memory zip (e.g. a .docx, which is a zip of XML parts) from a { name: content } map.
function zipToBuffer(parts) {
	return new Promise((resolve, reject) => {
		const a = new ZipArchive({ zlib: { level: 0 } });
		const chunks = [];
		a.on('data', (d) => chunks.push(d));
		a.on('warning', reject);
		a.on('error', reject);
		a.on('end', () => resolve(Buffer.concat(chunks)));
		for (const [name, content] of Object.entries(parts)) a.append(content, { name });
		a.finalize().catch(reject);
	});
}

function reindex(mountpoint) { return WorkerRun.runWorker(path.join(__dirname, '..', 'SearchWorker.js'), { op: 'index', args: { mountpoint } }, null, { idleMs: 60000, idleMessage: 'Indexing' }); }
async function query(mountpoint, q) {
	const buf = await fsp.readFile(path.join(mountpoint, D.SEARCH_DIR, D.INDEX_NAME));
	const env = D.unpackEnvelope(buf); if (!env) return null;
	const ms = await MiniSearch.loadJSONAsync(env.indexJSON, D.MS_OPTIONS);
	return ms.search(q, { prefix: true, fuzzy: 0.2, boost: { name: 2 }, combineWith: 'AND' }).map(h => h.path);
}

let tmp = null;
async function main() {
	// Static invariant: the indexing worker's heap must sit well above the index-size ceiling. Saving the index
	// holds the live structure AND its serialized copy at once, and the graceful "index too large, keep the last
	// good one" refusal is decided from that serialized size — so if the heap were only ~2x the ceiling, a vault
	// whose index approaches the ceiling would be OOM-killed before the refusal ran, turning a clean message into a
	// crash-and-retry reindex loop. Pin the margin (cap >= 3x the ceiling) so it cannot silently regress.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	const capM = vaultSrc.match(/SearchWorker\.js[\s\S]{0,240}?maxOldGenerationSizeMb:\s*(\d+)/);
	const capBytes = capM ? Number(capM[1]) * 1024 * 1024 : 0;
	ok('the search worker heap cap leaves headroom above the index-size ceiling (>= 3x)', capBytes >= D.MAX_SEARCH_INDEX_BYTES * 3);

	// The inline/worker boundary must be a sane positive size strictly below the hard read cap: at or above the cap it
	// would never route to the worker (defeating the offload), and zero/negative would send every search to the worker
	// (defeating the fast cached path). Pin it so a bad edit to SEARCH_INLINE_MAX_BYTES fails here.
	ok('SEARCH_INLINE_MAX_BYTES sits sanely between 0 and the hard read cap', D.SEARCH_INLINE_MAX_BYTES > 0 && D.SEARCH_INLINE_MAX_BYTES < D.MAX_SEARCH_INDEX_BYTES);

	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-csearch-'));
	const mp = path.join(tmp, 'mount'); await fsp.mkdir(path.join(mp, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(mp, 'notes.txt'), 'the quick brown fox jumps over the lazy dog');
	await fsp.writeFile(path.join(mp, 'report.md'), '# Quarterly report\n\nRevenue grew and expenses fell.');
	await fsp.writeFile(path.join(mp, 'data.json'), JSON.stringify({ customer: 'acme', amount: 500 }));
	await fsp.writeFile(path.join(mp, 'sub', 'memo.txt'), 'a memo about widgets and gizmos');
	await fsp.writeFile(path.join(mp, 'photo.bin'), Buffer.from([0, 1, 2, 0, 255, 0])); // binary, not text-like -> skipped
	// Document formats, extracted with pure-JS readers: a real Word .docx, an Excel .xlsx, and an HTML page.
	const docxParts = {
		'[Content_Types].xml': '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
		'_rels/.rels': '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
		'word/document.xml': '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>confidential merger agreement</w:t></w:r></w:p></w:body></w:document>'
	};
	await fsp.writeFile(path.join(mp, 'deal.docx'), await zipToBuffer(docxParts)); // built with the same streaming zip writer the app uses
	// A real .xlsx fixture (sheet S1: Region/Note, EMEA/"quarterly revenue"), committed so the test needs no
	// spreadsheet-writing dependency — only the reader the app itself uses.
	await fsp.copyFile(path.join(__dirname, 'fixtures', 'book.xlsx'), path.join(mp, 'book.xlsx'));
	await fsp.writeFile(path.join(mp, 'page.html'), '<html><body><h1>Heading</h1><script>ignore()</script><p>penultimate paragraph</p></body></html>');
	await fsp.writeFile(path.join(mp, 'invoice.pdf'), Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n4 0 obj<</Length 46>>stream\nBT /F1 24 Tf 20 120 Td (remittance payable soon) Tj ET\nendstream\nendobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF', 'latin1'));

	// First build.
	const r1 = await reindex(mp);
	ok('a first build indexes text files and documents (binary skipped)', r1.indexed === 8 && r1.added === 8 && r1.removed === 0);
	ok('text inside a Word .docx is found', (await query(mp, 'merger')).some(p => p === 'deal.docx'));
	ok('text inside an Excel .xlsx is found', (await query(mp, 'quarterly')).some(p => p === 'book.xlsx'));
	ok('text inside an HTML page is found (tags stripped)', (await query(mp, 'penultimate')).some(p => p === 'page.html'));
	ok('text inside a PDF is found', (await query(mp, 'remittance')).some(p => p === 'invoice.pdf'));

	// --- hostile-document guards: a zip/xml bomb must be refused BEFORE the reader inflates it, and the HTML
	// stripper must stay linear on crafted input rather than backtracking for minutes. These run in the indexing
	// worker off the main loop, but a bomb there still breaks indexing and pins memory/CPU, so they are guarded. ---
	const Extract = require('../Extract');
	// A minimal, hand-crafted ZIP whose central directory CLAIMS a given uncompressed size and entry count, without
	// storing any data — exactly the shape of a bomb, and enough to exercise the pre-parse budget check.
	const craftZip = (uncompressed, entries = 1) => {
		const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt32LE(uncompressed >>> 0, 24);
		const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries, 8); eocd.writeUInt16LE(entries, 10); eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(0, 16);
		return Buffer.concat([cd, eocd]);
	};
	ok('a real office .docx is within the zip budget (not falsely rejected)', Extract.zipWithinBudget(await zipToBuffer(docxParts)) === true);
	ok('a zip claiming a huge uncompressed size is rejected as a bomb', Extract.zipWithinBudget(craftZip(Extract.ZIP_MAX_UNCOMPRESSED + 1)) === false);
	ok('a zip claiming a ZIP64 (0xFFFFFFFF) uncompressed size is rejected', Extract.zipWithinBudget(craftZip(0xffffffff)) === false);
	ok('a zip with an implausible entry count is rejected', Extract.zipWithinBudget(craftZip(10, Extract.ZIP_MAX_ENTRIES + 1)) === false);
	ok('a non-zip buffer is not treated as a parseable archive', Extract.zipWithinBudget(Buffer.from('this is not a zip at all')) === false);
	// A bomb-shaped .docx therefore extracts as empty (indexed by name), never handed to the inflating reader.
	ok('a bomb-shaped .docx extracts as empty rather than inflating', (await Extract.extractText(craftZip(Extract.ZIP_MAX_UNCOMPRESSED + 1), 'docx', 1024)) === '');

	// LYING ZIP: the dangerous case a declared-size check misses. A real deflate LOCAL file header holds a stream that
	// inflates to a chosen real size, while the archive's declared sizes AND its end-of-directory entry count lie. The
	// guard must walk the LOCAL headers (what the reader actually reads) and judge by the REAL inflated size, so a
	// stream that blows the budget is rejected even when the archive declares a few bytes or claims zero entries, while
	// a stream within the budget is accepted even though its declared size is not trusted. `eocdEntries` lets the test
	// make the central directory / end record lie about how many entries exist.
	// `fill` picks the content: a bomb (default) fills with one repeated byte so it compresses to almost nothing (tiny
	// on disk, huge inflated — a decompression bomb the byte budget catches); a realistic document ('real') uses varied
	// text that compresses only a few times, modeling an honest file.
	const craftDeflateZip = (realBytes, declaredSize, eocdEntries = 1, fill = 'bomb') => {
		const raw = fill === 'real'
			? Buffer.from('The quick brown fox jumps over the lazy dog. '.repeat(Math.ceil(realBytes / 45))).subarray(0, realBytes) // ~2-4x deflate ratio, like real text
			: Buffer.alloc(realBytes, 0x41);                  // 'A' * realBytes -> compresses near the DEFLATE max, inflates to realBytes
		const comp = zlib.deflateRawSync(raw);
		const name = Buffer.from('word/document.xml');
		const lfh = Buffer.alloc(30);
		lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(8, 8);   // method 8 = deflate
		lfh.writeUInt32LE(comp.length, 18); lfh.writeUInt32LE(declaredSize >>> 0, 22);
		lfh.writeUInt16LE(name.length, 26); lfh.writeUInt16LE(0, 28);
		const fileData = Buffer.concat([lfh, name, comp]);
		const cd = Buffer.alloc(46);
		cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(8, 10);
		cd.writeUInt32LE(comp.length, 20); cd.writeUInt32LE(declaredSize >>> 0, 24);
		cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(0, 42);                             // local header offset 0
		const cdBuf = Buffer.concat([cd, name]);
		const eocd = Buffer.alloc(22);
		eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(eocdEntries, 8); eocd.writeUInt16LE(eocdEntries, 10);
		eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(fileData.length, 16);
		return Buffer.concat([fileData, cdBuf, eocd]);
	};
	const lyingBomb = craftDeflateZip(Extract.ZIP_MAX_UNCOMPRESSED + 8 * 1024 * 1024, 12); // ~136 MiB real, declares 12 bytes
	ok('a zip that DECLARES a tiny size but really inflates past the budget is rejected', Extract.zipWithinBudget(lyingBomb) === false);
	ok('the lying bomb is small on disk (a declared-size check would have waved it through)', lyingBomb.length < 512 * 1024);
	ok('a lying .docx extracts as empty rather than inflating gigabytes into the worker', (await Extract.extractText(lyingBomb, 'docx', 1024)) === '');
	const honestSmall = craftDeflateZip(64 * 1024, 5, 1, 'real'); // 64 KiB real, declares only 5 bytes -> judged by REAL size, accepted
	ok('a zip within budget is accepted by its REAL inflated size, not its declared size', Extract.zipWithinBudget(honestSmall) === true);
	// The bypass a central-directory-driven guard misses: the end record claims ZERO entries, but a real local header
	// holds a budget-blowing deflate stream that a streaming reader (read-excel-file) would enumerate and inflate. The
	// local-header walk must still see it and refuse; an honest small archive that also lies about its count is fine.
	const zeroCountBomb = craftDeflateZip(Extract.ZIP_MAX_UNCOMPRESSED + 8 * 1024 * 1024, 12, 0);
	ok('a bomb hidden behind a zero-entry end record is still rejected (local-header walk, not the central directory)', Extract.zipWithinBudget(zeroCountBomb) === false);
	ok('a bomb behind a lying end record extracts as empty rather than inflating (xlsx path)', (await Extract.extractText(zeroCountBomb, 'xlsx', 1024)) === '');
	ok('an honest small archive that also lies about its entry count is still accepted', Extract.zipWithinBudget(craftDeflateZip(64 * 1024, 5, 0, 'real')) === true);
	// The element-count (DOM-amplification) layer: the readers build one heavy in-memory node per XML tag, so a
	// tag-dense part can exhaust a reader even while its INFLATED BYTES sit under the total budget. Bounding the byte
	// size is not enough; the tag count must be bounded too. Craft an entry that inflates well under the byte budget
	// but is nothing but tiny elements (tens of millions of tags, over the node cap), and an honest entry of similar
	// inflated size that is mostly text (few tags).
	const denseElementZip = (raw) => {
		const comp = zlib.deflateRawSync(raw);
		const name = Buffer.from('word/document.xml');
		const lfh = Buffer.alloc(30); lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(8, 8); lfh.writeUInt32LE(comp.length, 18); lfh.writeUInt32LE(raw.length >>> 0, 22); lfh.writeUInt16LE(name.length, 26);
		const fileData = Buffer.concat([lfh, name, comp]);
		const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(8, 10); cd.writeUInt32LE(comp.length, 20); cd.writeUInt32LE(raw.length >>> 0, 24); cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(0, 42);
		const cdBuf = Buffer.concat([cd, name]);
		const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10); eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(fileData.length, 16);
		return Buffer.concat([fileData, cdBuf, eocd]);
	};
	// Fixture node counts are DERIVED from the exported cap so they self-adjust if it is ever retuned (the cap is the
	// one guard constant that must not drift from its test). Each `<a/>` contributes one node marker ('<'), each
	// `a="1" ` one ('='). A meta-check keeps the "over" fixture under the byte budget so the NODE cap — not the byte
	// budget — is what rejects it (6 bytes per `a="1" ` node is the densest marker used below).
	const NODES_OVER = Extract.ZIP_MAX_NODES + 2 * 1024 * 1024;  // comfortably over the node cap
	const NODES_UNDER = Math.floor(Extract.ZIP_MAX_NODES / 2);   // comfortably under the node cap
	ok('the over-cap node fixtures stay under the byte budget (so the node cap is what rejects them)', NODES_OVER * 6 < Extract.ZIP_MAX_UNCOMPRESSED);
	const denseBomb = denseElementZip(Buffer.from('<a/>'.repeat(NODES_OVER))); // over the node cap, under the byte budget
	ok('a tag-dense entry under the byte budget is rejected by the element-count cap (DOM amplification)', Extract.zipWithinBudget(denseBomb) === false);
	ok('the dense-element bomb is small on disk', denseBomb.length < 512 * 1024);
	ok('a tag-dense .docx extracts as empty rather than building a giant DOM in the reader', (await Extract.extractText(denseBomb, 'docx', 1024)) === '');
	const textHeavy = denseElementZip(Buffer.from('<w:t>' + 'The quick brown fox jumps over the lazy dog. '.repeat(400000) + '</w:t>')); // ~18 MiB inflated, only a handful of tags
	ok('a text-heavy entry of similar inflated size (few tags) is accepted', Extract.zipWithinBudget(textHeavy) === true);
	// ATTRIBUTE amplification: attributes carry no '<' but each becomes a heavy DOM node, so a single element packed with
	// millions of attributes builds a giant DOM while a tag-only count sees almost nothing. Every attribute has an '=',
	// so counting '=' too catches it. Build one <w:t> element with enough attributes to pass the node cap (~14M `=`)
	// while staying UNDER the total byte budget, so it is the node-count cap (not the byte budget) that refuses it.
	const attrBomb = denseElementZip(Buffer.from('<w:t ' + 'a="1" '.repeat(NODES_OVER) + '/>')); // attributes over the node cap, inflated size under the byte budget, only one '<'
	ok('an attribute-dense entry (few tags, millions of attributes) is rejected by the node-count cap', Extract.zipWithinBudget(attrBomb) === false);
	ok('the attribute bomb is within the on-disk read cap (so it would otherwise reach the reader) yet is refused', attrBomb.length < D.EXTRACT_MAX_BYTES);
	ok('an attribute-dense .docx extracts as empty rather than building a giant DOM (mammoth path)', (await Extract.extractText(attrBomb, 'docx', 1024)) === '');
	// The node cap is a cheap pre-filter, not the memory guarantee (the isolated extraction process is), so it is kept
	// generous: a document with several million nodes — the size class of a large real spreadsheet — is accepted for
	// content indexing rather than falsely skipped. (A tighter cap used to reject data-heavy spreadsheets of this size.)
	const largeDoc = denseElementZip(Buffer.from('<w:t ' + 'a="1" '.repeat(NODES_UNDER) + '/>')); // nodes comfortably under the node cap and the byte budget
	ok('a document with several million nodes (a large real spreadsheet class) is accepted, not falsely rejected', Extract.zipWithinBudget(largeDoc) === true);
	// A STORED (uncompressed) entry that sets the data-descriptor flag must still be node-counted (using the central
	// directory's size), not skipped — otherwise a dense stored part reaches the reader unvetted. It exceeds the node
	// cap here only if its nodes are actually counted, so a rejection proves the stored + data-descriptor path is vetted.
	const storedDenseDD = (() => {
		const raw = Buffer.from('<w:t ' + 'a="1" '.repeat(NODES_OVER) + '/>'); // stored, attributes over the node cap
		const name = Buffer.from('word/document.xml');
		const lfh = Buffer.alloc(30); lfh.writeUInt32LE(0x04034b50, 0); lfh.writeUInt16LE(20, 4); lfh.writeUInt16LE(0x08, 6); lfh.writeUInt16LE(0, 8); lfh.writeUInt16LE(name.length, 26); // stored, data-descriptor flag set, local sizes left 0
		const fileData = Buffer.concat([lfh, name, raw]);
		const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(0, 10); cd.writeUInt32LE(raw.length >>> 0, 20); cd.writeUInt32LE(raw.length >>> 0, 24); cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(0, 42); // CD carries the real size
		const cdBuf = Buffer.concat([cd, name]);
		const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10); eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(fileData.length, 16);
		return Buffer.concat([fileData, cdBuf, eocd]);
	})();
	ok('a stored data-descriptor entry is still node-counted via the central directory (not skipped)', Extract.zipWithinBudget(storedDenseDD) === false);
	// The OTHER enumeration bypass: mammoth reads the CENTRAL DIRECTORY, not the local headers in order. So a bomb can
	// be hidden where a sequential local-header walk never reaches (behind a gap, or an honest first entry), while the
	// central directory still points the reader straight at it. The guard must vet the central-directory entries too.
	// Build: [honest small local entry][2-byte gap that ends the sequential walk][bomb local entry], with a central
	// directory that lists BOTH at their real offsets.
	const cdBypassBomb = (() => {
		const mk = (name, real, declared) => { const comp = zlib.deflateRawSync(Buffer.alloc(real, 0x41)); const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(8, 8); h.writeUInt32LE(comp.length, 18); h.writeUInt32LE(declared >>> 0, 22); h.writeUInt16LE(name.length, 26); return { local: Buffer.concat([h, Buffer.from(name), comp]), comp, name }; };
		const cd = (e, lho) => { const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(8, 10); c.writeUInt32LE(e.comp.length, 20); c.writeUInt32LE(12, 24); c.writeUInt16LE(e.name.length, 28); c.writeUInt32LE(lho >>> 0, 42); return Buffer.concat([c, Buffer.from(e.name)]); };
		const e1 = mk('a.xml', 64, 9), bomb = mk('word/document.xml', Extract.ZIP_MAX_UNCOMPRESSED + 8 * 1024 * 1024, 12);
		const gap = Buffer.from([0, 0]);
		const fileData = Buffer.concat([e1.local, gap, bomb.local]);
		const cdBuf = Buffer.concat([cd(e1, 0), cd(bomb, e1.local.length + gap.length)]);
		const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(2, 8); eocd.writeUInt16LE(2, 10); eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(fileData.length, 16);
		return Buffer.concat([fileData, cdBuf, eocd]);
	})();
	ok('a bomb reachable only via the central directory (not the sequential walk) is rejected', Extract.zipWithinBudget(cdBypassBomb) === false);
	ok('the central-directory bomb is small on disk', cdBypassBomb.length < 512 * 1024);
	ok('a central-directory bomb .docx extracts as empty rather than inflating (mammoth path)', (await Extract.extractText(cdBypassBomb, 'docx', 1024)) === '');

	// sliceText must not leave half of a surrogate pair at the cut: slicing "ab😀" to 3 UTF-16 units would end on a
	// lone high surrogate, so the trailing half is dropped (here to "ab"); a slice that ends on a whole character is
	// left intact.
	ok('sliceText drops a dangling high surrogate at the cut', Extract.sliceText('ab\u{1F600}', 3) === 'ab');
	ok('sliceText keeps a clean cut intact', Extract.sliceText('abcd', 3) === 'abc');
	ok('sliceText keeps a whole surrogate pair when it fits', Extract.sliceText('a\u{1F600}b', 3) === 'a\u{1F600}');
	// The HTML stripper is linear: a pathological run of unterminated <script tokens returns fast and correct.
	ok('stripHtml decodes entities and drops tags correctly', Extract.stripHtml('<p>a &amp; b <b>c</b></p>', 1000) === 'a & b c');
	const redosStart = Date.now();
	const redos = Extract.stripHtml('<script'.repeat(300000), 2 * 1024 * 1024);
	// A generous bound: a genuinely linear pass over 2 MB finishes in milliseconds, while catastrophic backtracking on
	// this input would run for many seconds (effectively forever), so a wide ceiling still catches ReDoS without
	// flaking on a throttled/shared CI runner where a tight 2 s bound could be crossed by scheduling jitter alone.
	ok('stripHtml stays linear on crafted input (no catastrophic backtracking)', (Date.now() - redosStart) < 8000 && typeof redos === 'string');
	ok('a word inside a file is found', (await query(mp, 'revenue')).some(p => p === 'report.md'));
	ok('a word in a nested file is found', (await query(mp, 'widgets')).some(p => p === 'sub/memo.txt'));
	ok('a value inside a json file is found', (await query(mp, 'acme')).some(p => p === 'data.json'));
	ok('prefix search matches', (await query(mp, 'quar')).some(p => p === 'report.md'));
	ok('a word that is in no file returns nothing', (await query(mp, 'zebra')).length === 0);

	// --- the LARGE-index query path: the same search, run OFF the event loop in the worker ---
	// A large index would stall the event loop if its string were materialized and MiniSearch.search ran inline, so
	// contentSearch hands a large index to the search worker's `query` op. Drive that op directly and confirm it
	// returns the SAME hits as the direct main-thread query for several terms — the two paths share SearchDefs.queryIndex,
	// so they must never diverge. Then confirm the empty-index and no-match cases degrade cleanly.
	async function workerQuery(mp2, q) { const r = await WorkerRun.runWorker(path.join(__dirname, '..', 'SearchWorker.js'), { op: 'query', args: { mountpoint: mp2, query: q } }, null, { maxMs: 60000, idleMessage: 'Searching' }); return { paths: (r.results || []).map((h) => h.path), r }; }
	for (const term of ['revenue', 'widgets', 'acme', 'quar', 'merger']) {
		const direct = (await query(mp, term)).slice().sort();
		const viaWorker = (await workerQuery(mp, term)).paths.slice().sort();
		ok('the worker query op matches the direct query for "' + term + '"', JSON.stringify(direct) === JSON.stringify(viaWorker));
	}
	ok('the worker query op returns nothing for a word in no file', (await workerQuery(mp, 'zebra')).paths.length === 0);
	ok('the worker query op shapes hits as { path, name, score }', await (async () => { const r = (await workerQuery(mp, 'revenue')).r; const h = (r.results || [])[0]; return !!h && typeof h.path === 'string' && typeof h.name === 'string' && typeof h.score === 'number'; })());
	{
		const empty = path.join(tmp, 'noindex'); await fsp.mkdir(empty, { recursive: true });
		ok('the worker query op reports no index when there is none (no hang, no throw)', (await workerQuery(empty, 'x')).r.noIndex === true);
	}

	// The persisted index is a gzipped envelope (compact, reloadable), not raw plaintext JSON.
	const raw = await fsp.readFile(path.join(mp, D.SEARCH_DIR, D.INDEX_NAME));
	ok('the index is written as a gzipped envelope', raw[0] === 0x1f && raw[1] === 0x8b);
	ok('a corrupt/incompatible envelope is rejected (forces a rebuild)', D.unpackEnvelope(Buffer.from('not gzip')) === null);

	// Envelope framing (v3: meta / manifest / index). A read caller omits opts and gets the schema fields and the
	// index string but NOT the manifest, so a large manifest is never parsed on the event loop; the indexing worker
	// asks for it explicitly. And the ONE inline parse a query does is hard-bounded: an index that claims a huge meta
	// length, or segment lengths that overrun the buffer, is refused (rebuild) rather than parsed or mis-sliced.
	{
		const zlib = require('zlib');
		const manifest = { 'a.txt': { size: 1, mtimeMs: 2 }, 'b/c.txt': { size: 3, mtimeMs: 4 } };
		const packed = D.packEnvelope({ manifest, indexJSON: '{"x":1}' });
		const read = D.unpackEnvelope(packed);
		ok('a read unpack exposes schema + fileCount and the index, but not the manifest', read && read.fileCount === 2 && read.indexJSON === '{"x":1}' && read.manifest === undefined);
		ok('a read unpack reports the index byte length cheaply', read && read.indexBytes === Buffer.byteLength('{"x":1}', 'utf8'));
		// The UI-polled status probe passes metaOnly, so the (up to 512 MiB) index string is NEVER materialized — it
		// only needs fileCount. It still gets the byte length for free. Building that string would otherwise be a
		// synchronous multi-hundred-megabyte toString on the event loop for a large (attacker-chosen) shared index.
		const meta = D.unpackEnvelope(packed, { metaOnly: true });
		ok('a metaOnly unpack exposes fileCount and index byte length but never materializes the index string', meta && meta.fileCount === 2 && meta.indexBytes === Buffer.byteLength('{"x":1}', 'utf8') && meta.indexJSON === undefined && meta.manifest === undefined);
		// The query path materializes the index STRING only when it is small enough to load and search inline. With
		// maxInlineIndexBytes set, a larger index comes back with its byte length but WITHOUT the string, so contentSearch
		// hands it to the worker instead of doing a multi-hundred-megabyte synchronous toString on the event loop.
		const gated = D.unpackEnvelope(packed, { maxInlineIndexBytes: 0 });
		ok('unpack withholds the index string above the inline cap but still reports its size', gated && gated.indexJSON === undefined && gated.indexBytes === Buffer.byteLength('{"x":1}', 'utf8'));
		const ungated = D.unpackEnvelope(packed, { maxInlineIndexBytes: 1 << 20 });
		ok('unpack materializes the index string when under the inline cap', ungated && ungated.indexJSON === '{"x":1}');
		// Source guard: contentSearch must actually ROUTE a large index to the worker query op — pin the gate so the
		// offload cannot silently regress to loading and searching a large index on the event loop.
		ok('contentSearch routes a large index to the worker query op (offload not regressed)', /maxInlineIndexBytes:\s*SearchDefs\.SEARCH_INLINE_MAX_BYTES/.test(vaultSrc) && /op:\s*'query'/.test(vaultSrc) && /!env\.indexJSON/.test(vaultSrc));
		const full = D.unpackEnvelope(packed, { withManifest: true });
		ok('a worker unpack (withManifest) returns the change manifest intact', full && full.manifest && full.manifest['b/c.txt'] && full.manifest['b/c.txt'].size === 3);
		const bigMeta = Buffer.alloc(8); bigMeta.writeUInt32BE(5 * 1024 * 1024, 0); bigMeta.writeUInt32BE(0, 4);
		ok('an envelope claiming an over-cap meta length is rejected', D.unpackEnvelope(zlib.gzipSync(Buffer.concat([bigMeta, Buffer.alloc(16)]))) === null);
		const overrun = Buffer.alloc(8); overrun.writeUInt32BE(10, 0); overrun.writeUInt32BE(1 << 20, 4);
		ok('an envelope whose segment lengths overrun the buffer is rejected', D.unpackEnvelope(zlib.gzipSync(Buffer.concat([overrun, Buffer.from('{"schemaVersion":3}')]))) === null);
	}

	// Incremental: edit one file, add one, delete one. Only those move.
	await fsp.writeFile(path.join(mp, 'report.md'), '# Annual report\n\nProfit soared on strong margins.');
	await fsp.writeFile(path.join(mp, 'new.txt'), 'a brand new document about penguins');
	await fsp.rm(path.join(mp, 'data.json'));
	const r2 = await reindex(mp);
	ok('a second build is incremental (1 added, 1 changed, 1 removed)', r2.added === 1 && r2.changed === 1 && r2.removed === 1);
	ok('the edited file is found by its new content', (await query(mp, 'penguins')).some(p => p === 'new.txt'));
	ok('the edited file is found by its new words', (await query(mp, 'margins')).some(p => p === 'report.md'));
	ok('the edited file no longer matches its OLD content', !(await query(mp, 'expenses')).length);
	ok('the deleted file is gone from the index', !(await query(mp, 'acme')).length);

	// A no-op rebuild moves nothing AND rewrites nothing: the persisted bytes must stay byte-identical. Rewriting an
	// unchanged index would needlessly repack it (possibly into different bytes after a dependency upgrade) and, since
	// the index file is part of the vault's tamper baseline, could raise a FALSE tamper alarm on a sealed vault the
	// user never touched.
	const indexPath = path.join(mp, D.SEARCH_DIR, D.INDEX_NAME);
	const beforeNoop = await fsp.readFile(indexPath);
	const r3 = await reindex(mp);
	ok('a rebuild with no changes moves nothing', r3.added === 0 && r3.changed === 0 && r3.removed === 0 && r3.indexed === 8);
	ok('a no-change rebuild reports unchanged and leaves the index bytes untouched', r3.unchanged === true && (await fsp.readFile(indexPath)).equals(beforeNoop));

	// A word stored DECOMPOSED (NFD — as macOS and many exported documents do) must still be found by an ordinary
	// (NFC) query, because the index normalizes extracted text to NFC to match the NFC-normalized query. Without that,
	// an accented term would match a file's NAME but not the same word inside its body.
	await fsp.writeFile(path.join(mp, 'cafe.txt'), 'meet at the café by noon'); // "café" written with a combining acute (NFD)
	const r4 = await reindex(mp);
	ok('a new file is indexed incrementally', r4.added === 1);
	ok('an accented word stored decomposed (NFD) is found by an NFC query', (await query(mp, 'café')).some(p => p === 'cafe.txt'));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CONTENT-SEARCH CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
