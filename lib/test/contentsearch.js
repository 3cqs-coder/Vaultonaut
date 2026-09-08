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
	ok('a word inside a file is found', (await query(mp, 'revenue')).some(p => p === 'report.md'));
	ok('a word in a nested file is found', (await query(mp, 'widgets')).some(p => p === 'sub/memo.txt'));
	ok('a value inside a json file is found', (await query(mp, 'acme')).some(p => p === 'data.json'));
	ok('prefix search matches', (await query(mp, 'quar')).some(p => p === 'report.md'));
	ok('a word that is in no file returns nothing', (await query(mp, 'zebra')).length === 0);

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
