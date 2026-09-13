'use strict';
// lib/test/extractisolation.js — document text extraction runs in an ISOLATED, resource-capped worker so a crafted
// document can never crash, wedge, or OOM the indexing worker. This proves the property that the in-process zip-bomb
// guard cannot: a "reference bomb" spreadsheet — a tiny file that names a cell at row 20,000,000, which the reader
// (read-excel-file) tries to realize by padding its row array to that length — sails past every byte/ratio/node
// check (it has a handful of tags and inflates to almost nothing) yet exhausts memory the moment the reader parses
// it. The isolation contains it: the extraction worker hits its heap cap and is terminated, the indexer catches that,
// indexes the poison file by NAME only, and finishes the run with every other file fully indexed. No crash, no hang,
// no lost file — and nothing is ever written to the vault by extraction, so backups/mirrors/syncs are unaffected.
//
// Run:  node lib/test/extractisolation.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const MiniSearch = require('minisearch');
const { ZipArchive } = require('archiver');
const WorkerRun = require('../WorkerRun');
const Extract = require('../Extract');
const D = require('../SearchDefs');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Build a minimal, read-excel-file-parseable .xlsx whose single sheet references a cell at a huge row number. The
// reader dimensions its output arrays by cell reference, so parsing this pads millions of empty rows — an OOM that
// no source-byte inspection can predict.
function refBombXlsx(row) {
	return new Promise((resolve, reject) => {
		const a = new ZipArchive({ zlib: { level: 6 } });
		const chunks = [];
		a.on('data', (d) => chunks.push(d)); a.on('warning', reject); a.on('error', reject);
		a.on('end', () => resolve(Buffer.concat(chunks)));
		a.append('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>', { name: '[Content_Types].xml' });
		a.append('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>', { name: '_rels/.rels' });
		a.append('<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S1" sheetId="1" r:id="rId1"/></sheets></workbook>', { name: 'xl/workbook.xml' });
		a.append('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>', { name: 'xl/_rels/workbook.xml.rels' });
		a.append('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="' + row + '"><c r="A' + row + '" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>', { name: 'xl/worksheets/sheet1.xml' });
		a.finalize().catch(reject);
	});
}

function reindex(mountpoint) { return WorkerRun.runWorker(path.join(__dirname, '..', 'SearchWorker.js'), { op: 'index', args: { mountpoint } }, null, { idleMs: 120000, idleMessage: 'Indexing' }); }
async function query(mountpoint, q) {
	const buf = await fsp.readFile(path.join(mountpoint, D.SEARCH_DIR, D.INDEX_NAME));
	const env = D.unpackEnvelope(buf); if (!env) return [];
	const ms = await MiniSearch.loadJSONAsync(env.indexJSON, D.MS_OPTIONS);
	return ms.search(q, { prefix: true, fuzzy: 0.2, boost: { name: 2 }, combineWith: 'AND' }).map((h) => h.path);
}

let tmp = null;
async function main() {
	const bomb = await refBombXlsx(20000000); // references row 20,000,000

	// The guard alone does NOT save us here: the reference bomb passes every in-process check, so only the isolated,
	// resource-capped extraction worker prevents the OOM. This is exactly why extraction must be isolated.
	ok('the reference bomb passes the in-process zip-bomb guard (so isolation is what protects the indexer)', Extract.zipWithinBudget(bomb) === true);
	ok('the reference bomb is tiny on disk', bomb.length < 8 * 1024);

	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-extiso-'));
	const mp = path.join(tmp, 'mount'); await fsp.mkdir(mp, { recursive: true });
	await fsp.writeFile(path.join(mp, 'ledger.xlsx'), bomb);                                  // the poison document
	await fsp.writeFile(path.join(mp, 'report.md'), '# Quarterly report\n\nRevenue grew and expenses fell.'); // a healthy neighbor
	await fsp.writeFile(path.join(mp, 'notes.txt'), 'the quick brown fox jumps over the lazy dog');

	// The whole point: reindexing a vault that contains the poison document COMPLETES rather than crashing or hanging.
	let result = null, threw = false;
	try { result = await reindex(mp); } catch (_) { threw = true; }
	ok('reindexing a vault containing the reference bomb completes without crashing or hanging', !threw && !!result);

	// The poison file is not lost — it is still indexed by NAME (searchable by its filename), just without cell text.
	ok('the poison document is still indexed by name (not dropped from the index)', (await query(mp, 'ledger')).includes('ledger.xlsx'));
	// Its healthy neighbors are fully content-indexed — one bad file does not degrade the rest of the run.
	ok('a healthy neighbor is fully content-indexed in the same run', (await query(mp, 'revenue')).includes('report.md'));
	ok('a healthy plain-text neighbor is content-indexed too', (await query(mp, 'brown')).includes('notes.txt'));
	// A second reindex is stable — the poison file must not cause a re-extract crash loop (it is unchanged, so skipped).
	let threw2 = false; try { await reindex(mp); } catch (_) { threw2 = true; }
	ok('a second reindex over the same vault is stable (no crash loop on the poison file)', !threw2);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EXTRACT-ISOLATION CHECKS PASSED'));
	if (tmp) { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); if (tmp) { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} } process.exit(1); });
