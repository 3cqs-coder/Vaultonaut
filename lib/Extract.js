'use strict';
// lib/Extract.js — pull searchable text out of common document formats so content search can reach INSIDE
// them, not just plain-text files. It uses pure-JS readers (no native binaries, cross-platform) and runs only
// in the indexing WORKER thread, off the main event loop, one file at a time and bounded by the caller's size
// cap — so a large or awkward document never blocks the app. There is no OCR: a scanned PDF or an image has no
// text layer, so it simply indexes as empty rather than pulling in a heavy recognition engine.
//
// Supported: PDF (its text layer), Word (.docx), Excel (.xlsx/.xlsm, each sheet flattened to CSV text), and
// HTML (tags stripped to readable text). Plain text / markdown / code / json / csv are read directly by the
// caller and never reach here. The legacy binary .xls format (pre-2007) is not indexed for content — such a
// file still stores, mounts, and is found by name; only its cell text is skipped.

// The document readers are required LAZILY, inside extractText and guarded, so a reader that cannot load on a
// given host (a missing dependency, say) degrades to "skip this file" rather than crashing the whole indexing
// worker at load time. Text/code/markdown files never need any of these. Every reader is pure JavaScript with
// no native addon, so the same code runs on every platform with nothing to compile at install time.

// Strip an HTML document to readable text: drop script/style bodies, remove tags, decode the common entities,
// and collapse whitespace. Enough to make a saved web page searchable by its words.
//
// Implemented as a single LINEAR forward scan using indexOf, NOT with a `<(script|style)[\s\S]*?<\/\1>` /
// `<[^>]+>` regex. Those regexes backtrack catastrophically on crafted input — a document of many unterminated
// `<script` (or bare `<`) tokens makes each match attempt scan to end-of-string, which is O(n^2) and can pin the
// indexing worker's CPU for minutes on a ~24 MB file. A forward scan touches each character a constant number of
// times, so hostile HTML costs the same as ordinary HTML. Output stops once it reaches the byte cap, so neither
// time nor memory can run past what will actually be indexed.
function stripHtml(s, cap) {
	s = String(s);
	const lower = s.toLowerCase(); // computed ONCE (never per-iteration, which would itself be O(n^2))
	const limit = (cap && cap > 0) ? cap : Infinity;
	let out = '', i = 0; const n = s.length;
	while (i < n && out.length < limit) {
		const lt = s.indexOf('<', i);
		if (lt < 0) { out += s.slice(i); break; }
		if (lt > i) { out += s.slice(i, lt); i = lt; continue; }
		// At a '<'. If it opens a script/style element, skip its whole body in one indexOf; the extractor never
		// wants that text. Otherwise skip just this one tag up to its '>'.
		const skip = lower.startsWith('script', i + 1) ? 'script' : lower.startsWith('style', i + 1) ? 'style' : null;
		if (skip) { const close = lower.indexOf('</' + skip, i + 1); i = close < 0 ? n : close; out += ' '; continue; }
		const gt = s.indexOf('>', i);
		i = gt < 0 ? n : gt + 1; out += ' ';
	}
	// Decode the common entities on the now tag-free text (fixed-literal replaces — no backtracking), with &amp;
	// LAST so an encoded entity like &amp;lt; is not double-decoded into a '<'. Then collapse whitespace.
	return out
		.replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, '&')
		.replace(/\s+/g, ' ').trim();
}

// DOCX and XLSX are ZIP archives, and their readers (mammoth / read-excel-file) inflate and build a full in-memory
// DOM BEFORE this code can slice the text out — so a small "zip bomb" (a few kilobytes that inflate to gigabytes)
// would exhaust the worker heap despite the 24 MB on-disk read cap, and an out-of-memory crash is not catchable by
// the try/catch below. Guard by reading the ZIP CENTRAL DIRECTORY, which records each entry's UNCOMPRESSED size
// without inflating anything, and refusing to hand the buffer to the reader when the total uncompressed size or the
// entry count is implausibly large for a real document. The bounds are generous for a genuine large office file yet
// far below any bomb; an over-budget file simply indexes by name (returns ''). Pure Node, cross-platform.
const ZIP_MAX_UNCOMPRESSED = 128 * 1024 * 1024; // total inflated bytes across all entries
const ZIP_MAX_ENTRIES = 8192;                   // a real docx/xlsx has tens of entries; thousands means a nested bomb
function zipWithinBudget(buf) {
	try {
		if (!Buffer.isBuffer(buf) || buf.length < 22) return false;
		// Locate the End Of Central Directory record (signature 0x06054b50), scanning back over the fixed 22-byte
		// record plus an optional comment (up to 65535 bytes). The whole file is in the buffer here (it is under the
		// 24 MB read cap), so the record is present for any well-formed archive.
		let eocd = -1; const minPos = Math.max(0, buf.length - (22 + 0xffff));
		for (let i = buf.length - 22; i >= minPos; i--) { if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
		if (eocd < 0) return false; // not a well-formed zip we can vet -> do not inflate it
		const entries = buf.readUInt16LE(eocd + 10);
		const cdOffset = buf.readUInt32LE(eocd + 16);
		if (entries > ZIP_MAX_ENTRIES || cdOffset === 0xffffffff) return false; // too many entries, or ZIP64 (far larger than any real document here) -> treat as a bomb
		let p = cdOffset, total = 0, seen = 0;
		while (seen < entries && p + 46 <= buf.length) {
			if (buf.readUInt32LE(p) !== 0x02014b50) break; // central-directory header signature
			const uncomp = buf.readUInt32LE(p + 24);
			if (uncomp === 0xffffffff) return false;               // ZIP64 per-entry size -> bomb
			total += uncomp;
			if (total > ZIP_MAX_UNCOMPRESSED) return false;
			p += 46 + buf.readUInt16LE(p + 28) + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32); // + name + extra + comment
			seen++;
		}
		return true;
	} catch (_) { return false; } // any parse trouble -> be safe, do not hand it to the inflating reader
}

// Only the first CAP bytes of a document are ever indexed, so there is no reason to materialize more than that
// while extracting — doing so is what lets a modest spreadsheet balloon into gigabytes of CSV in the worker
// heap. Every branch is bounded to produce at most ~CAP: the spreadsheet reader caps the rows it even parses,
// accumulation stops once the budget is met, and every result is sliced. CAP defaults generously; the caller
// passes the real per-file budget.
// A fallback only: the caller (the indexing worker) ALWAYS passes the real per-file budget
// (SearchDefs.PER_FILE_TEXT_CAP), so this value is never load-bearing and cannot drift into a bug. It is kept
// generous so a direct call with no cap still behaves sanely.
const DEFAULT_CAP = 2 * 1024 * 1024;
const XLSX_MAX_ROWS = 50000; // rows parsed per sheet — bounds the parse and the generated CSV regardless of input
const PDF_MAX_PAGES = 5000;  // pages visited per PDF — bounds the walk even for a document whose pages hold NO
                             // text (a scanned PDF never fills the byte cap, so without this the loop would visit
                             // every page of an image-only document and could stall the worker)

// Read an .xlsx/.xlsm workbook (an in-memory buffer) into an array of sheets, each a rows array of cell values.
// read-excel-file returns every sheet as [{ sheet, data }]; a flat rows array (a single sheet) is also handled,
// so this stays correct if the reader's shape shifts. The stream is one-shot, hence built here per call.
async function xlsxSheetRows(buffer) {
	const readXlsxFile = require('read-excel-file/node');
	const { Readable } = require('stream');
	const res = await readXlsxFile(Readable.from(buffer));
	if (!Array.isArray(res)) return [];
	if (res.length && Array.isArray(res[0])) return [res];                       // a flat rows array = a single sheet
	return res.map(s => (s && Array.isArray(s.data)) ? s.data : null).filter(Boolean);
}

// Extract text from a file's bytes by extension. Returns a string (possibly empty for a no-text-layer file),
// or null if the format is not one we extract (the caller then skips or treats it as plain text). Never throws.
async function extractText(buffer, ext, cap = DEFAULT_CAP) {
	try {
		switch (String(ext || '').toLowerCase()) {
			case 'pdf': {
				// A pure-JS PDF.js build (no native canvas — that dependency is for page rendering, which we never
				// do). We only want the text layer. verbosity 0 keeps PDF.js from logging warnings about odd but
				// harmless documents into the indexing worker. Pages are read ONE AT A TIME and accumulation stops the
				// moment it reaches the budget, so peak memory and time stay bounded no matter how many pages a
				// document has or how large its text layer decompresses to — a whole-document merge would defeat the
				// cap by materializing everything first. The document proxy is always destroyed so nothing is
				// retained between files.
				const { getDocumentProxy } = require('unpdf');
				const doc = await getDocumentProxy(new Uint8Array(buffer), { verbosity: 0 });
				try {
					const parts = []; let total = 0;
					const lastPage = Math.min(doc.numPages, PDF_MAX_PAGES); // hard page ceiling — bounds the walk even with no text
					for (let i = 1; i <= lastPage; i++) {
						const page = await doc.getPage(i);
						let piece = '';
						try {
							// Accumulate item by item and stop the moment the running total reaches the budget, so a single
							// page with an enormous text layer cannot balloon the heap building a string we would only slice away.
							for (const it of (await page.getTextContent()).items || []) {
								const s = (it && it.str) || '';
								if (s) piece += (piece ? ' ' : '') + s;
								if (total + piece.length >= cap) break;
							}
						} finally { try { page.cleanup(); } catch (_) {} }
						if (piece) { parts.push(piece); total += piece.length + 1; }
						if (total >= cap) break; // have the budget's worth — stop rather than parse the rest and throw it away
					}
					return parts.join('\n').slice(0, cap);
				} finally { try { await doc.destroy(); } catch (_) {} }
			}
			case 'docx':
				if (!zipWithinBudget(buffer)) return ''; // a zip/xml bomb would inflate past the heap before we could slice — skip it (index by name)
				return ((await require('mammoth').extractRawText({ buffer })).value || '').slice(0, cap);
			case 'xlsx': case 'xlsm': {
				if (!zipWithinBudget(buffer)) return ''; // same bomb guard as docx: the reader inflates the whole workbook before any row cap applies
				const parts = []; let total = 0;
				for (const rows of await xlsxSheetRows(buffer)) {
					const csv = rows.slice(0, XLSX_MAX_ROWS)
						.map(r => (Array.isArray(r) ? r : []).map(c => (c == null ? '' : String(c))).join(','))
						.join('\n').trim();
					if (csv) { parts.push(csv); total += csv.length; if (total >= cap) break; } // stop once we have the budget's worth
				}
				return parts.join('\n\n').slice(0, cap);
			}
			case 'html': case 'htm':
				return stripHtml(buffer.toString('utf8'), cap).slice(0, cap);
			default:
				return null;
		}
	} catch (_) { return ''; } // a malformed document indexes as empty rather than breaking the whole run
}

// The formats this module can extract — the caller's allowlist for "needs an extractor" (vs. plain text).
const EXTRACTABLE = new Set(['pdf', 'docx', 'xlsx', 'xlsm', 'html', 'htm']);

module.exports = { extractText, EXTRACTABLE, stripHtml, zipWithinBudget, ZIP_MAX_UNCOMPRESSED, ZIP_MAX_ENTRIES };
