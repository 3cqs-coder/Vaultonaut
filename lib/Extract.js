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
function stripHtml(s) {
	return String(s)
		.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
		.replace(/<[^>]+>/g, ' ')
		.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
		.replace(/\s+/g, ' ').trim();
}

// Only the first CAP bytes of a document are ever indexed, so there is no reason to materialize more than that
// while extracting — doing so is what lets a modest spreadsheet balloon into gigabytes of CSV in the worker
// heap. Every branch is bounded to produce at most ~CAP: the spreadsheet reader caps the rows it even parses,
// accumulation stops once the budget is met, and every result is sliced. CAP defaults generously; the caller
// passes the real per-file budget.
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
				return ((await require('mammoth').extractRawText({ buffer })).value || '').slice(0, cap);
			case 'xlsx': case 'xlsm': {
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
				return stripHtml(buffer.toString('utf8')).slice(0, cap);
			default:
				return null;
		}
	} catch (_) { return ''; } // a malformed document indexes as empty rather than breaking the whole run
}

// The formats this module can extract — the caller's allowlist for "needs an extractor" (vs. plain text).
const EXTRACTABLE = new Set(['pdf', 'docx', 'xlsx', 'xlsm', 'html', 'htm']);

module.exports = { extractText, EXTRACTABLE };
