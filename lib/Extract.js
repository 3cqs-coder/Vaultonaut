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

const zlib = require('zlib'); // a Node built-in; used to vet a ZIP's REAL inflated size before a reader touches it

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
// the try/catch below. A ZIP records each entry's uncompressed size, but that field is ATTACKER-CONTROLLED and the
// inflating readers IGNORE it (DEFLATE is self-terminating; they decompress the whole stream regardless), so a
// declared-size check is worthless.
//
// The two readers ENUMERATE entries differently: read-excel-file walks the LOCAL FILE HEADERS from the start of the
// file, while mammoth (via jszip) reads the CENTRAL DIRECTORY. A guard that checked only one of the two could be
// bypassed by an archive whose two enumerations disagree — hiding the bomb in an entry the checked enumeration never
// reaches while the reader's enumeration still inflates it. So this vets BOTH: it inflates every entry reached by the
// sequential local-header walk AND every entry listed in the central directory, charging each unique data offset once.
//
// This runs as a cheap PRE-FILTER inside the isolated extraction process — it rejects the obvious bombs before they
// cost a full parse, but it is NOT the memory guarantee (the process's own heap and RSS caps are, so anything that
// slips past this is still contained). It therefore uses only the checks that are cheap and never wrongly reject a
// real document:
//   * a total UNCOMPRESSED budget across the whole archive — rejects a decompression bomb (a few kilobytes that
//     inflate to gigabytes) and bounds this guard's own inflation;
//   * a NODE-count cap — the readers do not just hold the inflated bytes: they build a full in-memory DOM (mammoth via
//     jszip) or row/string arrays (read-excel-file), and every XML element AND every attribute becomes a heavy node.
//     That node amplification, not the byte count, is what a small file can use to exhaust a reader. Every element
//     carries a '<' and every attribute a '=', so counting both markers upper-bounds the node count whether the bomb
//     is element- or attribute-dense. Kept generous so a legitimately large spreadsheet is still indexed, not skipped;
//   * an ENTRY-COUNT cap — thousands of entries means a nested bomb, not a document.
// Declared sizes are never trusted (DEFLATE is self-terminating; the readers decompress the whole stream regardless):
// every deflate entry is actually inflated through a bounded inflater whose ceiling makes zlib THROW the instant the
// output would exceed the remaining budget. An over-budget, over-dense, or malformed file simply indexes by name
// (returns ''). Pure Node (zlib), cross-platform.
const ZIP_MAX_UNCOMPRESSED = 128 * 1024 * 1024; // total REAL inflated bytes across all entries (both enumerations, deduped); rejects a decompression bomb and bounds this guard's own inflation
const ZIP_MAX_NODES = 12000000;                 // total XML nodes ('<' elements + '=' attributes) across the archive — a cheap density pre-filter. Kept generous so a legitimately large spreadsheet (tens of thousands of rows of real data) is still content-indexed rather than falsely skipped; anything denser than a real document is rejected here, and anything that slips past is contained by the extraction process's heap and RSS caps
const ZIP_MAX_ENTRIES = 8192;                   // a real docx/xlsx has tens of entries; thousands means a nested bomb
function zipWithinBudget(buf) {
	try {
		if (!Buffer.isBuffer(buf) || buf.length < 22) return false;
		const vetted = new Set(); // data offsets already charged/counted, so an entry reached by BOTH enumerations is done once
		const state = { budget: ZIP_MAX_UNCOMPRESSED, entries: 0, nodes: 0 };
		// Bound the XML NODE count of an entry's real content: every element opens with '<' and every attribute has a
		// '=', so counting both markers upper-bounds the DOM/array nodes the reader will build (the amplification the byte
		// budget cannot see). Accumulates across entries and stops early once the cap is passed. Well-formed XML escapes
		// '<' in text as &lt;, so a raw '<' marks a tag; a stray '=' in text only over-counts (safe); binary parts hold
		// only sparse incidental markers and never approach the cap.
		const countNodes = (content) => {
			for (const marker of [0x3c, 0x3d]) { // '<' then '='
				let i = -1;
				while (state.nodes <= ZIP_MAX_NODES && (i = content.indexOf(marker, i + 1)) !== -1) state.nodes++;
				if (state.nodes > ZIP_MAX_NODES) return false;
			}
			return true;
		};
		// Vet the entry whose LOCAL header starts at `lho`: determine its real content (inflate a deflate stream to its
		// own end, bounded; or take a stored slice), charge the REAL size to the shared budget and node-count it, once
		// per unique data offset. The deflate stream is self-terminating, so inflating from the data start captures
		// exactly what a reader would decompress regardless of any declared size. `cdComp` is the compressed size from
		// the central directory (passed by the CD walk); it supplies the size when the local header omits it (a data
		// descriptor). Returns the compressed length to step over for the sequential walk, or null when that length is
		// not available here (a data descriptor — the central-directory walk still covers the entry), or false on any
		// anomaly, ratio, size, or node-count breach.
		const vet = (lho, cdComp) => {
			if (lho < 0 || lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) return false;
			if (++state.entries > ZIP_MAX_ENTRIES) return false;    // implausibly many entries across both walks -> a nested bomb
			const flags = buf.readUInt16LE(lho + 6);
			const method = buf.readUInt16LE(lho + 8);
			const compSize = buf.readUInt32LE(lho + 18);
			const uncomp = buf.readUInt32LE(lho + 22);
			const nameLen = buf.readUInt16LE(lho + 26);
			const extraLen = buf.readUInt16LE(lho + 28);
			if (compSize === 0xffffffff || uncomp === 0xffffffff) return false; // ZIP64 sizes -> beyond what we vet
			const dataStart = lho + 30 + nameLen + extraLen;
			if (dataStart > buf.length) return false;
			const hasDataDescriptor = (flags & 0x08) !== 0;        // real sizes are in a trailing descriptor, not this header
			const step = hasDataDescriptor ? null : compSize;      // null: cannot step over it in the sequential walk
			if (vetted.has(dataStart)) return step;                // already inflated + counted via the other enumeration
			let content;                                            // the real bytes to node-count, once determined
			if (method === 8) {                                     // deflate: inflate to the stream's own end, bounded by the remaining budget
				// maxOutputLength makes zlib throw the moment the output would exceed the remaining budget, so a lying or
				// bomb stream can never materialize more than what is left of the budget before it is refused.
				try { content = zlib.inflateRawSync(buf.subarray(dataStart), { maxOutputLength: Math.max(1, state.budget) }); }
				catch (_) { return false; }                         // over the budget, or a corrupt/truncated stream -> refuse (index by name)
				state.budget -= content.length;
			} else if (method === 0) {                              // stored: content == data (1:1), bounded by the (<=24 MB) buffer
				const storedLen = !hasDataDescriptor ? compSize : (cdComp > 0 ? cdComp : -1); // a stored data-descriptor entry has no local size; the CD supplies it
				if (storedLen < 0) return null;                     // stored + data descriptor with no CD size here -> leave UNVETTED for the CD walk (do not mark done)
				if (dataStart + storedLen > buf.length) return false;
				content = buf.subarray(dataStart, dataStart + storedLen);
				state.budget -= storedLen;
			} else { return false; }                                // an unknown method we cannot vet -> refuse
			vetted.add(dataStart);
			if (state.budget < 0) return false;
			if (content.length && !countNodes(content)) return false; // too many XML nodes for the reader to build -> refuse
			return step;
		};
		// 1) Sequential local-header walk — the entry set/order a streaming reader (read-excel-file) consumes.
		let p = 0, sawLocal = false;
		while (p + 30 <= buf.length && buf.readUInt32LE(p) === 0x04034b50) {
			const step = vet(p, 0);
			if (step === false) return false;
			sawLocal = true;
			if (step === null) break;                               // data descriptor: next offset is unknown here; the central-directory walk covers the rest
			p = p + 30 + buf.readUInt16LE(p + 26) + buf.readUInt16LE(p + 28) + step;
		}
		// 2) Central-directory walk — the entry set a random-access reader (mammoth/jszip) consumes. Vets every entry it
		//    lists (deduped against the walk above by data offset), closing any gap between the two enumerations.
		let eocd = -1; const minPos = Math.max(0, buf.length - (22 + 0xffff));
		for (let i = buf.length - 22; i >= minPos; i--) { if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
		if (eocd >= 0) {
			const cdEntries = buf.readUInt16LE(eocd + 10);
			const cdOffset = buf.readUInt32LE(eocd + 16);
			if (cdEntries > ZIP_MAX_ENTRIES || cdOffset === 0xffffffff) return false; // too many entries, or ZIP64
			let q = cdOffset, seenCd = 0;
			while (seenCd < cdEntries && q + 46 <= buf.length) {
				if (buf.readUInt32LE(q) !== 0x02014b50) break;      // central-directory header signature
				const cdComp = buf.readUInt32LE(q + 20);            // the central directory's compressed size (real even when the local header is a data descriptor)
				const lho = buf.readUInt32LE(q + 42);
				if (lho === 0xffffffff) return false;               // ZIP64 offset
				if (vet(lho, cdComp) === false) return false;       // inflate this entry too (deduped) — catches a bomb the sequential walk never reached
				q += 46 + buf.readUInt16LE(q + 28) + buf.readUInt16LE(q + 30) + buf.readUInt16LE(q + 32); // + name + extra + comment
				seenCd++;
			}
		}
		return sawLocal || vetted.size > 0;                         // saw at least one readable entry within budget via either enumeration
	} catch (_) { return false; } // any parse trouble -> be safe, do not hand it to the inflating reader
}

// Only the first CAP bytes of a document are ever indexed, so there is no reason to build more text than that
// while extracting. Every branch is bounded to produce at most ~CAP: for a ZIP-based document the bomb guard
// caps the total INFLATED bytes the reader can materialize, the CSV builder stops accumulating once the budget
// is met and takes only the first rows, PDF text is streamed page by page and stops at the budget, and every
// result is sliced. CAP defaults generously; the caller passes the real per-file budget.
// A fallback only: the caller (the indexing worker) ALWAYS passes the real per-file budget
// (SearchDefs.PER_FILE_TEXT_CAP), so this value is never load-bearing and cannot drift into a bug. It is kept
// generous so a direct call with no cap still behaves sanely.
const DEFAULT_CAP = 2 * 1024 * 1024;
const XLSX_MAX_ROWS = 50000; // rows taken per sheet when flattening to CSV. read-excel-file materializes every parsed
                              // row first (the ZIP bomb guard is what bounds that), so this caps the CSV we then build, not the parse
const PDF_MAX_PAGES = 5000;  // pages visited per PDF — bounds the walk even for a document whose pages hold NO
                             // text (a scanned PDF never fills the byte cap, so without this the loop would visit
                             // every page of an image-only document and could stall the worker)

// Slice extracted text to the budget WITHOUT leaving half a surrogate pair at the cut. A plain .slice on a
// UTF-16 string can split an astral character (an emoji, some CJK), leaving a lone high surrogate — harmless to
// search but an odd token and an invalid stored code unit, so trim a dangling one. O(1) after the slice.
function sliceText(s, cap) {
	let out = String(s).slice(0, cap);
	const last = out.charCodeAt(out.length - 1);
	if (last >= 0xd800 && last <= 0xdbff) out = out.slice(0, -1); // dangling high surrogate at the cut -> drop it
	return out;
}

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
							// STREAM the page's text content in chunks rather than materializing the whole items array up front:
							// a single page whose content stream decodes to millions of text operators would build one enormous
							// array (an uncatchable out-of-memory) before any cap could apply. The reader is a pull stream, so once
							// the running total reaches the budget we cancel it and PDF.js stops parsing the rest of the page.
							const reader = page.streamTextContent({}).getReader();
							try {
								for (;;) {
									const { done, value } = await reader.read();
									if (done) break;
									for (const it of (value && value.items) || []) {
										const s = (it && it.str) || '';
										if (s) piece += (piece ? ' ' : '') + s;
										if (total + piece.length >= cap) break;
									}
									if (total + piece.length >= cap) break;
								}
							} finally { try { await reader.cancel(); } catch (_) {} }
						} finally { try { page.cleanup(); } catch (_) {} }
						if (piece) { parts.push(piece); total += piece.length + 1; }
						if (total >= cap) break; // have the budget's worth — stop rather than parse the rest and throw it away
					}
					return sliceText(parts.join('\n'), cap);
				} finally { try { await doc.destroy(); } catch (_) {} }
			}
			case 'docx':
				if (!zipWithinBudget(buffer)) return ''; // a zip/xml bomb would inflate past the heap before we could slice — skip it (index by name)
				return sliceText((await require('mammoth').extractRawText({ buffer })).value || '', cap);
			case 'xlsx': case 'xlsm': {
				if (!zipWithinBudget(buffer)) return ''; // same bomb guard as docx: the reader inflates the whole workbook before any row cap applies
				const parts = []; let total = 0;
				for (const rows of await xlsxSheetRows(buffer)) {
					const csv = rows.slice(0, XLSX_MAX_ROWS)
						.map(r => (Array.isArray(r) ? r : []).map(c => (c == null ? '' : String(c))).join(','))
						.join('\n').trim();
					if (csv) { parts.push(csv); total += csv.length; if (total >= cap) break; } // stop once we have the budget's worth
				}
				return sliceText(parts.join('\n\n'), cap);
			}
			case 'html': case 'htm':
				return sliceText(stripHtml(buffer.toString('utf8'), cap), cap);
			default:
				return null;
		}
	} catch (_) { return ''; } // a malformed document indexes as empty rather than breaking the whole run
}

// The formats this module can extract — the caller's allowlist for "needs an extractor" (vs. plain text).
const EXTRACTABLE = new Set(['pdf', 'docx', 'xlsx', 'xlsm', 'html', 'htm']);

module.exports = { extractText, EXTRACTABLE, stripHtml, sliceText, zipWithinBudget, ZIP_MAX_UNCOMPRESSED, ZIP_MAX_ENTRIES };
