'use strict';
// lib/SearchDefs.js — shared definitions for CONTENT search (searching inside files, not just names). Used by
// both the query path (lib/Vault.js) and the indexing worker (lib/SearchWorker.js), so the index is always
// built and read with the SAME options — MiniSearch does not store its options in the serialized index, and
// loading with different options silently corrupts results.
//
// The index is one file INSIDE the vault, written through the encrypted mount, so plaintext never touches the
// physical disk and the index is covered by the vault's tamper baseline like any other file (excluding it by
// name would leave a tamper-invisible slot, so it is never excluded). The index reveals nothing a holder of
// the read key could not already read from the files themselves.

const crypto = require('crypto');
const zlib = require('zlib');
const gunzip = require('util').promisify(zlib.gunzip); // async inflate (libuv threadpool) for the main-thread callers
const Brand = require('./Brand');

const SCHEMA_VERSION = 3; // v3: meta / manifest / index framing (see packEnvelope) — an older file is rejected and rebuilt
const MAX_META_BYTES = 64 * 1024; // the meta is a tiny fixed record (schema fingerprint + file count); cap it hard so the ONE inline (event-loop) JSON.parse a reader does is always small, even for a hostile index that inflates near the ceiling
// The largest the compressed index file may be, and the largest it may inflate to. The index lives INSIDE the
// vault store, so for a shared or imported vault its bytes are chosen by whoever produced the ciphertext — a
// gzip bomb (tiny compressed, enormous inflated) would otherwise block the event loop and exhaust memory when the
// query path inflates it. Bounding the gunzip output makes a bomb throw as soon as it exceeds the ceiling
// (unpackEnvelope then returns null -> "rebuild from scratch"), while still admitting a very large legitimate
// index. Generous vs any real index, yet a hard cap.
const MAX_SEARCH_INDEX_BYTES = 512 * 1024 * 1024;
// MiniSearch options. MUST be passed identically to build and to load — keep this the single source.
const MS_OPTIONS = { idField: 'id', fields: ['name', 'text'], storeFields: ['path', 'name'] };
// A stable fingerprint of the schema + options, stored in the envelope so a mismatch (after an upgrade that
// changes either) forces a clean rebuild rather than loading an incompatible index.
const OPTIONS_HASH = crypto.createHash('sha256').update('search-schema-v' + SCHEMA_VERSION + '\n' + JSON.stringify(MS_OPTIONS)).digest('hex').slice(0, 16);

const SEARCH_DIR = '.' + Brand.slug + '-search';   // lives beside the vault's files, inside the mount
const NOTES_DIR = '.' + Brand.slug + '-notes';     // the tool's own typed-secret store, also inside the mount
const INDEX_NAME = 'index';                          // one gzipped envelope file
// The tool's own in-mount directories: real content of the vault (so they stay in the tamper baseline), but not
// USER content, so a user-facing file listing, a name search, and the content indexer all hide them. Single-sourced
// here so those consumers can never disagree about what is internal. Matches the directory itself or anything under
// it; the caller strips a trailing slash. NOT part of isIgnoredVaultPath — excluding them from the baseline would
// leave a tamper-invisible slot, which the notes and index deliberately avoid.
const INTERNAL_DIRS = [SEARCH_DIR, NOTES_DIR];
function inInternalDir(p) {
	const d = String(p || '').replace(/\/+$/, '');
	return INTERNAL_DIRS.some((dir) => d === dir || d.startsWith(dir + '/'));
}
const PER_FILE_TEXT_CAP = 2 * 1024 * 1024;           // index at most this many bytes of text per file (head)
const HARD_FILE_CEIL = 64 * 1024 * 1024;             // never even open a file bigger than this
const EXTRACT_MAX_BYTES = 24 * 1024 * 1024;          // above this, a document (PDF/Word/Excel) is indexed by name only — parsing a very large document can expand far beyond its size in memory, so it is skipped rather than risk the indexing worker

// Text-like extensions we extract as plain UTF-8. Binary and unknown types are skipped (with a NUL-byte
// backstop below for an allowlisted file that is actually binary). PDF/DOCX extraction is a later phase.
const TEXT_EXTS = new Set([
	'txt', 'text', 'md', 'markdown', 'rst', 'log', 'csv', 'tsv', 'json', 'jsonl', 'ndjson', 'xml', 'yaml', 'yml',
	'toml', 'ini', 'conf', 'cfg', 'env', 'properties', 'html', 'htm', 'css', 'scss', 'less', 'svg',
	'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'rb', 'go', 'rs', 'java', 'kt', 'c', 'h', 'cpp', 'hpp', 'cc',
	'cs', 'php', 'pl', 'lua', 'sh', 'bash', 'zsh', 'sql', 'r', 'swift', 'm', 'tex', 'bib', 'srt', 'vtt',
]);

// Formats that are not plain text but whose text a pure-JS reader can extract. The one source of truth is
// Extract.EXTRACTABLE, imported here so the two can never drift; requiring Extract is cheap because its document
// readers are loaded lazily, on first use, inside the indexing worker — never at module load on the query path.
const EXTRACT_EXTS = require('./Extract').EXTRACTABLE;

function extOf(name) { const m = /\.([A-Za-z0-9]+)$/.exec(name || ''); return m ? m[1].toLowerCase() : ''; }
function isTextLike(name) { return TEXT_EXTS.has(extOf(name)); }
function isExtractable(name) { return EXTRACT_EXTS.has(extOf(name)); }
function isIndexable(name) { return isTextLike(name) || isExtractable(name); }
// A quick "is this actually text" backstop: a NUL byte in the head almost always means binary.
function looksBinary(buf) { const n = Math.min(buf.length, 8192); for (let i = 0; i < n; i++) if (buf[i] === 0) return true; return false; }

// The envelope wraps the serialized MiniSearch index with a tiny META record (schema fingerprint + file count) and
// the change-detection MANIFEST ({ relPath -> { size, mtimeMs } }). Stored gzipped.
//
// Framing: gzip( [uint32 BE metaLen][uint32 BE manifestLen][meta JSON][manifest JSON][raw index JSON bytes] ). Three
// segments in size order of who needs them: (1) the META is small and fixed-size, so any reader JSON.parses only it
// inline (bounded by MAX_META_BYTES) to check the schema and read the file count; (2) the MANIFEST scales with file
// count and is needed ONLY by the indexing worker to diff changes, so read callers skip it entirely and never parse
// it on the event loop; (3) the index is raw bytes handed straight to MiniSearch's async loader. This keeps the one
// inline parse a query does always tiny — a hostile index cannot enlarge the meta to stall the loop — and drops a
// wasted whole-manifest parse from every search. An older or incompatible file fails the schema check and is rebuilt.
function packEnvelope({ manifest, indexJSON }) {
	const man = manifest || {};
	const meta = Buffer.from(JSON.stringify({ schemaVersion: SCHEMA_VERSION, optionsHash: OPTIONS_HASH, fileCount: Object.keys(man).length }), 'utf8');
	const manBuf = Buffer.from(JSON.stringify(man), 'utf8');
	const head = Buffer.allocUnsafe(8); head.writeUInt32BE(meta.length, 0); head.writeUInt32BE(manBuf.length, 4);
	return zlib.gzipSync(Buffer.concat([head, meta, manBuf, Buffer.from(indexJSON, 'utf8')]));
}
// Returns { schemaVersion, optionsHash, fileCount, indexJSON } (plus `manifest` when opts.withManifest) if the
// envelope is present AND matches the current schema/options, else null (missing/corrupt/incompatible → rebuild).
// The indexing worker passes { withManifest: true }; read callers omit it and never parse the manifest.
function unpackEnvelope(buf, opts) {
	try {
		// Bound the inflated size so a gzip bomb in a shared/imported vault's index can't block the loop or
		// exhaust memory — it throws at the ceiling and this returns null (rebuild from scratch).
		return parseEnvelope(zlib.gunzipSync(buf, { maxOutputLength: MAX_SEARCH_INDEX_BYTES }), opts);
	} catch (_) { return null; }
}
// Same as unpackEnvelope, but decompresses OFF the event loop (zlib.gunzip runs on the libuv threadpool) — used by
// the main-thread callers (content search + status) so a large index can't freeze the loop while it inflates. The
// worker uses the sync form above, where blocking is fine. Read callers omit opts, so only the small meta parses
// inline; the heavy index parse is done asynchronously by MiniSearch.loadJSONAsync in the caller.
async function unpackEnvelopeAsync(buf, opts) {
	try {
		return parseEnvelope(await gunzip(buf, { maxOutputLength: MAX_SEARCH_INDEX_BYTES }), opts);
	} catch (_) { return null; }
}
// Shared post-inflate step: read the two length prefixes, parse only the small META inline (gated on the current
// schema/options), and return the index as a string WITHOUT parsing it here. The MANIFEST is parsed only when
// opts.withManifest is set (the worker). Any length that overruns the buffer, or a meta larger than MAX_META_BYTES
// — which is also what an old (differently-framed) envelope decodes to — returns null so the index is rebuilt.
function parseEnvelope(inflated, opts) {
	if (!inflated || inflated.length < 8) return null;
	const metaLen = inflated.readUInt32BE(0);
	const manLen = inflated.readUInt32BE(4);
	if (metaLen <= 0 || metaLen > MAX_META_BYTES) return null; // hostile or old framing — bounded inline parse only
	const metaStart = 8, manStart = metaStart + metaLen, idxStart = manStart + manLen;
	if (idxStart > inflated.length) return null; // lengths overrun the buffer
	let meta; try { meta = JSON.parse(inflated.subarray(metaStart, manStart).toString('utf8')); } catch (_) { return null; }
	if (!meta || meta.schemaVersion !== SCHEMA_VERSION || meta.optionsHash !== OPTIONS_HASH) return null;
	const out = { schemaVersion: meta.schemaVersion, optionsHash: meta.optionsHash, fileCount: meta.fileCount || 0, indexJSON: inflated.subarray(idxStart).toString('utf8') };
	if (opts && opts.withManifest) { try { out.manifest = JSON.parse(inflated.subarray(manStart, idxStart).toString('utf8')); } catch (_) { return null; } }
	return out;
}

module.exports = {
	SCHEMA_VERSION, MS_OPTIONS, OPTIONS_HASH, SEARCH_DIR, NOTES_DIR, INDEX_NAME, INTERNAL_DIRS, inInternalDir, PER_FILE_TEXT_CAP, HARD_FILE_CEIL, EXTRACT_MAX_BYTES,
	extOf, isTextLike, isExtractable, isIndexable, looksBinary, packEnvelope, unpackEnvelope, unpackEnvelopeAsync, MAX_SEARCH_INDEX_BYTES,
};
