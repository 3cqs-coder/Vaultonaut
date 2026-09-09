'use strict';
// lib/SearchWorker.js — builds/refreshes a vault's CONTENT-search index off the main thread. It runs against
// a MOUNTED vault: it reads file contents off the mountpoint (plaintext, in RAM) and writes the serialized
// index back through the same mount (so only ciphertext reaches the physical disk). Indexing is incremental —
// a per-file (size + mtime) manifest means unchanged files are never re-read, and the manifest is the
// authority for detecting deletions. The heavy tokenizing/serializing lives here to keep the service's event
// loop clear, matching the pack, dispersal, and recovery workers.

const path = require('path');
const fsp = require('fs').promises;
const MiniSearch = require('minisearch');
const D = require('./SearchDefs');
const Common = require('./Common');
const Extract = require('./Extract'); // loaded only here, in the worker — its document readers never weigh on the main process

// The tool's own metadata files, never indexed (matched by basename, like the tamper-ignore set).
const INTERNAL = new Set(['.vaultcheck', '.vaultsnapshot', '.vaultsnapshot.new', '.vaultsession', '.vaultsession.new']);

// The searchable text of one file. A plain-text file is decoded directly; a document format (PDF, Word, Excel,
// HTML) is run through the pure-JS extractor. Everything is capped to the per-file text budget. Never throws.
// `size` is the file size already gathered during the walk, so an over-limit document is skipped WITHOUT reading it,
// and a plain-text file is read only up to the text cap instead of slurping up to the hard ceiling then slicing —
// bounding worker memory and mount I/O.
async function readText(mountpoint, rel, size) {
	const abs = path.join(mountpoint, rel);
	try {
		if (D.isExtractable(rel)) {
			if (size >= 0 && size > D.EXTRACT_MAX_BYTES) return ''; // known-oversize: index by name only, no read at all
			// Read at most EXTRACT_MAX_BYTES (+1 to detect overflow) from the fd, NEVER the whole file. A size of -1
			// (a mount whose stat failed — WinFsp) must not defeat the cap: without this bound, fsp.readFile would
			// slurp a huge document into worker memory and break the any-size / no-OOM invariant.
			let fh; try { fh = await fsp.open(abs, 'r'); } catch (_) { return ''; }
			try {
				const cap = D.EXTRACT_MAX_BYTES + 1;
				const buf = Buffer.allocUnsafe(cap);
				let off = 0; while (off < cap) { const { bytesRead } = await fh.read(buf, off, cap - off, off); if (bytesRead <= 0) break; off += bytesRead; }
				if (off > D.EXTRACT_MAX_BYTES) return ''; // over the parse limit — index by name only
				const t = await Extract.extractText(buf.subarray(0, off), D.extOf(rel), D.PER_FILE_TEXT_CAP);
				return (t || '').slice(0, D.PER_FILE_TEXT_CAP);
			} finally { try { await fh.close(); } catch (_) {} }
		}
		// Plain text: read only the first PER_FILE_TEXT_CAP bytes from the fd, never the whole file.
		let fh; try { fh = await fsp.open(abs, 'r'); } catch (_) { return ''; }
		try {
			const want = Math.min(D.PER_FILE_TEXT_CAP, (size > 0 ? size : D.PER_FILE_TEXT_CAP));
			const buf = Buffer.allocUnsafe(want);
			const { bytesRead } = await fh.read(buf, 0, want, 0);
			const head = buf.subarray(0, bytesRead);
			return D.looksBinary(head) ? '' : head.toString('utf8');
		} finally { try { await fh.close(); } catch (_) {} }
	} catch (_) { return ''; }
}

require('./WorkerRun').runChild({
	index: async ({ mountpoint }, progress) => {
		const indexDir = path.join(mountpoint, D.SEARCH_DIR);
		const indexPath = path.join(indexDir, D.INDEX_NAME);

		// Load the existing index + manifest, or start fresh if missing/corrupt/incompatible. `loaded` records that we
		// read a clean existing envelope, so a no-change run can safely skip rewriting it (below).
		let ms = null, manifest = {}, loaded = false;
		try { const env = D.unpackEnvelope(await Common.readFileCapped(indexPath, D.MAX_SEARCH_INDEX_BYTES), { withManifest: true }); if (env) { ms = MiniSearch.loadJSON(env.indexJSON, D.MS_OPTIONS); manifest = env.manifest || {}; loaded = true; } } catch (_) {} // withManifest: the worker needs the change manifest to diff; capped like the main-thread reader so an oversized index can't be loaded whole
		if (!ms) { ms = new MiniSearch(D.MS_OPTIONS); manifest = {}; }

		// Walk the mount, collecting current text-like files and their change signatures. The walk (readdir+stat over
		// the whole tree) posts a periodic heartbeat so the idle watchdog never mistakes a large-but-healthy tree for a
		// wedged worker and kills the reindex before the indexing loop's own progress begins.
		const current = {};
		let scanned = 0;
		async function walk(rel) {
			let ents; try { ents = await fsp.readdir(path.join(mountpoint, rel), { withFileTypes: true }); } catch (_) { return; }
			for (const e of ents) {
				const r = rel ? rel + '/' + e.name : e.name;
				if (r === D.SEARCH_DIR) continue;                 // never index our own index
				if (e.isDirectory()) { await walk(r); continue; }
				if (!e.isFile() || INTERNAL.has(e.name) || !D.isIndexable(e.name)) continue;
				// A mount that serves readdir/read but FAILS fs.stat (WinFsp does exactly this) must NOT drop the file:
				// dropping it would leave it out of the index and, if it was already indexed, mark it "removed" (line
				// below). When stat does not answer, index the file anyway with a sentinel signature so it is always
				// covered rather than vanishing from search. While stat keeps failing the file stays indexed but is
				// not re-read (its sentinel signature matches), so a later content change is picked up once stat works.
				let st = null; try { st = await fsp.stat(path.join(mountpoint, r)); } catch (_) {}
				if (st && st.size > D.HARD_FILE_CEIL) continue; // skip only on a KNOWN oversize
				current[r] = st ? { size: st.size, mtimeMs: Math.round(st.mtimeMs) } : { size: -1, mtimeMs: -1 };
				if (++scanned % 200 === 0) progress({ percent: 0, label: 'Scanning files (' + scanned + ')' }); // heartbeat: feeds the idle watchdog during a long walk
			}
		}
		await walk('');

		// Diff against the manifest.
		const added = [], changed = [], removed = [];
		for (const r of Object.keys(current)) { const m = manifest[r]; if (!m) added.push(r); else if (m.size !== current[r].size || m.mtimeMs !== current[r].mtimeMs) changed.push(r); }
		for (const r of Object.keys(manifest)) if (!current[r]) removed.push(r);

		// Nothing changed AND the index loaded cleanly: leave it exactly as it is. Rewriting an unchanged index wastes
		// mount I/O, needlessly invalidates the in-memory search cache (which is keyed on the index file's mtime+size),
		// and — because the index file is part of the vault's tamper baseline — could re-pack the same logical index
		// into different bytes after a dependency upgrade and raise a FALSE tamper alarm on a sealed vault the user
		// never touched. A fresh (unloaded) index is still written even when empty, so a first build always persists.
		if (loaded && added.length === 0 && changed.length === 0 && removed.length === 0) {
			progress({ percent: 100, label: 'Index already up to date' });
			return { indexed: Object.keys(manifest).length, added: 0, changed: 0, removed: 0, unchanged: true };
		}

		for (const r of removed) { try { ms.discard(r); } catch (_) {} delete manifest[r]; }

		const work = added.concat(changed); const total = work.length; let done = 0;
		for (const r of work) {
			const name = r.slice(r.lastIndexOf('/') + 1).normalize('NFC'); // NFC so an accented name matches a browser (NFC) query even when the mount reports it decomposed (NFD, e.g. macOS)
			// Normalize the extracted body to NFC as well: a document authored or exported on macOS (or any NFD source)
			// stores accented characters decomposed, so without this a search for "café" would match a file NAMED
			// café.txt but not the word "café" inside it — the query is NFC-normalized, so the indexed text must be too.
			const doc = { id: r, path: r, name, text: (await readText(mountpoint, r, current[r].size) || '').normalize('NFC') };
			try { if (manifest[r]) ms.replace(doc); else ms.add(doc); manifest[r] = current[r]; } catch (_) {}
			if (++done % 25 === 0 || done === total) progress({ percent: total ? Math.round(done / total * 100) : 100, label: 'Indexing (' + done + '/' + total + ')' });
		}

		progress({ percent: 99, label: 'Saving index' }); // heartbeat before the serialize+gzip+write, which post nothing
		ms.vacuum(); // clear tombstones so the persisted index is compact

		// Write the envelope back through the mount, atomically.
		await fsp.mkdir(indexDir, { recursive: true });
		// A UNIQUE temp (not a fixed ".new") means two concurrent reindexes write SEPARATE files, so the atomic
		// rename always leaves a WHOLE index (last wins), never an interleaved/truncated one. The cost is that a hard
		// crash between write and rename orphans a distinct temp here, and no external sweep scans a vault's search
		// dir — so clean stale index temps first. Age-gate the cleanup well past the worker's 3-minute idle limit, so
		// it removes only crash orphans and never a CONCURRENT reindex's still-in-flight temp.
		const base = path.basename(indexPath);
		try { for (const n of await fsp.readdir(indexDir)) { if (n !== base && n.startsWith(base + '.') && n.endsWith('.tmp')) { try { const st = await fsp.stat(path.join(indexDir, n)); if (Date.now() - st.mtimeMs > 5 * 60 * 1000) await fsp.rm(path.join(indexDir, n), { force: true }); } catch (_) {} } } } catch (_) {}
		const out = D.packEnvelope({ manifest, indexJSON: JSON.stringify(ms) });
		const tmp = Common.uniqueTempPath(indexPath);
		try { await fsp.writeFile(tmp, out); await Common.renameWithRetry(tmp, indexPath); } // retry a transient Windows lock rather than failing the index write
		catch (e) { try { await fsp.rm(tmp, { force: true }); } catch (_) {} throw e; } // clean our own temp on a graceful failure (a hard crash is handled by the age-gated cleanup above on the next run)

		return { indexed: Object.keys(manifest).length, added: added.length, changed: changed.length, removed: removed.length };
	},
}, { label: 'search-index' });

// Exported ONLY so a drift-guard test can assert this internal-name set stays in sync with the canonical set in
// Vault.js (and the mobile client's copy). Requiring this module runs runChild(), which is a no-op outside a worker.
module.exports = { INTERNAL };
