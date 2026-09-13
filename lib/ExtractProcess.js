'use strict';
// lib/ExtractProcess.js — runs document text extraction in a separate CHILD PROCESS, fully isolated from the indexing
// worker and the main app. Parsing an UNTRUSTED document (Word/Excel/PDF/HTML) is the one indexing step a crafted
// file can turn into an out-of-memory crash or a CPU hang: the reader libraries build an in-memory model whose size
// cannot be predicted from the bytes (a tiny file can expand into tens of millions of DOM/array nodes, or decode a
// compressed stream into gigabytes of native memory). A worker THREAD cannot contain that — it shares the app's
// address space, so the growth (especially OFF-HEAP/native memory, which a JS-heap cap does not bound) counts against
// the whole app and, on some platforms, is not even returned to the OS when the thread ends, so repeated documents
// ratchet the app's memory toward a crash. A separate PROCESS has its own address space: its memory never counts
// against the app and the OS reclaims all of it on exit, so no single document and no sequence of documents can
// exhaust the parent. This is the standard, robust defense for untrusted-document parsing — isolate the parser in its
// own resource-capped process — and it contains the whole class of amplification bombs, known and unknown, without
// trying to predict each one.
//
// SearchWorker forks one of these per document (via WorkerRun.runProcess) with a hard JS-heap cap (--max-old-space-
// size) and a wall-clock time budget, and passes an off-heap RSS budget the child enforces on itself. Any blow-up
// ends this child; the parent catches that and indexes the file by NAME only, then moves on — the app never crashes,
// wedges, or drops the file, and extraction writes nothing to disk (no residue for backup/mirror/sync). A fresh
// process per document means no state leaks between files and a poison file can never affect the next. Extract's
// cheap in-process zip-bomb pre-filter still runs first here to reject the obvious cases quickly. The heavy readers
// load lazily on first use. Reuses the shared WorkerRun child-process contract, which behaves identically on macOS,
// Linux, and Windows.

require('./WorkerRun').runProcessChild({
	// The bytes arrive as a structured-cloned copy over IPC (advanced serialization preserves the Buffer), so the
	// indexer's shared read buffer never crosses the process boundary. extractText is self-contained and never throws,
	// but the runProcessChild wrapper also turns any surprise into a clean error the parent can fall back on.
	extract: async ({ buf, ext, cap }) => (await require('./Extract').extractText(Buffer.from(buf), ext, cap)) || '',
}, { label: 'extract' });
