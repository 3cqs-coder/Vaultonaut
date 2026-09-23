'use strict';
// lib/test/liveindex.js — guards for keeping the content-search index fresh WITHOUT a manual "Update index", across the
// two mechanisms that do it:
//   • the search-time refresh (the guarantee): an "inside files" search first brings the index up to date incrementally,
//     in the web UI and the CLI, so a file added while the vault was open is findable;
//   • the best-effort live watcher (the convenience): while a vault is mounted, file changes trigger an incremental,
//     debounced reindex in the background.
// The watcher must never weaken a vault invariant, so these are the properties under test: it is torn down on
// unmount/lock (so nothing is read after the vault is gone), it only runs on a read-write mount that already has an
// index, it never re-triggers on its own index writes, and it reindexes off the event loop. These are source-level
// checks, so the test can never hang or flake.
//
// Run:  node lib/test/liveindex.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (rel) => { try { return fs.readFileSync(path.join(__dirname, '..', '..', rel), 'utf8'); } catch (_) { return ''; } };

const vault = read('lib/Vault.js');
const app = read('lib/webserver/public/js/app.js');
const commands = read('lib/Commands.js');

// ── The best-effort live watcher (lib/Vault.js) ───────────────────────────────────────────────────────────────────
// It must be TORN DOWN wherever the search-index cache is evicted (a clean unmount AND a lock/crash sweep), so the
// watcher never outlives the mount and never reads a vault after it is locked. Assert stopIndexWatch sits beside BOTH
// evictSearchIndexCache calls that drop a plaintext-derived index.
const evicts = (vault.match(/evictSearchIndexCache\(/g) || []).length;
const stops = (vault.match(/stopIndexWatch\(/g) || []).length;
ok('the live watcher is torn down at every mount teardown (stopIndexWatch beside each cache eviction)', evicts >= 2 && stops >= evicts - 0 && /stopIndexWatch\(mountpoint\);\s*\/\/[^\n]*\n\s*evictSearchIndexCache\(mountpoint\)/.test(vault) && /stopIndexWatch\(m\.mountpoint\);[\s\S]{0,200}evictSearchIndexCache\(m\.mountpoint\)/.test(vault));

// It must not write on a read-only mount (nothing to keep fresh, and a reader must never write). It maintains only an
// index that ALREADY exists — never builds one unprompted — and that is gated at FIRE time (inside the debounce), so a
// vault whose first index is built after mount still becomes watched without a remount.
ok('the watcher does nothing on a read-only mount', /function startIndexWatch\([^)]*\)\s*\{\s*if\s*\(readOnly\)\s*return;/.test(vault));
ok('the watcher reindexes only when an index already exists (gated at fire time, never builds one unprompted)', /fsp\.access\(searchIndexPathFor\(mountpoint\)\)\.then\(\(\)\s*=>\s*contentReindex\(rec\.vault/.test(vault));
ok('a reindex self-starts the watcher, so an already-mounted vault becomes hands-off with no remount', /startIndexWatch\(mountpoint,\s*abs,\s*false\)/.test(vault));

// It must not re-trigger on its OWN index writes (which land inside the search directory), or it would reindex forever.
ok('the watcher ignores churn inside the search directory (no self-retrigger)', /seg\s*===\s*SearchDefs\.SEARCH_DIR/.test(vault));

// It must be DEBOUNCED (a multi-file copy fires many events) and reindex through the normal worker path (off the event
// loop), not inline.
ok('the watcher debounces bursts before reindexing', /INDEX_WATCH_DEBOUNCE_MS/.test(vault) && /rec\.timer = setTimeout\(/.test(vault) && /contentReindex\(rec\.vault,\s*\{\s*allowOcr:\s*true\s*\}\)/.test(vault));

// The watcher is started right where the on-mount refresh is (so it shares the mount lifecycle) and keyed by mountpoint
// so a second mount of the same path does not stack watchers.
ok('the watcher is started on mount', /startIndexWatch\(res\.mountpoint,\s*presentVault,\s*opts\.readOnly\)/.test(vault));
ok('one watcher per mount (keyed by mountpoint, deduped)', /if\s*\(indexWatchers\.has\(mountpoint\)\)\s*return;/.test(vault));

// ── The search-time refresh — the guarantee (web + CLI) ───────────────────────────────────────────────────────────
// Web: an inside-files search brings the index up to date first, ONCE per dialog session (so refining a query does not
// re-walk the vault every keystroke), and it is best-effort (a failure still lets the search run).
ok('the web inside-files search refreshes the index before searching', /await ensureContentIndexFresh\(\);[\s\S]{0,200}\/api\/content-search/.test(app));
ok('the web refresh runs on EVERY inside-files search (no once-per-session gate that could skip a just-added file)', /function ensureContentIndexFresh\(\)\s*\{(?![\s\S]{0,120}return;)[\s\S]{0,240}apiStream\('\/api\/content-reindex'/.test(app) && !/contentIndexFreshFor/.test(app));
ok('the web refresh is best-effort (a failure still lets the search proceed)', /apiStream\('\/api\/content-reindex'[\s\S]{0,120}catch\s*\(_\)\s*\{[^}]*\}/.test(app));

// CLI: `search --in` refreshes first (incrementally, with OCR) unless --no-refresh is passed, and the refresh is
// best-effort (swallowed) so it never breaks a search.
ok('the CLI inside-files search refreshes first unless --no-refresh', /if\s*\(!flags\['no-refresh'\]\)\s*\{[\s\S]{0,240}contentReindex\(target,\s*\{\s*onProgress:[^}]*allowOcr:\s*true\s*\}\)/.test(commands));
ok('the CLI --no-refresh flag is registered', /'no-refresh'/.test(commands));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LIVE-INDEX CHECKS PASSED'));
process.exit(failures ? 1 : 0);
