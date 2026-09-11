'use strict';
// lib/test/tamperhonestydrift.js — a source-level drift guard for the self-heal-honesty and tamper-tolerance
// invariants added when a deleted file that self-healing could not rebuild made a tamper check fail with a raw engine
// error. These behaviors are only exercised end-to-end under a mount driver (healunrecoverable.js) or the bundled
// engine (tamperdamaged.js); this guard locks them at the source level so they hold on every CI runner, including a
// driverless, engine-less one. It reads source and checks invariants, in the style of the other *drift.js guards.
//
// Run:  node lib/test/tamperhonestydrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return ''; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

const V = read('lib/Vault.js');

// 1. The tamper scan (captureFiles) must NOT abort on a per-file content failure: it reports `damaged` and only throws
//    when a non-zero exit is NOT fully explained by such per-file failures. Lock the gate shape and the return.
const cf = fnBody(V, 'async function captureFiles(');
ok('captureFiles collects the damaged files from the engine stderr', /hashsumDamagedFiles\(h\.stderr\)/.test(cf));
// The parsed names are cross-referenced against the REAL listing (sizes.has), which is load-bearing for fail-closed: a
// fatal/global error line that happens to look per-file yields a name absent from the listing, so it is dropped and
// damaged stays empty, forcing the abort. Dropping this filter would let such an error read as "clean but for N".
ok('captureFiles cross-references parsed names against the real listing (sizes.has) — the fail-closed backstop', /hashsumDamagedFiles\(h\.stderr\)\.filter\([^)]*sizes\.has\(/.test(cf));
ok('captureFiles aborts ONLY on a non-zero exit not explained by per-file damage', /h\.status\s*!==\s*0\s*&&\s*!\(\s*damaged\.length\s*>\s*0\s*&&\s*hashsumErrorsAllPerFile\(/.test(cf));
ok('captureFiles returns the damaged list to callers', /return\s*\{[^}]*damaged\s*\}/.test(cf));

// 2. hashsumErrorsAllPerFile must be fail-closed: it requires the engine's end-of-run summary, so a truncated stderr
//    or a fatal error (both drop the summary) can never be mistaken for "all per-file". Both the single-error
//    ("Failed to hashsum:") and the counted (" with N errors") forms must be accepted — rclone prints the single form
//    for exactly one error, and requiring only the counted form once reintroduced the reported abort regression.
const ape = fnBody(V, 'function hashsumErrorsAllPerFile(');
ok('the per-file decision requires the engine completion summary (fail-closed on truncation)', /completed\s*&&/.test(ape) && /\.every\(/.test(ape));
ok('both the single-error and counted summary forms are accepted (locks the abort regression fix)', /Failed to hashsum\(:\|\s*with\s*\\d\+\s*error\)/.test(ape));

// 3. audit() must surface `damaged` as its own report field and make it count as not-clean, but must NOT file it under
//    tampering — damage at rest is corruption, not an attack, so it is its own finding (no false tamper alarm).
const au = fnBody(V, 'async function audit(');
ok('audit sets report.damaged from the capture', /report\.damaged\s*=\s*cur\.damaged/.test(au));
ok('a damaged file makes the result not-clean', /report\.clean\s*=[^;]*!report\.damaged\.length/.test(au));
ok('audit does NOT push damaged into the tamper list (no false tamper alarm)', !/tamper\.push\([^)]*damaged/i.test(au) && !/damagedNote/.test(V));

// 4. writeSnapshot must REFUSE a deep, non-auto snapshot over a damaged vault (never bake damage into a baseline), and
//    the gate must be `!auto` so the auto/unmount baseline — the never-wedge path — can never be blocked by it.
const ws = fnBody(V, 'async function writeSnapshot(');
ok('writeSnapshot refuses a deep, non-auto snapshot over damaged files', /deep\s*&&\s*!auto\s*&&\s*cap\.damaged/.test(ws));
ok('the snapshot refusal carries e.damaged for the caller', /e\.damaged\s*=\s*cap\.damaged/.test(ws));

// 5. healCore must be honest: it returns the files it could not fully recover, and never counts a partly-rebuilt file
//    as repaired (it drops it from repairedFiles so its metadata is not restored as if pristine).
const R = read('lib/Recovery.js');
const hc = fnBody(R, 'async function healCore(');
ok('healCore records the files it could not fully rebuild', /unrecoverableCandidates/.test(hc));
ok('healCore drops a partly-rebuilt file from repairedFiles (not counted as repaired)', /repairedFiles\.delete\(/.test(hc));
ok('healCore returns unrecoverable and unrecoverableFiles', /unrecoverable:\s*unrecoverableFiles\.length/.test(hc) && /unrecoverableFiles\b/.test(hc));

// 6. The reporting keys the data-loss message on `unrecoverable` (real lost files), not `unrecoverableStripes` (which
//    can be a parity-only shortfall) — so a parity-only degradation never false-alarms as data loss.
ok('the CLI heal reporting distinguishes lost files (unrecoverable) from a parity-only shortfall', /h\.unrecoverable\b/.test(read('lib/Commands.js')) && /h\.unrecoverableStripes/.test(read('lib/Commands.js')));
ok('the web heal reporting distinguishes lost files from a parity-only shortfall', /h\.unrecoverable\b/.test(read('lib/webserver/public/js/app.js')));

// 7. The audit surfaces damaged files as their OWN group (with a count) in both the CLI and the web, not only buried in
//    the tamper-note text — so a UI refactor cannot silently drop the dedicated, countable list the user relies on.
ok('the CLI audit lists damaged files as their own group', /list\('Damaged[^']*',\s*rep\.damaged\)/.test(read('lib/Commands.js')));
ok('the web audit renders damaged files as their own file list', /fileList\([^)]*[Dd]amaged[^)]*,\s*r\.damaged\)/.test(read('lib/webserver/public/js/app.js')));
ok('the web change-count summary includes a damaged count', /e\.damaged\b/.test(read('lib/webserver/public/js/app.js')));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TAMPER-HONESTY-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
