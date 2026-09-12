'use strict';
// lib/test/uiguards.js — source guards for two web-UI safety patterns that have regressed before and are easy to
// drop when adding a handler:
//   1. A click handler that MINTS A REVOCABLE CAPABILITY (a share link, a one-time phone session) must be wrapped in
//      guarded(), so a fast double-click cannot create two grants where the UI then tracks (and can revoke) only one,
//      silently orphaning the other. This bit the share-link button, which minted a duplicate, un-revocable link.
//   2. A dialog list loader that fetches per-vault content must capture its target before the await and bail if the
//      user navigated away, so a late response can never paint one vault's items into another vault's open dialog.
// Static only (no browser, no engine) — a fast, cross-platform drift guard like the other UI-source tests.
//
// Run:  node lib/test/uiguards.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const app = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');

// 1. Every capability-minting button is guarded against a double-click. Adding one here when a new share/session
//    minting button is introduced keeps the invariant enforced.
for (const id of ['sendCreate', 'mobileGetCode']) {
	const re = new RegExp("#" + id + "'\\)\\.addEventListener\\('click',\\s*guarded\\(");
	ok('the capability-minting #' + id + ' handler is wrapped in guarded() (no double-mint)', re.test(app));
}

// 2. The Notes list loader guards against a late cross-vault response, like the members/keys/share loaders.
const notesBody = (function () { const i = app.indexOf('async function loadNotesList('); if (i < 0) return ''; const j = app.indexOf('\n}', i); return j < 0 ? app.slice(i) : app.slice(i, j); })();
ok('loadNotesList captures its target and bails on a late response (no cross-vault paint)', /const target = notesTarget;/.test(notesBody) && /if \(notesTarget !== target\) return/.test(notesBody));

// 3. High-stakes, repeated action buttons must carry an accessible name that identifies WHICH item they act on, so a
// screen-reader user browsing by control does not hear a row of identical "Remove"/"Revoke" and destroy the wrong key
// or link. The per-key Remove and per-share Revoke buttons name the key/link in an aria-label; the import folder
// checkbox (whose visible name lives in a sibling button, not a wrapping label) names the folder it selects.
ok('the per-key Remove button carries an item-identifying aria-label', /aria-label="Remove \$\{esc\(\(kind/.test(app));
ok('the per-share Revoke button carries an item-identifying aria-label', /aria-label="Revoke ' \+ esc\(s\.label/.test(app));
ok('the import folder checkbox has an accessible name', /<input type="checkbox" class="pick-box" aria-label="Select \$\{esc\(f\.name\)\}/.test(app));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UI-GUARD CHECKS PASSED'));
process.exit(failures ? 1 : 0);
