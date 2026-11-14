'use strict';
// lib/test/noteingresscap.js — the HTTP JSON ingress cap for /api/note-save must be sized from the SAME constant as
// the secure-note item policy (NotesLimits.MAX_BODY_BYTES), never a smaller hardcoded limit. A lower ingress cap would
// reject a policy-valid note at the web edge with a confusing 413, even though the backend writer accepts it and the
// importer can create it — so a note between a small default and the 1 MiB item cap would become un-editable on the
// web. This guards the single-sourcing so the ingress limit and the item policy can never silently drift apart.
//
// Run:  node lib/test/noteingresscap.js

const fs = require('fs');
const path = require('path');
const NotesLimits = require('../vault/notesLimits');

let failures = 0;
function ok(name, cond, extra) { console.log((cond ? '  ok   ' : '  FAIL ') + name + (extra ? ' — ' + extra : '')); if (!cond) failures++; }

const src = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');

// 1. The dedicated limit is DERIVED from the shared constant, not a literal that could sit below the item policy.
ok('the note-save ingress limit derives from NotesLimits.MAX_BODY_BYTES (single source)',
	/NOTE_SAVE_BODY_LIMIT\s*=\s*Math\.\w+\(\s*NotesLimits\.MAX_BODY_BYTES/.test(src));

// 2. The note-save route uses the dedicated parser, not only the small global one.
ok('/api/note-save uses the dedicated jsonNoteSave parser',
	/app\.post\('\/api\/note-save',\s*jsonNoteSave\s*,/.test(src));

// 3. The small global JSON parser is SKIPPED for /api/note-save, so it cannot reject the larger body first.
ok('the small global JSON parser is skipped for /api/note-save',
	/req\.path === '\/api\/note-save'[\s\S]{0,60}next\(\)[\s\S]{0,80}jsonSmall/.test(src));

// 4. The derived ingress cap is at least the item body cap (headroom factor >= 1), so a policy-valid note always fits.
const m = src.match(/NOTE_SAVE_BODY_LIMIT\s*=\s*Math\.ceil\(\s*NotesLimits\.MAX_BODY_BYTES\s*\*\s*([0-9.]+)\s*\)/);
const factor = m ? parseFloat(m[1]) : 0;
ok('the derived ingress cap is at least the item body cap (factor >= 1)', factor >= 1, 'factor=' + factor);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTE-INGRESS-CAP CHECKS PASSED'));
process.exit(failures ? 1 : 0);
