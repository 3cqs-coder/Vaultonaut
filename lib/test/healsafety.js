'use strict';
// lib/test/healsafety.js — a same-size change to a file is indistinguishable from a same-length EDIT without the
// vault key, so the user-facing "Check & repair" (web) and `vdisk heal` (CLI) must NEVER silently revert it —
// reverting a real edit would be silent data loss. Both call paths therefore pass preserveInPlaceEdits, so a
// same-size mismatch is preserved and reported by default and repaired only under an explicit force. This is a
// source-level drift guard (a live end-to-end test would need a real mount), so a future refactor cannot quietly
// drop the flag and re-open the data-loss path.
//
// Run:  node lib/test/healsafety.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

// The CLI `heal` command must pass preserveInPlaceEdits (its --force still overrides it to repair genuine bit-rot).
const cmd = read('Commands.js');
ok('the CLI heal passes preserveInPlaceEdits so a same-size change is not silently reverted', /vdisk\.heal\([\s\S]*?preserveInPlaceEdits:\s*true/.test(cmd));
ok('the CLI reports the preserved same-size files (inPlaceDeferred)', /inPlaceDeferred/.test(cmd));

// The web /api/heal route must pass preserveInPlaceEdits AND accept an explicit force override.
const web = read('webserver/index.js');
ok('the web /api/heal route passes preserveInPlaceEdits so a same-size change is not silently reverted', /Vault\.heal\([\s\S]*?preserveInPlaceEdits:\s*true/.test(web));
ok('the web /api/heal route accepts an explicit force override from the request', /\.force\b/.test(web) && /force,\s*preserveInPlaceEdits:\s*true/.test(web));

// The web UI must surface the preserved same-size files and offer an explicit "repair it anyway" (force) action, so
// the packaged desktop app (which has no CLI) can still repair a genuine same-size bit-rot.
const app = read('webserver/public/js/app.js');
ok('the web UI offers a force "repair it anyway" action for same-size changes', /healSameSize/.test(app) && /runHeal\(allowUnverified,\s*true\)/.test(app));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HEAL-SAFETY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
