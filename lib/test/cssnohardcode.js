'use strict';
// lib/test/cssnohardcode.js — a WATCHDOG for the standing "every color comes from a theme token" rule. The theme
// contrast test checks the token palettes; nothing stopped a rule body from hardcoding a literal color that looks fine
// in the light theme but renders unreadable in dark or sepia (and escapes the contrast test entirely, because it never
// touches a token). This strips the token-DEFINITION blocks (`:root` and the `[data-theme]` overrides, where literals
// legitimately live) and the `var(--x, #fallback)` fallbacks (which are token-backed), then holds every remaining
// color literal in a rule body to a REVIEWED allowlist. A NEW hardcoded color trips the test so it gets reviewed —
// either turned into a token or, if it is a deliberate theme-neutral exception, added here with a reason.
//
// Run:  node lib/test/cssnohardcode.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Reviewed, deliberate literals that are theme-neutral or intentionally fixed:
//   #fff — white text/ground on a colored fill or a QR/switch surface (reads on any theme);
//   the search-highlight trio (dark text on a fixed yellow highlight — a print-marker convention, readable everywhere);
//   translucent dark shadow overlays (a drop shadow is theme-neutral by design).
const ALLOW = new Set([
	'#fff', '#ffffff', '#000', '#000000',
	'#ffe066', '#1a1400', '#ffb300', // search highlight (bg / text / active bg)
	'rgba(0, 0, 0, .22)', 'rgba(0,0,0,.12)', 'rgba(0,0,0,.25)', 'rgba(6, 10, 18, .45)', 'rgba(8, 12, 24, .4)', 'rgba(8, 12, 24, .5)',
]);

const cssFile = path.join(__dirname, '..', 'webserver', 'public', 'css', 'app.css');
let css = fs.readFileSync(cssFile, 'utf8');
// Remove where literals legitimately live: token-definition blocks and var() fallbacks.
css = css.replace(/:root[^{]*\{[^}]*\}/g, '').replace(/\[data-theme[^{]*\{[^}]*\}/g, '').replace(/var\([^)]*\)/g, '');
const literals = [...css.matchAll(/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)/g)].map((m) => m[0]);
const offenders = [...new Set(literals)].filter((c) => !ALLOW.has(c));
ok('no un-reviewed hardcoded color literal appears in a CSS rule body (use a theme token)', offenders.length === 0);
if (offenders.length) for (const o of offenders) console.log('        hardcoded color not on the reviewed allowlist: ' + o);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CSS-NO-HARDCODE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
