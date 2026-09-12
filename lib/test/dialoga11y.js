'use strict';
// lib/test/dialoga11y.js — every modal <dialog> must have an ACCESSIBLE NAME. A native <dialog> opened with
// showModal() does NOT take its name from a heading it contains (per ARIA-in-HTML), so a screen reader announces a
// dialog with only an <h3> inside as an unnamed "dialog". The name must come from aria-label or aria-labelledby. This
// regressed once (all but one dialog were unnamed), so pin it: every <dialog> in the web UI carries one of those, and
// every aria-labelledby points at an id that actually exists in the markup (no dangling reference that names nothing).
//
// Static parse only (no browser, no engine — fast and cross-platform, like the other UI-markup guards).
//
// Run:  node lib/test/dialoga11y.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const ejs = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'views', 'index.ejs'), 'utf8');

	const dialogTags = [...ejs.matchAll(/<dialog\b[^>]*>/g)].map((m) => m[0]);
	ok('index.ejs has <dialog> elements to check', dialogTags.length > 0);

	// 1. Every dialog has an accessible name (aria-label or aria-labelledby).
	const unnamed = dialogTags.filter((t) => !/\baria-label(?:ledby)?=/.test(t))
		.map((t) => (/\bid="([^"]+)"/.exec(t) || [, '(no id)'])[1]);
	ok('every <dialog> has an accessible name (aria-label or aria-labelledby)' + (unnamed.length ? ' — missing on: ' + unnamed.join(', ') : ''), unnamed.length === 0);

	// 2. Every aria-labelledby resolves to an id that exists somewhere in the markup (no dangling reference).
	const refs = [...ejs.matchAll(/aria-labelledby="([^"]+)"/g)].flatMap((m) => m[1].trim().split(/\s+/));
	const ids = new Set([...ejs.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
	const dangling = [...new Set(refs.filter((r) => !ids.has(r)))];
	ok('every aria-labelledby points at an id that exists' + (dangling.length ? ' — dangling: ' + dangling.join(', ') : ''), dangling.length === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DIALOG-A11Y CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
