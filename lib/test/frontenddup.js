'use strict';
// lib/test/frontenddup.js — guard against DUPLICATE top-level function declarations in the front-end bundles. Two
// `function foo() {}` at the same scope do not raise an error: the LAST one silently SHADOWS the earlier, so a call
// meant for one runs the other. This caused a real bug — two relTime() functions with different signatures made a
// one-argument call return "NaN … ago" in the devices activity feed. Source-only (no DOM, no engine), so it runs on
// every platform and CI runner and fails the build if a duplicate is reintroduced.
//
// Run:  node lib/test/frontenddup.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');

// Top-level function declarations only (a line that STARTS with `function name(`), which are the ones that hoist and
// silently shadow. A nested/indented function is a different scope and is not flagged.
function duplicateFns(rel) {
	let src = ''; try { src = fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return { missing: true, dups: [] }; }
	const seen = new Map();
	src.split('\n').forEach((line, i) => { const m = /^function ([A-Za-z0-9_$]+)\s*\(/.exec(line); if (m) seen.set(m[1], (seen.get(m[1]) || []).concat(i + 1)); });
	return { missing: false, dups: [...seen.entries()].filter(([, lines]) => lines.length > 1) };
}

const bundles = ['lib/webserver/public/js/app.js', 'lib/webserver/public/mobile/app.js', 'lib/webserver/public/js/login.js'];
let scanned = 0;
for (const rel of bundles) {
	const r = duplicateFns(rel);
	if (r.missing) continue; // a bundle that is not present in this layout is simply skipped
	scanned++;
	ok(rel + ' has no duplicate top-level function declaration' + (r.dups.length ? ' (found: ' + r.dups.map(([n, l]) => n + ' @ lines ' + l.join(', ')).join('; ') + ')' : ''), r.dups.length === 0);
}
ok('the scan inspected the front-end bundles', scanned > 0);

// The scanner itself must actually catch a duplicate (so a future refactor cannot neuter it into a silent pass).
const probe = (() => { const s = 'function a() {}\nfunction b() {}\nfunction a() {}\n'; const seen = new Map(); s.split('\n').forEach((l) => { const m = /^function ([A-Za-z0-9_$]+)\s*\(/.exec(l); if (m) seen.set(m[1], (seen.get(m[1]) || 0) + 1); }); return [...seen.values()].some((c) => c > 1); })();
ok('the duplicate-function scanner catches a planted duplicate', probe === true);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FRONTEND-DUP CHECKS PASSED'));
process.exit(failures ? 1 : 0);
