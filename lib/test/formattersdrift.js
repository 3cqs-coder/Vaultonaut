'use strict';
// lib/test/formattersdrift.js — the human-readable byte formatter is written twice: fmtBytes in the desktop client
// (lib/webserver/public/js/app.js) and human in the mobile viewer (lib/webserver/public/mobile/app.js), because the
// mobile viewer is an isolated offline bundle that cannot import the desktop script. The two have DRIFTED before (the
// mobile copy once stopped at GB while the desktop copy went to PB), so a size read one way on the phone and another
// way on the desktop. This guard extracts both functions from source, runs them side by side across a representative
// range (boundaries, every unit up to PB, and the invalid inputs), and fails if they ever disagree — so the two
// copies can never silently diverge again.
//
// Run:  node lib/test/formattersdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Pull a named function's SOURCE text out of a client file (these run in the browser, so they can't just be required),
// then turn it into a callable via new Function. Scoped to the function keyword through its closing line.
function extractFn(file, name) {
	const src = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', file), 'utf8');
	const start = src.indexOf('function ' + name + '(');
	if (start < 0) return null;
	// Walk braces from the first { after the signature to the matching }, so a single-line or multi-line body both work.
	const open = src.indexOf('{', start);
	let depth = 0, end = -1;
	for (let i = open; i < src.length; i++) { if (src[i] === '{') depth++; else if (src[i] === '}') { depth--; if (depth === 0) { end = i; break; } } }
	if (end < 0) return null;
	const body = src.slice(open + 1, end);
	return new Function('n', body);
}

function main() {
	const fmtBytes = extractFn('js/app.js', 'fmtBytes');
	const human = extractFn('mobile/app.js', 'human');
	ok('found the desktop fmtBytes', typeof fmtBytes === 'function');
	ok('found the mobile human', typeof human === 'function');
	if (!fmtBytes || !human) { console.log('\n1 CHECK(S) FAILED'); process.exit(1); }

	// A representative sweep: sub-KB, each unit boundary and mid-range, the PB range (the drift that bit before), and
	// the invalid inputs both must reject to ''.
	const KB = 1024, MB = KB * 1024, GB = MB * 1024, TB = GB * 1024, PB = TB * 1024;
	const cases = [0, 1, 512, 1023, 1024, 1536, 99 * KB, 100 * KB, MB, 1.5 * MB, 999 * MB, GB, 250 * GB, TB, 3 * TB, PB, 5 * PB, 9999 * PB, -1, NaN, Infinity];
	let mismatch = null;
	for (const v of cases) { if (fmtBytes(v) !== human(v)) { mismatch = v; break; } }
	ok('the desktop and mobile byte formatters agree on every value', mismatch === null);
	if (mismatch !== null) console.log('    first disagreement at ' + mismatch + ': desktop="' + fmtBytes(mismatch) + '" mobile="' + human(mismatch) + '"');
	// Spot-check a couple of exact strings so a matched-but-wrong pair (both drifting together) is still caught.
	ok('a mid-range value formats as expected', fmtBytes(1.5 * MB) === '1.5 MB');
	ok('the PB range is reached (not capped at GB or TB)', fmtBytes(5 * PB) === '5.0 PB');

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FORMATTER-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
