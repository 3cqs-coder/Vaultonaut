'use strict';
// lib/test/vbsencoding.js — the Windows autostart entry and desktop launcher both run through a .vbs wrapper that
// wscript.exe executes. wscript reads a .vbs as the system ANSI code page unless the file is BOM-marked Unicode,
// so a plain UTF-8 file whose embedded paths contain a non-code-page character (e.g. a non-Latin username in the
// data-dir path) is mis-decoded and the launch silently fails. Both writers must therefore emit UTF-16LE with a
// BOM. This is a source guard (the write path only runs on Windows, so it can't be exercised cross-platform).
//
// Run:  node lib/test/vbsencoding.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

function main() {
	for (const [file, label] of [['Autostart.js', 'the autostart entry'], ['Shortcut.js', 'the desktop launcher']]) {
		const src = read(file);
		// The .vbs write must prepend a BOM and encode UTF-16LE.
		ok(label + ' writes its .vbs as UTF-16LE with a BOM', /writeFile\([^)]*'\\ufeff' \+ vbs[^)]*'utf16le'\)/.test(src));
		// Guard against a plain UTF-8 write of the vbs sneaking back in (writeFile(vbs) with no encoding).
		ok(label + ' does not write the .vbs as plain UTF-8', !/writeFile\((?:info\.vbsPath|info\.vbs),\s*vbs\)/.test(src));
	}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VBS-ENCODING CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
