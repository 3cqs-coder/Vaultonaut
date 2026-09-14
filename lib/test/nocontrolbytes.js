'use strict';
// lib/test/nocontrolbytes.js — no JavaScript source file may contain a RAW control byte (0x00-0x1F other than tab,
// newline, and carriage return). Such bytes are invisible, make plain grep and file(1) treat the file as binary (which
// silently hides those lines from code search, linters, and security scanners), and are fragile: an editor "trim", a
// git normalization filter, or a copy-paste can drop or alter them with no visible diff — which for a control-char
// filename filter or a hash separator would silently change behavior. Write them as \x.. escapes instead (byte-identical
// at runtime, plain-text source). This guard keeps them from creeping back in. Pure static scan — fast, cross-platform.
//
// Run:  node lib/test/nocontrolbytes.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const repo = path.join(__dirname, '..', '..');
const roots = [path.join(repo, 'lib'), repo]; // lib/** plus the top-level scripts (verify.js, vaultonaut.js)
const SKIP_DIRS = new Set(['node_modules', '.git', '.test-data', 'data', 'src-tauri']); // build/vendor/data trees
// Control bytes that must never appear raw in source: 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, and DEL 0x7F. Tab (0x09),
// newline (0x0A), and carriage return (0x0D) are legitimate whitespace and allowed.
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

function jsFiles(dir, top) {
	const out = [];
	let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return out; }
	for (const e of entries) {
		if (e.name.startsWith('.') && e.isDirectory()) continue;
		const p = path.join(dir, e.name);
		if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) out.push(...jsFiles(p, false)); }
		else if (e.isFile() && e.name.endsWith('.js')) { if (top && !['verify.js', 'vaultonaut.js'].includes(e.name)) continue; out.push(p); }
	}
	return out;
}

const files = new Set();
files.add(path.join(repo, 'verify.js'));
files.add(path.join(repo, 'vaultonaut.js'));
for (const f of jsFiles(path.join(repo, 'lib'), false)) files.add(f);

let scanned = 0, offenders = [];
for (const f of files) {
	let s; try { s = fs.readFileSync(f, 'utf8'); } catch (_) { continue; }
	scanned++;
	if (CONTROL.test(s)) {
		const line = s.split('\n').findIndex(l => CONTROL.test(l)) + 1;
		offenders.push(path.relative(repo, f) + ':' + line);
	}
}
ok('the scan inspected a realistic number of JS source files', scanned >= 60);
ok('no JS source file contains a raw control byte: ' + (offenders.slice(0, 10).join(', ') || 'none'), offenders.length === 0);
// Self-test: the pattern must actually catch a raw NUL, or the guard proves nothing.
ok('the control-byte pattern catches a raw NUL', CONTROL.test('a\x00b') && !CONTROL.test('a\tb\nc\rd'));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NO-CONTROL-BYTES CHECKS PASSED'));
process.exit(failures ? 1 : 0);
