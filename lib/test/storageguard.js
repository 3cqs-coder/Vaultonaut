'use strict';
// lib/test/storageguard.js — a browser's Web Storage (localStorage / sessionStorage) can THROW on access, not just
// return null: Safari's "Block All Cookies", a locked-down profile, or private mode make the very first getItem/setItem
// raise a SecurityError. The theme is read during boot, so one unguarded access there throws before the UI renders and
// leaves the whole interface blank. That shipped once and was fixed by wrapping every access in try/catch. This test
// pins the whole class: every localStorage/sessionStorage access in every served front-end bundle must sit inside a
// try block, so a future unguarded access fails here instead of blanking a user's app. Pure — no engine, no browser.
//
// Run:  node lib/test/storageguard.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const pub = path.join(__dirname, '..', 'webserver', 'public');

// Replace the INSIDE of every string, template, comment, and regular-expression literal with spaces (newlines kept, so
// line numbers survive). Braces, the word "try", and "localStorage" that appear inside a literal or a comment then
// cannot confuse the brace scan below. A regex literal is told apart from a division by the previous significant
// character — a division only follows a value (an identifier, number, or a closing ) ] }), so a `/` after anything
// else, or at the start, begins a regex. This is the standard heuristic and is exact for the code these bundles use.
function blankLiterals(src) {
	const out = src.split('');
	const n = src.length;
	const blank = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
	let i = 0, prev = '';
	while (i < n) {
		const c = src[i];
		if (c === '/' && src[i + 1] === '/') { let j = i + 2; while (j < n && src[j] !== '\n') j++; blank(i, j); i = j; continue; }
		if (c === '/' && src[i + 1] === '*') { let j = i + 2; while (j < n && !(src[j] === '*' && src[j + 1] === '/')) j++; j = Math.min(n, j + 2); blank(i, j); i = j; continue; }
		if (c === '"' || c === "'" || c === '`') { let j = i + 1; while (j < n && src[j] !== c) { if (src[j] === '\\') j++; j++; } j = Math.min(n, j + 1); blank(i + 1, j - 1); prev = c; i = j; continue; }
		if (c === '/') {
			const isRegex = prev === '' || '([{,;:=!&|?+-*%^~<>'.indexOf(prev) >= 0;
			if (isRegex) { let j = i + 1, inClass = false; while (j < n) { const d = src[j]; if (d === '\\') { j += 2; continue; } if (d === '[') inClass = true; else if (d === ']') inClass = false; else if (d === '/' && !inClass) break; else if (d === '\n') break; j++; } j = Math.min(n, j + 1); blank(i + 1, j - 1); prev = '/'; i = j; continue; }
		}
		if (!/\s/.test(c)) prev = c;
		i++;
	}
	return out.join('');
}

// Walk the literal-blanked source once, keeping a stack of open braces that remembers whether each block was opened by
// `try`. An access is guarded when ANY enclosing block on the stack is a try block (so `try { if (x) { localStorage… } }`
// counts). Returns the 1-based line numbers of any UNGUARDED access.
function unguardedStorageLines(rawSrc) {
	const src = blankLiterals(rawSrc);
	const n = src.length;
	const stack = []; // each: true if a try block
	const bad = [];
	const wordBefore = (idx) => { let k = idx - 1; while (k >= 0 && /\s/.test(src[k])) k--; let end = k + 1; while (k >= 0 && /[A-Za-z0-9_$]/.test(src[k])) k--; return src.slice(k + 1, end); };
	const lineAt = (idx) => rawSrc.slice(0, idx).split('\n').length;
	for (let i = 0; i < n; i++) {
		const c = src[i];
		if (c === '{') { stack.push(wordBefore(i) === 'try'); continue; }
		if (c === '}') { stack.pop(); continue; }
		if (c === 'l' || c === 's') {
			const m = src.slice(i, i + 15).match(/^(localStorage|sessionStorage)\s*\./);
			if (m) {
				// only a real member access, not part of a longer identifier (e.g. myLocalStorage)
				const pc = i > 0 ? src[i - 1] : '';
				if (!/[A-Za-z0-9_$]/.test(pc)) { if (!stack.some(Boolean)) bad.push(lineAt(i)); i += m[0].length - 1; }
			}
		}
	}
	return bad;
}

// Every served bundle that can touch Web Storage. Any file with an access must have all of them guarded.
const files = ['js/app.js', 'js/theme-boot.js', 'js/login.js', 'js/webauthn.js', 'mobile/app.js', 'mobile/theme-boot.js', 'mobile/crypt-reader.js', 'send/app.js', 'shared/secret-schema.js', 'shared/safe-text.js'];
let scanned = 0, withAccess = 0;
for (const rel of files) {
	const p = path.join(pub, rel);
	let src; try { src = fs.readFileSync(p, 'utf8'); } catch (_) { continue; } // a bundle may not exist on every branch
	scanned++;
	if (!/(localStorage|sessionStorage)\s*\./.test(src)) continue;
	withAccess++;
	const bad = unguardedStorageLines(src);
	ok(rel + ' — every Web Storage access is inside a try block', bad.length === 0);
	if (bad.length) console.log('       unguarded at line(s): ' + bad.join(', '));
}
ok('the scan actually inspected the front-end bundles', scanned >= 6);
ok('at least one bundle uses Web Storage (the scanner has real work to check)', withAccess >= 1);

// --- self-test: the scanner MUST flag a bare, unguarded access, or it proves nothing ---
ok('scanner flags a bare unguarded access', unguardedStorageLines('function f(){ var t = localStorage.getItem("x"); }').length === 1);
ok('scanner accepts an inline try-guarded access', unguardedStorageLines('try { localStorage.setItem("x", 1); } catch (_) {}').length === 0);
ok('scanner accepts a multi-line try-guarded access', unguardedStorageLines('try {\n  var s = localStorage.getItem("x");\n} catch (e) {}').length === 0);
ok('scanner accepts a try with a nested block', unguardedStorageLines('try { if (x) { localStorage.removeItem("x"); } } catch (_) {}').length === 0);
ok('scanner ignores an access written inside a string or comment', unguardedStorageLines('var s = "localStorage.getItem"; // localStorage.setItem here too\n').length === 0);
ok('scanner does not match a longer identifier ending in Storage', unguardedStorageLines('var x = myLocalStorage.getItem("x");').length === 0);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL STORAGE-GUARD CHECKS PASSED'));
process.exit(failures ? 1 : 0);
