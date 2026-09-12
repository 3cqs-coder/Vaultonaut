'use strict';
// lib/test/enginenameleak.js — the standing rule is that the underlying engine (and any other project) is never named
// in code, comments, or user-facing surfaces: the encryption engine is "the engine". This guards the USER-FACING web
// assets — everything the browser and the phone viewer load and a user can read in page source or the network tab.
// One of these files was once named after the engine and described it by name in its comments; this keeps that from
// creeping back after a rename.
//
// Scope: the served files under lib/webserver/public/. Third-party libraries under any vendor/ folder are excluded
// (they are not ours to rename). The ONLY allowed occurrence is the on-disk crypt-format magic bytes, the ASCII
// "RCLONE\0\0" file header — an unavoidable fact of the format the decryptor reads, not a project reference — so those
// are stripped before the check. Any other mention of the engine's name (case-insensitive), in a filename or the text,
// fails the build.
//
// Static only (no engine, no server, no network — fast and cross-platform).
//
// Run:  node lib/test/enginenameleak.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const PUBLIC = path.join(__dirname, '..', 'webserver', 'public');
const TEXT_EXT = new Set(['.js', '.mjs', '.html', '.htm', '.ejs', '.css', '.json', '.webmanifest', '.svg', '.txt']);
// The on-disk crypt magic, "RCLONE\0\0", as it appears in source (a JS string with escaped NULs) — the one allowed
// occurrence. Stripped before scanning so it never counts as a name reference.
const MAGIC = /RCLONE\\0\\0/g;
const NAME = /rclone/i; // the engine's project name, in any case

function walk(dir, out) {
	let entries = [];
	try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return out; }
	for (const e of entries) {
		if (e.isDirectory()) { if (e.name === 'vendor') continue; walk(path.join(dir, e.name), out); }
		else out.push(path.join(dir, e.name));
	}
	return out;
}

function main() {
	const files = walk(PUBLIC, []);
	ok('there are public web assets to scan', files.length > 0);

	const badNames = files.filter((f) => NAME.test(path.basename(f)));
	ok('no user-facing web asset is NAMED after the engine' + (badNames.length ? ': ' + badNames.map((f) => path.relative(PUBLIC, f)).join(', ') : ''), badNames.length === 0);

	const offenders = [];
	for (const f of files) {
		if (!TEXT_EXT.has(path.extname(f).toLowerCase())) continue;
		let s;
		try { s = fs.readFileSync(f, 'utf8'); } catch (_) { continue; }
		const stripped = s.replace(MAGIC, ''); // remove the allowed on-disk magic bytes
		if (NAME.test(stripped)) offenders.push(path.relative(PUBLIC, f));
	}
	ok('no user-facing web asset NAMES the engine in its text' + (offenders.length ? ' — found in: ' + offenders.join(', ') : ''), offenders.length === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-NAME-LEAK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
