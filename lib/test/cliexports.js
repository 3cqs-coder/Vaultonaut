'use strict';
// lib/test/cliexports.js — the CLI (lib/Commands.js) calls the library through `vdisk` (lib/index.js). Every
// `vdisk.<method>` it uses MUST be exported by index, or that command throws "vdisk.<method> is not a function" at
// runtime — a class of bug the CLI's own tests do not otherwise catch (e.g. displayName, which was on Vault but not
// re-exported). This pins the contract. It also confirms the externalized CLI notices parse into their blocks.
//
// Run:  node lib/test/cliexports.js

const fs = require('fs');
const path = require('path');
const idx = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const src = fs.readFileSync(path.join(__dirname, '..', 'Commands.js'), 'utf8');
	const used = [...new Set([...src.matchAll(/\bvdisk\.([a-zA-Z0-9_]+)/g)].map(m => m[1]))].sort();
	ok('the CLI uses a non-trivial number of library methods (sanity)', used.length > 50);
	const missing = used.filter(m => typeof idx[m] === 'undefined'); // a missing (undefined) export is the bug; a value export like kdfLevels is fine
	ok('every vdisk.<member> the CLI uses is exported by lib/index.js' + (missing.length ? ' — missing: ' + missing.join(', ') : ''), missing.length === 0);

	// The externalized CLI notices must parse into their four non-empty blocks (a missing file would silently print
	// nothing for a destructive/expert action's disclosure).
	const notices = fs.readFileSync(path.join(__dirname, '..', 'templates', 'notices.txt'), 'utf8');
	const sections = {};
	let cur = null, buf = [];
	for (const line of notices.split('\n')) {
		const m = /^\[(.+)\]\s*$/.exec(line);
		if (m) { if (cur) sections[cur] = buf.join('\n').trim(); cur = m[1]; buf = []; }
		else if (cur !== null) buf.push(line);
	}
	if (cur) sections[cur] = buf.join('\n').trim();
	for (const key of ['decoy-limits', 'travel-limits', 'emergency-limits', 'rotate-limits']) {
		ok('notices.txt has a non-empty [' + key + '] block', !!sections[key] && sections[key].length > 40);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLI-EXPORT CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
