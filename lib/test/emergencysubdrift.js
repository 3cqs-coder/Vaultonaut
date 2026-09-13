'use strict';
// lib/test/emergencysubdrift.js — the `emergency` command's SUB-command surface lives in four places that
// commanddrift.js does not cover (it guards only top-level commands): the usage string in cmdEmergency, the built-in
// help (help.txt), the README command reference, and the actual `sub === '...'` handler branches. This pins them
// together so adding or renaming a sub-command cannot fall out of step. Pure file parsing — no engine, cross-platform.
//
// Run:  node lib/test/emergencysubdrift.js

const fs = require('fs');
const path = require('path');
const libDir = path.join(__dirname, '..');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Pull the "<a|b|c>" sub-command list that immediately follows "emergency " in a line of text.
function subList(text) { const m = /emergency <([a-z0-9|_-]+)>/i.exec(text); return m ? m[1].split('|').map(s => s.trim()).filter(Boolean) : null; }

function main() {
	const cmds = fs.readFileSync(path.join(libDir, 'Commands.js'), 'utf8');
	const help = fs.readFileSync(path.join(libDir, 'templates', 'help.txt'), 'utf8');
	const readme = fs.readFileSync(path.join(libDir, '..', 'docs', 'README.md'), 'utf8');

	// Scope the handler search to cmdEmergency's body, since `sub === '...'` also appears in other command handlers.
	const emStart = cmds.indexOf('async function cmdEmergency(');
	const emEnd = cmds.indexOf('\nasync function ', emStart + 10);
	const emBody = cmds.slice(emStart, emEnd > 0 ? emEnd : cmds.length);
	ok('cmdEmergency was found', emStart >= 0 && emBody.length > 100);

	// The usage string inside cmdEmergency is the source of truth for the surface.
	const usage = subList(emBody);
	ok('the emergency usage string lists its sub-commands', Array.isArray(usage) && usage.length >= 10);
	ok('the built-in help lists the same emergency sub-commands as the usage string', JSON.stringify(subList(help)) === JSON.stringify(usage));
	ok('the README lists the same emergency sub-commands as the usage string', JSON.stringify(subList(readme)) === JSON.stringify(usage));

	// Every listed sub-command has a matching `sub === '<token>'` branch in cmdEmergency.
	for (const t of usage || []) ok('sub-command "' + t + '" has a handler branch', emBody.includes("sub === '" + t + "'"));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-SUBDRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
