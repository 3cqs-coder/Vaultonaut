'use strict';
// lib/test/commanddrift.js — one guard against the CLI command surface drifting apart. Adding, renaming, or
// removing a command otherwise touches three places that are easy to fall out of step: the dispatch switch in
// Commands.js, the built-in help (lib/templates/help.txt), and the "## Commands" reference in docs/README.md.
// This pins them together so a change to one that misses another fails here instead of shipping. The web UI is a
// separate surface (its buttons call the same Vault.* API the CLI does, so capability cannot diverge); this guards
// the documented command list. Pure file parsing — no engine, non-blocking, cross-platform.
//
// Run:  node lib/test/commanddrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond, detail) { console.log((cond ? '  ok   ' : '  FAIL ') + name + (cond || !detail ? '' : '  → ' + detail)); if (!cond) failures++; }

const libDir = path.join(__dirname, '..');
const commandsSrc = fs.readFileSync(path.join(libDir, 'Commands.js'), 'utf8');
const helpSrc = fs.readFileSync(path.join(libDir, 'templates', 'help.txt'), 'utf8');
const readmeSrc = fs.readFileSync(path.join(libDir, '..', 'docs', 'README.md'), 'utf8');

// Labels a dispatch group may carry that are deliberately NOT documented (help/argv plumbing, not user commands).
// `help` and its flag forms are the meta command that prints the list itself, so it is not listed within it.
const UNDOCUMENTED_OK = new Set(['help', '--help', '-h', 'undefined']);

// ── Parse the command dispatch (switch (cmd) { … }) into handler GROUPS of case-labels. ──────────────
// Each group is the set of case-labels sharing one handler, so aliases (e.g. 'revoke-share'/'revokeshare')
// land in the same group and the guard only requires ONE label per group to be documented.
function dispatchGroups() {
	const from = commandsSrc.indexOf('switch (cmd)');
	if (from < 0) throw new Error('command dispatch switch not found');
	const rest = commandsSrc.slice(from);
	const end = rest.search(/\n\t\t\}\n/); // the two-tab close of the switch body
	const body = rest.slice(0, end < 0 ? rest.length : end);
	const groups = [];
	let pending = [];
	for (const line of body.split('\n')) {
		const labels = [...line.matchAll(/case (?:'([a-z][a-z0-9-]*)'|(undefined)|'(--help|-h)')\s*:/g)].map(m => m[1] || m[2] || m[3]);
		if (labels.length) pending.push(...labels);
		if (/(await |break;|return |[a-zA-Z]\(\);?)/.test(line.replace(/case .*?:/g, '')) && pending.length) { groups.push(pending); pending = []; }
	}
	if (pending.length) groups.push(pending);
	return groups;
}

// ── The `vdisk <cmd>` token from each documented line (help.txt and the README "## Commands" fenced block). ──
function tokensFromLines(text) {
	const set = new Set();
	for (const line of text.split('\n')) { const m = /^\s*vdisk\s+([a-z][a-z0-9-]*)/.exec(line); if (m) set.add(m[1]); }
	return set;
}
function readmeCommandBlock() {
	const at = readmeSrc.indexOf('## Commands');
	const open = readmeSrc.indexOf('```', at);
	const close = readmeSrc.indexOf('```', open + 3);
	return readmeSrc.slice(open + 3, close);
}

function main() {
	const groups = dispatchGroups();
	const help = tokensFromLines(helpSrc);
	const readme = tokensFromLines(readmeCommandBlock());
	const dispatchLabels = new Set(groups.flat());

	ok('the dispatch has a healthy number of commands', groups.length > 80, 'groups=' + groups.length);
	ok('help.txt lists a healthy number of commands', help.size > 80, 'help=' + help.size);

	// 1. Help and the README command reference must list the EXACT same command set.
	const inHelpNotReadme = [...help].filter(c => !readme.has(c));
	const inReadmeNotHelp = [...readme].filter(c => !help.has(c));
	ok('every help.txt command is in the README command list', inHelpNotReadme.length === 0, inHelpNotReadme.join(', '));
	ok('every README command is in help.txt', inReadmeNotHelp.length === 0, inReadmeNotHelp.join(', '));

	// 2. Every documented command must actually be dispatchable (no doc pointing at a command that does not exist).
	const undispatchable = [...help].filter(c => !dispatchLabels.has(c));
	ok('every documented command is dispatchable', undispatchable.length === 0, undispatchable.join(', '));

	// 3. Every dispatch group must be documented by at least one of its labels — so a new command can never be
	//    added to the CLI without also appearing in the help and the README.
	const undocumented = groups
		.filter(g => !g.some(l => help.has(l)) && !g.every(l => UNDOCUMENTED_OK.has(l)))
		.map(g => g.join('/'));
	ok('every dispatch command group is documented (help + README)', undocumented.length === 0, undocumented.join('  '));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL COMMAND-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
