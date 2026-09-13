'use strict';
// lib/test/scheduletz.js — daily schedules are stored and evaluated in UTC (so a job fires at the same absolute
// moment on every machine, and sync/mirror cadences stay uniform), while both the web interface and the CLI take and
// show the user's LOCAL time. This pins that the local<->UTC conversion is present at every edge, guarding against a
// regression of the bug where the backend read UTC but a surface sent/showed raw local time — which fired daily jobs
// off by the timezone offset for every non-UTC user. Pure file parsing; no engine.
//
// Run:  node lib/test/scheduletz.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const app = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');
	const cmds = fs.readFileSync(path.join(__dirname, '..', 'Commands.js'), 'utf8');
	const vault = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');

	// The backend evaluates the daily time in UTC (built with Date.UTC in isScheduleDue).
	ok('the backend builds the daily schedule instant in UTC', /Date\.UTC\(now\.getUTCFullYear\(\)/.test(vault));

	// Both surfaces define the local<->UTC helpers.
	ok('the web interface defines the local<->UTC schedule-time helpers', /function localHmToUtc\(/.test(app) && /function utcHmToLocal\(/.test(app));
	ok('the CLI defines the local<->UTC schedule-time helpers', /function localHmToUtc\(/.test(cmds) && /function utcHmToLocal\(/.test(cmds));

	// PARITY: the two copies must stay byte-identical. The browser copy cannot `require` the Node module, so the
	// helpers are unavoidably duplicated — but a one-sided edit would make a time set on one surface (say, the web
	// interface) fire at a different local moment than the same time set on the other (the CLI). Extract each
	// single-line definition from both files and require them to match, so any future edit has to touch both.
	const lineOf = (src, name) => { const m = new RegExp('^function ' + name + '\\(.*$', 'm').exec(src); return m ? m[0].trim() : null; };
	for (const name of ['localHmToUtc', 'utcHmToLocal']) {
		const a = lineOf(app, name), c = lineOf(cmds, name);
		ok('the ' + name + ' helper is defined identically in the web interface and the CLI (no drift)', !!a && a === c);
	}

	// Web: the backup save converts the picked local time to UTC; the render converts the stored UTC time back to local.
	ok('the web backup save converts the picked local time to UTC', /localHmToUtc\(h, m\)/.test(app));
	ok('the web backup render converts the stored UTC time to local', /utcHmToLocal\(sch\.hour, sch\.minute\)/.test(app));
	ok('the web scrub save stores its fixed nightly time as UTC', /localHmToUtc\(3, 0\)/.test(app));

	// CLI: converts the --daily local time to UTC on input, and shows the stored UTC time in local.
	ok('the CLI converts the --daily local time to UTC', /localHmToUtc\(hour, minute\)/.test(cmds));
	ok('the CLI shows the stored UTC time in local', /utcHmToLocal\(s\.hour, s\.minute\)/.test(cmds));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SCHEDULE-TZ CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
