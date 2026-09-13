'use strict';
// lib/test/cliparse.js — the command-line argument parser. A value-less switch (for example --force) must NOT
// consume the token after it, so a switch can be placed BEFORE a positional (`unmount --force /path`) without
// swallowing the path — the common stuck-mount escape hatch. Value-taking flags must still bind their value in both
// the `--flag value` and `--flag=value` forms. This pins both, and guards the boolean-flag set against a value flag
// being added by mistake (which would break that flag's space-separated form).
//
// Run:  node lib/test/cliparse.js

const fs = require('fs');
const path = require('path');
const { parse, _flagSets } = require('../Commands');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	// A boolean switch before a positional leaves the positional intact (does not eat it as the switch's value).
	for (const [argv, sw] of [
		[['unmount', '--force', '/Volumes/MyVault'], 'force'],
		[['mount', '--read-only', '/path/to/vault'], 'read-only'],
		[['rotate', '--yes', 'MyVault'], 'yes'],
		[['secure-remove', '--panic', 'MyVault'], 'panic'],
		[['ui', '--desktop', 'extra'], 'desktop'],
	]) {
		const r = parse(argv);
		ok('a boolean --' + sw + ' before a positional is a switch and keeps the positional', r.flags[sw] === true && r.positionals.length === 2 && r.positionals[1] === argv[2]);
	}

	// A value flag still binds its value, in both forms, and does not become a stray positional.
	const spaced = parse(['ui', '--bind', '0.0.0.0', '--port', '7420']);
	ok('a value flag binds a space-separated value', spaced.flags.bind === '0.0.0.0' && spaced.flags.port === '7420' && spaced.positionals.length === 1);
	const eq = parse(['ui', '--bind=127.0.0.1', '--kdf=high']);
	ok('a value flag binds an =value', eq.flags.bind === '127.0.0.1' && eq.flags.kdf === 'high');

	// A value flag mixed with a boolean switch before the positional resolves both correctly.
	const mixed = parse(['mount', '--read-only', '--bind', '127.0.0.1', '/p']);
	ok('a switch and a value flag together keep the value and the positional', mixed.flags['read-only'] === true && mixed.flags.bind === '127.0.0.1' && mixed.positionals[1] === '/p');

	// DRIFT GUARD: no flag the CLI reads AS A VALUE may be in the boolean-flag set — that would break its
	// space-separated form. Pin the value flags that were specifically confirmed to take a value (a bare form of each
	// is rejected or resolved as a value by its handler, never treated as a switch). A boolean form here proves the
	// set does not wrongly classify them.
	for (const vf of ['bind', 'port', 'out', 'kdf', 'cloud', 'keep', 'expect', 'label', 'dest', 'mountpoint', 'token', 'from', 'to']) {
		const r = parse(['cmd', '--' + vf, 'somevalue', 'positional']);
		ok('value flag --' + vf + ' still consumes its value (not misclassified as a switch)', r.flags[vf] === 'somevalue' && r.positionals[1] === 'positional');
	}

	// DRIFT GUARD 2: BOOLEAN_FLAGS and VALUE_FLAGS must be disjoint — a flag classified as both would break either its
	// switch form or its space-separated value form.
	const { BOOLEAN_FLAGS, VALUE_FLAGS, KNOWN_FLAGS } = _flagSets;
	const overlap = [...BOOLEAN_FLAGS].filter(f => VALUE_FLAGS.has(f));
	ok('BOOLEAN_FLAGS and VALUE_FLAGS are disjoint (no flag is both a switch and a value)', overlap.length === 0);

	// DRIFT GUARD 3: KNOWN_FLAGS must be COMPLETE — every flag a handler reads must be listed, or the new unknown-flag
	// warning would fire on a real, valid flag. Scan Commands.js for every flags['x'] / flags.x access and require each
	// to be known. (data-dir / dns-order are consumed upstream and are already in VALUE_FLAGS.)
	const cmdSrc = fs.readFileSync(path.join(__dirname, '..', 'Commands.js'), 'utf8');
	const accessed = new Set();
	for (const m of cmdSrc.matchAll(/flags\['([a-z0-9-]+)'\]/g)) accessed.add(m[1]);
	for (const m of cmdSrc.matchAll(/flags\.([a-zA-Z][a-zA-Z0-9]*)/g)) accessed.add(m[1]);
	const missing = [...accessed].filter(f => !KNOWN_FLAGS.has(f));
	ok('every flag a handler reads is in KNOWN_FLAGS (the unknown-flag warning never fires on a real flag): ' + (missing.join(', ') || 'none missing'), missing.length === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLI-PARSE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
