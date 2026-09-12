'use strict';
// lib/test/relayportdrift.js — the relay hub's default control port and public data-port range must be single-sourced
// in Common, the same way the UI port is, so the hub (`vdisk hub`), the serve-through-relay client, and the stored
// relay registration can never disagree. A zero-config hub-and-node connect depends on them matching. This guards
// against a literal 7443 (or the 20000-20099 range) creeping back into the relay modules and silently re-drifting.
//
// Run:  node lib/test/relayportdrift.js

const fs = require('fs');
const path = require('path');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (rel) => { try { return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8'); } catch (_) { return ''; } };
// Strip line comments so an illustrative "7443" inside a comment (e.g. an IPv6 example) is not treated as a literal.
const codeOnly = (src) => src.replace(/\/\/.*$/gm, '');

function main() {
	ok('Common single-sources the relay port and data-port range', Common.DEFAULT_RELAY_PORT === 7443 && Array.isArray(Common.DEFAULT_RELAY_DATA_PORT_RANGE) && Common.DEFAULT_RELAY_DATA_PORT_RANGE.length === 2);

	// The hub builder must default from the shared constants, not a literal.
	const relay = read('Relay.js');
	ok('Relay.runHub defaults controlPort from Common.DEFAULT_RELAY_PORT', /controlPort = Common\.DEFAULT_RELAY_PORT/.test(relay));
	ok('Relay.runHub defaults portRange from Common.DEFAULT_RELAY_DATA_PORT_RANGE', /portRange = Common\.DEFAULT_RELAY_DATA_PORT_RANGE/.test(relay));

	// No relay module may carry the bare literal in CODE (comments are allowed for examples).
	for (const rel of ['Relay.js', 'Commands.js', 'Vault.js']) {
		ok('no literal 7443 in ' + rel + ' code (use Common.DEFAULT_RELAY_PORT)', !/\b7443\b/.test(codeOnly(read(rel))));
	}
	ok('no literal 20000, 20099 range in Commands.js code', !/\b20000\s*,\s*20099\b/.test(codeOnly(read('Commands.js'))));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELAY-PORT-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
