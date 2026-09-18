'use strict';
// lib/test/spawnisolation.js — a DRIFT GUARD protecting the "tests run fully isolated" contract at its weakest seam:
// a test that spawns the REAL app in a CHILD process. In-process isolation is enforced by the _setup preload and the
// fail-safe in Common.dataDir, but a child process is a fresh Node that re-resolves its own data directory. If a test
// launches vaultonaut.js (the CLI) or the web/background service in a child WITHOUT isolating it — either the
// `-r _setup.js` preload or an explicit `--data-dir` — that child writes to the user's REAL data directory (vault
// list, locks, ledgers). testisolation.js proves the mechanisms work; this guard proves every test actually uses one.
//
// It statically scans each test's child-process spawns. A spawn that launches the app (vaultonaut.js, the webserver
// module, or a `.start(` on it) must carry an isolation token in the same call. A deliberate exception (a probe that
// runs WITHOUT the preload precisely to test the fail-safe) opts out with a `spawn-isolation-ok` marker in the call.
//
// Run:  node -r ./lib/test/_setup.js lib/test/spawnisolation.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const TEST_DIR = __dirname;
// A spawn launches the app when its arguments name the CLI entry, the web service module, or start it.
const APP_LAUNCH = /vaultonaut\.js|['"][^'"]*lib\/webserver['"]|\.start\(/;
// It is isolated when it preloads the setup shim (literal or via a SETUP constant) or pins an explicit data dir.
const ISOLATED = /_setup|\bSETUP\b|--data-dir/;
// An intentional non-isolated spawn (testing the fail-safe itself) carries this marker in the call window.
const OPT_OUT = /spawn-isolation-ok/;
const SPAWN_CALL = /\b(?:spawnSync|spawn|execFile|execFileSync)\s*\(/g;

function scan(file, text) {
	let m;
	while ((m = SPAWN_CALL.exec(text)) !== null) {
		// Look at the call and its argument list — a generous window that covers a multi-line argument array.
		const window = text.slice(m.index, m.index + 600);
		if (!APP_LAUNCH.test(window)) continue;      // not launching the app — nothing to isolate
		if (OPT_OUT.test(window)) continue;          // a deliberate, documented fail-safe probe
		if (ISOLATED.test(window)) continue;         // isolated correctly
		ok('a child that launches the app is isolated (' + path.basename(file) + ' near offset ' + m.index + ')', false);
	}
}

function main() {
	const before = failures;
	for (const name of fs.readdirSync(TEST_DIR)) {
		if (!name.endsWith('.js')) continue;
		if (name === path.basename(__filename)) continue; // this guard names the tokens literally; do not scan itself
		let text = '';
		try { text = fs.readFileSync(path.join(TEST_DIR, name), 'utf8'); } catch (_) { continue; }
		scan(path.join(TEST_DIR, name), text);
	}
	ok('every test that spawns the app in a child process isolates it (preload or --data-dir)', failures === before);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SPAWN-ISOLATION CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
