'use strict';
// lib/test/settingsdrift.js — guards against a whole class of "my setting didn't stick" bugs. The web interface
// learns the current settings from two server payloads: the frequent state poll (buildState) and the response to
// saving a setting (POST /api/settings). If those two are hand-built separately they drift — a field returned by
// the save but missing from the state poll silently fails to restore on the next page load (exactly how the sync
// speed limit once reset itself to "No limit" after a reload even though it was saved on disk). This test pins two
// invariants so that cannot recur:
//   1. Both payloads are built by the ONE shared publicSettings() helper, never a separate inline object.
//   2. Every setting the client actually reads (state.settings.X) is a field publicSettings() emits — so the UI can
//      never read a setting the server does not send.
// Pure/static source analysis — no engine and no running server, so it is fast and cross-platform.
//
// Run:  node lib/test/settingsdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const web = path.join(__dirname, '..', 'webserver');
const read = (p) => fs.readFileSync(p, 'utf8');

function main() {
	const server = read(path.join(web, 'index.js'));
	const app = read(path.join(web, 'public', 'js', 'app.js'));

	// 1. The shared helper exists, and both payloads route through it (no separately hand-built settings object).
	ok('the server defines a single publicSettings() helper', /function publicSettings\s*\(/.test(server));
	const usbuild = (server.match(/settings:\s*publicSettings\(/g) || []).length;
	ok('both the state poll and the settings-save response build settings via publicSettings()', usbuild >= 2);
	// A hand-built "settings: { autoLockMinutes: ... }" object is the drift pattern this replaced — it must be gone,
	// except inside publicSettings() itself. Strip that one function body, then require no inline settings object.
	const withoutHelper = server.replace(/function publicSettings\s*\([^)]*\)\s*\{[\s\S]*?\n\}/, '');
	ok('no route hand-builds an inline settings object (would drift from publicSettings)', !/settings:\s*\{\s*autoLockMinutes/.test(withoutHelper));

	// 2. Every setting the client reads must be a field publicSettings() emits.
	const emitted = new Set();
	const body = (server.match(/function publicSettings\s*\([^)]*\)\s*\{([\s\S]*?)\n\}/) || [])[1] || '';
	for (const m of body.matchAll(/^\s*([a-zA-Z][a-zA-Z0-9]*)\s*:/gm)) emitted.add(m[1]);
	ok('publicSettings() emits a non-trivial set of fields', emitted.size >= 4);

	const read_ = new Set();
	for (const m of app.matchAll(/state\.settings(?:\s*&&\s*state\.settings)?\.([a-zA-Z][a-zA-Z0-9]*)/g)) read_.add(m[1]);
	ok('the client reads at least one setting from the state payload', read_.size >= 1);
	for (const key of read_) ok('client-read setting "' + key + '" is emitted by publicSettings()', emitted.has(key));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SETTINGS-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
