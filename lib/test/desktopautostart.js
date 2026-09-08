'use strict';
// lib/test/desktopautostart.js — a DRIFT GUARD over the desktop-app vs headless autostart split. Vaultonaut runs
// two ways from one codebase: a headless/CLI install (servers doing backups, mirroring, scheduled work with no
// GUI) and the packaged native desktop app. Autostart must serve BOTH from one mechanism — install the same login
// service — while differing in exactly one place: a command-line install also adds a clickable browser-launcher so
// daily use needs no terminal, but the desktop app must NOT (it is already that clickable app, and a second one of
// the same name collides with it in the system's app list). That single difference is driven by one fact,
// Common.isDesktopApp(), set from the desktop shell's --desktop launch flag. This asserts the whole chain stays
// wired so it can never silently drift back to double-installing (or stop skipping) the launcher.
//
// Run:  node -r ./lib/test/_setup.js lib/test/desktopautostart.js

const fs = require('fs');
const path = require('path');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const REPO = path.join(__dirname, '..', '..');
function read(rel) { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (_) { return ''; } }

function main() {
	// 1) The single source of truth: default off, and it round-trips.
	ok('isDesktopApp() defaults to false (a plain/headless install)', Common.isDesktopApp() === false);
	Common.setDesktopApp(true); ok('setDesktopApp(true) is reflected', Common.isDesktopApp() === true);
	Common.setDesktopApp(false); ok('setDesktopApp(false) is reflected', Common.isDesktopApp() === false);

	// 2) Startup maps the launch flag to that fact.
	const entry = read('vaultonaut.js');
	ok('startup sets the desktop-app flag from --desktop', /flags\.desktop/.test(entry) && /setDesktopApp\(true\)/.test(entry));

	// 3) Both autostart install sites gate the clickable launcher on NOT being the desktop app — so the desktop app
	//    installs only the login service, and a headless/CLI install still gets its launcher.
	const web = read(path.join('lib', 'webserver', 'index.js'));
	ok('the web autostart route skips the launcher for the desktop app', /!Common\.isDesktopApp\(\)/.test(web) && /Shortcut'\)\.create\(\)/.test(web));
	const cmds = read(path.join('lib', 'Commands.js'));
	ok('the CLI autostart install skips the launcher for the desktop app', /!Common\.isDesktopApp\(\)/.test(cmds) && /Shortcut\.create\(\)/.test(cmds));

	// 4) The desktop shell actually passes --desktop (skips cleanly if the packaging tree is absent).
	const mainRs = path.join(REPO, 'src-tauri', 'src', 'main.rs');
	if (fs.existsSync(mainRs)) {
		ok('the desktop shell launches the backend with --desktop', /"--desktop"/.test(fs.readFileSync(mainRs, 'utf8')));
	} else {
		console.log('  skip  (no src-tauri desktop shell in this checkout)');
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DESKTOP-AUTOSTART CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
