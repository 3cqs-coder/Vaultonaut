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

	// 3b) The clickable launcher that create() writes must escape shell-special characters in the paths it embeds,
	// the same way Autostart escapes its service commands. A macOS home directory, a Linux username, or a custom
	// data directory can legally contain "$", a backtick, or a quote; unescaped inside the launcher's double-quoted
	// POSIX shell script or .desktop Exec line, the launcher would silently fail to start the app on a click. Pin
	// that Shortcut defines the escaper AND applies it to the node, script, and data-dir paths on both platforms.
	const sc = read(path.join('lib', 'Shortcut.js'));
	ok('Shortcut defines a POSIX double-quote escaper (\\ ` $ ")', /shDq\s*=\s*\(s\)\s*=>\s*String\(s\)\.replace\(\/\(\[\\\\`\$"\]\)\//.test(sc));
	ok('the macOS launcher shell script escapes the node and script paths', /exec "'\s*\+\s*shDq\(node\)\s*\+\s*'" "'\s*\+\s*shDq\(script\)/.test(sc));
	ok('the Linux .desktop Exec line escapes the node and script paths (with %-doubling)', /deArg\s*=\s*\(s\)\s*=>\s*shDq\(s\)\.replace\(\/%\/g/.test(sc) && /Exec="'\s*\+\s*deArg\(node\)\s*\+\s*'" "'\s*\+\s*deArg\(script\)/.test(sc));
	ok('the data-dir fragment is escaped on both platforms', /shDq\(ddPath\)/.test(sc) && /deArg\(ddPath\)/.test(sc));

	// 3c) Start-at-login vs the desktop app: when a TRUSTED instance (the login/background service) already holds the
	// shared loopback port, the desktop app must show that instance instead of failing on the busy port. The `ui`
	// backend signals this to the shell by exiting with Common.DESKTOP_ATTACH_EXIT_CODE. Pin that the handoff fires
	// ONLY for the desktop app AND only for a trusted owner (OwnerClient.find — an owner-only pidfile), never for a
	// process that merely answers the port (a squatter), which must never be shown in the trusted window.
	ok('the ui backend hands off to a running trusted instance for the desktop app', /runningOwner && Common\.isDesktopApp\(\)[\s\S]{0,220}process\.exit\(Common\.DESKTOP_ATTACH_EXIT_CODE\)/.test(cmds));
	ok('the handoff is gated on a TRUSTED owner (OwnerClient.find), not a bare port response', /const runningOwner = await OwnerClient\.find\(\)/.test(cmds));

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
