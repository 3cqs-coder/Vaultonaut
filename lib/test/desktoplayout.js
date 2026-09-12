'use strict';
// lib/test/desktoplayout.js — a DRIFT GUARD over the desktop bundle's layout and identity contract, which is
// otherwise spread across three languages with nothing tying them together: the Rust shell (`src-tauri/src/
// main.rs`), the staging script (`src-tauri/prepare-sidecar.js`), and the Tauri config (`src-tauri/
// tauri.conf.json`). A mismatch here breaks app launch only at full-build-and-run time, which the unit suite
// never reaches — so assert the contract statically. Also enforces the single-sourced facts: the loopback port
// matches the Node default, the product name matches Brand, and the version matches across all three files.
// Skips gracefully when the packaging tree is absent.
//
// Run:  node -r ./lib/test/_setup.js lib/test/desktoplayout.js

const fs = require('fs');
const path = require('path');
const Common = require('../Common');
const Brand = require('../Brand');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DESKTOP-LAYOUT CHECKS PASSED')); process.exit(failures ? 1 : 0); }
const REPO = path.join(__dirname, '..', '..');
const ST = path.join(REPO, 'src-tauri');
function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return ''; } }

// Extract the Linux apt package set from a blob (the `apt install` line, across backslash continuations).
function aptPackages(text) {
	const lines = String(text).split('\n');
	let i = lines.findIndex((l) => l.includes('libwebkit2gtk'));
	if (i < 0) return null;
	let joined = '';
	for (; i < lines.length; i++) { joined += ' ' + lines[i]; if (!lines[i].trimEnd().endsWith('\\')) break; }
	const known = new Set(['build-essential', 'curl', 'wget', 'file']);
	return new Set(joined.replace(/\\/g, ' ').split(/\s+/).filter(Boolean).filter((t) => t.startsWith('lib') || known.has(t)));
}

function main() {
	if (!fs.existsSync(path.join(ST, 'src', 'main.rs'))) { console.log('  skip  (no src-tauri desktop shell in this checkout)'); return done(); }

	const mainRs = read(path.join(ST, 'src', 'main.rs'));
	let conf = {}; try { conf = JSON.parse(read(path.join(ST, 'tauri.conf.json'))); } catch (_) {}
	let prep; try { prep = require(path.join(ST, 'prepare-sidecar.js')); } catch (e) { ok('the staging script loads', false); return done(); }
	const pkg = (() => { try { return JSON.parse(read(path.join(REPO, 'package.json'))); } catch (_) { return {}; } })();
	const cargo = read(path.join(ST, 'Cargo.toml'));

	// Layout contract: the dirs the shell reads == the dirs the staging writes == the resources the config bundles.
	ok('the staged app dir is named "app"', path.basename(prep.APP_DIR) === 'app');
	ok('the runtime is staged INSIDE app/ (ships with the bundle; pinned by version, not covered by the signed manifest)', prep.RUNTIME_DIR === path.join(prep.APP_DIR, 'runtime'));
	ok('the config bundles the "app" resource', !!(conf.bundle && conf.bundle.resources && Object.prototype.hasOwnProperty.call(conf.bundle.resources, 'app')));
	ok('the shell resolves the runtime under app/runtime', /"app"\)\s*\.join\("runtime"\)/.test(mainRs));
	ok('the shell resolves the entry as app/vaultonaut.js', /"app"\)\s*\.join\("vaultonaut\.js"\)/.test(mainRs));

	// Host-independent bundle signing: the build must EMBED the committed, maintainer-signed manifest by copying it
	// into the staged app — never hold a private key. This is what lets a hosted CI runner produce a verifiable build
	// without the signing key ever leaving the maintainer's machine. Guard both halves so the CI-safe flow cannot regress.
	const signBundle = read(path.join(ST, 'sign-bundle.js'));
	ok('sign-bundle embeds the committed manifest by copying it into the bundle', /copyFileSync/.test(signBundle) && /MANIFEST_NAME/.test(signBundle));
	ok('sign-bundle holds no private key at build time (never signs)', !/signManifest|release-signing-key|loadSeed/.test(signBundle));
	// A Windows-only crash class: Tauri's resource_dir() is a \\?\ verbatim path, which Node cannot use as its main
	// entry script (it aborts in module resolution before any of our code runs). The shell MUST strip that prefix
	// before deriving the Node and entry paths, or the packaged app never starts on Windows.
	ok('the shell strips the Windows verbatim path prefix from resource_dir (plain_path)', /plain_path\(app\.path\(\)\.resource_dir/.test(mainRs));

	// Lock-on-exit is a core safety guarantee: every quit gesture must route through the backend drain-and-lock, and a
	// second quit while the drain is running must not abort it. A live shutdown test would need a packaged app and a
	// real quit gesture, so these are static guards at the same level as the other main.rs invariants above.
	ok('the shell drains-and-locks the backend on both window close and quit', /WindowEvent::CloseRequested/.test(mainRs) && /RunEvent::ExitRequested/.test(mainRs) && /shutdown_in_background\(/.test(mainRs));
	ok('a last-resort RunEvent::Exit still stops the backend', /RunEvent::Exit\s*=>/.test(mainRs) && /stop_backend\(&mut child, SHUTDOWN_GRACE\)/.test(mainRs));
	// The window is hidden before the drain so it vanishes at once rather than freezing for the multi-second lock. The
	// hide is a UI call reached from a background thread (the quit-confirmation dialog), so it must be marshaled to the
	// main thread (run_on_main_thread) or it can be dropped and the window stays visible for the whole drain.
	ok('the background drain hides the window (on the main thread) before draining', /fn shutdown_in_background[\s\S]{0,1200}run_on_main_thread\(move \|\| \{ let _ = win\.hide\(\)[\s\S]{0,400}stop_backend\(/.test(mainRs));
	ok('a second quit gesture cannot abort an in-progress drain', /SHUTTING_DOWN/.test(mainRs) && /DRAIN_DONE/.test(mainRs));
	ok('stop_backend asks for a clean stop (SIGTERM) before force-killing on unix', /SIGTERM[\s\S]{0,500}child\.kill\(\)/.test(mainRs));
	// The Windows drain: there is no SIGTERM for a windowless child, so the shell must send a cooperative "quit" on the
	// backend's stdin (piped for exactly that) and the backend must listen for it — otherwise a Windows quit hard-kills
	// mid-upload. Guard both ends so the cross-platform drain can't silently regress back to a Windows-only hard kill.
	ok('the shell pipes stdin and sends a cooperative quit line to the backend', /Stdio::piped\(\)/.test(mainRs) && /write_all\(b"quit/.test(mainRs));
	const serverJs = read(path.join(REPO, 'lib', 'webserver', 'index.js'));
	ok('the desktop backend watches stdin for the shell\'s quit signal', /watchStdinForQuit\(/.test(serverJs) && /isDesktopApp\(\)/.test(serverJs));

	// The desktop shell hides the window and WAITS a background-drain grace (~5 min) for the backend to drain and lock
	// before force-killing. The backend must NOT force-kill itself at the tight launchd cap (15s) off-systemd, or a
	// large cloud vault's write-back is abandoned mid-upload (an orphaned ".partial") long before the shell's grace
	// runs. And the backend must treat stdin EOF (parent death — a force-terminated shell) as a quit, or it orphans
	// holding the port and mounted drives. Both are behaviorally hard to exercise here (a real desktop launch / a
	// killed parent + a process exit), so pin the mechanisms at the source.
	const procReg = read(path.join(REPO, 'lib', 'ProcRegistry.js'));
	ok('the shutdown drain gives the desktop app a generous cap, not the tight launchd cap', /isDesktopApp\(\)/.test(procReg) && /isDesktop \? [\d.]+ \* 60 \* 1000 : 15 \* 1000/.test(procReg));
	ok('the desktop backend treats stdin EOF (a dead shell) as a quit, so it never orphans', /process\.stdin\.on\('end', \(\) => gracefulExit\(0\)\)/.test(procReg));

	// The loopback port is single-sourced in spirit: the Rust constant must equal the Node default.
	const portMatch = mainRs.match(/UI_PORT:\s*u16\s*=\s*(\d+)/);
	ok('the shell UI_PORT matches Common.DEFAULT_UI_PORT', !!portMatch && Number(portMatch[1]) === Common.DEFAULT_UI_PORT);

	// Identity is single-sourced in Brand; the config must not drift from it.
	ok('the config productName matches Brand.name', conf.productName === Brand.name);

	// The window's backgroundColor paints the WebView surface from the first frame, BEFORE the splash HTML renders.
	// Without it, a fresh launch shows a white flash on WebKitGTK (Linux) — the window appears before the WebView
	// paints, so the styled splash is invisible for a beat while macOS's WKWebView paints it immediately. Setting the
	// window color to the splash's OWN dark background makes every platform show the same dark loading surface at once.
	// Couple the two here so they can never drift apart: the config color must equal the ui-shell's dark body color.
	const win = (conf.app && Array.isArray(conf.app.windows) ? conf.app.windows : []).find(w => w && w.label === 'main') || {};
	const shellHtml = read(path.join(ST, 'ui-shell', 'index.html'));
	const shellDarkBg = (shellHtml.match(/body\s*\{[^}]*background:\s*(#[0-9a-fA-F]{6})/) || [])[1];
	ok('the main window sets a backgroundColor (no white flash before the splash paints)', typeof win.backgroundColor === 'string' && /^#[0-9a-fA-F]{6}$/.test(win.backgroundColor));
	ok('the window backgroundColor matches the splash\'s dark background (no drift)', !!shellDarkBg && String(win.backgroundColor).toLowerCase() === shellDarkBg.toLowerCase());

	// On Linux the WebKitGTK WebView fails to composite on many GPU/driver/compositor combinations, so the window
	// paints its background color but the interface (or the loading splash) never renders — a blank dark window,
	// often only on a relaunch. The shell disables the DMABUF renderer on Linux ONLY (macOS/Windows are untouched)
	// BEFORE the webview is created, so the WebView paints reliably everywhere. Guard both halves so the fix can't
	// silently regress: the Linux-only guard and the disable itself, applied before the Tauri builder runs.
	ok('the shell disables the WebKitGTK DMABUF renderer on Linux to fix the blank-window/no-splash bug', /#\[cfg\(target_os = "linux"\)\][\s\S]{0,400}WEBKIT_DISABLE_DMABUF_RENDERER/.test(mainRs));
	ok('the Linux WebView tuning runs before the webview is created (first thing in main)', /fn main\(\)\s*\{\s*[\s\S]{0,200}tune_linux_webview\(\);[\s\S]{0,200}tauri::Builder/.test(mainRs));

	// One version across every file a release bump can touch, with the root package.json as the single source of
	// truth. tauri.conf.json SINGLE-SOURCES its version by reading the root package.json (Tauri v2 accepts a
	// package.json path in `version`), so the desktop installer's version can never fall behind the runtime version —
	// assert that exact path so it is never reverted to a drifting literal. Cargo.toml carries a separate literal (it
	// cannot read package.json), so it is enforced equal to the product version.
	const cargoVer = (cargo.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
	ok('the config version single-sources from the root package.json (not a drifting literal)', conf.version === '../package.json');
	ok('the Cargo.toml version matches package.json', cargoVer === pkg.version);

	// Real installers on every OS (not just macOS app/dmg). targets is an explicit list: AppImage is intentionally
	// omitted (its bundler downloads unpinned tools over the network, so it is neither reproducible nor reliable) —
	// deb + rpm cover the Debian and RPM families, and any other distribution uses the standalone install.
	const targets = (conf.bundle && Array.isArray(conf.bundle.targets)) ? conf.bundle.targets : [];
	ok('bundle targets cover macOS (dmg), Windows (nsis/msi), and Linux (deb + rpm)',
		targets.includes('dmg') && (targets.includes('nsis') || targets.includes('msi')) && targets.includes('deb') && targets.includes('rpm'));

	// The pinned build runtime is single-sourced and must stay at/above the feature floor (post-quantum seals need
	// 24.7), so every platform bundles the same version and no pin bump silently disables a feature.
	const pin = String(prep.PINNED_NODE || '').split('.').map(Number);
	ok('the pinned Node version is set and >= 24.7 (all features enabled, same on every platform)', pin.length >= 2 && (pin[0] > 24 || (pin[0] === 24 && pin[1] >= 7)));

	// The MINIMUM runtime (engines.node) must ALSO sit at/above the post-quantum floor, so a from-source or CLI install
	// can never run on a Node old enough to silently downgrade person-sealed access to the classical-only method.
	const eng = String((pkg.engines && pkg.engines.node) || '').replace(/[^0-9.]/g, '').split('.').map(Number);
	ok('engines.node minimum is >= 24.7 (no silent post-quantum downgrade for a headless install)', eng.length >= 2 && (eng[0] > 24 || (eng[0] === 24 && eng[1] >= 7)));

	// If the CI workflow exists, the Node it installs must match the pin (otherwise a CI build would be refused by
	// the runtime-version check — catch that here rather than at build time).
	const wf = path.join(REPO, '.github', 'workflows', 'release.yml');
	if (fs.existsSync(wf)) {
		const wfText = read(wf);
		const nv = (wfText.match(/node-version:\s*([0-9.]+)/) || [])[1];
		ok('the CI workflow pins the same Node version as PINNED_NODE', nv === prep.PINNED_NODE);

		// The Linux build dependencies are listed in two places (the workflow and the build README). They must
		// stay identical, or a hand-run Linux build will be missing what CI installs (or vice versa).
		const readmeApt = aptPackages(read(path.join(ST, 'README.md')));
		const wfApt = aptPackages(wfText);
		const same = readmeApt && wfApt && readmeApt.size === wfApt.size && [...readmeApt].every((p) => wfApt.has(p));
		ok('the Linux build dependencies match between the workflow and the build README', !!same);

		// The manual-build-without-a-version-bump path must stay wired: a workflow_dispatch release_tag input and
		// a release job. If either is renamed away, no-version builds or drafting break silently.
		ok('the workflow keeps its release_tag manual input', /release_tag:/.test(wfText));
		ok('the workflow keeps its release job', /^\s{2}release:/m.test(wfText));
	}

	return done();
}
main();
