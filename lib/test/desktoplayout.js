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
	const procReg = read(path.join(REPO, 'lib', 'ops', 'ProcRegistry.js'));
	ok('the shutdown drain gives the desktop app a generous cap, not the tight launchd cap', /isDesktopApp\(\)/.test(procReg) && /isDesktop \? [\d.]+ \* 60 \* 1000 : 15 \* 1000/.test(procReg));
	ok('the desktop backend treats stdin EOF (a dead shell) as a quit, so it never orphans', /process\.stdin\.on\('end', \(\) => gracefulExit\(0\)\)/.test(procReg));

	// DATA-LOSS ORDERING: the desktop backend's own self-kill cap MUST stay safely below the shell's force-kill grace.
	// The shell hides the window and waits BACKGROUND_DRAIN_GRACE for the backend to drain-and-lock before it SIGKILLs;
	// if the backend's cap were >= that grace, the shell would hard-kill a still-flushing backend and abandon an
	// in-flight cloud upload (an orphaned ".partial"). The two numbers live in different languages with nothing tying
	// them, so pin the ordering with a margin. (Extract seconds from each side rather than matching a fixed literal.)
	const graceSecs = (() => { const m = mainRs.match(/BACKGROUND_DRAIN_GRACE:\s*Duration\s*=\s*Duration::from_secs\((\d+)\)/); return m ? parseInt(m[1], 10) : NaN; })();
	const desktopCapSecs = (() => { const m = procReg.match(/isDesktop\s*\?\s*([\d.]+)\s*\*\s*60\s*\*\s*1000/); return m ? parseFloat(m[1]) * 60 : NaN; })();
	ok('the desktop backend self-kill cap stays safely below the shell force-kill grace (no mid-flush hard kill)', Number.isFinite(graceSecs) && Number.isFinite(desktopCapSecs) && desktopCapSecs <= graceSecs - 15);

	// The shell must PROBE the exact loopback paths the backend REGISTERS. A /__ready path mismatch makes every desktop
	// launch fall to the startup-error screen (the shell never sees the token echo); a /__mounted mismatch misfires the
	// quit confirmation. Tie the Rust request lines to the JS route registrations so a rename on either side is caught.
	ok('the shell probes the same /__ready and /__mounted paths the backend registers', /GET \/__ready /.test(mainRs) && /GET \/__mounted /.test(mainRs) && /app\.get\('\/__ready'/.test(serverJs) && /app\.get\('\/__mounted'/.test(serverJs));

	// The /__mounted token header is a bare literal in BOTH languages (unlike /__owner-check, which single-sources it
	// via Common.OWNER_TOKEN_HEADER). Pin that the header the shell SENDS equals the one the backend READS, compared
	// case-insensitively (HTTP header names are case-insensitive). A rename on one side would silently always prompt.
	const mountedHeaderRs = (mainRs.match(/GET \/__mounted[\s\S]{0,160}?\\n([\w-]+-Token): \{\}/) || [])[1];
	const mountedHeaderJs = (serverJs.match(/req\.headers\['([a-z-]*vaultonaut-token)'\]/) || [])[1];
	ok('the /__mounted token header matches between the shell and the backend (case-insensitive)', !!mountedHeaderRs && !!mountedHeaderJs && mountedHeaderRs.toLowerCase() === mountedHeaderJs.toLowerCase());

	// The shell's mount-probe socket timeout MUST exceed the backend's own /__mounted answer budget, or the probe times
	// out first and the quit confirmation appears on every quit. Extract both millisecond numbers and assert the order.
	const probeMs = (() => { const m = mainRs.match(/probe_mounted\([^;]*?from_millis\((\d+)\)/); return m ? parseInt(m[1], 10) : NaN; })();
	const mountedBudgetMs = (() => { const m = serverJs.match(/app\.get\('\/__mounted'[\s\S]{0,800}?withTimeout\(Vault\.listMounts\(\),\s*(\d+)\)/); return m ? parseInt(m[1], 10) : NaN; })();
	ok('the shell mount-probe timeout exceeds the backend /__mounted answer budget (no false quit prompt)', Number.isFinite(probeMs) && Number.isFinite(mountedBudgetMs) && probeMs > mountedBudgetMs);

	// ORDERING: the parent-death watch must be armed BEFORE the server enters its long-running phase, so a slow or
	// wedged startup step can never leave it unarmed — which is exactly how a sidecar gets orphaned when the app is
	// force-quit during a first-run engine download or a stalled scan. The watch has no awaited engine work ahead of it
	// today (the engine downloads lazily, not on the startup path); pin that it stays ahead of server.listen so a future
	// refactor cannot move it behind a slow await and reintroduce the orphan window.
	{
		const armAt = serverJs.indexOf('watchStdinForQuit(');
		const listenAt = serverJs.search(/server\.listen\(/);
		ok('the desktop parent-death watch is armed before the server starts listening (so a slow startup can never orphan it)', armAt > 0 && listenAt > 0 && armAt < listenAt);
	}

	// The loopback port is single-sourced in spirit: the Rust constant must equal the Node default.
	const portMatch = mainRs.match(/UI_PORT:\s*u16\s*=\s*(\d+)/);
	ok('the shell UI_PORT matches Common.DEFAULT_UI_PORT', !!portMatch && Number(portMatch[1]) === Common.DEFAULT_UI_PORT);

	// Attach-to-a-running-instance: when "Start at login" already has a trusted Vaultonaut on the port, the desktop
	// app must show THAT instance rather than fail on the busy port. The backend signals this with a distinct exit
	// code the shell recognizes; the code is single-sourced in Common and must match the shell's constant.
	const exitMatch = mainRs.match(/EXIT_ATTACH:\s*i32\s*=\s*(\d+)/);
	ok('the shell EXIT_ATTACH matches Common.DESKTOP_ATTACH_EXIT_CODE', !!exitMatch && Number(exitMatch[1]) === Common.DESKTOP_ATTACH_EXIT_CODE);
	// The shell maps that exit code to an ATTACH outcome (not a failure) and, on attach, marks ATTACHED without
	// draining or stopping anything (the child that reported the code has already exited; there is nothing of ours).
	ok('the shell treats the attach exit code as an ATTACH outcome, not a failure', /code == EXIT_ATTACH \{ Startup::Attach \} else \{ Startup::Failed \}/.test(mainRs));
	ok('on attach the shell marks ATTACHED and shows the running instance', /Startup::Attach =>[\s\S]{0,200}ATTACHED\.store\(true[\s\S]{0,160}show_window_or_defer\(&handle\)/.test(mainRs));
	// Attached mode must NOT drain, lock, or stop the service the shell did not start — it just closes the window and
	// leaves the background login service running. Both the window-close and the app-quit handlers short-circuit on
	// ATTACHED before any confirmation or shutdown, and the last-resort Exit backstop skips stopping the backend too.
	ok('the window-close handler short-circuits in attached mode (no drain/lock)', /CloseRequested \{ api, \.\. \} = event \{[\s\S]{0,360}if ATTACHED\.load\([\s\S]{0,80}return;/.test(mainRs));
	ok('the quit handler short-circuits in attached mode (leaves the background service running)', /RunEvent::ExitRequested \{ api, \.\. \} => \{[\s\S]{0,160}if ATTACHED\.load\(/.test(mainRs));
	ok('the last-resort Exit backstop does not stop the backend in attached mode', /RunEvent::Exit =>[\s\S]{0,800}if !ATTACHED\.load\(/.test(mainRs));

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
	// Drag-and-drop parity: Tauri's webview intercepts OS file-drops as a native event by default, so the DOM 'drop'
	// handler (used to add a .vault folder by dropping it) never fires in the packaged app — it works only in a plain
	// browser. Disabling the native handler lets the SAME web drop handler run in desktop and standalone alike. This is
	// a runtime-only behavior the unit suite cannot reach, so pin it here so the packaged app never silently loses drop.
	ok('the desktop window disables Tauri native drag-drop so the DOM file-drop handler runs in the app (not only in a browser)', win.dragDropEnabled === false);
	// Splash flow: the window loads the bundled splash (ui-shell/index.html) via the app's asset protocol and shows it
	// on its own until the readiness thread navigates it to the running backend (show_outcome). The earlier Linux-ONLY
	// loopback-HTTP re-navigation was REMOVED — by churning the webview away from the just-loaded splash it kept the
	// window black on Linux (while macOS/Windows, which skipped it, painted fine), and a sibling build on the same
	// WebKitGTK/Tauri stack paints its bundled splash with no such code. Pin the real flow, and pin the machinery's
	// ABSENCE so it is not reintroduced without a conscious change.
	ok('the shell shows the outcome by navigating the window to the running backend when ready', /fn show_outcome[\s\S]{0,500}window\.navigate\(url\)/.test(mainRs));
	ok('the Linux loopback-HTTP splash re-paint machinery is gone (it kept the window black on Linux)', !/fn start_splash_server\b/.test(mainRs) && !/fn nudge_repaint\b/.test(mainRs) && !/SPLASH_DONE/.test(mainRs) && !/SPLASH_PORT/.test(mainRs));

	// On Linux the WebKitGTK WebView fails to composite on many GPU/driver/compositor combinations, so the window
	// paints its background color but the interface (or the loading splash) never renders — a blank dark window,
	// often only on a relaunch. The shell disables the DMABUF renderer on Linux ONLY (macOS/Windows are untouched)
	// BEFORE the webview is created, so the WebView paints reliably everywhere. Guard both halves so the fix can't
	// silently regress: the Linux-only guard and the disable itself, applied before the Tauri builder runs.
	ok('the shell disables the WebKitGTK DMABUF renderer on Linux to fix the blank-window/no-splash bug', /#\[cfg\(target_os = "linux"\)\][\s\S]{0,400}WEBKIT_DISABLE_DMABUF_RENDERER/.test(mainRs));
	// The stronger escalation for machines where disabling only the DMABUF renderer is not enough: turn off GPU
	// compositing entirely so the WebView renders in software and paints on any driver. Pin it so it is never dropped.
	ok('the shell also disables WebKitGTK GPU compositing on Linux (software render) for the stubborn black-window cases', /#\[cfg\(target_os = "linux"\)\][\s\S]{0,600}WEBKIT_DISABLE_COMPOSITING_MODE/.test(mainRs));
	// Disable NVIDIA's explicit-sync path too — free, and it heads off a related Wayland crash. One of the three
	// WebKit/driver flags the known-good sibling build on this stack uses; pin it so it is never dropped.
	ok('the shell disables NVIDIA explicit sync on Linux (heads off a related Wayland crash)', /#\[cfg\(target_os = "linux"\)\][\s\S]{0,1200}__NV_DISABLE_EXPLICIT_SYNC/.test(mainRs));
	// Deliberately NOT forced: LIBGL_ALWAYS_SOFTWARE (llvmpipe) and GDK_BACKEND=x11 (XWayland). They were added by
	// cumulative escalation, never confirmed to cure the black window, and both can STOP a WebKitGTK surface from ever
	// presenting — forcing GDK_BACKEND=x11 panicked GTK init outright on a GNOME/Wayland test machine. A known-good
	// build on the same WebKitGTK/Tauri stack uses only the three flags above. Pin their ABSENCE from the set list (the
	// `("NAME", "1")` tuple form) so they can't creep back as defaults; the comment above may still name them.
	ok('the shell does NOT force software GL (LIBGL_ALWAYS_SOFTWARE) — it can suppress the first paint', !/\(\s*"LIBGL_ALWAYS_SOFTWARE"/.test(mainRs));
	ok('the shell does NOT force the X11/XWayland backend (GDK_BACKEND=x11) — it can stop the surface presenting', !/\(\s*"GDK_BACKEND"/.test(mainRs));
	ok('the Linux WebView tuning runs before the webview is created (first thing in main)', /fn main\(\)\s*\{\s*[\s\S]{0,200}tune_linux_webview\(\);[\s\S]{0,200}tauri::Builder/.test(mainRs));

	// Single-window coordination: a second desktop launch of the SAME instance must raise the existing window, not
	// stack a duplicate — coordinated through the backend over loopback (one authority per port + data dir), so a
	// genuinely separate instance (its own backend) and a CLI/headless server are untouched. Lock both sides.
	ok('the backend serves the loopback single-window endpoints (claim/heartbeat/focus/release)', ['/__shell-claim', '/__shell-heartbeat', '/__shell-focus', '/__shell-release'].every(function (p) { return serverJs.indexOf("'" + p + "'") !== -1; }));
	ok('every single-window endpoint is loopback-only (a network caller is refused)', (serverJs.match(/\/__shell-(claim|heartbeat|focus|release)'[\s\S]{0,140}isLoopbackAddr/g) || []).length === 4);
	ok('a claim is refused while another LIVE shell owns the window, and liveness is a TTL (a crash cannot block a window)', /shellOwnerLive\(\) && shellWindowOwner\.token !== tok[\s\S]{0,100}claimed: false/.test(serverJs) && /SHELL_WINDOW_TTL_MS/.test(serverJs));
	// The backend's STARTER shell always wins a claim (primaryShellToken), so a stall past the TTL that let a second
	// launch grab the window is reclaimed deterministically — two windows can never persist. The shell passes its token
	// on spawn, and its heartbeat reclaims whenever it is told it lost ownership (owner:false).
	ok('the backend grants the starter shell (primaryShellToken) its claim even over a live owner', /tok !== primaryShellToken && shellOwnerLive\(\)/.test(serverJs) && /const primaryShellToken = shellToken \|\| null/.test(serverJs));
	ok('the shell tells its backend which shell started it (--shell-token on spawn)', /\.arg\("--shell-token"\)[\s\S]{0,120}SHELL_TOKEN\.get\(\)/.test(mainRs) && /shellToken \} = \{\}/.test(serverJs));
	ok('the shell heartbeat reclaims ownership if it is displaced, and the displaced attached shell then exits', /owner\\":false[\s\S]{0,400}\/__shell-claim[\s\S]{0,300}!reclaimed && ATTACHED\.load[\s\S]{0,150}std::process::exit\(0\)/.test(mainRs));
	ok('the shell claims the window before showing it, for both Ready and Attach', /Startup::Ready => show_window_or_defer/.test(mainRs) && /Startup::Attach =>[\s\S]{0,260}show_window_or_defer/.test(mainRs));
	ok('a second shell exits WITHOUT a window only when it did not start the backend (never orphans its own)', /!claimed && ATTACHED\.load[\s\S]{0,200}std::process::exit\(0\)/.test(mainRs));
	ok('the shell releases its single-window claim on exit (so close-then-reopen is immediate)', /RunEvent::Exit =>[\s\S]{0,500}\/__shell-release/.test(mainRs));

	// One version across every file a release bump can touch, with the root package.json as the single source of
	// truth. tauri.conf.json SINGLE-SOURCES its version by reading the root package.json (Tauri v2 accepts a
	// package.json path in `version`), so the desktop installer's version can never fall behind the runtime version —
	// assert that exact path so it is never reverted to a drifting literal. Cargo cannot read JSON, so its crate
	// version is deliberately a fixed placeholder that Tauri never uses for the app/installer version.
	const cargoVer = (cargo.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
	ok('the config version single-sources from the root package.json (not a drifting literal)', conf.version === '../package.json');
	ok('the Cargo.toml version is the fixed 0.0.0 placeholder', cargoVer === '0.0.0');

	// One app identifier for desktop, Android, and iOS. The platform configs inherit the base identifier, and the
	// generated Android/iOS projects are derived from it. Pin the settled value and forbid a per-platform override, so
	// a desktop and a phone build can never install as two different applications.
	ok('the one app identifier is com.vaultonaut.app', conf.identifier === 'com.vaultonaut.app');
	const androidConf = (() => { try { return JSON.parse(read(path.join(ST, 'tauri.android.conf.json')) || '{}'); } catch (_) { return {}; } })();
	const iosConf = (() => { try { return JSON.parse(read(path.join(ST, 'tauri.ios.conf.json')) || '{}'); } catch (_) { return {}; } })();
	ok('Android and iOS configs inherit the one identifier (no per-platform override)', !androidConf.identifier && !iosConf.identifier);
	const genGradle = read(path.join(ST, 'gen', 'android', 'app', 'build.gradle.kts'));
	if (genGradle) ok('the generated Android project uses the one identifier', /namespace\s*=\s*"com\.vaultonaut\.app"/.test(genGradle) && /applicationId\s*=\s*"com\.vaultonaut\.app"/.test(genGradle));
	const genIos = read(path.join(ST, 'gen', 'apple', 'project.yml'));
	if (genIos) ok('the generated iOS project uses the one identifier', /PRODUCT_BUNDLE_IDENTIFIER:\s*com\.vaultonaut\.app\b/.test(genIos) && !/com\.3cqs/.test(genIos));

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

	// The Docker image's integrity-gate also installs a Node (.github/workflows/docker.yml). It is the one Node-version
	// site NOT covered by the release.yml check below, so a PINNED_NODE bump could leave it silently behind — bind it to
	// the pin here too, so all Node-version sites in the repo move together. (If docker.yml ever stops pinning a Node,
	// there is nothing to drift, so an empty set passes.)
	const dockerWf = path.join(REPO, '.github', 'workflows', 'docker.yml');
	if (fs.existsSync(dockerWf)) {
		const dockerNodeVersions = [...read(dockerWf).matchAll(/node-version:\s*([0-9.]+)/g)].map((m) => m[1]);
		ok('every docker.yml node-version pins the same Node as PINNED_NODE', dockerNodeVersions.every((v) => v === prep.PINNED_NODE));
	}

	// If the CI workflow exists, the Node it installs must match the pin (otherwise a CI build would be refused by
	// the runtime-version check — catch that here rather than at build time).
	const wf = path.join(REPO, '.github', 'workflows', 'release.yml');
	if (fs.existsSync(wf)) {
		const wfText = read(wf);
		// EVERY `node-version:` in the workflow must equal the pin, not just the first — the file pins Node in more than
		// one job (test and build), and a drift in only the second would slip past a first-match check and then be
		// rejected at build time by the runtime-version gate.
		const nodeVersions = [...wfText.matchAll(/node-version:\s*([0-9.]+)/g)].map((m) => m[1]);
		ok('every CI node-version pins the same Node as PINNED_NODE', nodeVersions.length >= 1 && nodeVersions.every((v) => v === prep.PINNED_NODE));

		// Every installer-producing bundle target must have a matching upload glob in the workflow's collect-installers
		// step. Adding or renaming a Tauri target (e.g. appimage) would otherwise drop that installer from every release,
		// and the `if-no-files-found: error` guard only fires when the WHOLE set is empty, so the loss would be silent.
		// `app` produces no installer file, so it is excluded from this mapping.
		const TARGET_EXT = { dmg: '.dmg', nsis: '.exe', msi: '.msi', deb: '.deb', rpm: '.rpm', appimage: '.AppImage' };
		const missingGlob = targets.filter((t) => TARGET_EXT[t]).filter((t) => !wfText.includes('*' + TARGET_EXT[t]));
		ok('every installer bundle target has an upload glob in the release workflow (no silently dropped installer)', missingGlob.length === 0);

		// macOS ships ONE universal binary (Intel + Apple Silicon), built on a single Apple-Silicon runner so it never
		// depends on the retiring Intel CI images. Pin the moving parts so a refactor cannot silently drop Intel support
		// or the universal Node: the build selects the universal target, installs both Rust targets, and lipo-combines a
		// universal Node (derived from the pinned runner Node — no second version to drift) for the bundled runtime; and
		// the staging/build scripts honor those two environment variables. (The Intel storage-engine and anonymizing-network
		// downloads that a universal app needs at runtime are guarded by enginepin.js and torsetup.js, which pin the
		// darwin/x64 builds — process.arch is 'x64' when the universal app runs on an Intel Mac.)
		ok('the macOS build targets a universal (Intel + Apple Silicon) binary', /VAULTONAUT_TAURI_TARGET=universal-apple-darwin/.test(wfText));
		ok('the macOS build installs both Rust targets for the universal binary', /rustup target add x86_64-apple-darwin aarch64-apple-darwin/.test(wfText));
		ok('the macOS build lipo-combines a universal Node from the pinned runner Node', /NODE_VER="\$\(node -v/.test(wfText) && /lipo -create -output universal-node/.test(wfText) && /VAULTONAUT_RUNTIME_NODE=/.test(wfText));
		ok('the per-arch Node builds are checksum-verified before combining', /SHASUMS256\.txt/.test(wfText) && /shasum -a 256 -c/.test(wfText));
		ok('the combined universal Node is verified to contain both architecture slices', /lipo -archs universal-node/.test(wfText) && /grep -qw x86_64/.test(wfText) && /grep -qw arm64/.test(wfText));
		ok('prepare-sidecar stages the provided universal runtime, and the build honors the target', /VAULTONAUT_RUNTIME_NODE/.test(read(path.join(ST, 'prepare-sidecar.js'))) && /VAULTONAUT_TAURI_TARGET/.test(read(path.join(ST, 'tauri-build.js'))));

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

		// The build-only path must stay wired and safe: a `build_only` manual input, and a release-job guard that skips
		// releasing when it is set (only on a manual run). If the guard is dropped, a build-only run could silently
		// publish or overwrite a release — the exact accident this switch exists to prevent — so pin both here.
		ok('the workflow keeps its build_only manual input', /build_only:/.test(wfText));
		ok('the release job is gated so build_only skips it on a manual run', /github\.event\.inputs\.build_only\s*!=\s*'true'/.test(wfText) && /github\.event_name\s*!=\s*'workflow_dispatch'/.test(wfText));

		// The unit suite must run on all three platforms, not Linux alone, so the many platform-specific branches and
		// the unmount ladder get real execution rather than only source pins. ALL THREE platforms now GATE a release:
		// there is no continue-on-error exempting any leg, so a broken cross-platform path on any of them blocks the
		// build and release rather than shipping. (The one previously known Windows flake — the relay per-IP grouping
		// assertions, whose loopback remoteAddress can be momentarily empty there — is skipped on Windows at the
		// assertion level in relayhardening.js, so Windows can gate without flaking.) Pin that shape.
		const testJob = (wfText.match(/\n {2}test:\n[\s\S]*?(?=\n {2}\w)/) || [''])[0];
		ok('the CI test job runs on Linux, macOS, and Windows', /ubuntu-22\.04/.test(testJob) && /macos-latest/.test(testJob) && /windows-latest/.test(testJob));
		ok('every platform gates the release — no continue-on-error exempts any leg', !/continue-on-error/.test(testJob));
	}

	return done();
}
main();
