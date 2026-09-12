'use strict';
// lib/Autostart.js — install the local UI to launch automatically at login/boot,
// the same way on each platform:
//   • macOS   — a LaunchAgent plist in ~/Library/LaunchAgents (launchctl)
//   • Linux   — a systemd user service in ~/.config/systemd/user (+ linger)
//   • Windows — the per-user Run key at logon, launched through a hidden VBScript
//               wrapper so no console shows (reg stores the command verbatim, avoiding
//               the schtasks /tr quoting pitfalls). Uninstall also clears any scheduled
//               task a previous version may have created.
//
// Only the UI server is auto-started; vaults are never auto-mounted because the
// tool never stores passwords — you open the UI and unlock a vault when you want
// it. install/uninstall/status are async and shell out with a timeout so they
// cannot hang.

const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');
const Common = require('./Common');
const Brand = require('./Brand');

const LABEL = 'com.' + Brand.slug + '.ui';
const LINUX_UNIT = Brand.slug + '.service';
const WIN_TASK = Brand.serviceId;

// Promise-based command runner with a timeout, so an install step can never hang. Shared with the rest of the
// app so the spawn options live in one place; it rejects on a non-zero exit unless ignoreError.
const sh = Common.runCmdOrThrow;
// Run a REQUIRED install step, but on failure raise a self-explaining error: a plain sentence naming what could
// not be done and how to fix it, with the underlying tool's own message appended — instead of surfacing a bare
// launchctl/systemctl/reg error to the user, who would have no idea what to do with it.
async function shStep(cmd, args, friendly, opts) {
	try { return await sh(cmd, args, opts); }
	catch (e) { const detail = (e && e.message ? String(e.message).trim() : ''); throw new Error(friendly + (detail ? ' (' + cmd + ' said: ' + detail + ')' : '')); }
}

const scriptPath = Common.appScriptPath;

function paths() {
	if (process.platform === 'darwin') {
		return { platform: 'macos', servicePath: path.join(os.homedir(), 'Library', 'LaunchAgents', LABEL + '.plist') };
	}
	if (process.platform === 'linux') {
		const configDir = path.join(os.homedir(), '.config', 'systemd', 'user');
		return { platform: 'linux', configDir, servicePath: path.join(configDir, LINUX_UNIT) };
	}
	if (process.platform === 'win32') {
		return { platform: 'windows', taskName: WIN_TASK, vbsPath: path.join(Common.dataDir(), Brand.slug + '-ui.vbs') };
	}
	return null;
}

// Extract the network bind address a service command was installed with, so status() can report whether the
// auto-started interface is loopback-only or network-reachable. Best-effort and format-tolerant: it matches the
// macOS plist argument pair and the plain `--bind <addr>` form used in the systemd unit and the Windows VBS.
function bindFromServiceText(text) {
	if (!text) return null;
	let m = /<string>--bind<\/string>\s*<string>([^<]+)<\/string>/.exec(text);
	if (m) return m[1].trim();
	m = /--bind\s+"?([^\s"]+)"?/.exec(text);
	return m ? m[1] : null;
}

// Resolve the optional network bind, with NO side effects, so the same rule is used everywhere and can be unit
// tested. A loopback or empty value returns null (the this-computer-only default — no `--bind` is written); a real
// (non-loopback) value must be a syntactically valid IP address, else it throws before anything is installed.
function resolveBindArg(bind) {
	if (bind == null || !String(bind).trim() || Common.isLoopbackHost(bind)) return null;
	const b = String(bind).trim();
	if (!require('net').isIP(b)) throw new Error('Cannot set up start-at-login on the address "' + b + '": it is not a valid IP address to bind to.');
	return b;
}

// Build the platform's service-file text from already-resolved parts, with NO side effects. Kept separate from
// install() so the exact generated command can be unit-tested — including that a loopback/empty bind writes no
// `--bind` — and verified against bindFromServiceText, without touching the machine's real login entries. `bindArg`
// is the validated network IP or null; `ddOverride` is a custom data directory or null. The Windows result is the
// raw VBS (install adds the UTF-16 BOM when it writes the file).
function buildServiceText(platform, { node, script, port, bindArg = null, ddOverride = null, root = '' }) {
	// Restart policy is the same on macOS and Linux: relaunch only after an UNCLEAN exit (a crash), and stay stopped
	// after a clean exit — so `launchctl stop` / `systemctl --user stop` actually stops the service (it shuts down
	// cleanly via gracefulExit → exit 0) instead of it immediately relaunching. macOS gets this via
	// KeepAlive={SuccessfulExit:false} (not an unconditional KeepAlive); Linux via Restart=on-failure.
	if (platform === 'macos') {
		const x = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
		return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${x(node)}</string>
    <string>${x(script)}</string>
    <string>ui</string>
    <string>--port</string>
    <string>${port}</string>${bindArg ? '\n    <string>--bind</string>\n    <string>' + x(bindArg) + '</string>' : ''}${ddOverride ? '\n    <string>--data-dir</string>\n    <string>' + x(ddOverride) + '</string>' : ''}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>WorkingDirectory</key><string>${x(root)}</string>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>`;
	}
	if (platform === 'linux') {
		// Escape a value interpolated into the systemd ExecStart's double-quoted argument: "%" is a systemd specifier
		// (e.g. %h expands to the home dir), "$" is variable expansion, and '"'/'\' are the quoting/escape characters —
		// so a data-dir path containing any of them would otherwise be mis-expanded or break the quoting, launching the
		// service against the wrong directory. Doubling %/$ and backslash-escaping "/\ is systemd's own literal form.
		const sd = (s) => String(s).replace(/[\\"%$]/g, c => ({ '\\': '\\\\', '"': '\\"', '%': '%%', '$': '$$' }[c]));
		// Type=notify + WatchdogSec makes systemd a hardware-style dead-man for a HUNG (not just crashed) service:
		// the service pings only while its health tick keeps completing (see lib/SdNotify.js), so a wedge stops the
		// pings and systemd restarts it. Restart=on-failure covers a crash AND a watchdog timeout AND a Guardian
		// kill (all non-clean), while a deliberate `systemctl stop` stays stopped. TimeoutStopSec is generous so a
		// legitimate slow drain-on-stop (flushing writes) is never mistaken for a hang. The StartLimit is the
		// crash-loop ceiling. NotifyAccess=all lets the OS `systemd-notify` helper (a child) deliver the pings.
		return `[Unit]
Description=${Brand.name} UI
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=all
WatchdogSec=60
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart="${sd(node)}" "${sd(script)}" ui --port ${port}${bindArg ? ' --bind ' + bindArg : ''}${ddOverride ? ' --data-dir "' + sd(ddOverride) + '"' : ''}
WorkingDirectory="${sd(root)}"
Restart=on-failure
RestartSec=10
TimeoutStopSec=600

[Install]
WantedBy=default.target
`;
	}
	// Windows: --supervised makes the launched process a tiny crash-restart supervisor (Windows has no
	// launchd/systemd equivalent), so the service comes back on its own after a crash.
	return Common.windowsHiddenRunVbs(node, script, 'ui --port ' + port + (bindArg ? ' --bind ' + bindArg : '') + ' --supervised' + (ddOverride ? ' --data-dir ""' + ddOverride + '""' : ''));
}

// Install autostart for the UI on the given port. Returns { platform, servicePath, port, bind }.
// `deferStart` writes the login entry WITHOUT starting the service right now — needed when a service that is already
// running installs autostart for itself (the web UI's "Start at login" toggle): loading/reloading the job would
// disturb or replace the very process serving the request. The entry still takes effect at the next login. The CLI
// leaves it false, so a fresh `autostart install` from a terminal both registers and starts the service. On Windows
// this is moot — writing the Run key never starts anything now — so both paths behave the same there.
// `bind` makes the auto-started interface reachable from other devices: when it is a real (non-loopback) IP, a
// `--bind <ip>` argument is written into the service command, so the interface comes up exposed at the next login.
// An exposed interface requires a web password and serves over TLS; the caller is responsible for ensuring a
// password is set first (the CLI and the web route both check). A loopback or empty bind is omitted, leaving the
// long-standing this-computer-only default.
async function install(port = Common.DEFAULT_UI_PORT, { deferStart = false, bind = null } = {}) {
	const info = paths();
	if (!info) throw new Error('Autostart is not supported on this platform.');
	// Resolve the optional network bind up front so a bad value fails before anything is written.
	const bindArg = resolveBindArg(bind);
	// Launch through the branded binary so the auto-started service shows under the
	// branded name (from Brand.slug) in Activity Monitor / Task Manager, not "node". Rebuilt here so a
	// Node upgrade since the last install is picked up.
	const node = require('./Launcher').ensure({ force: true });
	const script = scriptPath(), root = Common.root();
	// Carry a custom data directory into the service command so the auto-started service uses the SAME data dir the
	// user chose, not the default (which would split locks/state/settings across two locations). A default install
	// carries no --data-dir, so it always tracks the current default.
	const ddOverride = Common.dataDirOverridePath();

	if (info.platform === 'macos') {
		const plist = buildServiceText('macos', { node, script, port, bindArg, ddOverride, root });
		await fsp.mkdir(path.dirname(info.servicePath), { recursive: true });
		await fsp.writeFile(info.servicePath, plist);
		if (!deferStart) {
			await sh('launchctl', ['unload', info.servicePath], { ignoreError: true });
			await shStep('launchctl', ['load', info.servicePath], 'Could not register the login-start service with launchctl. Check that you are in a normal (not restricted or remote) login session, then run install again.');
		}
		return { platform: info.platform, servicePath: info.servicePath, port, bind: bindArg };
	}

	if (info.platform === 'linux') {
		const unit = buildServiceText('linux', { node, script, port, bindArg, ddOverride, root });
		await fsp.mkdir(info.configDir, { recursive: true });
		await fsp.writeFile(info.servicePath, unit);
		await sh('systemctl', ['--user', 'daemon-reload'], { ignoreError: true });
		await shStep('systemctl', ['--user', 'enable', ...(deferStart ? [] : ['--now']), LINUX_UNIT], 'Could not enable the user service with systemctl. Make sure a systemd user session is available (a normal desktop or lingering login), then run install again.');
		await sh('loginctl', ['enable-linger', os.userInfo().username], { ignoreError: true });
		return { platform: info.platform, servicePath: info.servicePath, port, bind: bindArg };
	}

	// Windows: hidden VBS wrapper launched from the per-user Run key at logon. The Run
	// key is the primary mechanism (not a scheduled task) because reg stores the command
	// verbatim, whereas schtasks /tr mangles the embedded quotes needed for paths with
	// spaces across Windows versions. It needs no administrator rights and no reboot.
	await fsp.mkdir(Common.dataDir(), { recursive: true });
	const vbs = buildServiceText('windows', { node, script, port, bindArg, ddOverride, root });
	// Write UTF-16LE with a BOM: wscript reads a .vbs as the system ANSI code page unless it is BOM-marked Unicode,
	// so a UTF-8 file with a non-ASCII path (e.g. a non-Latin username in the data-dir path) would be mis-decoded
	// and the launch would silently fail. A BOM-marked UTF-16 file is read correctly on every code page.
	await fsp.writeFile(info.vbsPath, '\ufeff' + vbs, 'utf16le');
	await shStep('reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', info.taskName, '/t', 'REG_SZ', '/d', `wscript.exe "${info.vbsPath}"`, '/f'], 'Could not add the startup entry to the Windows registry. Try running install again from your normal user account.');
	return { platform: info.platform, servicePath: info.vbsPath, port, bind: bindArg };
}

// Remove autostart. Best-effort; never throws for a missing service.
// `keepRunning` removes the login entry WITHOUT stopping a currently-running service — needed when the running
// service turns ITSELF off (the web UI's "Start at login" toggle): stopping it mid-request would drop the response
// and take the app down. On macOS that means skipping `launchctl unload` (which SIGTERMs the job); on Linux, using
// `disable` without `--now`. Either way the login entry is gone, so it will not start at the next login, and the
// current process keeps running until it is closed normally. Windows never stops the process here anyway — the
// process was launched from the Run key at logon and keeps running after the key is removed.
async function uninstall({ keepRunning = false } = {}) {
	const info = paths();
	if (!info) throw new Error('Autostart is not supported on this platform.');
	if (info.platform === 'macos') {
		if (!keepRunning) await sh('launchctl', ['unload', info.servicePath], { ignoreError: true });
		await fsp.rm(info.servicePath, { force: true });
	} else if (info.platform === 'linux') {
		await sh('systemctl', ['--user', 'disable', ...(keepRunning ? [] : ['--now']), LINUX_UNIT], { ignoreError: true });
		await fsp.rm(info.servicePath, { force: true });
		await sh('systemctl', ['--user', 'daemon-reload'], { ignoreError: true });
	} else {
		await sh('schtasks', ['/delete', '/tn', info.taskName, '/f'], { ignoreError: true });
		await sh('reg', ['delete', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', info.taskName, '/f'], { ignoreError: true });
		await fsp.rm(info.vbsPath, { force: true });
	}
	return { platform: info.platform };
}

// Read the network bind out of an installed service file, best-effort, so status() can say whether the
// auto-started interface is this-computer-only or network-reachable. Returns null on any read/parse problem
// (the .vbs is UTF-16; the plist/unit are UTF-8, but the argument we look for is plain ASCII either way).
function installedBind(servicePath, windows) {
	try {
		if (!servicePath || !fs.existsSync(servicePath)) return null;
		const text = fs.readFileSync(servicePath, windows ? 'utf16le' : 'utf8');
		return bindFromServiceText(text);
	} catch (_) { return null; }
}
// Extract the SCRIPT path a service command was installed to run, so a moved or deleted install (a dangling launch
// target) can be detected before it silently fails to come up at the next login. Best-effort and format-tolerant
// across the three formats this module writes: the macOS plist ProgramArguments (node then script), the systemd
// `ExecStart="<node>" "<script>" ui …`, and the Windows VBS `Run """<node>"" ""<script>"" …`.
function scriptFromServiceText(text) {
	if (!text) return null;
	let m = /Run\s+"""[^"]*""\s+""([^"]+)""/.exec(text);                                                   // Windows VBS
	if (m) return m[1].trim();
	m = /ExecStart="[^"]*"\s+"([^"]+)"/.exec(text);                                                        // systemd unit
	if (m) return m[1].trim();
	m = /<key>ProgramArguments<\/key>\s*<array>\s*<string>[^<]*<\/string>\s*<string>([^<]+)<\/string>/.exec(text); // macOS plist (2nd arg)
	return m ? m[1].trim() : null;
}
function installedScript(servicePath, windows) {
	try {
		if (!servicePath || !fs.existsSync(servicePath)) return null;
		const text = fs.readFileSync(servicePath, windows ? 'utf16le' : 'utf8');
		return scriptFromServiceText(text);
	} catch (_) { return null; }
}
// Extract the NODE binary path a service command was installed to run (the first argument, before the script), so a
// service whose node path no longer exists — a headless install where the runtime was moved or removed — can be
// detected before it silently fails to come up at the next login. Same three formats as scriptFromServiceText, but
// the first argument rather than the second. Best-effort; returns null when it cannot parse (never a false alarm).
function nodeFromServiceText(text) {
	if (!text) return null;
	let m = /Run\s+"""([^"]+)""/.exec(text);                                         // Windows VBS (1st quoted arg)
	if (m) return m[1].trim();
	m = /ExecStart="([^"]+)"/.exec(text);                                            // systemd unit (1st = node)
	if (m) return m[1].trim();
	m = /<key>ProgramArguments<\/key>\s*<array>\s*<string>([^<]+)<\/string>/.exec(text); // macOS plist (1st arg = node)
	return m ? m[1].trim() : null;
}
function installedNode(servicePath, windows) {
	try {
		if (!servicePath || !fs.existsSync(servicePath)) return null;
		const text = fs.readFileSync(servicePath, windows ? 'utf16le' : 'utf8');
		return nodeFromServiceText(text);
	} catch (_) { return null; }
}

// Whether autostart is currently installed, and if so whether it is network-reachable (bind is non-null).
async function status() {
	const info = paths();
	if (!info) return { platform: process.platform, installed: false, supported: false };
	if (info.platform === 'windows') {
		const bind = installedBind(info.vbsPath, true), script = installedScript(info.vbsPath, true);
		const node = installedNode(info.vbsPath, true);
		try { await sh('reg', ['query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', info.taskName]); return { platform: 'windows', installed: true, supported: true, servicePath: info.vbsPath, bind, script, node }; }
		catch (_) { return { platform: 'windows', installed: fs.existsSync(info.vbsPath), supported: true, servicePath: info.vbsPath, bind, script, node }; }
	}
	const installed = fs.existsSync(info.servicePath);
	return { platform: info.platform, installed, supported: true, servicePath: info.servicePath, bind: installed ? installedBind(info.servicePath, false) : null, script: installed ? installedScript(info.servicePath, false) : null, node: installed ? installedNode(info.servicePath, false) : null };
}

module.exports = { install, uninstall, status, bindFromServiceText, scriptFromServiceText, nodeFromServiceText, buildServiceText, resolveBindArg };
