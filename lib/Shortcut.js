'use strict';
// lib/Shortcut.js — create a clickable desktop/menu launcher that opens the app, so daily use needs
// neither a terminal nor a remembered URL. It is a thin, lightweight helper: the launcher simply runs
// "<app> open", which starts the background service if needed and opens the web interface in the
// browser. No native GUI, no bundled binary, no secret handling — the same posture as launch-at-login.
//
//   • macOS   — a minimal .app bundle in ~/Applications (a shell script that runs "open")
//   • Linux   — a .desktop entry in ~/.local/share/applications (appears in the app menu)
//   • Windows — a hidden VBScript that runs "open", plus a Start-menu .lnk pointing at it (made with
//               PowerShell, so no console window ever flashes)
//
// create/remove/status are async, shell out only where a shortcut format requires it (Windows .lnk),
// and are best-effort: a failure is reported, never thrown into anything critical.

const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');
const Common = require('./Common');
const Brand = require('./Brand');

// Shared command runner (rejects on a non-zero exit unless ignoreError), so the spawn options live in one place.
const sh = Common.runCmdOrThrow;
const ICON_DIR = path.join(__dirname, 'assets'); // bundled launcher icons: logo.icns (macOS), logo.png (Linux), logo.ico (Windows)

const scriptPath = Common.appScriptPath;
// The branded node binary (same one autostart uses), so a launched service shows under the product name.
function nodeBin() { try { return require('./Launcher').ensure(); } catch (_) { return process.execPath; } }

function paths() {
	if (process.platform === 'darwin') {
		const appDir = path.join(os.homedir(), 'Applications', Brand.name + '.app');
		return { platform: 'macos', appDir, exe: path.join(appDir, 'Contents', 'MacOS', Brand.name), plist: path.join(appDir, 'Contents', 'Info.plist') };
	}
	if (process.platform === 'linux') {
		const dir = path.join(os.homedir(), '.local', 'share', 'applications');
		return { platform: 'linux', dir, desktop: path.join(dir, Brand.slug + '.desktop') };
	}
	if (process.platform === 'win32') {
		// Honor %APPDATA% (roaming profiles and folder redirection can put it outside ~/AppData/Roaming); fall back
		// to the conventional location only when the variable is unset.
		const roaming = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
		const startMenu = path.join(roaming, 'Microsoft', 'Windows', 'Start Menu', 'Programs');
		return { platform: 'windows', vbs: path.join(Common.dataDir(), Brand.slug + '-open.vbs'), lnk: path.join(startMenu, Brand.name + '.lnk') };
	}
	return null;
}

// Create the launcher. Returns { platform, path } (the clickable item's path).
async function create() {
	const info = paths();
	if (!info) throw new Error('A desktop launcher is not supported on this platform.');
	const node = nodeBin(), script = scriptPath();
	// If the user chose a custom data directory, the launcher must open the app against the SAME one (a default
	// launcher carries no path and tracks the current default). `dd*` are the ready-to-append flag fragments.
	const ddPath = Common.dataDirOverridePath();
	// Escape a value placed inside a POSIX double-quoted string: inside double quotes only \ ` $ " stay special, so
	// backslash-escape exactly those (backslash first). Without this, an install path or a custom data directory
	// containing one of them — a "$" is legal in a Linux home/username, for example — would break the generated
	// launcher so a click does nothing. This mirrors the escaping Autostart already applies to its service commands.
	const shDq = (s) => String(s).replace(/([\\`$"])/g, '\\$1');
	// A .desktop Exec argument is quoted like a shell word (the same escaping) and is then field-code processed, so a
	// literal percent sign must additionally be doubled.
	const deArg = (s) => shDq(s).replace(/%/g, '%%');
	const ddVbs = ddPath ? ' --data-dir ""' + ddPath + '""' : ''; // VBS double-quote escaping

	if (info.platform === 'macos') {
		await fsp.mkdir(path.dirname(info.exe), { recursive: true });
		// Give the launcher app the brand icon so it shows the logo in the Applications folder and the Dock, not a
		// generic placeholder. Best-effort: a missing/uncopyable icon just falls back to the default.
		const res = path.join(info.appDir, 'Contents', 'Resources');
		let hasIcon = false;
		try { await fsp.mkdir(res, { recursive: true }); await fsp.copyFile(path.join(ICON_DIR, 'logo.icns'), path.join(res, 'logo.icns')); hasIcon = true; } catch (_) {}
		// A tiny agent app: its executable is a shell script that runs "open" and exits. exec keeps the
		// process id so the app closes cleanly once the browser has been opened.
		const ddSh = ddPath ? ' --data-dir "' + shDq(ddPath) + '"' : '';
		const shell = '#!/bin/sh\nexec "' + shDq(node) + '" "' + shDq(script) + '" open' + ddSh + '\n';
		await fsp.writeFile(info.exe, shell, { mode: 0o755 });
		const plist = '<?xml version="1.0" encoding="UTF-8"?>\n'
			+ '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
			+ '<plist version="1.0"><dict>'
			+ '<key>CFBundleName</key><string>' + Brand.name + '</string>'
			+ '<key>CFBundleDisplayName</key><string>' + Brand.name + '</string>'
			+ '<key>CFBundleIdentifier</key><string>com.' + Brand.slug + '.launcher</string>'
			+ '<key>CFBundleExecutable</key><string>' + Brand.name + '</string>'
			+ (hasIcon ? '<key>CFBundleIconFile</key><string>logo</string>' : '')
			+ '<key>CFBundlePackageType</key><string>APPL</string>'
			+ '<key>CFBundleVersion</key><string>1.0</string>'
			+ '<key>LSUIElement</key><true/>'
			+ '</dict></plist>\n';
		await fsp.writeFile(info.plist, plist);
		// Bump the bundle's mtime so Finder/LaunchServices refresh the cached icon for a re-created launcher.
		try { const now = new Date(); await fsp.utimes(info.appDir, now, now); } catch (_) {}
		return { platform: info.platform, path: info.appDir };
	}

	if (info.platform === 'linux') {
		await fsp.mkdir(info.dir, { recursive: true });
		const entry = '[Desktop Entry]\n'
			+ 'Type=Application\n'
			+ 'Name=' + Brand.name + '\n'
			+ 'Comment=Open ' + Brand.name + ' in your browser\n'
			+ 'Exec="' + deArg(node) + '" "' + deArg(script) + '" open' + (ddPath ? ' --data-dir "' + deArg(ddPath) + '"' : '') + '\n'
			+ 'Icon=' + path.join(ICON_DIR, 'logo.png') + '\n' // the brand icon in the app menu, not a generic placeholder
			+ 'Terminal=false\n'
			+ 'Categories=Utility;Security;\n';
		await fsp.writeFile(info.desktop, entry, { mode: 0o755 });
		return { platform: info.platform, path: info.desktop };
	}

	// Windows: a hidden VBS that runs "open" (no console window), plus a Start-menu .lnk to it. The .lnk
	// is created with PowerShell's WScript.Shell, the standard scriptable way, so we add no dependency.
	await fsp.mkdir(Common.dataDir(), { recursive: true });
	const vbs = Common.windowsHiddenRunVbs(node, script, 'open' + ddVbs);
	// UTF-16LE + BOM so wscript reads a non-ASCII install path correctly (a plain UTF-8 .vbs is decoded as the
	// system ANSI code page and would silently fail to launch when the path contains non-code-page characters).
	await fsp.writeFile(info.vbs, '\ufeff' + vbs, 'utf16le');
	await fsp.mkdir(path.dirname(info.lnk), { recursive: true });
	const ps = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('" + info.lnk.replace(/'/g, "''") + "');"
		+ "$s.TargetPath='wscript.exe';"
		+ "$s.Arguments='\"" + info.vbs.replace(/'/g, "''") + "\"';"
		+ "$s.Description='Open " + Brand.name + "';"
		+ "$s.IconLocation='" + path.join(ICON_DIR, 'logo.ico').replace(/'/g, "''") + "';" // the brand icon on the Start-menu shortcut
		+ "$s.Save()";
	await sh('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]);
	return { platform: info.platform, path: info.lnk };
}

// Remove the launcher. Best-effort; never throws for a missing item.
async function remove() {
	const info = paths();
	if (!info) throw new Error('A desktop launcher is not supported on this platform.');
	if (info.platform === 'macos') await fsp.rm(info.appDir, { recursive: true, force: true });
	else if (info.platform === 'linux') await fsp.rm(info.desktop, { force: true });
	else { await fsp.rm(info.lnk, { force: true }); await fsp.rm(info.vbs, { force: true }); }
	return { platform: info.platform };
}

async function status() {
	const info = paths();
	if (!info) return { platform: process.platform, installed: false, supported: false };
	const target = info.platform === 'macos' ? info.appDir : info.platform === 'linux' ? info.desktop : info.lnk;
	return { platform: info.platform, installed: fs.existsSync(target), supported: true, path: target };
}

module.exports = { create, remove, status };
