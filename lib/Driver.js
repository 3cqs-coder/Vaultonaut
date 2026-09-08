'use strict';
// lib/Driver.js — detect the userspace-filesystem driver each platform needs to
// present a mounted volume, and give clear install guidance when it is missing.
//
// Mounting a volume is done by the operating system's kernel, so a small driver
// must be present. This is the one piece we cannot download into data/bin — it is
// a signed system component the user installs once. We detect it and, if absent,
// tell the user exactly what to install. Everything else (creating a vault, listing
// it, copying files in and out) works with no driver at all.

const fs = require('fs');
const path = require('path');
const Common = require('./Common');

// Run a probe command and report whether it exited 0, bounded by a timeout so a HUNG helper binary can never
// block the caller (detect runs on the web server's status poll, where a wedged fusermount would otherwise
// freeze the event loop). Async (never spawnSync) so it yields the loop while the probe runs.
async function cmdOk(cmd, args, timeoutMs) { return (await Common.runCmd(cmd, args, { timeout: timeoutMs })).ok; }

// Returns { ok, name, detail, install } describing the mount driver status. Async: the Linux path probes
// helper binaries, which must never block the event loop.
async function detect() {
	const plat = process.platform;
	if (plat === 'darwin') return detectMac();
	if (plat === 'win32') return detectWindows();
	if (plat === 'linux') return detectLinux();
	return { ok: false, name: null, detail: 'Unsupported platform: ' + plat, install: null };
}

// The FUSE-T shared library, if installed, as the path we point the engine at. FUSE-T
// is what lets macOS Finder copies (which write extended attributes the engine itself
// does not implement) succeed, so it is the driver this tool uses on macOS. Returns the
// dylib path or null.
function fusetLibPath() {
	const candidates = ['/usr/local/lib/libfuse-t.dylib', '/opt/homebrew/lib/libfuse-t.dylib'];
	for (const p of candidates) { try { if (fs.existsSync(p)) return p; } catch (_) {} }
	return null;
}

function detectMac() {
	// This tool uses FUSE-T on macOS, and selects it explicitly for its own engine (see
	// Rclone.spawnMount), so it works even when macFUSE is ALSO installed — macFUSE is
	// left completely untouched for whatever other apps on the machine rely on it. FUSE-T
	// is required because the engine cannot write the extended
	// attributes macOS attaches during a Finder/`cp` copy; macFUSE surfaces that as a
	// failed copy ("error code -8062"), whereas FUSE-T handles the attributes itself.
	const fusetLib = fusetLibPath();
	const macfuse = fs.existsSync('/Library/Filesystems/macfuse.fs') || fs.existsSync('/usr/local/lib/libfuse.2.dylib');
	if (fusetLib) {
		return { ok: true, name: 'FUSE-T', detail: 'FUSE-T is installed' + (macfuse ? ' (macFUSE is also present and left intact for your other apps).' : ' (no kernel extension).'), install: null, fusetLib };
	}
	// Without FUSE-T, copying files into a vault with Finder fails. macFUSE alone cannot do
	// it, so guide the user to add FUSE-T — which is kext-free and safe to keep ALONGSIDE
	// macFUSE. Mounting is still allowed on macFUSE (reading works; `cp -X` works), but with
	// a clear warning, so an existing macFUSE user is never hard-blocked.
	const install = 'Install FUSE-T (kext-free, no reboot, safe to keep alongside macFUSE): https://www.fuse-t.org/  — or run:  vdisk install-driver';
	if (macfuse) {
		return { ok: true, name: 'macFUSE', detail: 'macFUSE only.', install,
			warn: 'macFUSE is installed but FUSE-T is not. You can mount and read, but copying files into a vault with Finder will fail (error -8062) because the engine cannot write macOS extended attributes through macFUSE. Install FUSE-T to fix it — macFUSE can stay for your other apps.' };
	}
	return { ok: false, name: null, detail: 'No macOS mount driver found.', install };
}

function detectWindows() {
	// Look for WinFsp under the real Program Files directories the OS reports (these are
	// OS-provided install locations, not user configuration), so a system drive other than C:
	// or a relocated Program Files is still found — rclone itself locates WinFsp the same way.
	// The literal C: paths remain only as a last-resort fallback if those locations are unset.
	const roots = [process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.ProgramW6432,
		'C:\\Program Files', 'C:\\Program Files (x86)'].filter(Boolean);
	const winfsp = roots.some(r => { try { return fs.existsSync(path.join(r, 'WinFsp')); } catch (_) { return false; } });
	if (winfsp) return { ok: true, name: 'WinFsp', detail: 'WinFsp is installed.', install: null };
	return {
		ok: false, name: null,
		detail: 'WinFsp is not installed.',
		install: 'Install WinFsp (one signed installer, no reboot): https://winfsp.dev/rel/  — or:  winget install WinFsp.WinFsp'
	};
}

async function detectLinux() {
	// The kernel FUSE device is what a userspace mount needs. The mount engine calls
	// the FUSE 3 helper (fusermount3) specifically and does not fall back to FUSE 2's
	// fusermount, so a system with only FUSE 2 must still install fuse3 even though
	// /dev/fuse and fusermount are present — detecting them alone would be a false
	// "ready" that fails at the first mount.
	const dev = fs.existsSync('/dev/fuse');
	const fuse3 = await cmdOk('fusermount3', ['-V'], 3000);
	const fuse2 = fuse3 ? false : await cmdOk('fusermount', ['-V'], 3000);
	const install = 'Install FUSE 3:\n' +
		'  • Debian/Ubuntu:  sudo apt install fuse3\n' +
		'  • Fedora/RHEL:    sudo dnf install fuse3\n' +
		'  • Arch:           sudo pacman -S fuse3';
	if (dev && fuse3) return { ok: true, name: 'FUSE', detail: 'Kernel FUSE (fuse3) is available.', install: null };
	if (dev && fuse2) return { ok: false, name: null, detail: 'Only FUSE 2 (fusermount) was found; the mount engine requires FUSE 3 (fusermount3).', install };
	return { ok: false, name: null, detail: '/dev/fuse or the fusermount3 helper is missing.', install };
}

module.exports = { detect };
