'use strict';
// lib/Launcher.js — give the long-running service and guardian a real, friendly
// name in the OS process viewers that read the EXECUTABLE FILENAME (macOS Activity
// Monitor, Windows Task Manager) — which no runtime API can change. The trick is to
// run Node from a file named after the product (Brand.slug). We create that as a HARDLINK
// to the current node binary: it costs no extra disk, stays identical to the
// installed Node (same inode), and preserves the binary's code signature because the
// bytes are unchanged. If a hardlink is not possible (e.g. a different filesystem) we
// fall back to a copy. A plain symlink is deliberately NOT used — macOS resolves it
// back to "node".
//
// This complements process.title (which covers ps/top/htop on macOS and Linux). The
// autostart entry and the guardian are launched through this branded binary so they
// appear under the branded name everywhere; a one-off manual run still shows the friendly
// name in ps via process.title.

const fs = require('fs');
const path = require('path');
const Common = require('./Common');
const Brand = require('./Brand');

function launcherPath() { return path.join(Common.binDir(), Common.exeName(Brand.slug)); }

// Is this process the Node bundled INSIDE a macOS .app? When it is, helpers (the service, the guardian) are
// launched through that same bundled Node instead of a branded copy placed elsewhere — there is no reason to
// make a copy, and reusing the bundled runtime keeps every helper on the exact same binary. The desktop shell
// bundles that Node under Contents/Resources (not Contents/MacOS), so helpers launched from it are ordinary
// background processes with no Dock tile. Detected from the executable path so it is general (works wherever
// the app is installed) and only ever true on macOS.
function insideMacAppBundle(execPath = process.execPath, platform = process.platform) { return platform === 'darwin' && String(execPath).includes('.app/Contents/'); }

// Is the existing launcher still the current node? A hardlink shares node's inode;
// a copy should match its size and mtime. Comparing this way (not just a recorded
// path string) catches an in-place Node upgrade that replaces the binary at the same
// path with a new inode.
function isCurrent(target, src) {
	try {
		const t = fs.statSync(target), s = fs.statSync(src);
		if (t.ino === s.ino && t.dev === s.dev) return true;                    // same inode (hardlink)
		return t.size === s.size && Math.abs(t.mtimeMs - s.mtimeMs) < 1000;      // matching copy
	} catch (_) { return false; }
}

// Ensure the branded launcher exists and points at the current node. Rebuilt when it
// has gone stale (Node upgraded) or when force:true. Returns the launcher path, or
// the plain node path if it cannot be created for any reason.
function ensure({ force = false } = {}) {
	const src = process.execPath;
	// Inside a macOS .app, launch helpers through the bundled Node itself (no external copy needed): it lives
	// under Contents/Resources, so the service and guardian started from it show no stray tile in the Dock.
	// Everywhere else (a normal CLI or service install) the branded copy below still gives helpers a friendly
	// process filename.
	if (insideMacAppBundle()) return src;
	const target = launcherPath();
	try {
		Common.ensureDir(Common.binDir());
		Common.hardenDir(Common.binDir()).catch(() => {}); // owner-only (chmod on POSIX, an owner-only NTFS ACL on Windows), best-effort — a plain chmod would be a no-op on Windows, so no other user can swap the launcher
		// If THIS process is the branded launcher itself (started via it — e.g. by autostart), src and target are the
		// SAME file. Never delete-and-recreate then, even under force: rmSync would remove the running launcher AND the
		// very source we would relink from, so the relink/copy fails and the launcher is lost — which broke the app
		// icon after toggling autostart. It is current by definition, so just return it. Common.samePath is case-folded
		// (correct on macOS/Windows case-insensitive filesystems).
		if (Common.samePath(src, target)) return target;
		// Rebuild ONLY when the launcher is genuinely missing or stale. isCurrent already detects a Node upgrade (its
		// size/mtime change), so a real change is always picked up. `force` no longer re-does the build of an
		// ALREADY-identical launcher: on a host where the data dir and Node live on different volumes the hardlink
		// fails and the rebuild falls back to copying the whole (~100 MB) binary, and doing that on every autostart
		// toggle blocked the running server's event loop for no benefit. The `force` parameter is kept for callers'
		// intent but no longer triggers a needless copy.
		if (fs.existsSync(target) && isCurrent(target, src)) return target;
		void force;

		try { fs.rmSync(target, { force: true }); }
		catch (_) {
			// Windows will not delete a currently-running image; renaming it aside IS
			// allowed, which frees the path for the fresh launcher. The stale file is
			// harmless and is cleared on the next run.
			try { fs.rmSync(target + '.old', { force: true }); } catch (_) {}
			try { fs.renameSync(target, target + '.old'); } catch (_) {}
		}
		try {
			fs.linkSync(src, target); // hardlink: no disk cost, signature preserved
		} catch (_) {
			fs.copyFileSync(src, target); // fallback: a separate copy
			if (process.platform !== 'win32') { try { fs.chmodSync(target, 0o755); } catch (_) {} }
			// Match the source's mtime so isCurrent() recognizes the copy next time and
			// does not needlessly re-copy the (large) binary on every call.
			try { const s = fs.statSync(src); fs.utimesSync(target, s.atime, s.mtime); } catch (_) {}
		}
		return fs.existsSync(target) ? target : src;
	} catch (_) { return src; }
}

module.exports = { ensure, launcherPath, insideMacAppBundle };
