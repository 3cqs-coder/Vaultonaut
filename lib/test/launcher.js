'use strict';
// lib/test/launcher.js — the branded launcher binary that the app icon and autostart run. The critical property:
// ensure() must NEVER delete the launcher when the running process IS that launcher (src === target), or it erases
// itself and cannot relink — which broke the app icon after toggling autostart. Also covers normal creation and
// idempotence. Operates entirely on a temp fake "node" file (process.execPath is overridden), so it never touches
// the real Node binary. Cross-platform (hardlink or copy; the launcher name gets the platform's exe suffix).
//
// Run:  node lib/test/launcher.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const Common = require('../Common');
const Launcher = require('../Launcher');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-launcher-'));
	const origExec = process.execPath;
	const origBinDir = Common.binDir;
	// Stub the directory hardening. On Windows hardenDir SPAWNS icacls asynchronously (fire-and-forget); this test is
	// synchronous and exits the moment it finishes, so the process would tear down while those child-process handles
	// are still in flight — hitting a libuv assertion ("!(handle->flags & UV_HANDLE_CLOSING)", src\\win\\async.c) and
	// aborting the runner. The test exercises the LAUNCHER logic, not ACL hardening, so no-op it. (Production is
	// unaffected: the long-lived service keeps running, so the real icacls call settles normally.)
	const origHarden = Common.hardenDir;
	Common.hardenDir = async () => true;
	try {
		// A stand-in for the Node binary, so nothing here can affect the real one.
		const fakeNode = path.join(tmp, 'fake-node');
		fs.writeFileSync(fakeNode, 'FAKE-NODE-BINARY-CONTENT', { mode: 0o755 });
		Object.defineProperty(process, 'execPath', { value: fakeNode, configurable: true, writable: true });
		Common.binDir = () => path.join(tmp, 'bin');
		const target = Launcher.launcherPath();

		// 1) Normal creation: the branded launcher is made from the current executable.
		const r1 = Launcher.ensure({ force: true });
		ok('ensure() creates the branded launcher', r1 === target && fs.existsSync(target));
		ok('the launcher has the executable content', fs.readFileSync(target, 'utf8') === 'FAKE-NODE-BINARY-CONTENT');

		// 2) Idempotent: a second call keeps a working launcher.
		const r2 = Launcher.ensure();
		ok('ensure() is idempotent (launcher still present)', r2 === target && fs.existsSync(target));

		// 2b) Background mode (used by the crash-safety guardian on the hot path) must still build via the INSTANT
		//     hardlink synchronously on one volume — only a cross-volume byte COPY is deferred off the event loop. So
		//     after removing the launcher, a background ensure() recreates it and returns the branded path right away.
		fs.rmSync(target, { force: true });
		const rbg = Launcher.ensure({ background: true });
		ok('background ensure() rebuilds via the instant hardlink synchronously on one volume', rbg === target && fs.existsSync(target));

		// 3) THE GUARD: when the running process IS the launcher (src === target), a forced ensure() must NOT delete
		//    it. Before the fix, rmSync removed it and the relink failed, erasing the launcher.
		Object.defineProperty(process, 'execPath', { value: target, configurable: true, writable: true });
		const r3 = Launcher.ensure({ force: true });
		ok('a forced ensure() does not erase the launcher when it is the running process', r3 === target && fs.existsSync(target));
		ok('the launcher content survives the self-referential force', fs.existsSync(target) && fs.readFileSync(target, 'utf8') === 'FAKE-NODE-BINARY-CONTENT');

		// 4) macOS .app detection. Inside a bundle, ensure() must launch helpers through the BUNDLED Node (which
		//    carries the app's identity, so the service and guardian raise no stray Dock tile) rather than an
		//    external branded copy. Detected purely from the executable path, so it is checked directly here.
		ok('a Node bundled under Contents/Resources is detected as inside a macOS bundle', Launcher.insideMacAppBundle('/Applications/Vaultonaut.app/Contents/Resources/runtime/node', 'darwin') === true);
		ok('a plain Node path is NOT treated as a macOS bundle', Launcher.insideMacAppBundle('/usr/local/bin/node', 'darwin') === false);
		ok('the same bundled path on another platform is not a macOS bundle', Launcher.insideMacAppBundle('/Applications/Vaultonaut.app/Contents/Resources/runtime/node', 'linux') === false);
		// Inside a bundle, ensure() returns the bundled Node itself (no external copy is created).
		Object.defineProperty(process, 'execPath', { value: path.join(tmp, 'Vaultonaut.app', 'Contents', 'Resources', 'runtime', 'node'), configurable: true, writable: true });
		const origPlatform = process.platform;
		try {
			Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });
			ok('inside a macOS .app, ensure() returns the bundled Node (no external copy)', Launcher.ensure({ force: true }) === process.execPath);
		} finally {
			Object.defineProperty(process, 'platform', { value: origPlatform, configurable: true });
		}
	} finally {
		Object.defineProperty(process, 'execPath', { value: origExec, configurable: true, writable: true });
		Common.binDir = origBinDir;
		Common.hardenDir = origHarden;
		try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LAUNCHER CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
