'use strict';
// lib/DriverInstall.js — fetch and launch the correct mount driver installer for
// this operating system, so a new user can get from "no driver" to "ready" without
// hunting down downloads.
//
//   macOS   — FUSE-T (kext-free, no reboot). Downloaded .pkg, opened in Installer.
//   Windows — WinFsp. Downloaded .msi, launched via msiexec.
//   Linux   — FUSE ships with the distro; we return the exact package command
//             (installing it needs root, which we never take on our own).
//
// TRUST MODEL. Two layers, and it is honest about what each proves. (1) The download is verified against the checksum
// the driver's release publishes, which catches corruption or tampering IN TRANSIT — but that checksum comes from the
// same source as the file, so it is not, by itself, proof of authenticity against a compromised release. (2) The
// AUTHENTICITY anchor is the operating system's own code-signature check when the installer RUNS: macOS Gatekeeper
// assesses the .pkg's notarization when Installer opens it, and Windows checks the .msi's Authenticode signature and
// shows its publisher. The launch path below deliberately uses those OS front doors (`open`, `msiexec`) and never a
// flag that would suppress that verification. Unlike the engine — which pins a per-platform checksum in code — the
// drivers are fetched at their latest published version, because a mount driver gets security fixes a user should not
// be pinned away from; the reproducibility/authenticity a committed pin would add is left to the OS signature instead.
//
// Downloading and running an installer is an outward, user-driven action: it is
// triggered only when the user asks (the `install-driver` command or the button in
// the UI), never automatically.

const path = require('path');
const { spawn } = require('child_process');
const Common = require('./Common');
const Net = require('./Net');
const Driver = require('./Driver');

// Launch a native installer with an always-present OS tool, detached so it keeps
// running after this process returns.
function launch(cmd, args) {
	try {
		const c = spawn(cmd, args, { detached: true, stdio: 'ignore' });
		c.on('error', () => {}); // avoid an uncaught 'error' event taking down the host on spawn failure
		c.unref();
		return true;
	} catch (_) { return false; }
}

async function fetchAndVerify(repo, matchFn, label) {
	Common.ensureDir(Common.binDir());
	const asset = await Net.githubLatestAsset(repo, matchFn);
	// Never download and launch a privileged installer we cannot verify.
	if (!asset.sha256) throw new Error('Refusing to launch an unverified ' + label + ' installer (no published checksum).');
	const dest = path.join(Common.binDir(), asset.name);
	Common.log('Downloading ' + label + ' ' + asset.tag + ' (checksum-verified)…');
	await Net.download(asset.url, dest, { label, expectedSha256: asset.sha256 });
	return dest;
}

async function install() {
	if (process.platform === 'darwin') {
		const pkg = await fetchAndVerify('macos-fuse-t/fuse-t', a => /^fuse-t-macos-installer-.*\.pkg$/i.test(a.name), 'FUSE-T');
		const ok = launch('open', [pkg]);
		Common.log('Opened the FUSE-T installer — follow its prompts to finish.');
		return { platform: 'macos', driver: 'FUSE-T', installer: pkg, launched: ok };
	}
	if (process.platform === 'win32') {
		const msi = await fetchAndVerify('winfsp/winfsp', a => /^winfsp-\d[\d.]*\.msi$/i.test(a.name), 'WinFsp');
		const ok = launch('msiexec', ['/i', msi]);
		Common.log('Launched the WinFsp installer — follow its prompts to finish.');
		return { platform: 'windows', driver: 'WinFsp', installer: msi, launched: ok };
	}
	if (process.platform === 'linux') {
		// Installing a package requires root, which we never assume; hand back the
		// exact command for the user to run.
		const guidance = ((await Driver.detect()).install) || 'Install FUSE with your package manager, e.g. sudo apt install fuse3';
		return { platform: 'linux', driver: 'FUSE', launched: false, instructions: guidance };
	}
	throw new Error('Automatic driver install is not supported on this platform.');
}

module.exports = { install };
