'use strict';
// lib/TorSetup.js — download a known-good, CHECKSUM-VERIFIED Tor into the per-user bin dir, so onion transport works
// with no setup at all, exactly the way the storage engine is fetched. It downloads the Tor Project's official
// "expert bundle" (a standalone tor, not the browser) for this platform, verifies it against a checksum COMMITTED here
// (taken from the Tor Project's signed SHA256SUMS at the pinned version), extracts it, and — on macOS, where a
// downloaded UNSIGNED binary is killed by the OS on Apple Silicon — ad-hoc code-signs it so it runs. Nothing is
// bundled in the installer; a first onion use downloads it once and caches it. Cross-platform (macOS/Windows/Linux)
// and non-blocking (streamed download, subprocess extract/sign, everything async).
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const { spawn } = require('child_process');
const Common = require('./Common');
const Net = require('./Net');

// The Tor Browser release whose expert bundle carries the tested tor (tor 0.4.9.x). Bump this AND the checksums below
// together, from the Tor Project's signed SHA256SUMS, as one reviewed change — never edit a checksum on its own.
const PINNED_TAG = '15.0.23';
// The COMMITTED SHA-256 of each platform's expert-bundle archive, taken from the Tor Project's signed SHA256SUMS for
// PINNED_TAG. A download is verified against THIS value, not whatever the mirror serves, so a swapped or corrupt
// archive is never extracted or run — and it is never installed without a checksum match.
const PINNED_SHA256 = {
	'linux-x86_64': '08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985',
	'linux-i686': 'af684a8839d61778b5722938e43cc0c1cc9886f8fd8b7fb33d056077363edfba',
	'macos-aarch64': 'e8ea3f667c83309abad34280f0f9e1cfae52843da6b8db111ca15d6221051db5',
	'macos-x86_64': 'be1be1cb13cd093713f02a0beade0d2471b61119011bfeb0efc08353eadf2e4e',
	'windows-x86_64': '231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e',
	'windows-i686': '1e4de9a4f1d99b8f40b5e0c75f3dcc3ea51b0aeab040d48fd23881e9fa94979a',
};
// Map Node's platform/arch to the Tor expert-bundle suffix; null for an unsupported platform (then onion mode stays on
// the detect-a-running-Tor path only, and automatic download is simply not offered).
function torSuffix(platform, arch) {
	platform = platform || process.platform; arch = arch || process.arch;
	const a = arch === 'arm64' ? 'aarch64' : (arch === 'x64' ? 'x86_64' : (arch === 'ia32' ? 'i686' : arch));
	if (platform === 'darwin') return (a === 'aarch64' || a === 'x86_64') ? 'macos-' + a : null;
	if (platform === 'linux') return (a === 'x86_64' || a === 'i686') ? 'linux-' + a : null;
	if (platform === 'win32') return (a === 'x86_64' || a === 'i686') ? 'windows-' + a : null;
	return null;
}
function pinnedSha256(platform, arch) { const s = torSuffix(platform, arch); return (s && PINNED_SHA256[s]) || null; }
function torRoot() { return path.join(Common.binDir(), 'tor'); }
function torDir() { return path.join(torRoot(), 'tor'); }               // the bundle's tor/ dir — used as the tor process's CWD
function torBinPath() { return path.join(torDir(), Common.exeName('tor')); }
function ptDir() { return path.join(torDir(), 'pluggable_transports'); } // lyrebird / conjure-client live here
function geoipPath() { return path.join(torRoot(), 'data', 'geoip'); }
function geoip6Path() { return path.join(torRoot(), 'data', 'geoip6'); }
function tagSidecar() { return path.join(torRoot(), '.tag'); }

async function readTag() { try { return (await fsp.readFile(tagSidecar(), 'utf8')).trim(); } catch (_) { return ''; } }
function log(m) { try { Common.log('[tor] ' + m); } catch (_) {} }

// Run a short-lived subprocess to completion; resolve { code, out } (never throws). Used for extraction and signing.
function runTool(cmd, args, opts) {
	return new Promise((resolve) => {
		let out = ''; let child;
		try { child = spawn(cmd, args, Object.assign({ windowsHide: true }, opts)); } catch (e) { return resolve({ code: -1, out: String(e && e.message || e) }); }
		if (child.stdout) child.stdout.on('data', (d) => { out += d; });
		if (child.stderr) child.stderr.on('data', (d) => { out += d; });
		child.on('error', (e) => resolve({ code: -1, out: String(e && e.message || e) }));
		child.on('close', (code) => resolve({ code: code, out: out }));
	});
}

// Extract a .tar.gz with the platform's own tar (macOS/Linux ship it; Windows 10 1803+ ships tar.exe). Cross-platform,
// no dependency, and it preserves the executable bits and the bundle's tor/, data/, docs/ layout.
async function extractTarGz(archive, destDir) {
	await fsp.mkdir(destDir, { recursive: true });
	const r = await runTool('tar', ['-xzf', archive, '-C', destDir]);
	if (r.code !== 0) throw new Error('Could not extract the Tor download (' + (r.out || 'tar failed').trim().slice(0, 200) + ').');
}

// macOS only: the expert-bundle binaries are UNSIGNED, and the OS refuses to run an unsigned binary on Apple Silicon
// (it is killed with SIGKILL). An ad-hoc signature (`codesign --sign -`) makes it runnable without any developer
// account — the same treatment a locally built tool gets. Sign every dylib first, then the tor binary. No-op elsewhere.
async function adhocSignMac(root) {
	if (process.platform !== 'darwin') return;
	const toolDir = path.join(root, 'tor');
	let entries = []; try { entries = await fsp.readdir(toolDir); } catch (_) { return; }
	for (const name of entries) { if (/\.dylib$/i.test(name)) await runTool('codesign', ['--force', '--sign', '-', path.join(toolDir, name)]); }
	await runTool('codesign', ['--force', '--sign', '-', path.join(toolDir, 'tor')]);
	// The pluggable-transport binaries (lyrebird, conjure-client) are UNSIGNED too and would be SIGKILLed on Apple
	// Silicon exactly like tor, so ad-hoc sign each one — otherwise a bridge would silently fail to launch its transport.
	const pt = path.join(toolDir, 'pluggable_transports');
	let pts = []; try { pts = await fsp.readdir(pt); } catch (_) { return; }
	for (const name of pts) { if (!/\.(md|json|txt)$/i.test(name)) await runTool('codesign', ['--force', '--sign', '-', path.join(pt, name)]); }
}
// Read and parse the bundle's pt_config.json (which ships the ClientTransportPlugin lines and the default bridge lines
// for each transport), so bridges are driven by the Tor Project's own config and stay correct across bundle updates —
// nothing brittle is hardcoded. The plugin exec path is made RELATIVE to the tor/ dir (${pt_path} -> ./pluggable_transports/),
// so Tor resolves it against its working directory: the install path contains a space (…/Application Support/…) and
// Tor's ClientTransportPlugin parser splits on spaces, so an ABSOLUTE path would break — a relative one never does.
// One-time read, cached for the process; async so it never blocks the event loop. Returns null when there is no config.
let _ptCache = null;
async function readPtConfig() {
	if (_ptCache) return _ptCache;
	let raw; try { raw = await fsp.readFile(path.join(ptDir(), 'pt_config.json'), 'utf8'); } catch (_) { return null; }
	let cfg; try { cfg = JSON.parse(raw); } catch (_) { return null; }
	const resolve = (line) => String(line || '').replace(/\$\{pt_path\}/g, './pluggable_transports/');
	const transports = {};
	for (const k of Object.keys(cfg.pluggableTransports || {})) transports[k] = resolve(cfg.pluggableTransports[k]);
	_ptCache = { recommendedDefault: cfg.recommendedDefault || 'obfs4', transports: transports, bridges: cfg.bridges || {} };
	return _ptCache;
}

// Ensure a working, checksum-verified Tor is installed, and return its paths. Downloads it once (verified) if missing
// or if the pinned version changed, else uses the cache. Throws a clear error on an unsupported platform or a failed
// download, so onion mode falls back to a detected system Tor. Single-flighted so two callers never double-download.
let _inFlight = null;
function ensureTor() { if (!_inFlight) { _inFlight = ensureImpl().finally(() => { _inFlight = null; }); } return _inFlight; }
async function ensureImpl() {
	const suffix = torSuffix();
	if (!suffix) throw Object.assign(new Error('Automatic Tor download is not available for this platform; run Tor yourself to use onion mode.'), { code: 'TOR_UNSUPPORTED' });
	const sha256 = pinnedSha256();
	const binPath = torBinPath();
	// Cached and current? Use it. (The tor binary existing plus a matching tag is the fast path; the checksum was
	// verified when it was downloaded, and the archive — not the extracted binary — is what carries the pinned sum.)
	if (fs.existsSync(binPath) && (await readTag()) === PINNED_TAG) return paths();
	const root = torRoot();
	Common.ensureDir(Common.binDir());
	await Common.hardenDir(Common.binDir()).catch(() => {});
	// Fresh install (or a version bump): download the verified archive to a temp, extract it into place, sign on macOS.
	const fileName = 'tor-expert-bundle-' + suffix + '-' + PINNED_TAG + '.tar.gz';
	const url = 'https://archive.torproject.org/tor-package-archive/torbrowser/' + PINNED_TAG + '/' + fileName;
	const tmpArchive = path.join(Common.binDir(), '_tor_download.' + process.pid + '.' + Date.now() + '.tar.gz');
	log('Downloading Tor ' + PINNED_TAG + ' for ' + suffix + ' (one time)…');
	try {
		await Net.download(url, tmpArchive, { expectedSha256: sha256, label: 'Tor' });
		await fsp.rm(root, { recursive: true, force: true }).catch(() => {}); // clear any prior/partial install
		await extractTarGz(tmpArchive, root);
		await adhocSignMac(root);
		_ptCache = null; // a fresh install may carry new transports/bridges — re-read pt_config on next use
		if (process.platform !== 'win32') {
			try { await fsp.chmod(torBinPath(), 0o755); } catch (_) {}
			// Make the pluggable-transport binaries executable too, so a bridge can launch its transport.
			try { const pts = await fsp.readdir(ptDir()); for (const n of pts) { if (!/\.(md|json|txt)$/i.test(n)) await fsp.chmod(path.join(ptDir(), n), 0o755).catch(() => {}); } } catch (_) {}
		}
		if (!fs.existsSync(torBinPath())) throw new Error('The Tor download did not contain the expected binary.');
		try { const p = tagSidecar(); await fsp.writeFile(p, PINNED_TAG); await Common.fsyncPath(p); } catch (_) {}
		log('Tor is installed.');
		return paths();
	} finally { try { await fsp.unlink(tmpArchive); } catch (_) {} }
}
function paths() { return { tor: torBinPath(), torDir: torDir(), geoip: geoipPath(), geoip6: geoip6Path(), tag: PINNED_TAG }; }
// Is a downloaded Tor already installed (so we can offer onion mode without a running system Tor)?
function isInstalled() { return fs.existsSync(torBinPath()); }

module.exports = { ensureTor, isInstalled, torSuffix, pinnedSha256, torBinPath, torDir, ptDir, readPtConfig, geoipPath, geoip6Path, PINNED_TAG, PINNED_SHA256 };
