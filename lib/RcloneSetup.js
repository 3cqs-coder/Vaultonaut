'use strict';
// lib/RcloneSetup.js — download a known-good, CHECKSUM-VERIFIED rclone binary into
// data/bin so every install runs the same build with mount support, regardless of
// what (if anything) the user has on PATH. This matters: some package-manager builds
// of rclone are compiled WITHOUT mount support on macOS and refuse to mount, so a
// system copy cannot be relied on for the real-time disk feature — we ship our own.
//
// Version policy: a specific known-good version is pinned (PINNED_TAG) so a fresh install always gets a build this
// tool has been tested against; a future rclone regression cannot break new installs on the day it lands. The pin is
// tied to a Vaultonaut release: updating the engine means bumping PINNED_TAG and its committed checksums together,
// testing, and releasing — and every existing install then converges on that build (ensure() re-downloads when the
// cached engine's recorded tag no longer matches the pin). `ensure({ latest: true })` opts in to the newest release.
//
// Integrity: for a pinned install the expected SHA-256 is COMMITTED in this file per platform (PINNED_SHA256), so the
// download is verified against the value shipped and tested with this release, not whatever the source's metadata
// reports at install time (a platform not in that table, and --latest, fall back to the release's published
// checksum). The binary is fetched from the rclone.org download mirror (falling back to the GitHub asset) and
// verified against that checksum before use — and NEVER installed without a checksum. The cached binary is
// re-verified once per process, and data/bin is owner-only.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const Common = require('./Common');
const Net = require('./Net');

const PINNED_TAG = 'v1.75.1'; // known-good, tested rclone version

// The COMMITTED SHA-256 of each platform's PINNED_TAG archive, so the engine's integrity is tied to a tested
// Vaultonaut release: a download is verified against the value the maintainer shipped, independent of what the
// download source's metadata happens to say at install time (and it still verifies when that metadata is
// unavailable). Keyed by archiveSuffix(), so it is cross-platform by construction — macOS, Linux, and Windows across
// every architecture rclone publishes. Updating the engine is a deliberate, reviewable change: bump PINNED_TAG AND
// these sums together, test, and release; every install then converges on that exact build (see ensure(), which
// re-downloads when a cached engine's recorded tag no longer matches the pin). A platform absent here degrades
// safely to the release's published checksum. These are the archive (.zip) checksums straight from
// https://downloads.rclone.org/v1.75.1/SHA256SUMS.
const PINNED_SHA256 = {
	'osx-amd64': '29253d0288b8fbbac46baad6e5f6add6cb01d462c79f10805bbd4631c4cdf82c',
	'osx-arm64': 'c61d7a371c62bcbbe882c3423aa4b8bf63485c248dd0f692997b8f0c3f6d0c6f',
	'linux-amd64': '982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab',
	'linux-arm64': '03f2504174034b6d004152ed7369251c9a9ec1f7e0836eda420f5c7a5ec0dff9',
	'linux-arm-v7': '33c683053b677d9a89d4a985e8a25cfed7c8a95dd8379e367a5c73d8745356c3',
	'windows-amd64': '200eb602c126d82aa38b51e0f6b9ae837473ff99b51278d3f6f837574c494d6e',
	'windows-arm64': 'c3c6cd0424dd49076ad179c30c3f9e5cde2c004ec07ea9fe6911f23e32eafe0f',
	'windows-386': '42257481a961b39cdee3b3eea7b9945a1961825e332d07b3aa321808c0afc436',
};
// The committed checksum for this machine's build (or a given platform/arch), or null when this platform is not in
// the table (then the release's published checksum is used, as before).
function pinnedSha256(platform = process.platform, arch = process.arch) { const s = archiveSuffix(platform, arch); return (s && PINNED_SHA256[s]) || null; }

let verifiedThisProcess = false;

function log(msg) { Common.log('[Engine] ' + msg); }
function rclonePath() { return path.join(Common.binDir(), Common.exeName('rclone')); }
function shaSidecar() { return rclonePath() + '.sha256'; }
function tagSidecar() { return rclonePath() + '.tag'; } // the release tag the cached binary was installed from — drives the currency (auto-upgrade) check, separate from the binary-hash integrity sidecar
async function recordedTag() { try { return (await fsp.readFile(tagSidecar(), 'utf8')).trim(); } catch (_) { return ''; } }
async function writeTagSidecar(tag) { try { const p = tagSidecar(), tmp = p + '.tmp-' + process.pid; await fsp.writeFile(tmp, String(tag || '')); await Common.fsyncPath(tmp); await Common.renameWithRetry(tmp, p); } catch (_) {} }

// True if a binary at p exists AND runs (`version` exits 0). The version probe is bounded by a timeout so a
// HUNG or malicious binary can never wedge the caller — doctor() reaches this on the web status poll. It is
// ASYNC (never spawnSync) so a slow probe yields the event loop instead of freezing every other request. A
// timed-out or failed probe reports "does not work".
async function works(p) {
	try {
		await fsp.access(p);
		return (await Common.runCmd(p, ['version'], { timeout: 4000 })).ok;
	} catch (_) { return false; }
}

// Compare the installed engine to the checksum recorded when it was downloaded and verified against the official
// release. PURE classification — no side effects — so both the run-time gate (cachedVerified) and the boot
// watchdog (integrityStatus) share ONE comparison and can never drift on how "is this engine authentic?" is
// decided. Returns:
//   'ok'           — the binary matches its recorded checksum
//   'mismatch'     — a checksum is recorded and the binary does NOT match it (swapped/corrupt): never trust it
//   'unverifiable' — the binary AND a recorded checksum both exist, but the binary could not be hashed to compare
//                    right now (a transient read error): FAIL CLOSED — do not run it unverified this pass
//   'unrecorded'   — the binary exists but no checksum is recorded yet (a legacy pre-checksum install)
//   'absent'       — no binary present at all
async function checksumState() {
	try { await fsp.access(rclonePath()); } catch (_) { return 'absent'; }
	const want = (await fsp.readFile(shaSidecar(), 'utf8').catch(() => '')).trim();
	if (!want) return 'unrecorded';
	let got;
	try { got = await Net.sha256File(rclonePath()); }
	catch (_) { return 'unverifiable'; } // present binary + recorded checksum, but unhashable right now — never run it unverified
	return got.toLowerCase() === want.toLowerCase() ? 'ok' : 'mismatch';
}

// Durable, atomic write of the checksum sidecar (temp + fsync + rename), so a crash can't leave a torn or
// zero-length sidecar that would fail the next verify and force a needless re-download.
async function writeSidecar(hex) {
	const p = shaSidecar();
	const tmp = p + '.tmp-' + process.pid;
	try { await fsp.writeFile(tmp, hex); await Common.fsyncPath(tmp); await Common.renameWithRetry(tmp, p); }
	catch (e) { try { await fsp.unlink(tmp); } catch (_) {} throw e; }
}

// The run-time gate: is the cached engine safe to run WITHOUT a fresh download? Verifies at most once per
// process. Only a binary that matches its recorded checksum returns 'ok'. A legacy install with no recorded
// checksum ('unrecorded') is NOT blessed in place here — it is returned as-is so ensure() re-downloads and
// verifies it against the official release when the network is reachable, closing the gap where an attacker who
// can write data/bin could swap the binary AND delete the sidecar to dodge a 'mismatch'. Only the OFFLINE
// fallback (see ensure) records the current binary's hash as trust-on-first-use, because there is then no way to
// re-verify. Returns checksumState's value verbatim.
async function cachedVerified() {
	if (verifiedThisProcess) return 'ok';
	const state = await checksumState();
	if (state === 'ok') { verifiedThisProcess = true; return 'ok'; }
	if (state === 'mismatch') log('Cached engine failed checksum verification — re-downloading.');
	return state; // 'mismatch' | 'unverifiable' | 'unrecorded' | 'absent'
}

// Map this machine's CPU architecture to the name the official rclone release archives use. Returns null for an
// architecture rclone does not publish, so the caller surfaces a clear "no build for your platform" message rather
// than installing an unrunnable binary. Node reports 'arm' for ARMv7 on modern single-board computers, and the
// minimum Node this tool requires has no ARMv6 build, so 'arm' maps to rclone's v7 archive.
function rcloneArch(arch = process.arch) {
	switch (arch) {
		case 'arm64': return 'arm64';
		case 'x64': return 'amd64';
		case 'ia32': return '386';
		case 'arm': return 'arm-v7';
		default: return null;
	}
}
// Map platform/arch to the official rclone release archive suffix, or null when there is no build for this machine.
// Parameterized (defaulting to this machine) so the mapping is unit-testable across platforms and architectures.
function archiveSuffix(platform = process.platform, arch = process.arch) {
	const a = rcloneArch(arch);
	if (!a) return null;
	if (platform === 'darwin') return 'osx-' + a;
	if (platform === 'linux') return 'linux-' + a;
	if (platform === 'win32') return 'windows-' + a;
	return null;
}

// Resolve the release for this platform: version tag, expected SHA-256, the
// preferred rclone.org download URL, and a GitHub fallback URL.
async function resolveRelease({ latest = false } = {}) {
	const suffix = archiveSuffix();
	if (!suffix) { const e = new Error('no engine build for ' + process.platform + '/' + process.arch); e.code = 'NO_ASSET'; throw e; } // → the caller's NO_ASSET branch prints clear "not published for this platform/architecture" guidance
	const zipMatch = a => a.name.startsWith('rclone-v') && a.name.endsWith('-' + suffix + '.zip');
	const asset = latest
		? await Net.githubLatestAsset('rclone/rclone', zipMatch)
		: await Net.githubAssetForTag('rclone/rclone', PINNED_TAG, zipMatch);

	// Prefer the COMMITTED checksum for a pinned install, so the download is verified against the value shipped and
	// tested with this Vaultonaut release rather than whatever the source's metadata reports now. --latest cannot be
	// pinned (it is a future, untested version), so it uses the release's published checksum. A platform not in the
	// committed table also falls back to the published checksum.
	let sha256 = (!latest && pinnedSha256()) || asset.sha256;
	if (!sha256) {
		// Fall back to the release's SHA256SUMS file rather than proceeding unverified.
		try {
			const sums = latest
				? await Net.githubLatestAsset('rclone/rclone', a => a.name === 'SHA256SUMS')
				: await Net.githubAssetForTag('rclone/rclone', PINNED_TAG, a => a.name === 'SHA256SUMS');
			const line = (await Net.getText(sums.url)).split(/\r?\n/).find(l => l.trim().endsWith(asset.name));
			if (line) sha256 = line.trim().split(/\s+/)[0];
		} catch (_) {}
	}
	return {
		tag: asset.tag,
		sha256,
		fileName: asset.name,
		primaryUrl: 'https://downloads.rclone.org/' + asset.tag + '/' + asset.name, // rclone.org mirror
		fallbackUrl: asset.url // official GitHub asset (same file, same checksum)
	};
}

// The archive extracts to a versioned folder (rclone-vX.Y.Z-<suffix>/) containing a
// single rclone binary. Lift it up into data/bin and clean up.
async function liftBinary(dir) {
	const nested = (await fsp.readdir(dir)).find(d => d.startsWith('rclone-v'));
	if (!nested) return false;
	const src = path.join(dir, nested, Common.exeName('rclone'));
	const dst = rclonePath();
	try { await fsp.rename(src, dst); } catch (_) { try { await fsp.copyFile(src, dst); } catch (_) {} }
	if (process.platform !== 'win32') { try { await fsp.chmod(dst, 0o755); } catch (_) {} }
	try { await fsp.rm(path.join(dir, nested), { recursive: true, force: true }); } catch (_) {}
	return fs.existsSync(dst);
}

// Once the bundled binary has been verified AND confirmed to run in this process, remember it so ensure() does
// not re-run the synchronous `version` probe on every mount/create (the binary does not change during a run).
// This keeps the recurring callers off a blocking spawnSync, matching resolve()'s own memoization.
let _ranOk = false;
// Ensure data/bin has a working, verified rclone. Returns { rclone, ok }.
async function ensure(opts = {}) {
	const dir = Common.binDir();
	Common.ensureDir(dir);
	await Common.hardenDir(dir).catch(() => {}); // owner-only (chmod on POSIX, an owner-only NTFS ACL on Windows) so no other user can swap the binary — a plain chmod is a no-op on Windows
	const bin = rclonePath();
	// Verify the checksum BEFORE running the binary, so a swapped/corrupt engine is never executed
	// even once; only a verified binary is then confirmed to actually run.
	const cache = await cachedVerified();
	// Currency: when this platform has a committed pinned checksum and the cached engine was installed from a
	// DIFFERENT release tag than the current pin (a Vaultonaut update moved the pin, a prior --latest install, or a
	// legacy install with no tag recorded), the cached engine is not the build tested with this release — fall through
	// and re-download the pinned version, verified against the committed checksum. Skipped for --latest (which opts
	// into the newest, not the pin) and once the engine is already confirmed this process (_ranOk). If the re-download
	// cannot happen (offline), fallback() below still returns the working cached engine, so nothing ever breaks.
	let stale = false;
	if (!_ranOk && !opts.latest && pinnedSha256()) { stale = (await recordedTag()) !== PINNED_TAG; }
	if (cache === 'ok' && !stale && (_ranOk || await works(bin))) { _ranOk = true; return { rclone: bin, ok: true }; }
	if (stale && cache === 'ok') log('Updating the bundled engine to the version tested with this release (' + PINNED_TAG + ').');

	// When a re-download isn't possible (offline, or no checksum published), fall back ONLY to the already-installed
	// BUNDLED engine, and only if it passes its checksum and actually runs. NEVER a system rclone on PATH: it could
	// be any version with different crypt behavior, which could corrupt or misread a vault — so we fail closed
	// instead, and the caller's clear "run setup while online" message tells the user what to do.
	const fallback = async () => {
		if (cache === 'mismatch' || cache === 'unverifiable') {
			// A checksum is recorded and the binary either FAILED it (mismatch) or could not be hashed to compare
			// (unverifiable). Either way it is not verified, so it must NOT be run — fail closed until it can be
			// re-downloaded and verified.
			log(cache === 'mismatch'
				? 'The cached engine failed checksum verification and cannot be re-downloaded right now — it will not be used.'
				: 'The cached engine could not be checksum-verified right now and will not be used until it can be re-downloaded and verified.');
			return { rclone: null, ok: false };
		}
		// 'unrecorded' (a legacy install with no sidecar) or 'absent'. We only reach here when a fresh verified
		// download is NOT possible (offline / no release / no published checksum) — when it IS, ensure() re-downloaded
		// and verified above instead. Accept the bundled binary only if it exists and RUNS; and for a legacy
		// 'unrecorded' binary, record its hash now (trust-on-first-use) so later runs are checked against it. This is
		// the unavoidable offline case — online, 'unrecorded' is re-verified against the official release, never TOFU'd.
		if (await works(bin)) {
			if (cache === 'unrecorded') { try { await writeSidecar(await Net.sha256File(bin)); } catch (_) {} }
			_resolvedBin = bin; return { rclone: bin, ok: true };
		}
		return { rclone: null, ok: false };
	};

	let rel;
	try { rel = await resolveRelease(opts); }
	catch (e) {
		if (e && e.code === 'NO_ASSET') log('No engine build is published for this platform (' + process.platform + '/' + process.arch + ') — the release naming may have changed.');
		else log('Could not reach the engine release servers (offline?): ' + e.message);
		rel = null;
	}
	if (!rel) return await fallback();
	if (!rel.sha256) { log('Refusing to install the engine without a verifiable checksum.'); return await fallback(); }

	log('Setting up the bundled engine (' + rel.tag + ', one-time download, checksum-verified)…');
	// Download to a PER-PROCESS temp zip and extract into a PER-PROCESS temp folder, then lift the binary into place.
	// The background auto-installer and a concurrent operation that also calls ensureEngine() can now run at once, so
	// unique temp paths keep them from overwriting each other's download or extract; both produce the same verified
	// binary, and the final rename into data/bin is atomic (last writer wins, identical bytes).
	const stamp = process.pid + '-' + Date.now().toString(36);
	const zip = path.join(dir, '_rclone_download.' + stamp + '.zip');
	const exdir = path.join(dir, '_rclone_extract.' + stamp);
	const cleanup = async () => { try { await fsp.unlink(zip); } catch (_) {} try { await fsp.rm(exdir, { recursive: true, force: true }); } catch (_) {} };
	try {
		try { await Net.download(rel.primaryUrl, zip, { label: 'engine', expectedSha256: rel.sha256 }); }
		catch (e1) { log('Primary source failed (' + e1.message + '); trying the official GitHub source…'); await Net.download(rel.fallbackUrl, zip, { label: 'engine', expectedSha256: rel.sha256 }); }
		await Net.unzip(zip, exdir);
		await liftBinary(exdir);
		await cleanup();
		if (await works(bin)) {
			// Record the INSTALLED binary's own hash (not the zip's) so a later swap of
			// the cached file is detected. The zip's checksum already verified the
			// download above.
			try { await writeSidecar(await Net.sha256File(bin)); } catch (_) {}
			await writeTagSidecar(rel.tag); // record the installed tag so a later pin bump is detected and re-downloaded
			verifiedThisProcess = true; _ranOk = true;
			log('Bundled engine ready (checksum verified).');
			return { rclone: bin, ok: true };
		}
		log('Engine binary missing after extract.');
		return { rclone: null, ok: false };
	} catch (e) {
		await cleanup();
		log('Engine setup failed: ' + e.message);
		return { rclone: null, ok: false };
	}
}

// Resolve the bundled rclone path WITHOUT downloading — ALWAYS the bundled engine, NEVER a system rclone on PATH
// (see resolve() below for why). The result is memoized for the process so the recurring callers (the 12s health
// tick's autoLockTick, unmount drain, etc.) don't re-spawn a blocking `rclone version` probe every time — the
// engine binary does not change during a run. Only the PRESENT-file path is cached, so a call made before the
// engine is installed simply retries until the bundled binary exists.
let _resolvedBin = null;
// Passive integrity check for the boot watchdog: re-hash the installed engine binary and compare it to
// the checksum recorded when it was downloaded and verified against the official release. Purely
// read-only — never re-downloads, never rewrites the sidecar — so it is safe to run on any tick. Returns
// 'ok', 'mismatch' (the binary changed since it was verified — possibly swapped or tampered),
// 'unrecorded' (no recorded checksum to compare, e.g. a legacy install), or 'absent' (no binary yet).
// Hashing reads the file only (no spawn), and any error degrades to 'absent' rather than throwing.
async function integrityStatus() {
	// Reuse the one shared comparison so the watchdog and the run-time gate never disagree on authenticity. A
	// transient can't-hash ('unverifiable') reads as not-verified for the warn-only watchdog.
	const state = await checksumState();
	return state === 'unverifiable' ? 'absent' : state; // 'ok' | 'mismatch' | 'unrecorded' | 'absent'
}

// Passive readiness check for the status poll: is a verified, runnable engine ALREADY installed? It NEVER
// downloads and never runs a long op — only the cheap, bounded checks (checksum match + a 4s `version` probe) —
// so doctor() can report readiness instantly on a fresh install and let the caller trigger the (background)
// download, instead of blocking the poll on a tens-of-MB first-run install. Returns the same { rclone, ok } shape
// as ensure(). A binary that is present but not yet checksum-verified reads as not-ready (ensure() will verify it).
async function probe() {
	const bin = rclonePath();
	if ((await checksumState()) !== 'ok') return { rclone: null, ok: false };
	if (!(await works(bin))) return { rclone: null, ok: false };
	return { rclone: bin, ok: true };
}

function resolve() {
	if (_resolvedBin) return _resolvedBin;
	const bin = rclonePath();
	// Pure path getter — it must NEVER spawn (it is reached synchronously on teardown/tick paths where a spawned
	// probe could stall the event loop). It ALWAYS returns the bundled engine path, never a system `rclone` on
	// PATH: a system rclone could be any version with different crypt behavior or flags, so using it — even as a
	// fallback — could corrupt or misread a vault. If the bundled engine is not installed yet, a caller that spawns
	// this path fails cleanly with "not found" (and the caller's message points to `setup`), which is what we want.
	// The memo is set only once the file is present, so a call made before install upgrades on a later call.
	if (fs.existsSync(bin)) _resolvedBin = bin;
	return bin;
}

// The installed engine's version as "vX.Y.Z", or null when it can't be determined. A bounded, best-effort spawn used
// by the boot self-check to warn on drift from the tested pin; it must never throw or block, and it never runs a
// system binary (only the bundled one). Cached for the process — the binary does not change during a run.
let _versionCache;
async function installedVersion() {
	if (_versionCache !== undefined) return _versionCache;
	try {
		const r = await Common.runCmd(rclonePath(), ['version'], { timeout: 4000 });
		const m = r.ok ? /rclone\s+v?(\d+\.\d+\.\d+)/i.exec(String(r.stdout || '')) : null;
		_versionCache = m ? ('v' + m[1]) : null;
	} catch (_) { _versionCache = null; }
	return _versionCache;
}

module.exports = { ensure, probe, resolve, integrityStatus, installedVersion, PINNED_TAG, PINNED_SHA256, pinnedSha256, archiveSuffix, rcloneArch };
