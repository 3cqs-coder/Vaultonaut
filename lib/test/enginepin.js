'use strict';
// lib/test/enginepin.js — the pinned encryption-engine version is tied to a tested release: its per-platform archive
// checksum is COMMITTED in code (not fetched at install time), so a download is verified against the value shipped
// and tested with this build. This locks that table down and, crucially, proves it is CROSS-PLATFORM: every
// platform/architecture the tool will try to install for (macOS, Linux, Windows across the architectures rclone
// publishes) has a well-formed committed checksum, so no supported platform silently falls back to an unpinned,
// metadata-fetched checksum. A checksum that is malformed, or missing for a supported platform, fails here.
//
// Run:  node lib/test/enginepin.js   (no engine, no network)

const Rc = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const isSha256 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s); // lowercase 64-hex, the form the verifier compares

// Every platform/architecture the installer supports, and whether rclone publishes a build for it. The ones marked
// published MUST have a committed checksum; the unpublished ones correctly have no build (archiveSuffix → null).
const MATRIX = [
	['darwin', 'arm64', true], ['darwin', 'x64', true],
	['linux', 'x64', true], ['linux', 'arm64', true], ['linux', 'arm', true],
	['win32', 'x64', true], ['win32', 'arm64', true], ['win32', 'ia32', true],
];

async function main() {
	// Every committed entry is a well-formed lowercase SHA-256 (a malformed value would reject every download).
	let allHex = true;
	for (const [suffix, sum] of Object.entries(Rc.PINNED_SHA256)) { if (!isSha256(sum)) { ok('PINNED_SHA256["' + suffix + '"] is a valid 64-hex checksum', false); allHex = false; } }
	if (allHex) ok('every committed checksum is a valid lowercase 64-hex SHA-256', true);

	// No two platforms accidentally share a checksum (a copy-paste slip would make one platform verify another's zip).
	const vals = Object.values(Rc.PINNED_SHA256);
	ok('committed checksums are all distinct (no copy-paste slip)', new Set(vals).size === vals.length);

	// CROSS-PLATFORM COVERAGE: every supported platform/arch resolves to an archive suffix AND has a committed
	// checksum, so macOS, Linux, and Windows are all pinned — none quietly falls back to a fetched checksum.
	for (const [platform, arch, published] of MATRIX) {
		const suffix = Rc.archiveSuffix(platform, arch);
		if (published) {
			ok(platform + '/' + arch + ' maps to an archive suffix', !!suffix);
			ok(platform + '/' + arch + ' has a committed pinned checksum', isSha256(Rc.pinnedSha256(platform, arch)));
		}
	}

	// An unsupported architecture has no build and no pinned checksum (the caller shows a clear "no build" message).
	ok('an unsupported architecture resolves to no suffix', Rc.archiveSuffix('linux', 'mips') === null);
	ok('an unsupported architecture has no pinned checksum', Rc.pinnedSha256('linux', 'mips') === null);

	// Every committed suffix is one archiveSuffix can actually produce (a stray/typo key would never be consulted).
	const producible = new Set();
	for (const [platform, arch] of MATRIX) { const s = Rc.archiveSuffix(platform, arch); if (s) producible.add(s); }
	for (const suffix of Object.keys(Rc.PINNED_SHA256)) ok('committed suffix "' + suffix + '" is one the installer can produce', producible.has(suffix));

	// --- Engine-trust robustness pins (behaviorally hard to force without a real download + a locked/swapped binary,
	//     so pin the mechanisms statically). ---
	const fs = require('fs'); const path = require('path');
	const setupSrc = fs.readFileSync(path.join(__dirname, '..', 'RcloneSetup.js'), 'utf8');
	// (a) The once-per-process verification memo can be cleared, so the periodic self-check's "re-verified on the next
	//     mount" remediation actually happens in a long-running process instead of only after a restart.
	ok('RcloneSetup exposes invalidateVerification() to reset the verification memo', typeof Rc.invalidateVerification === 'function');
	// (b) liftBinary confirms the NEW binary actually landed by hashing the destination — not just existsSync, which on
	//     Windows stays true when a locked engine leaves the OLD binary behind and the update is silently lost.
	ok('liftBinary hash-verifies the destination against the extracted binary', /wantHash = await Net\.sha256File\(src\)/.test(setupSrc) && /await Net\.sha256File\(dst\)\)\s*===\s*wantHash/.test(setupSrc));
	// (c) ensure() must NOT record the new tag/hash when the lift fails (that would falsely mark the update done and
	//     stop future retries) — it keeps the existing verified engine and reports the in-use reason.
	ok('ensure() falls back instead of recording success on a failed lift', /const lifted = await liftBinary/.test(setupSrc) && /if \(lifted && await works\(bin\)\)/.test(setupSrc) && /if \(!lifted\)/.test(setupSrc));
	// (d) The self-check clears the memo on a detected mismatch, so its remediation is real.
	const scSrc = fs.readFileSync(path.join(__dirname, '..', 'SelfCheck.js'), 'utf8');
	ok('the engine_integrity self-check invalidates the verification memo on a mismatch', /Setup\.invalidateVerification\(\)/.test(scSrc));

	// A pinned install must resolve the download WITHOUT calling the GitHub releases API: that API rate-limits
	// unauthenticated callers and returns HTTP 403 from shared CI runner IPs, which broke a fresh install (and the
	// smoke test) there. Stub the API callers to throw, then confirm a pinned resolve still succeeds via the
	// rclone.org mirror + the committed checksum, with a direct GitHub asset URL (not the API) as the fallback.
	const Net = require('../Net');
	const origTag = Net.githubAssetForTag, origLatest = Net.githubLatestAsset;
	Net.githubAssetForTag = async () => { throw new Error('the GitHub API must not be called for a pinned install'); };
	Net.githubLatestAsset = async () => { throw new Error('the GitHub API must not be called for a pinned install'); };
	try {
		const rel = await Rc._resolveRelease({});
		ok('a pinned install resolves without calling the GitHub API', !!rel && rel.tag === Rc.PINNED_TAG);
		ok('the pinned download uses the rclone.org mirror and the committed checksum', /^https:\/\/downloads\.rclone\.org\//.test(rel.primaryUrl) && rel.sha256 === Rc.pinnedSha256());
		ok('the pinned fallback is a direct GitHub asset URL, not the rate-limited API', /^https:\/\/github\.com\/rclone\/rclone\/releases\/download\//.test(rel.fallbackUrl) && !/api\.github\.com/.test(rel.fallbackUrl));
	} catch (e) { ok('a pinned resolve does not need the GitHub API (it threw: ' + (e && e.message) + ')', false); }
	finally { Net.githubAssetForTag = origTag; Net.githubLatestAsset = origLatest; }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-PIN CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
