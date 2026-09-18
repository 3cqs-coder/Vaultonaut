'use strict';
// lib/test/engineairgap.js — proves the air-gap promise behaviorally: once a verified engine is cached, RcloneSetup
// .ensure() returns success WITHOUT touching the network. This is the property the container relies on (it bakes a
// checksum-verified engine into the image so a serving node never downloads on its first serve), and the property an
// egress-restricted or offline host relies on. A regression that made ensure() re-hit GitHub even with a good cached
// engine would silently break every air-gapped deployment; this catches it. Skips cleanly when no engine can be
// obtained (a runner with no driver or no network to prime the cache), matching the other engine-dependent tests.
//
// Run:  node -r ./lib/test/_setup.js lib/test/engineairgap.js

const RcloneSetup = require('../RcloneSetup');
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// Prime the cache: a real ensure() that installs (or reuses) the pinned engine and writes its checksum/tag
	// sidecars. If it cannot be obtained here (no network to prime, or the binary will not run on this runner), there
	// is nothing to prove about the cached path — skip, exactly as the mount tests do without a driver.
	const primed = await RcloneSetup.ensure().catch(() => ({ ok: false }));
	if (!primed.ok) { console.log('  skip  (no engine could be primed on this host; nothing to test air-gapped)'); process.exit(0); }

	// Forget the in-process "already verified" memo so the next ensure() must re-derive success from the ON-DISK cache,
	// which is exactly the path a fresh air-gapped process takes.
	RcloneSetup.invalidateVerification();

	// Trip-wire the network. Every Net entry point ensure() could use to reach out is replaced with a stub that records
	// the attempt and throws. If the cached-engine path is correct, NONE of these runs. Local-only helpers (sha256File,
	// unzip) stay real — hashing the cached binary and any local file work is not network.
	const NET_METHODS = ['download', 'getText', 'githubLatestAsset', 'githubAssetForTag'];
	const saved = {};
	let networkTouched = null;
	for (const m of NET_METHODS) {
		saved[m] = Net[m];
		Net[m] = (...a) => { networkTouched = m; throw new Error('air-gap violation: Net.' + m + ' was called'); };
	}

	let result = { ok: false };
	try {
		result = await RcloneSetup.ensure().catch((e) => ({ ok: false, err: e && e.message }));
	} finally {
		for (const m of NET_METHODS) Net[m] = saved[m]; // always restore so later tests keep a working Net
	}

	ok('a cached, verified engine makes ensure() succeed with no network access', result.ok === true && networkTouched === null);
	ok('no network entry point was reached on the cached-engine path', networkTouched === null);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-AIRGAP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
