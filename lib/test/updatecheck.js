'use strict';
// lib/test/updatecheck.js — the optional "is there a newer version?" check (lib/UpdateCheck.js). It must compare
// versions NUMERICALLY (so 1.9 < 1.10), pick the highest published tag regardless of the host's ordering, never
// download anything, and NEVER throw — a slow, unreachable, or malformed source resolves to { ok:false } so no
// caller is broken. It also confirms the security-relevant default: the automatic check is OFF unless the user turns
// it on, and it is gated in the web server on that opt-in setting. The network call is exercised with a stubbed
// global fetch, so the test is offline and deterministic.
//
// Run:  node lib/test/updatecheck.js

const fs = require('fs');
const path = require('path');
const U = require('../UpdateCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Swap in a fake fetch for one call, then restore. `impl` receives (url, opts).
async function withFetch(impl, fn) {
	const real = global.fetch;
	global.fetch = impl;
	try { return await fn(); } finally { global.fetch = real; }
}
const jsonRes = (body, okFlag = true, status = 200) => ({ ok: okFlag, status, json: async () => body });

async function main() {
	// --- pure version logic ---
	ok('compareVersions is numeric (1.9 < 1.10)', U.compareVersions('1.9', '1.10') === -1 && U.compareVersions('1.10', '1.9') === 1);
	ok('compareVersions treats equal versions as equal (1.9 == 1.9.0)', U.compareVersions('1.9', '1.9.0') === 0);
	ok('compareVersions ignores a leading v and a pre-release suffix', U.compareVersions('v2.0.0', '2.0.0-rc1') === 0 && U.compareVersions('v2.0.1', '2.0.0') === 1);
	ok('latestTag picks the highest version, ignoring a non-version tag', U.latestTag([{ name: 'v1.2.0' }, { name: 'nightly' }, { name: '1.10.0' }, { name: 'v1.9.9' }]) === '1.10.0');
	ok('latestTag returns null for no usable tags', U.latestTag([]) === null && U.latestTag([{ name: '' }, {}]) === null);
	ok('isAhead detects a local build newer than the latest release', U.isAhead('2.0.0', '1.9.0') === true && U.isAhead('1.0.0', '1.9.0') === false);

	// --- checkForUpdate against a stubbed source ---
	const current = require('../ReleaseIntegrity').appVersion() || '0.0.0';
	const higher = (U.parseVersion(current)[0] || 0) + 1 + '.0.0';
	const up = await withFetch(async () => jsonRes([{ name: higher }, { name: current }]), () => U.checkForUpdate());
	ok('an update is reported when the source has a higher version', up.ok === true && up.updateAvailable === true && up.latest === higher);
	ok('the result carries the current version and a releases link, and downloads nothing', up.current === current && /releases$/.test(up.releasesUrl));

	const same = await withFetch(async () => jsonRes([{ name: current }]), () => U.checkForUpdate());
	ok('no update is reported when the source matches the current version', same.ok === true && same.updateAvailable === false);

	const notArray = await withFetch(async () => jsonRes({ message: 'rate limited' }), () => U.checkForUpdate());
	ok('a non-list response fails closed (ok:false), never throws', notArray.ok === false && !!notArray.error);

	const httpErr = await withFetch(async () => jsonRes([], false, 503), () => U.checkForUpdate());
	ok('an HTTP error fails closed', httpErr.ok === false && !!httpErr.error);

	const threw = await withFetch(async () => { throw Object.assign(new Error('boom'), { name: 'TypeError' }); }, () => U.checkForUpdate());
	ok('a fetch that throws is caught (ok:false), never propagates', threw.ok === false && !!threw.error);

	const aborted = await withFetch(async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); }, () => U.checkForUpdate({ timeoutMs: 1000 }));
	ok('a timeout/abort is reported as a timeout, not a crash', aborted.ok === false && /timed out/i.test(aborted.error));

	let sawUrl = null;
	await withFetch(async (url) => { sawUrl = url; return jsonRes([{ name: current }]); }, () => U.checkForUpdate({ url: 'https://example.test/tags' }));
	ok('a custom source URL is honored (not locked to one host)', sawUrl === 'https://example.test/tags');

	// --- security default: the AUTOMATIC check is OFF unless opted in, and gated on that setting in the web server ---
	const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the automatic update check is exposed as off-by-default (!!s.autoUpdateCheck)', /autoUpdateCheck:\s*!!s\.autoUpdateCheck/.test(serverSrc));
	ok('the automatic update tick only runs when the user opted in', /if \(s\.autoUpdateCheck &&/.test(serverSrc));
	ok('the automatic update check is throttled (not on every tick)', /AUTO_UPDATE_INTERVAL_MS/.test(serverSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UPDATE-CHECK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
