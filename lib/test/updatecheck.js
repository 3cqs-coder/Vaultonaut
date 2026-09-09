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
// Model a real fetch Response closely enough for the bounded reader: a Headers-like `get`, a `text()` (which the
// reader uses when the body is not an async-iterable stream), and `json()` for good measure.
const jsonRes = (body, okFlag = true, status = 200) => {
	const text = typeof body === 'string' ? body : JSON.stringify(body);
	return { ok: okFlag, status, headers: { get: () => String(Buffer.byteLength(text, 'utf8')) }, text: async () => text, json: async () => body };
};

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

	// The response body is untrusted, so an oversized one (a hostile or misconfigured endpoint) is rejected before it
	// can exhaust memory — the check fails closed rather than reading gigabytes. Modeled with a Content-Length beyond
	// the cap; the reader rejects on the declared size without pulling the body.
	const huge = await withFetch(async () => ({ ok: true, status: 200, headers: { get: () => String(64 * 1024 * 1024) }, text: async () => '[]', json: async () => [] }), () => U.checkForUpdate());
	ok('an oversized response fails closed (ok:false), never read into memory', huge.ok === false && !!huge.error);

	const threw = await withFetch(async () => { throw Object.assign(new Error('boom'), { name: 'TypeError' }); }, () => U.checkForUpdate());
	ok('a fetch that throws is caught (ok:false), never propagates', threw.ok === false && !!threw.error);

	// A source that sends headers immediately but then DRIPS the body forever (staying under the size cap) must not
	// hang the check: the abort deadline covers the body read, not just the connect phase. The mock's body only settles
	// when the request is aborted, so this proves the deadline reaches the body. It resolves in about the timeout, not
	// forever; the outer race guards the test itself against a regression that would hang.
	const dripRes = (opts) => ({ ok: true, status: 200, headers: { get: () => null }, body: (async function* () { await new Promise((_, reject) => { const s = opts && opts.signal; if (s) s.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true }); }); })(), text: async () => new Promise((_, reject) => { const s = opts && opts.signal; if (s) s.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); }) });
	const t0 = Date.now();
	const drip = await Promise.race([
		withFetch(async (_u, opts) => dripRes(opts), () => U.checkForUpdate({ timeoutMs: 1000 })),
		new Promise((resolve) => setTimeout(() => resolve({ ok: 'HUNG' }), 6000)),
	]);
	ok('a slow-drip body is aborted by the deadline (never hangs)', drip.ok === false && (Date.now() - t0) < 5500);

	const aborted = await withFetch(async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); }, () => U.checkForUpdate({ timeoutMs: 1000 }));
	ok('a timeout/abort is reported as a timeout, not a crash', aborted.ok === false && /timed out/i.test(aborted.error));

	let sawUrl = null;
	await withFetch(async (url) => { sawUrl = url; return jsonRes([{ name: current }]); }, () => U.checkForUpdate({ url: 'https://example.test/tags' }));
	ok('a custom source URL is honored (not locked to one host)', sawUrl === 'https://example.test/tags');

	// A custom --url must be an http(s) web address: a non-web scheme (file:, data:, gopher:) is rejected before any
	// fetch, so it can never read a local file or reach a non-web endpoint. The fetch must not even be called.
	for (const bad of ['file:///etc/passwd', 'data:text/plain,[]', 'gopher://x', 'not a url']) {
		let called = false;
		const res = await withFetch(async () => { called = true; return jsonRes([]); }, () => U.checkForUpdate({ url: bad }));
		ok('a non-web update source is rejected before fetching (' + bad.slice(0, 12) + '…)', res.ok === false && !!res.error && called === false);
	}

	// --- security default: the AUTOMATIC check is OFF unless opted in, and gated on that setting in the web server ---
	const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the automatic update check is exposed as off-by-default (!!s.autoUpdateCheck)', /autoUpdateCheck:\s*!!s\.autoUpdateCheck/.test(serverSrc));
	ok('the automatic update tick only runs when the user opted in', /if \(s\.autoUpdateCheck &&/.test(serverSrc));
	ok('the automatic update check is throttled (not on every tick)', /AUTO_UPDATE_INTERVAL_MS/.test(serverSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UPDATE-CHECK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
