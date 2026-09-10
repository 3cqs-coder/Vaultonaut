'use strict';
// lib/test/pwnedcheck.js — the privacy-preserving breach lookup (lib/PwnedCheck.js). Proves k-anonymity (only the
// 5-hex SHA-1 prefix is ever sent), correct suffix matching, that padded count-0 rows are ignored (no false hit),
// that a network failure yields 0 rather than throwing, and that the per-prefix cache collapses repeat requests.
// No real network: global.fetch is stubbed to serve a canned range response and to record what prefix was asked for.
//
// Run:  node lib/test/pwnedcheck.js

const crypto = require('crypto');
const PwnedCheck = require('../PwnedCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const sha1 = (s) => crypto.createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();

async function main() {
	const PW = 'P@ssw0rd';                       // a known-breached example
	const CLEAN = 'a-long-unique-passphrase-that-is-not-in-any-list-9f3a2b';
	const hBad = sha1(PW), prefixBad = hBad.slice(0, 5), sufBad = hBad.slice(5);
	const hClean = sha1(CLEAN), prefixClean = hClean.slice(0, 5), sufClean = hClean.slice(5);

	const asked = [];
	let sawPadding = false;
	// Stub fetch: record the requested URL + whether Add-Padding was set, and serve a body for the bad prefix that
	// contains the real suffix (count 87310) plus a PADDING row carrying count 0 that must be ignored.
	global.fetch = async (url, opts) => {
		asked.push(url);
		if (opts && opts.headers && String(opts.headers['Add-Padding']).toLowerCase() === 'true') sawPadding = true;
		const prefix = url.split('/').pop();
		let lines;
		if (prefix === prefixBad) lines = [sufBad + ':87310', '0000000000000000000000000000000000A:0']; // real hit + a count-0 pad
		else lines = ['1111111111111111111111111111111111B:0', '2222222222222222222222222222222222C:0']; // only padding
		return { ok: true, status: 200, headers: { get: () => null }, async text() { return lines.join('\r\n'); } };
	};

	const cache = new Map();
	ok('a known-breached password is reported with its count', (await PwnedCheck.count(PW, { cache })) === 87310);
	ok('the request sent ONLY the 5-hex prefix (k-anonymity), never the password or full hash', asked.length === 1 && asked[0].endsWith('/' + prefixBad) && !asked[0].includes(sufBad) && !asked[0].includes(PW));
	ok('the request set Add-Padding so the response size leaks nothing', sawPadding);

	ok('a password absent from the list returns 0', (await PwnedCheck.count(CLEAN, { cache })) === 0);
	ok('the clean lookup used its own prefix', asked[asked.length - 1].endsWith('/' + prefixClean) && prefixClean.length === 5);

	// A count-0 padded row must never be treated as a hit. Force a password whose suffix equals a padded row's suffix.
	global.fetch = async () => ({ ok: true, status: 200, headers: { get: () => null }, async text() { return sufClean + ':0'; } });
	ok('a padded (count 0) row is not a false breach hit', (await PwnedCheck.count(CLEAN, {})) === 0);

	// The per-prefix cache means repeat lookups of the same prefix cost no extra request.
	asked.length = 0;
	global.fetch = async (url) => { asked.push(url); return { ok: true, status: 200, headers: { get: () => null }, async text() { return sufBad + ':5'; } }; };
	const c2 = new Map();
	await PwnedCheck.count(PW, { cache: c2 }); await PwnedCheck.count(PW, { cache: c2 });
	ok('the per-prefix cache collapses repeat requests to one', asked.length === 1);

	// A network error yields 0 (best-effort), never a throw that could wedge a health scan.
	global.fetch = async () => { throw new Error('offline'); };
	let threw = false, val = null;
	try { val = await PwnedCheck.count(PW, {}); } catch (_) { threw = true; }
	ok('a network failure yields 0 rather than throwing', !threw && val === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PWNED-CHECK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
