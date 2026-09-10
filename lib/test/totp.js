'use strict';
// lib/test/totp.js — the on-device 2FA generator in the shared schema (secret-schema.js): base32 decoding, otpauth
// URI parsing, and RFC 6238 TOTP code derivation. This is what shows a user their live 2FA code, so a silent
// regression here would hand out WRONG codes and lock people out of their accounts — it must be pinned to the
// standard's known-answer vectors. The module is browser code (a UMD that attaches to the global); we point it at
// the Node global so it uses Node's built-in Web Crypto (crypto.subtle) for the HMAC, exactly as a browser would.
//
// Run:  node lib/test/totp.js

global.self = globalThis; // make the UMD attach VaultSecret to the global, and use globalThis.crypto.subtle
require('../webserver/public/shared/secret-schema.js');
const VS = globalThis.VaultSecret;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	ok('the shared schema exposes the TOTP API', VS && typeof VS.totpCode === 'function' && typeof VS.parseTotp === 'function');

	// base32 decodes the RFC 4648 test secret to its ASCII bytes.
	const dec = Buffer.from(VS.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'));
	ok('base32Decode matches the known RFC seed "12345678901234567890"', dec.toString('utf8') === '12345678901234567890');

	// RFC 6238 known-answer vectors (SHA-1, 6 digits, 30s period) — the 6-digit truncation of the published 8-digit codes.
	const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
	const cfg = { secret, algorithm: 'SHA1', digits: 6, period: 30 };
	const vectors = [[59, '287082'], [1111111109, '081804'], [1234567890, '005924'], [2000000000, '279037']];
	let allMatch = true, secs = null;
	for (const [t, expected] of vectors) {
		const r = await VS.totpCode(cfg, t * 1000);
		if (r.code !== expected) { allMatch = false; console.log('     (t=' + t + ' got ' + r.code + ' expected ' + expected + ')'); }
		if (t === 59) secs = r.secondsRemaining;
	}
	ok('totpCode reproduces the RFC 6238 SHA-1/6-digit known-answer vectors', allMatch);
	ok('totpCode reports the seconds remaining in the window', secs === 30 - (59 % 30));

	// An otpauth:// URI parses out the secret and the digits/period/algorithm/issuer.
	const p = VS.parseTotp('otpauth://totp/ACME:jo@acme.com?secret=' + secret + '&issuer=ACME&algorithm=SHA1&digits=8&period=60');
	ok('parseTotp reads secret, digits, period, algorithm, and issuer from a URI', p.secret === secret && p.digits === 8 && p.period === 60 && p.algorithm === 'SHA1' && p.issuer === 'ACME');
	// A bare base32 secret parses to defaults (6 digits / 30s / SHA1).
	const b = VS.parseTotp(secret);
	ok('a bare base32 secret parses to the standard defaults', b.secret === secret && b.digits === 6 && b.period === 30 && b.algorithm === 'SHA1');
	// An 8-digit config yields the full published vector.
	ok('an 8-digit config yields the full published vector at t=59', (await VS.totpCode({ secret, algorithm: 'SHA1', digits: 8, period: 30 }, 59000)).code === '94287082');
	// An empty/garbage secret rejects rather than emitting a bogus code.
	let rejected = false; try { await VS.totpCode(VS.parseTotp(''), 59000); } catch (_) { rejected = true; }
	ok('an empty secret rejects instead of producing a fake code', rejected);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TOTP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
