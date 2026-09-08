'use strict';
// lib/test/webauthn.js — the shared browser WebAuthn helper (public/js/webauthn.js), which the login page and the
// app both load. Its base64url codec is on the credential path for BOTH passwordless sign-in and device unlock, so
// a silent regression here would break login and unlock at once with no other test catching it. This loads the
// browser file in a minimal fake-window and pins the codec's round-trip, its URL-safe/no-padding output (it must
// match the server's base64url), and that the assertion helper stays present.
//
// Run:  node lib/test/webauthn.js  (no engine, no network)

const path = require('path');
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Minimal browser globals the file's IIFE touches at load time (btoa/atob + a window to attach to). crypto/navigator
// are only reached INSIDE derivePrfSecret, which this test does not call, so they are not needed to load or to test
// the codec.
global.window = {};
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.atob = (s) => Buffer.from(s, 'base64').toString('binary');

require(path.join('..', 'webserver', 'public', 'js', 'webauthn.js'));
const W = global.window.WebAuthnUtil;

ok('webauthn.js exposes WebAuthnUtil with the expected shape', !!W && typeof W.b64uEncode === 'function' && typeof W.b64uDecode === 'function' && typeof W.derivePrfSecret === 'function');

// Round-trip a spread of byte patterns, including the values that exercise the URL-safe substitutions (0xFB->'-',
// 0xFF/0xC0 groups -> '_') and every remainder length (padding cases).
const cases = [[], [0], [255], [0, 1, 2, 3], [250, 251, 252, 253, 254, 255], [1], [1, 2], [1, 2, 3], [1, 2, 3, 4]];
let allRoundTrip = true, allUrlSafe = true, matchesServer = true;
for (const arr of cases) {
	const bytes = new Uint8Array(arr);
	const enc = W.b64uEncode(bytes);
	if (/[+/=]/.test(enc)) allUrlSafe = false; // URL-safe alphabet, no '=' padding
	const dec = W.b64uDecode(enc);
	if (Buffer.compare(Buffer.from(dec), Buffer.from(bytes)) !== 0) allRoundTrip = false;
	// The server reads/writes these as Node base64url; the browser codec must agree exactly or credentials mismatch.
	if (enc !== Buffer.from(bytes).toString('base64url')) matchesServer = false;
}
ok('b64uEncode/b64uDecode round-trips every byte pattern', allRoundTrip);
ok('b64uEncode output is URL-safe with no padding', allUrlSafe);
ok('the browser codec matches Node base64url exactly (server/client agree)', matchesServer);

// A value with all three special bytes, checked against a known-good base64url, guards the alphabet mapping itself.
ok('a known vector encodes to the expected base64url', W.b64uEncode(new Uint8Array([251, 255, 192])) === Buffer.from([251, 255, 192]).toString('base64url'));
// Decoding is tolerant of input that arrives without padding (the wire form).
ok('b64uDecode accepts unpadded input', Buffer.from(W.b64uDecode('AAEC')).equals(Buffer.from([0, 1, 2])));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WEBAUTHN CHECKS PASSED'));
process.exit(failures ? 1 : 0);
