'use strict';
// lib/test/relaycode.js — the relay INVITE code (makeRelayCode / parseRelayCode) bundles a hub address and token
// into one paste and round-trips exactly, and rejects malformed or foreign input. Pure and fast: no engine, mount
// driver, or network — so it runs on every platform. The code is a small base64 JSON, mirroring the peer connect
// code, so it is cross-platform (Node Buffer) and cross-browser (atob + TextDecoder) by construction.
//
// Run:  node lib/test/relaycode.js

const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	// --- round-trip: what the hub encodes is exactly what a node decodes ---
	const code = Vault.makeRelayCode({ host: 'hub.example.com:7443', token: 'abcdef0123456789abcd' });
	const rc = Vault.parseRelayCode(code);
	ok('a relay code decodes back to the same host and token', rc && rc.host === 'hub.example.com:7443' && rc.token === 'abcdef0123456789abcd');
	ok('the code is plain base64 (paste-safe, no newlines or spaces)', /^[A-Za-z0-9+/=]+$/.test(code));

	// --- the browser decode path (atob + TextDecoder) yields the same object, so the web UI and the CLI agree ---
	const bytes = Uint8Array.from(Buffer.from(code, 'base64')); // atob(code) equivalent
	const viaBrowser = JSON.parse(new TextDecoder().decode(bytes));
	ok('the browser-style decode matches (t/host/token)', viaBrowser.t === 'relay' && viaBrowser.host === 'hub.example.com:7443' && viaBrowser.token === 'abcdef0123456789abcd');

	// --- the web "Run a relay" panel builds the SAME code in the browser (base64 of UTF-8 JSON); a node must accept it ---
	const browserJson = JSON.stringify({ v: 1, t: 'relay', host: 'h.example.com:7443', token: 'tok0123456789abcdef0' });
	const browserCode = Buffer.from(browserJson, 'utf8').toString('base64'); // equals btoa(unescape(encodeURIComponent(json))) for this ASCII payload
	const fromBrowser = Vault.parseRelayCode(browserCode);
	ok('a browser-built invite code is accepted by parseRelayCode', fromBrowser && fromBrowser.host === 'h.example.com:7443' && fromBrowser.token === 'tok0123456789abcdef0');

	// --- fails closed on bad or foreign input (returns null, never throws) ---
	ok('garbage is rejected', Vault.parseRelayCode('not a code') === null);
	ok('empty is rejected', Vault.parseRelayCode('') === null);
	ok('a peer connect code (different type) is rejected', Vault.parseRelayCode(Vault.makePeerCode({ url: 'https://x', user: 'u', pass: 'p' })) === null);
	ok('a code missing the token is rejected', Vault.parseRelayCode(Buffer.from(JSON.stringify({ v: 1, t: 'relay', host: 'h:1' })).toString('base64')) === null);
	ok('a code missing the host is rejected', Vault.parseRelayCode(Buffer.from(JSON.stringify({ v: 1, t: 'relay', token: 't' })).toString('base64')) === null);
	ok('an over-long string is rejected before decoding', Vault.parseRelayCode('A'.repeat(9000)) === null);

	// --- FORWARD COMPATIBILITY: a paste made by a NEWER build must still be read by this one. The parsers read known
	//     fields by explicit key and ignore the rest, so a bumped version and extra keys are tolerated (additive-only,
	//     matching the standing backward-compatibility rule for the paste formats). This pins that so a future field can
	//     never be added in a way that makes an existing build reject the whole code. ---
	const futureRelay = Buffer.from(JSON.stringify({ v: 2, t: 'relay', host: 'hub.example.com:7443', token: 'abcdef0123456789abcd', region: 'eu', ttl: 3600 })).toString('base64');
	const rcFuture = Vault.parseRelayCode(futureRelay);
	ok('a newer relay code (bumped version + unknown fields) still decodes its host and token', rcFuture && rcFuture.host === 'hub.example.com:7443' && rcFuture.token === 'abcdef0123456789abcd');

	const futurePeer = Buffer.from(JSON.stringify({ v: 2, url: 'https://x.example:7443', user: 'u', pass: 'p', hint: 'lan-first', note: 'ignored' })).toString('base64');
	const pcFuture = Vault.parsePeerCode(futurePeer);
	ok('a newer peer connect code (bumped version + unknown fields) still decodes its url and login', pcFuture && pcFuture.url === 'https://x.example:7443' && pcFuture.user === 'u' && pcFuture.password === 'p');

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL RELAY-CODE CHECKS PASSED');
}
main();
