'use strict';
// lib/test/apitoken.js — API bearer tokens (for headless / third-party access to the local API) are created, verified
// in constant time, listed without leaking the secret, and revoked. Pure and fast: it exercises the Vault helpers
// against the test data directory, with no engine, mount driver, or network.
//
// Run:  node lib/test/apitoken.js

const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// Start from a clean slate so the test is idempotent even when the data directory persists between local runs.
	for (const t of await Vault.listApiTokens()) await Vault.revokeApiToken(t.id);

	ok('a random string does not verify before any token exists', (await Vault.verifyApiToken('vdt_nope')) === false);

	const r = await Vault.createApiToken('CI runner');
	ok('a created token has an id and the given label', !!r.id && r.label === 'CI runner');
	ok('the token is returned in the clear once, with the vdt_ prefix', typeof r.token === 'string' && r.token.startsWith('vdt_'));
	ok('the created token verifies', (await Vault.verifyApiToken(r.token)) === true);
	ok('a wrong token does not verify', (await Vault.verifyApiToken('vdt_wrong')) === false);
	ok('a near-miss (extra char) does not verify', (await Vault.verifyApiToken(r.token + 'x')) === false);
	ok('an empty token does not verify', (await Vault.verifyApiToken('')) === false);

	const list = await Vault.listApiTokens();
	ok('the token appears in the list with its metadata', list.length === 1 && list[0].id === r.id && list[0].label === 'CI runner' && !!list[0].createdAt);
	ok('the list never leaks the hash or the token', !('hash' in list[0]) && !('token' in list[0]));

	const rev = await Vault.revokeApiToken(r.id);
	ok('revoking reports it was removed', rev.removed === true);
	ok('a revoked token no longer verifies', (await Vault.verifyApiToken(r.token)) === false);
	ok('revoking an unknown id reports nothing removed', (await Vault.revokeApiToken('deadbeef')).removed === false);

	// A second token is independent of the first (each is its own credential).
	const a = await Vault.createApiToken('a'), b = await Vault.createApiToken('b');
	ok('two tokens both verify independently', (await Vault.verifyApiToken(a.token)) && (await Vault.verifyApiToken(b.token)));
	await Vault.revokeApiToken(a.id);
	ok('revoking one leaves the other working', !(await Vault.verifyApiToken(a.token)) && (await Vault.verifyApiToken(b.token)));

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL API-TOKEN CHECKS PASSED');
}
main().catch((e) => { console.error(e); process.exit(1); });
