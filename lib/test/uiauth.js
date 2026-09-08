'use strict';
// lib/test/uiauth.js — the optional web-interface login. Covers the stateless auth crypto (password
// hashing, the signed session token, and the cookie flags), the persistence round-trip, and the
// guard that refuses to expose the interface over the network without a password. The full HTTP
// login flow (form -> cookie -> authorized request) is exercised by hand against a running instance;
// this locks in the logic that must never regress.
//
// Run:  node lib/test/uiauth.js

const UiAuth = require('../UiAuth');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	console.log('[password hashing]');
	const stored = await UiAuth.hashPassword('correct horse battery');
	ok('the right password verifies', (await UiAuth.verifyPassword('correct horse battery', stored)) === true);
	ok('a wrong password is rejected', (await UiAuth.verifyPassword('wrong horse', stored)) === false);
	ok('an empty password is rejected', (await UiAuth.verifyPassword('', stored)) === false);
	ok('a missing verifier is rejected, not thrown', (await UiAuth.verifyPassword('x', null)) === false);
	ok('two hashes of the same password differ (random salt)', (await UiAuth.hashPassword('same')).verifier !== stored.verifier);

	console.log('[signed session token]');
	const secret = UiAuth.newSecret();
	const token = UiAuth.signSession(secret, 3600);
	ok('a freshly signed token verifies', !!UiAuth.verifySession(token, secret));
	ok('a token signed with another secret is rejected', UiAuth.verifySession(token, UiAuth.newSecret()) === null);
	ok('a tampered token is rejected', UiAuth.verifySession(token.slice(0, -2) + (token.endsWith('a') ? 'b' : 'a'), secret) === null);
	ok('an expired token is rejected', UiAuth.verifySession(UiAuth.signSession(secret, -1), secret) === null);
	ok('garbage is rejected, not thrown', UiAuth.verifySession('not.a.token', secret) === null);

	console.log('[cookie flags]');
	const insecure = UiAuth.setCookieHeader('T', { secure: false });
	const withTls = UiAuth.setCookieHeader('T', { secure: true });
	ok('the cookie is HttpOnly and SameSite=Strict', /HttpOnly/.test(insecure) && /SameSite=Strict/.test(insecure));
	ok('the Secure flag is set only under TLS', !/Secure/.test(insecure) && /Secure/.test(withTls));
	ok('cookies parse back out', UiAuth.parseCookies('a=1; vd_session=' + encodeURIComponent(token))[UiAuth.COOKIE_NAME] === token);
	// A malformed percent-escape must NOT throw (which would surface as a 500 instead of "unauthenticated"): the
	// bad pair is skipped and the good one still parses, so a broken/hostile Cookie header can't crash requests.
	let cookieThrew = false; let parsed = null;
	try { parsed = UiAuth.parseCookies('bad=%zz; good=1'); } catch (_) { cookieThrew = true; }
	ok('a malformed cookie value does not throw and the valid pair still parses', !cookieThrew && parsed && parsed.good === '1');

	console.log('[persistence round-trip]');
	const before = (await Vault.getSettings()).ui;
	if (before) {
		console.log('  (a web-interface password is already set — skipping the round-trip so it is not disturbed)');
	} else {
		await Vault.setUiPassword('a-strong-passphrase');
		const a = await Vault.getUiAuth();
		ok('after setting, a login is enabled and the verifier is stored', a.enabled === true && !!a.password && !!a.secret);
		ok('the stored password verifies through the KDF', (await UiAuth.verifyPassword('a-strong-passphrase', a.password)) === true);
		const rotated = (await Vault.setUiPassword('a-different-passphrase')) && (await Vault.getUiAuth());
		ok('changing the password rotates the signing secret (logs out old sessions)', rotated.secret !== a.secret);
		await Vault.clearUiPassword();
		ok('after clearing, no login is required', (await Vault.getUiAuth()).enabled === false);
	}
	ok('a too-short password is refused', await refused(() => Vault.setUiPassword('short')));
	// Restore a clean slate regardless of the branch above (only if we created one).
	if (!before) { try { await Vault.clearUiPassword(); } catch (_) {} }

	console.log('[refuse to expose without a password]');
	const orig = Vault.getUiAuth;
	Vault.getUiAuth = async () => ({ enabled: false, password: null, secret: null });
	try {
		const { start } = require('../webserver');
		ok('binding to a network address without a password throws (fails fast, no side effects)', await refused(() => start(0, { bind: '0.0.0.0' })));
		// A DNS name that merely starts with "127." must NOT be mistaken for loopback (it would skip the
		// mandatory password + TLS). Treated as exposed -> refused without a password.
		ok('a "127.example.com" bind is treated as exposed, not loopback', await refused(() => start(0, { bind: '127.example.com' })));
		// An access list whose every rule is invalid must FAIL CLOSED on an exposed bind: refuse to start, never
		// silently collapse to allow-all. (This check runs before the password/cert checks, so it fires here.)
		let allowErr = null; try { await start(0, { bind: '0.0.0.0', allowIp: 'not-an-ip, also-bad' }); } catch (e) { allowErr = e.message || ''; }
		ok('an exposed interface with only invalid --allow-ip rules refuses to start (fails closed)', /allow-ip/i.test(allowErr || ''));
	} finally { Vault.getUiAuth = orig; }

	console.log('[passwordless sign-in credentials — in an isolated data dir]');
	{
		const os = require('os'), path = require('path'), fs = require('fs');
		const Common = require('../Common');
		const savedDataDir = Common.dataDir, savedStatePath = Common.statePath;
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-uiwa-'));
		Common.dataDir = () => tmp; Common.statePath = () => path.join(tmp, 'state.json');
		try {
			// Enrolling a key needs a password first (it is an added method, never a replacement).
			ok('a sign-in key cannot be enrolled before a password is set', await refused(() => Vault.addUiWebauthn({ secret: 's', credentialId: 'c', prfSalt: 'p', password: 'x' })));
			await Vault.setUiPassword('a-strong-passphrase');
			// SECURITY: enrolling a passwordless method requires the CURRENT password, so a session alone (e.g. a
			// hijacked one) cannot plant a lasting backdoor credential.
			ok('enrolling a sign-in key is refused without the current password', await refused(() => Vault.addUiWebauthn({ secret: 'derived-secret', credentialId: 'cred-1', prfSalt: 'salt-1', password: 'wrong-password' })));
			ok('nothing was enrolled by the refused attempt', (await Vault.getUiAuth()).webauthn.length === 0);
			await Vault.addUiWebauthn({ secret: 'derived-secret', credentialId: 'cred-1', prfSalt: 'salt-1', label: 'Touch ID · 2026', password: 'a-strong-passphrase' });
			ok('an enrolled key verifies with its derived secret', (await Vault.verifyUiWebauthn('derived-secret')) === true);
			ok('a wrong secret is rejected', (await Vault.verifyUiWebauthn('nope')) === false);
			ok('an empty secret never matches', (await Vault.verifyUiWebauthn('')) === false);
			// SECURITY: changing the web password (the lock-out-everyone action) revokes enrolled keys.
			await Vault.setUiPassword('a-different-passphrase');
			ok('changing the web password revokes every enrolled sign-in key', (await Vault.verifyUiWebauthn('derived-secret')) === false && (await Vault.getUiAuth()).webauthn.length === 0);
			// The login-page descriptors carry no label (no info leak); the authenticated list does.
			await Vault.addUiWebauthn({ secret: 'x', credentialId: 'c2', prfSalt: 'p2', label: 'My Key', password: 'a-different-passphrase' });
			const auth = await Vault.getUiAuth();
			ok('login-page descriptors omit the label', Vault.uiWebauthnDescriptors(auth).every(d => d.label === undefined && d.id && d.prfSalt));
			ok('the authenticated management list keeps the label', Vault.listUiWebauthn(auth).some(d => d.label === 'My Key'));
			// Clearing the password drops the keys too, so a later password can never revive them.
			await Vault.clearUiPassword();
			ok('clearing the password removes enrolled keys', (await Vault.getUiAuth()).webauthn.length === 0);
		} finally { Common.dataDir = savedDataDir; Common.statePath = savedStatePath; try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} }
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WEB-LOGIN CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function refused(fn) { try { await fn(); return false; } catch (_) { return true; } }

main().catch(e => { console.error(e); process.exitCode = 1; });
