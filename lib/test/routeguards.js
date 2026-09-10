'use strict';
// lib/test/routeguards.js — pins input-hardening and network-exposure guards on the web routes so they cannot
// silently regress:
//   • Reading host files INTO a vault, or writing a rebuilt/unpacked vault OUT to a host folder, names a path on
//     this computer's disk. Like reveal and start-at-login, those are loopback-only — a network caller must never
//     make this machine read from or write to an arbitrary path (an arbitrary-file-read / drop-file lever). The
//     four routes that do this must refuse on an exposed bind. (Static guard: an exposed-bind end-to-end test needs
//     TLS + a login and would be flaky; a source guard is the right, cheap level, matching the other drift tests.)
//   • An explicit mount cache mode is validated against the engine's allowlist, not forwarded blindly.
//   • A non-numeric emergency grace period falls back to the default instead of persisting NaN.
//
// Run:  node lib/test/routeguards.js

const fs = require('fs');
const path = require('path');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const read = (p) => fs.readFileSync(p, 'utf8');

async function main() {
	// 1. The host-filesystem routes refuse on an exposed bind, via the shared helper.
	const server = read(path.join(__dirname, '..', 'webserver', 'index.js'));
	ok('the server defines refuseHostFsIfExposed', /const refuseHostFsIfExposed\s*=/.test(server));
	// For each route, isolate its handler body and assert it calls the guard.
	const bodyOf = (route, span = 400) => { const at = server.indexOf("'" + route + "'"); return at >= 0 ? server.slice(at, at + span) : ''; };
	for (const route of ['/api/import', '/api/import-files', '/api/reconstruct', '/api/unpack', '/api/shards-inspect', '/api/shards-repair', '/api/verify-backup', '/api/disperse']) {
		ok('route ' + route + ' refuses host-filesystem access on an exposed bind', /refuseHostFsIfExposed\(/.test(bodyOf(route)));
	}
	// 1b. Copying/serving a vault's ciphertext (and its wrapped key slots) off-machine, or listing its snapshots,
	// must require a credential that opens the vault on an exposed bind — else a network caller could exfiltrate
	// the key slots for an offline password attack. Pin the vault-read gate on each such route.
	for (const route of ['/api/mirror-set', '/api/mirror-sync', '/api/serve-start', '/api/disperse', '/api/backup', '/api/pack']) {
		ok('route ' + route + ' requires a vault credential when exposed', /requireVaultReadIfExposed\(/.test(bodyOf(route)));
	}
	// 1c. Introducing a caller-supplied OUTBOUND destination (a cloud remote, an off-site backup host) must be
	// refused on an exposed bind, so a network request cannot make this machine connect to an arbitrary address.
	for (const route of ['/api/cloud-remote', '/api/sftp-dest']) {
		ok('route ' + route + ' refuses a caller-supplied outbound destination when exposed', /refuseOutboundIfExposed\(/.test(bodyOf(route)));
	}
	// 1d. Opening a location in the file manager is loopback-only (it drives the host's opener).
	ok('route /api/reveal refuses to open a location when exposed', /if \(exposed\) throw/.test(bodyOf('/api/reveal')));

	// 1d-2. Unmounting (locking) a vault must also END any phone/in-app viewer session serving it — otherwise the
	// mobile session keeps serving that vault's ciphertext, and holding its in-memory key, after the user locked it.
	ok('route /api/unmount ends the vault\'s mobile sessions', /Mobile\.stopByVaultPath\(/.test(bodyOf('/api/unmount', 500)));

	// 1d-3. The cooperative stop channel must run the SAME graceful drain-and-lock as a signal (gracefulExit), so a
	// Windows headless service — which cannot catch a stop signal — still flushes writes and locks vaults on stop.
	// It responds first, then gracefulExits on the next tick so the reply reaches the caller before teardown.
	ok('route /api/service-stop triggers a graceful drain-and-lock shutdown', /ProcRegistry\.gracefulExit\(0\)/.test(bodyOf('/api/service-stop', 400)));

	// 1f. The web-auth choke points. These live in closures inside start() (not exported), so — like the exposed-bind
	// guards above — a source check is the right, non-flaky level: a live test would need TLS + a real login. They pin
	// the CSRF defense (a custom header no cross-origin page can set), the DNS-rebinding defense (loopback Host on the
	// default bind), the login gate (401 an API request / redirect a page when unauthenticated), and that a rotated
	// signing secret takes effect at once (the 1-second auth cache is dropped on logout and on setting the password).
	// The header name/value are single-sourced in Common (so the CLI sender and this checker can never drift); pin
	// the pair here so a rename stays deliberate, and confirm the guard reads them via the shared constants and 403s.
	const Common = require('../Common');
	ok('the anti-CSRF header pair is the single-sourced Common constant', Common.OWNER_CSRF_HEADER === 'x-vdisk' && Common.OWNER_CSRF_VALUE === '1');
	ok('the API guard requires the anti-CSRF custom header via the shared constant', /req\.get\(Common\.OWNER_CSRF_HEADER\) !== Common\.OWNER_CSRF_VALUE[\s\S]{0,40}status\(403\)/.test(server));
	ok('the API guard blocks DNS-rebinding with a loopback Host check on the default bind', /isLoopbackAddr\(host\) && host !== bindAddr\)[\s\S]{0,30}status\(403\)/.test(server));
	ok('the login gate 401s an unauthenticated API request and redirects a page', /req\.path\.startsWith\('\/api'\)[\s\S]{0,60}status\(401\)[\s\S]{0,120}redirect\('\/login'\)/.test(server));
	// The login gate FAILS CLOSED on an exposed bind with no password: startup refuses to bind exposed without one, so
	// the only way to reach "exposed + no password" is clearing the password while an exposed server runs. The gate
	// must refuse (503) rather than wave requests through — otherwise clearing the password at runtime would drop auth
	// for the whole network. The loopback default still waves through with next().
	ok('the login gate fails closed on an exposed bind with no password (does not wave through)', /if \(!a\.enabled\)[\s\S]{0,700}if \(exposed\)[\s\S]{0,400}status\(503\)[\s\S]{0,400}return next\(\)/.test(server));
	ok('logout drops the auth cache so a revoked secret cannot validate a stolen cookie', /rotateUiSecret\(\)[\s\S]{0,60}invalidateUiAuthCache\(\)/.test(server));
	ok('setting the web password drops the auth cache at once', /setUiPassword\([\s\S]{0,60}invalidateUiAuthCache\(\)/.test(server));
	// Enrolling a passwordless sign-in must require the current password (a session alone cannot plant a backdoor).
	ok('web-auth: enrolling a WebAuthn credential requires the current password', /async function addUiWebauthn\([\s\S]{0,900}verifyPassword\(String\(password/.test(read(path.join(__dirname, '..', 'Vault.js'))));

	// 1e. Start-at-login installs a system login service on THIS machine, so it is loopback-only — a network caller
	// must never register one. When the caller asks for a network-reachable bind, a web password must already be set
	// (an exposed interface always requires a login), mirroring the live `ui --bind` refusal. And setting the web
	// password from the app must re-issue the current session's cookie, because rotating the signing secret
	// invalidates it; without that the caller would be bounced to the login screen mid-flow. These pin that a future
	// edit cannot quietly let a remote caller install autostart, expose an interface with no login, or break the
	// set-password flow.
	ok('route /api/autostart-install refuses to install over a network connection', /if \(exposed\) throw/.test(bodyOf('/api/autostart-install', 1500)));
	ok('route /api/autostart-install requires a web password for a network bind', /getUiAuth\(\)\)\.enabled/.test(bodyOf('/api/autostart-install', 1500)));
	ok('route /api/web-password-set re-issues the session cookie after setting the password', /setUiPassword\(/.test(bodyOf('/api/web-password-set', 400)) && /setCookieHeader\(/.test(bodyOf('/api/web-password-set', 400)));

	// 2. The mount cache mode is validated against the engine's allowlist rather than passed through blindly.
	const vault = read(path.join(__dirname, '..', 'Vault.js'));
	ok('mount validates vfsCacheMode against the off/minimal/writes/full allowlist', /vfsCacheMode[\s\S]{0,120}\['off', 'minimal', 'writes', 'full'\]/.test(vault) || /\['off', 'minimal', 'writes', 'full'\]\.includes\(opts\.vfsCacheMode\)/.test(vault));

	// 3. A non-numeric emergency grace period falls back to the default (14 days), never persists NaN.
	const kp = vdisk.emergencyKeypair();
	await vdisk.emergencyEnroll({ contactPubKey: kp.publicKey, contactLabel: 'Test', inactivityDays: 30, graceDays: 'soon' });
	const st = await vdisk.getSettings();
	const graceMs = st.emergency && st.emergency.graceMs;
	ok('a non-numeric graceDays becomes the 14-day default, not NaN', Number.isFinite(graceMs) && graceMs === 14 * 86400000);
	// A valid number is still honored.
	await vdisk.emergencyEnroll({ contactPubKey: kp.publicKey, contactLabel: 'Test', inactivityDays: 30, graceDays: 7 });
	const st2 = await vdisk.getSettings();
	ok('a valid graceDays is honored', (st2.emergency && st2.emergency.graceMs) === 7 * 86400000);
	// Tidy the settings we wrote so the shared test data dir is left clean.
	try { await vdisk.emergencyDisarm(); } catch (_) {}

	// 4. Send-link routes: the recipient routes (/s and /shared) are the CAPABILITY themselves (the key is in the
	//    link), so they must sit BEFORE the login gate — otherwise setting a web password would silently break every
	//    shared link on an exposed bind. The CREATE endpoint (/api/send-create) must sit AFTER the gate (owner only),
	//    and the redeem route must be throttled against link-password guessing. Static ordering guard.
	const gateAt = server.indexOf("res.redirect('/login')"); // the UI login gate's redirect — everything after it is gated
	ok('the login gate is present (ordering anchor)', gateAt > 0);
	const sharedAt = server.indexOf("app.use('/shared'");
	const sRedeemAt = server.search(/\/\^\\\/s\\\/redeem/); // the /s/redeem route registration
	const sInfoAt = server.search(/\/\^\\\/s\\\/info/);
	const createAt = server.indexOf("'/api/send-create'");
	ok('the /shared mount is registered before the login gate', sharedAt > 0 && sharedAt < gateAt);
	ok('the /s/info and /s/redeem routes are registered before the login gate', sInfoAt > 0 && sInfoAt < gateAt && sRedeemAt > 0 && sRedeemAt < gateAt);
	ok('the /api/send-create route is registered after the login gate (owner only)', createAt > gateAt);
	ok('the /s/redeem route is throttled against link-password guessing', /sendFails\.blocked\(/.test(server) && /sendFails\.fail\(/.test(server));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ROUTE-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
