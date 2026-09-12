'use strict';
// lib/test/webauth.js — the web-interface authentication surface, END TO END over a real socket against the SAME
// server the app runs (webserver.start). The login gate, the anti-forgery header, and the DNS-rebinding host check
// were previously covered only by source-pin regexes, which can pass even when a guard is present but not actually
// gating (placed after a return, in the wrong branch, or unreachable). This stands up the real server with a
// password set and asserts BEHAVIOR: an unauthenticated page redirects to the login form and an unauthenticated API
// call is refused; a wrong password is rejected and the right one issues a session; an authenticated API call still
// needs the custom header (so a cross-origin page cannot drive it) and still refuses a spoofed Host (DNS-rebinding);
// and signing out rotates the session secret so the old cookie no longer works.
//
// Loopback only, no engine needed (the state endpoint reports an empty install). Run:  node lib/test/webauth.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const http = require('http');
const closeServersThenExit = require('./_exit'); // Windows-safe exit (drain sockets, await close) — avoids a libuv abort on process.exit()

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null, server = null;

// One raw HTTP request to the test server. Returns { status, setCookie, body }. Never follows redirects, so a 302 is
// observed directly. `host` overrides the Host header (to exercise the rebinding guard); `csrf` adds the anti-forgery
// header; `cookie` replays a session; a `json` body is sent as application/json.
function request(port, method, p, { cookie, csrf, host, json } = {}) {
	return new Promise((resolve, reject) => {
		const headers = {};
		if (cookie) headers['cookie'] = cookie;
		if (csrf) headers['x-vdisk'] = '1';
		if (host) headers['host'] = host;
		let data = null;
		if (json !== undefined) { data = Buffer.from(JSON.stringify(json)); headers['content-type'] = 'application/json'; headers['content-length'] = data.length; }
		const req = http.request({ hostname: '127.0.0.1', port, path: p, method, headers, family: 4 }, (res) => {
			let body = ''; res.setEncoding('utf8');
			res.on('data', (c) => body += c);
			res.on('end', () => resolve({ status: res.statusCode, setCookie: res.headers['set-cookie'] || null, location: res.headers['location'] || null, body }));
		});
		req.on('error', reject);
		req.setTimeout(8000, () => { req.destroy(new Error('request timed out')); });
		if (data) req.write(data);
		req.end();
	});
}
// Pull the vd_session cookie value back out of a Set-Cookie response, as a "name=value" string to replay.
function sessionCookie(setCookie) {
	for (const c of (setCookie || [])) { const m = /^(vd_session=[^;]*)/.exec(c); if (m) return m[1]; }
	return null;
}

async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-webauth-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	// Isolate every per-user path into the temp dir so the test never touches the real install or another test's state.
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	Common.runDir = () => path.join(dataDir, 'run');
	const Vault = require('../Vault');
	const { start } = require('../webserver');

	const PASSWORD = 'correct-horse-battery';
	await Vault.setUiPassword(PASSWORD); // a password set makes the login gate active even on loopback

	const started = await start(0, {}); // port 0 -> an ephemeral loopback port
	server = started.server;
	const port = server.address().port;

	// --- unauthenticated: a page redirects to login, an API call is refused ---
	const rootAnon = await request(port, 'GET', '/');
	ok('an unauthenticated page request redirects to the login form', rootAnon.status === 302 && /\/login/.test(rootAnon.location || ''));
	const apiAnon = await request(port, 'GET', '/api/state', { csrf: true });
	ok('an unauthenticated API call is refused with 401 and a login hint', apiAnon.status === 401 && /"login"\s*:\s*true/.test(apiAnon.body));

	// --- login: wrong password rejected, right password issues a session ---
	const badLogin = await request(port, 'POST', '/login', { json: { password: 'wrong-password' } });
	ok('a wrong password is rejected (not signed in)', badLogin.status === 401 && !sessionCookie(badLogin.setCookie));
	const goodLogin = await request(port, 'POST', '/login', { json: { password: PASSWORD } });
	const cookie = sessionCookie(goodLogin.setCookie);
	ok('the correct password signs in (302 + a session cookie)', goodLogin.status === 302 && !!cookie);

	// --- authenticated API still needs the anti-forgery header and a loopback Host ---
	const noHeader = await request(port, 'GET', '/api/state', { cookie });
	ok('an authenticated API call WITHOUT the anti-forgery header is refused (403)', noHeader.status === 403);
	const good = await request(port, 'GET', '/api/state', { cookie, csrf: true });
	ok('an authenticated API call WITH the header and a loopback Host succeeds (200)', good.status === 200);
	const rebind = await request(port, 'GET', '/api/state', { cookie, csrf: true, host: 'evil.example.com' });
	ok('a spoofed (non-loopback) Host is refused, blocking DNS-rebinding (403)', rebind.status === 403);

	// --- logout rotates the session secret, so the OLD cookie no longer works ---
	const logout = await request(port, 'POST', '/api/logout', { cookie, csrf: true });
	ok('logout succeeds', logout.status === 200);
	const afterLogout = await request(port, 'GET', '/api/state', { cookie, csrf: true });
	ok('the old cookie no longer authenticates after logout (401)', afterLogout.status === 401);

	await done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WEB-AUTH CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	closeServersThenExit(failures ? 1 : 0, server); // Windows-safe: drain sockets and await close before exit (see _exit.js)
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); closeServersThenExit(1, server); });
