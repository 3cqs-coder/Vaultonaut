'use strict';
// lib/OwnerClient.js — let the CLI route mount/unmount through a RUNNING local owner (the web / background
// service) so both paths go through the SAME long-lived process. That process holds the vault key in memory
// for the whole session, so it finalizes cleanly on unmount (re-signs the tamper baseline, clears the session
// marker) exactly as the web app does — which is what a separate short-lived `vdisk unmount` cannot do.
//
// Hard rules, so this can never break or block the mount path:
//   • It NEVER starts a service (no spawns). It only talks to one that is already running.
//   • Every call is non-blocking (async) and bounded by a timeout.
//   • Any failure — no owner, unreachable, a login-gated owner, a transport error — returns null / throws, and
//     the caller falls back to a direct in-process mount/unmount. The worst case is exactly today's behavior.
//
// Only a LOOPBACK owner is ever used (the service advertises its url only for a loopback bind); an exposed,
// password-gated, TLS service is never driven from here.

const http = require('http');
const path = require('path');
const fsp = require('fs').promises;
const Common = require('./Common');

// Cap the owner's JSON response so a wedged or hostile local endpoint can never grow this buffer without bound.
// The owner only ever returns small status objects, so this is generous headroom, not a real limit.
const MAX_OWNER_RESPONSE_BYTES = 4 * 1024 * 1024;

// Discover a running loopback owner from the service pidfile. Returns { url } or null. Non-blocking; never throws.
// SAFETY: the CLI is about to POST the vault password to this url, so the pidfile must be trustworthy. On POSIX
// we refuse a pidfile that another user could have planted or altered — one not owned by us, or writable by
// group/other — and fall back to a direct mount instead. (runDir is created 0700, so this only trips if the
// install's permissions were weakened.)
async function find() {
	try {
		const file = path.join(Common.runDir(), 'service.pid');
		if (process.platform !== 'win32') {
			const st = await fsp.stat(file);
			if (st.uid !== process.getuid() || (st.mode & 0o022)) return null; // foreign-owned or group/other-writable — do not trust
		}
		const rec = JSON.parse(await fsp.readFile(file, 'utf8'));
		if (rec && rec.url && rec.pid && Common.isProcessAlive(Number(rec.pid))) return { url: String(rec.url), token: rec.token ? String(rec.token) : null };
	} catch (_) {}
	return null;
}

// Confirm the loopback server at `url` is genuinely OUR running instance by proving it holds `token` — the owner
// secret the running service wrote into the owner-only pidfile. The token is sent in a header to /__owner-check,
// which answers only yes/no and never echoes it. Resolves true ONLY on a 2xx; every failure — no token, a
// non-loopback/non-http url, an unreachable or wrong server (404), a transport error, or a timeout — resolves false,
// so a caller can fail closed and refuse to trust the server. This closes the gap where a stale pidfile with a
// reused process id, or any other process merely holding the port, could otherwise be mistaken for the real service.
function verifyOwner(url, token, timeoutMs = 4000) {
	return new Promise((resolve) => {
		if (!token) return resolve(false);
		let u; try { u = new URL('/__owner-check', url); } catch (_) { return resolve(false); }
		if (u.protocol !== 'http:' || !Common.isLoopbackHost(u.hostname)) return resolve(false); // never probe a network/TLS address
		let settled = false; const done = (v) => { if (!settled) { settled = true; resolve(v); } };
		const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'GET', family: 4,
			headers: { 'x-vaultonaut-owner': String(token) } }, (res) => { res.resume(); done(res.statusCode >= 200 && res.statusCode < 300); });
		req.on('error', () => done(false));
		req.setTimeout(timeoutMs, () => { req.destroy(); done(false); });
		req.end();
	});
}

// The PID of the running local service from its pidfile, or null. Same trust check as find() — on POSIX a
// foreign-owned or group/other-writable pidfile is refused — but it does NOT require an advertised url, so it also
// locates an exposed (--bind) instance. Used by `stop` to signal the service. Non-blocking; never throws.
async function servicePid() {
	try {
		const file = path.join(Common.runDir(), 'service.pid');
		if (process.platform !== 'win32') {
			const st = await fsp.stat(file);
			if (st.uid !== process.getuid() || (st.mode & 0o022)) return null; // foreign-owned or group/other-writable — do not trust
		}
		const rec = JSON.parse(await fsp.readFile(file, 'utf8'));
		if (rec && rec.pid && Common.isProcessAlive(Number(rec.pid))) return Number(rec.pid);
	} catch (_) {}
	return null;
}

// POST a small JSON body to the owner's loopback API. Resolves { ok, status, body }. Rejects only on a transport
// failure or timeout (the caller then falls back). Sends the CSRF header the loopback API requires. `timeoutMs`
// is generous because an unmount waits for buffered writes to flush before it returns; it is a HARD wall-clock
// deadline (not http's idle timeout, which resets on each byte), so even a peer that dribbles bytes can never
// park the CLI past it.
function post(baseUrl, apiPath, body, timeoutMs = 6 * 60 * 60 * 1000) {
	return new Promise((resolve, reject) => {
		let u; try { u = new URL(apiPath, baseUrl); } catch (e) { return reject(e); }
		if (u.protocol !== 'http:' || !Common.isLoopbackHost(u.hostname)) return reject(new Error('owner url is not loopback http')); // never drive a network/TLS service
		const data = Buffer.from(JSON.stringify(body || {}), 'utf8');
		let settled = false, deadline = null;
		const finish = (fn, arg) => { if (settled) return; settled = true; if (deadline) clearTimeout(deadline); fn(arg); };
		const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST', family: 4,
			headers: { 'content-type': 'application/json', 'content-length': data.length, [Common.OWNER_CSRF_HEADER]: Common.OWNER_CSRF_VALUE } }, (res) => {
			let out = ''; res.setEncoding('utf8');
			res.on('data', (c) => { out += c; if (out.length > MAX_OWNER_RESPONSE_BYTES) req.destroy(new Error('owner response too large')); });
			res.on('end', () => { let j = null; try { j = JSON.parse(out); } catch (_) {} finish(resolve, { ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: j }); });
		});
		req.on('error', (e) => finish(reject, e));
		deadline = setTimeout(() => req.destroy(new Error('owner request timed out')), timeoutMs);
		if (deadline.unref) deadline.unref();
		req.end(data);
	});
}

// A login-gated owner (a UI password is set) answers an unauthenticated API call with 401 { login: true }; a
// non-loopback/rebinding guard answers 403. In both cases the CLI cannot drive this owner, so it falls back.
function isUsable(resp) { return !!resp && resp.status !== 401 && resp.status !== 403 && !(resp.body && resp.body.login); }

module.exports = { find, servicePid, post, isUsable, verifyOwner };
