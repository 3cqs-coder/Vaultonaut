'use strict';
// lib/Serve.js — Tier 2 "Anywhere access", node side. Serve a vault's ENCRYPTED folder over WebDAV
// (via the bundled engine) so another node can two-way mirror against it. Only ciphertext is served —
// the server never decrypts — and the endpoint is protected by generated credentials.
//
// Reachability is deliberately left to the operator's own transport: bound to loopback by default,
// it is reached from another machine through a tunnel or VPN you already run (which also encrypts the
// hop), or by binding a LAN/again-tunnelled address with a chosen bind. Vaultonaut stays
// self-contained — it serves a port; a relay/VPN/SSH tunnel forwards it. The content is encrypted
// either way, so even a plain hop only ever exposes ciphertext plus the endpoint credential.
//
// A short dir-cache keeps the served listing fresh so a change made to the vault on THIS node (a
// mount/unmount) becomes visible to the other side within seconds — which is what makes the mirror
// truly two-way rather than one-way.

const net = require('net');
const crypto = require('crypto');
const path = require('path');
const fsp = require('fs').promises;
const { spawn } = require('child_process');
const ProcRegistry = require('./ProcRegistry');
const Common = require('./Common');

// Write a one-line htpasswd file so the endpoint credential reaches the engine through a 0600 FILE (readable only by
// this user), not on the command line where any other local user could read it from the process list. rclone's basic
// auth accepts a {SHA} (SHA-1) entry, which Node produces natively — and the credential is a ~140-bit random token,
// far beyond any brute force, so an unsalted fast hash of it is not a weakness. The file lives in the app's run
// directory (already hardened to owner-only) and is deleted when the server stops. Returns the file path.
async function writeHtpasswd(user, pass) {
	const dir = Common.runDir();
	try { Common.ensureDir(dir); } catch (_) {}
	const hash = '{SHA}' + crypto.createHash('sha1').update(String(pass)).digest('base64');
	const file = path.join(dir, 'serve-' + crypto.randomBytes(9).toString('hex') + '.htpasswd');
	await fsp.writeFile(file, user + ':' + hash + '\n', { mode: 0o600 });
	return file;
}

// A free loopback TCP port (used when the caller does not pin one).
function freePort() {
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.once('error', reject);
		s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
	});
}

// A URL-safe random credential of exactly `len` alphanumeric characters (default 24 → ~140 bits). Generate extra
// random bytes and strip the non-alphanumeric base64url characters BEFORE slicing, so the result is never short of
// `len` (the old strip-after-slice could occasionally return a 22-23 character credential).
function genCred(len = 24) { return crypto.randomBytes(len + 16).toString('base64url').replace(/[-_]/g, '').slice(0, len); }

// Resolve once the server is accepting connections, or reject if it exits first / times out.
function waitListening(host, port, proc, timeoutMs = 8000) {
	const deadline = Date.now() + timeoutMs;
	return new Promise((resolve, reject) => {
		let done = false;
		const onExit = (code) => { if (!done) { done = true; reject(new Error('The server stopped before it was ready (exit ' + code + ').')); } };
		proc.once('exit', onExit);
		const tryOnce = () => {
			if (done) return;
			const sock = net.connect({ host, port }, () => { sock.destroy(); if (!done) { done = true; proc.removeListener('exit', onExit); resolve(); } });
			sock.once('error', () => { sock.destroy(); if (done) return; if (Date.now() > deadline) { done = true; proc.removeListener('exit', onExit); reject(new Error('The server did not start listening in time.')); } else { const t = setTimeout(tryOnce, 150); if (t.unref) t.unref(); } }); // unref: a pending retry must not keep the event loop alive after the caller has moved on
		};
		tryOnce();
	});
}

// Spawn `rclone serve webdav <dir>` over a vault's ciphertext folder with basic auth. Returns a
// handle: { proc, host, port, url, user, pass, stop() }. Credentials default to generated values.
async function serveWebdav(bin, dir, { host = '127.0.0.1', port, user, pass, readOnly = false, onLine, cert, key } = {}) {
	port = port || await freePort();
	user = user || 'vd';
	pass = pass || genCred();
	const addr = host + ':' + port;
	// Pass the credential to the engine via a 0600 htpasswd file, never on argv (where any local user could read it).
	const htpasswd = await writeHtpasswd(user, pass);
	const cleanupHtpasswd = () => { fsp.unlink(htpasswd).catch(() => {}); };
	const args = ['serve', 'webdav', dir, '--addr', addr, '--htpasswd', htpasswd,
		'--dir-cache-time', '5s',      // reflect a mount/unmount on this node to the other side within seconds
		'--vfs-cache-mode', 'off'];    // serve straight from the folder; writes from the peer land in it directly
	const secure = !!(cert && key);
	if (secure) args.push('--cert', cert, '--key', key); // TLS: the relay hop is then encrypted end to end
	if (readOnly) args.push('--read-only');
	const proc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); // windowsHide so the long-lived serve process never leaves a console window open on Windows
	ProcRegistry.track(proc);
	proc.once('exit', cleanupHtpasswd); // remove the credential file whenever the server exits (clean stop, crash, or kill)
	if (onLine) {
		const fwd = (b) => String(b).split('\n').forEach(l => { const t = l.trim(); if (t) onLine(t); });
		proc.stdout.on('data', fwd); proc.stderr.on('data', fwd);
	}
	try { await waitListening(host, port, proc, 8000); }
	catch (e) { try { proc.kill('SIGKILL'); } catch (_) {} cleanupHtpasswd(); throw e; }
	const stop = () => new Promise((resolve) => {
		if (proc.exitCode != null) { cleanupHtpasswd(); return resolve(); }
		// SIGKILL fallback if a graceful SIGTERM does not land in time. Clear it the instant the process exits, and
		// unref it, so a clean stop neither keeps the event loop alive for 3s nor fires a redundant kill on a dead pid.
		const killTimer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch (_) {} }, 3000);
		if (killTimer.unref) killTimer.unref();
		proc.once('exit', () => { clearTimeout(killTimer); resolve(); });
		try { proc.kill('SIGTERM'); } catch (_) {}
	});
	return { proc, host, port, url: (secure ? 'https://' : 'http://') + addr + '/', user, pass, secure, stop };
}

// Supervise a served node so it self-heals: if the engine process dies unexpectedly, it is restarted
// on the SAME port and credentials (so a client's saved peer keeps working), with exponential backoff
// and a cap on attempts — the same crash-restart shape a supervised worker pool uses. `stop()` marks
// the shutdown intentional so no restart is scheduled. `onEvent({type})` reports 'down' | 'restarting'
// | 'up' | 'gaveup' | 'error' for logging. The initial start still throws on failure so the caller can
// report a bad configuration up front; only later, unexpected deaths are auto-recovered.
const MAX_RESTARTS = 8, BASE_DELAY_MS = 1000, MAX_DELAY_MS = 30000, STABLE_MS = 60000;
async function superviseWebdav(bin, dir, opts = {}) {
	const host = opts.host || '127.0.0.1';
	const port = opts.port || await freePort(); // fixed for the lifetime, so restarts keep the endpoint
	// Pin the credentials ONCE here (generating them if the caller did not supply any), so every restart
	// serves on the SAME user/pass — otherwise a restart would mint fresh credentials and the endpoint
	// the caller already handed out would stop working.
	const cfg = { ...opts, host, port, user: opts.user || genCred(), pass: opts.pass || genCred() };
	let stopped = false, attempt = 0, current = null, restartTimer = null, restarting = null, startedAt = 0;
	const emit = (type, extra) => { try { if (opts.onEvent) opts.onEvent({ type, ...extra }); } catch (_) {} };
	// Only a serve that STAYED UP at least STABLE_MS clears the restart backoff on its next exit. A start-then-crash
	// loop (the engine comes up then dies within seconds) therefore keeps escalating its backoff toward the give-up
	// ceiling instead of respawning at a fixed 1-second cadence forever. This mirrors the login-service supervisor.
	const arm = (h) => { startedAt = Date.now(); h.proc.once('exit', () => { if (stopped) return; if (Date.now() - startedAt >= STABLE_MS) attempt = 0; emit('down'); schedule(); }); };
	const schedule = () => {
		if (stopped) return;
		attempt++;
		if (attempt > MAX_RESTARTS) { emit('gaveup', { attempt: attempt - 1 }); return; }
		const delay = Math.min(BASE_DELAY_MS * Math.pow(2, attempt - 1), MAX_DELAY_MS);
		emit('restarting', { attempt, delay });
		restartTimer = setTimeout(() => {
			if (stopped) return;
			// Track the in-flight restart so stop() can await it, and re-check `stopped` AFTER the new
			// serve is up: a stop that lands during the 1–8s startup window would otherwise leave a
			// freshly-spawned engine running unsupervised (an orphaned open endpoint past an intentional stop).
			restarting = (async () => {
				try {
					const h = await serveWebdav(bin, dir, cfg);
					if (stopped) { try { await h.stop(); } catch (_) {} return; }
					current = h; arm(current); emit('up'); // arm() resets the backoff only after a stable run, not on every start
				} catch (e) { if (!stopped) { emit('error', { error: (e && e.message) || String(e) }); schedule(); } }
				finally { restarting = null; }
			})();
		}, delay);
		if (restartTimer.unref) restartTimer.unref(); // never keep the process alive just to restart the serve
	};
	current = await serveWebdav(bin, dir, cfg); // initial start throws on failure (reported by the caller)
	arm(current);
	return {
		host, port, url: current.url, user: cfg.user, pass: cfg.pass, secure: current.secure,
		stop: async () => { stopped = true; try { clearTimeout(restartTimer); } catch (_) {} try { if (restarting) await restarting; } catch (_) {} if (current) await current.stop(); }
	};
}

module.exports = { serveWebdav, superviseWebdav, freePort, genCred };
