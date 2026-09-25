'use strict';
// lib/Onion.js — publish an ephemeral v3 onion service through a Tor that is ALREADY running (a system tor, or the Tor
// Browser). It lets a served vault or node be reached over an anonymizing overlay network with NO exposed IP and NO
// forwarded port, and it pierces NAT for free. It bundles nothing: it detects a running Tor's control port and speaks
// the control protocol. When no Tor is found it fails with a clear, actionable message, so onion mode simply stays
// unavailable rather than breaking anything else. The vault payload is ALREADY end-to-end encrypted (rclone crypt +
// the pinned TLS serve), so the overlay adds transport anonymity and reachability, never content secrecy — the onion
// address is an unguessable capability, and the existing serve login still gates access on top.
//
// Cross-platform: the control protocol and SOCKS are identical on macOS, Windows, and Linux — no platform-specific
// code. Non-blocking: every exchange is async socket I/O with hard timeouts.
const net = require('net');
const fsp = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const generateKeyPairAsync = require('util').promisify(crypto.generateKeyPair);

const CONTROL_PORTS = [9051, 9151]; // a system tor's control port, then the Tor Browser's bundled tor
const SOCKS_PORTS = [9050, 9150];   // the matching SOCKS ports (used by the CONNECTING side to reach a .onion)

// Open one control connection to 127.0.0.1:<port>. Resolves the connected socket or rejects (no Tor there).
function connectControl(port, host, timeoutMs) {
	host = host || '127.0.0.1'; timeoutMs = timeoutMs || 4000;
	return new Promise((resolve, reject) => {
		const sock = net.connect({ host: host, port: port });
		let settled = false;
		const to = setTimeout(() => { if (!settled) { settled = true; try { sock.destroy(); } catch (_) {} reject(new Error('control connect timed out')); } }, timeoutMs);
		sock.once('connect', () => { clearTimeout(to); if (!settled) { settled = true; resolve(sock); } });
		sock.once('error', (e) => { clearTimeout(to); if (!settled) { settled = true; reject(e); } });
	});
}

// Send one control command and resolve with { code, lines } (the reply lines with their status code stripped). A
// control reply ends at the first line that begins "NNN " (a space after the 3-digit code); "NNN-"/"NNN+" continue it.
// Rejects on a non-2xx status or a timeout, so a caller can fail closed.
function sendCmd(sock, cmd, timeoutMs) {
	timeoutMs = timeoutMs || 8000;
	return new Promise((resolve, reject) => {
		let buf = '';
		const lines = [];
		function cleanup() { clearTimeout(to); sock.removeListener('data', onData); sock.removeListener('error', onErr); }
		const onData = (d) => {
			buf += d.toString('utf8');
			let idx;
			while ((idx = buf.indexOf('\r\n')) >= 0) {
				const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
				const m = /^(\d{3})([ +-])([\s\S]*)$/.exec(line);
				if (!m) { lines.push(line); continue; }
				lines.push(m[3]);
				if (m[2] === ' ') { cleanup(); const code = Number(m[1]); if (code >= 200 && code < 300) resolve({ code: code, lines: lines }); else reject(Object.assign(new Error('Tor control error ' + code + ': ' + m[3]), { code: code })); return; }
			}
		};
		const onErr = (e) => { cleanup(); reject(e); };
		const to = setTimeout(() => { cleanup(); reject(new Error('Tor control command timed out')); }, timeoutMs);
		sock.on('data', onData); sock.once('error', onErr);
		sock.write(cmd + '\r\n');
	});
}

// The SAFECOOKIE HMAC keys are these exact ASCII strings (Tor control-spec §3.24).
const SC_SERVER_KEY = 'Tor safe cookie authentication server-to-controller hash';
const SC_CLIENT_KEY = 'Tor safe cookie authentication controller-to-server hash';

// Authenticate with whatever PROTOCOLINFO offers, preferring the safest available: NULL (open control port),
// SAFECOOKIE (challenge/response over the cookie — the Tor Browser default), or plain COOKIE.
async function authenticate(sock) {
	const pi = await sendCmd(sock, 'PROTOCOLINFO 1');
	const text = pi.lines.join('\n');
	const methods = ((/METHODS=([A-Z,]+)/.exec(text) || [])[1] || '');
	const cookieFile = (/COOKIEFILE="([^"]+)"/.exec(text) || [])[1];
	if (/\bNULL\b/.test(methods)) { await sendCmd(sock, 'AUTHENTICATE'); return 'null'; }
	if (cookieFile && /\bSAFECOOKIE\b/.test(methods)) {
		const cookie = await fsp.readFile(cookieFile);
		const clientNonce = crypto.randomBytes(32);
		const ch = await sendCmd(sock, 'AUTHCHALLENGE SAFECOOKIE ' + clientNonce.toString('hex'));
		const chText = ch.lines.join(' ');
		const serverHash = Buffer.from(((/SERVERHASH=([0-9A-Fa-f]+)/.exec(chText) || [])[1] || ''), 'hex');
		const serverNonce = Buffer.from(((/SERVERNONCE=([0-9A-Fa-f]+)/.exec(chText) || [])[1] || ''), 'hex');
		const msg = Buffer.concat([cookie, clientNonce, serverNonce]);
		const expectServer = crypto.createHmac('sha256', SC_SERVER_KEY).update(msg).digest();
		if (serverHash.length !== expectServer.length || !crypto.timingSafeEqual(serverHash, expectServer)) throw new Error('Tor SAFECOOKIE server hash did not verify — refusing to authenticate.');
		const clientHash = crypto.createHmac('sha256', SC_CLIENT_KEY).update(msg).digest();
		await sendCmd(sock, 'AUTHENTICATE ' + clientHash.toString('hex'));
		return 'safecookie';
	}
	if (cookieFile && /\bCOOKIE\b/.test(methods)) {
		const cookie = await fsp.readFile(cookieFile);
		await sendCmd(sock, 'AUTHENTICATE ' + cookie.toString('hex'));
		return 'cookie';
	}
	throw new Error('This Tor has no control-authentication method Vaultonaut can use (needs NULL, SAFECOOKIE, or COOKIE). If it is password-protected, remove the control password or use a cookie-authenticated Tor.');
}

// ── v3 client authorization ────────────────────────────────────────────────────────────────────────────────────
// A v3 onion address is an unguessable capability, but anyone who learns it can still reach the service. Client
// authorization closes that gap: the service is published with a client's x25519 PUBLIC key, and Tor then refuses to
// even acknowledge the service to anyone who cannot prove possession of the matching PRIVATE key. The address becomes
// useless on its own — invisible without the key — so a leaked or logged .onion is not enough to connect. We generate
// a fresh keypair per serve, hand Tor the public key (ClientAuthV3), and carry the private key inside the connect code
// so the intended peer authorizes automatically with no extra setup (matching how the rest of onion mode "just works").
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648 base32 — the alphabet Tor uses for onion keys/addresses
function base32(buf) {
	let out = '', bits = 0, val = 0;
	for (let i = 0; i < buf.length; i++) { val = (val << 8) | buf[i]; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
	if (bits > 0) out += B32[(val << (5 - bits)) & 31];
	return out;
}
// Generate a fresh x25519 keypair and return the two forms Tor's control protocol wants: the public key base32-encoded
// (for ADD_ONION ClientAuthV3=) and the private key base64-encoded (for ONION_CLIENT_AUTH_ADD x25519:). Async, so key
// generation never blocks the event loop. Raw 32-byte key bytes are read out via JWK, which works across Node versions.
async function makeClientAuthKeypair() {
	const { publicKey, privateKey } = await generateKeyPairAsync('x25519', {});
	const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
	const priv = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
	return { pub32: base32(pub), privB64: priv.toString('base64') };
}
// Register a client-authorization private key with a running Tor so THIS side can reach an authorized onion. The key is
// held in that Tor's client state for its lifetime only (no Flags=Permanent → nothing is written to disk), so it self-
// cleans and never persists a secret. The control socket is opened only for the add and closed immediately — the auth
// does not depend on the connection staying open (unlike an ephemeral service). Idempotent: re-adding replaces (251).
async function registerClientAuth(onionHost, privB64, opts) {
	opts = opts || {};
	const serviceId = String(onionHost || '').replace(/\.onion$/i, '');
	if (!/^[a-z2-7]{56}$/i.test(serviceId)) throw new Error('That onion address is not valid, so client authorization cannot be registered.');
	if (!privB64) throw new Error('No client-authorization key was provided.');
	const ports = opts.controlPort ? [opts.controlPort] : CONTROL_PORTS;
	let sock = null;
	for (const p of ports) { try { sock = await connectControl(p, opts.host, opts.timeoutMs); break; } catch (_) {} }
	if (!sock) throw Object.assign(new Error('No running Tor was found to register client authorization.'), { code: 'NO_TOR' });
	try { await authenticate(sock); await sendCmd(sock, 'ONION_CLIENT_AUTH_ADD ' + serviceId + ' x25519:' + privB64); return { ok: true }; }
	finally { try { sock.destroy(); } catch (_) {} }
}

// Publish an ephemeral v3 onion that forwards <virtualPort> to 127.0.0.1:<localPort>. Returns { onion, port, stop,
// clientAuthPriv }. The control connection is KEPT OPEN for the serve's lifetime: an ephemeral onion lives only while
// its control connection is open, so `stop()` (and any process exit that drops the socket) removes the onion
// automatically — nothing leaks past the session. `controlPort` overrides the auto-detected ports (used by tests).
// When `opts.clientAuth` is set, a fresh client keypair is generated, Tor is given the public half (ClientAuthV3), and
// the private half is returned as `clientAuthPriv` (base64) to travel in the connect code — the onion is then invisible
// to anyone without that key.
async function publishOnion(localPort, opts) {
	opts = opts || {};
	const virtualPort = opts.virtualPort || 80;
	const ports = opts.controlPort ? [opts.controlPort] : CONTROL_PORTS;
	let sock = null, lastErr = null;
	for (const p of ports) { try { sock = await connectControl(p, opts.host, opts.timeoutMs); break; } catch (e) { lastErr = e; } }
	if (!sock) throw Object.assign(new Error('No running Tor was found (looked for a control port on ' + ports.join(' and ') + '). Start Tor — or open the Tor Browser — to use onion mode. ' + (lastErr && lastErr.message ? '' : '')), { code: 'NO_TOR' });
	try {
		await authenticate(sock);
		let clientAuthPriv = null, authFlag = '';
		if (opts.clientAuth) { const kp = await makeClientAuthKeypair(); clientAuthPriv = kp.privB64; authFlag = ' ClientAuthV3=' + kp.pub32; }
		const r = await sendCmd(sock, 'ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=' + virtualPort + ',127.0.0.1:' + localPort + authFlag);
		const id = (/ServiceID=([a-z2-7]{56})/.exec(r.lines.join(' ')) || [])[1];
		if (!id) throw new Error('Tor accepted the request but did not return an onion address.');
		sock.on('error', () => {}); // the socket is now kept open for the serve lifetime; ignore late errors so a Tor blip cannot crash us
		return { onion: id + '.onion', port: virtualPort, clientAuthPriv: clientAuthPriv, stop: () => { try { sock.destroy(); } catch (_) {} } };
	} catch (e) { try { sock.destroy(); } catch (_) {} throw e; }
}

// Fast best-effort probe: is a usable Tor control port reachable? Used to offer or hide onion mode in the UI/CLI.
async function torAvailable() {
	for (const p of CONTROL_PORTS) { try { const s = await connectControl(p, '127.0.0.1', 900); s.destroy(); return true; } catch (_) {} }
	return false;
}

// The first reachable Tor SOCKS5 proxy URL, for routing a .onion CONNECTION through Tor (the connecting side). Returns
// `socks5h://127.0.0.1:<port>` (the "h" makes Tor resolve the .onion, never a local DNS leak) or null if none is up. A
// plain TCP connect is enough to tell the port is listening; the transfer tool (rclone) does the SOCKS handshake.
async function socksUrl() {
	if (_managed && _managed.socksPort) return 'socks5h://127.0.0.1:' + _managed.socksPort; // our own managed Tor, if running
	for (const p of SOCKS_PORTS) { try { const s = await connectControl(p, '127.0.0.1', 800); s.destroy(); return 'socks5h://127.0.0.1:' + p; } catch (_) {} }
	return null;
}
// Does a URL point at an onion address? (host ends in .onion) — used to decide whether a transfer needs the SOCKS route.
function isOnionUrl(u) { try { return /\.onion$/i.test(new URL(String(u)).hostname); } catch (_) { return /(^|\/\/|@)[a-z2-7]{16,56}\.onion(\b|[:/])/i.test(String(u || '')); } }

// ── Managed Tor: run our own downloaded Tor when the user has none, so onion mode works with no setup ──────────────
// A single background Tor helper for this process (like the storage engine, it is downloaded once, verified, and
// cached). It is torn down on shutdown/lock/travel and reaped by the process registry if the app is hard-killed, so it
// never leaks. Preferred only when no Tor the user already runs is reachable — then nothing is downloaded or managed.
let _managed = null; // { controlPort, socksPort, proc, dataDir, stop }
// A free loopback TCP port (Tor binds the control and SOCKS ports on 127.0.0.1 only).
function freePort() { return new Promise((resolve, reject) => { const s = net.createServer(); s.on('error', reject); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); }); }
async function startManagedTor() {
	if (_managed) return _managed;
	const TorSetup = require('./TorSetup');
	const Common = require('./Common');
	const ProcRegistry = require('./ProcRegistry');
	const { spawn } = require('child_process');
	const paths = await TorSetup.ensureTor(); // downloads + verifies once, else cached
	const socksPort = await freePort(), controlPort = await freePort();
	const dataDir = path.join(Common.runDir(), 'tor-' + crypto.randomBytes(5).toString('hex'));
	await fsp.mkdir(dataDir, { recursive: true }); try { await fsp.chmod(dataDir, 0o700); } catch (_) {}
	// ClientOnly + AvoidDiskWrites keep it a lean, disk-light client; cookie auth means our control client authenticates
	// with the same SAFECOOKIE path it already uses for a system Tor. Loopback-only control and SOCKS ports.
	const args = ['--SocksPort', '127.0.0.1:' + socksPort, '--ControlPort', '127.0.0.1:' + controlPort, '--CookieAuthentication', '1',
		'--GeoIPFile', paths.geoip, '--GeoIPv6File', paths.geoip6, '--DataDirectory', dataDir, '--Log', 'notice stdout', '--ClientOnly', '1', '--AvoidDiskWrites', '1'];
	let proc; try { proc = spawn(paths.tor, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { throw Object.assign(new Error('Could not start the downloaded Tor: ' + (e && e.message || e)), { code: 'TOR_START' }); }
	try { ProcRegistry.track(proc); } catch (_) {} // reaped on a hard kill, so a managed Tor never leaks
	const stop = () => { try { proc.kill('SIGTERM'); } catch (_) {} fsp.rm(dataDir, { recursive: true, force: true }).catch(() => {}); if (_managed && _managed.proc === proc) _managed = null; }; // fire-and-forget cleanup — never blocks the shared service
	const ready = new Promise((resolve, reject) => {
		let done = false, buf = '';
		// A first bootstrap can be slow (building circuits); allow a generous window. A network that blocks Tor's own
		// traffic never reaches 100% — the timeout then surfaces a clear "could not connect" so onion mode is skipped.
		const to = setTimeout(() => { if (!done) { done = true; reject(new Error('Tor started but could not connect to the network in time — a firewall may be blocking it.')); } }, 180000);
		const onData = (d) => { buf += d.toString('utf8'); if (buf.length > 65536) buf = buf.slice(-8192); if (!done && /Bootstrapped 100%/.test(buf)) { done = true; clearTimeout(to); resolve(); } };
		if (proc.stdout) proc.stdout.on('data', onData); if (proc.stderr) proc.stderr.on('data', onData);
		proc.on('error', (e) => { if (!done) { done = true; clearTimeout(to); reject(e); } });
		proc.on('exit', (c) => { if (!done) { done = true; clearTimeout(to); reject(new Error('Tor exited before connecting (code ' + c + ').')); } });
	});
	_managed = { controlPort: controlPort, socksPort: socksPort, proc: proc, dataDir: dataDir, stop: stop };
	try { await ready; } catch (e) { stop(); throw e; }
	return _managed;
}
// Stop the managed Tor helper if it is running (called on shutdown/lock/travel). Safe to call when none is running.
function stopManagedTor() { if (_managed) { try { _managed.stop(); } catch (_) {} _managed = null; } }
// Ensure a Tor is available for onion mode and return { controlPort, socksPort, managed }. Prefers a Tor the user is
// ALREADY running (nothing to download or manage); otherwise downloads and runs our own managed Tor. Non-blocking.
async function provideTor() {
	for (let i = 0; i < CONTROL_PORTS.length; i++) { try { const s = await connectControl(CONTROL_PORTS[i], '127.0.0.1', 800); s.destroy(); return { controlPort: CONTROL_PORTS[i], socksPort: SOCKS_PORTS[i], managed: false }; } catch (_) {} }
	const m = await startManagedTor();
	return { controlPort: m.controlPort, socksPort: m.socksPort, managed: true };
}
// Can onion mode be offered? True if a Tor is running OR one has already been downloaded (so it can be started quickly).
async function onionAvailable() { if (await torAvailable()) return true; try { return require('./TorSetup').isInstalled(); } catch (_) { return false; } }

module.exports = { publishOnion, registerClientAuth, makeClientAuthKeypair, base32, torAvailable, socksUrl, isOnionUrl, authenticate, sendCmd, connectControl, provideTor, startManagedTor, stopManagedTor, onionAvailable, CONTROL_PORTS, SOCKS_PORTS };
