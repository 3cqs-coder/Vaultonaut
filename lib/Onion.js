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
const crypto = require('crypto');

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

// Publish an ephemeral v3 onion that forwards <virtualPort> to 127.0.0.1:<localPort>. Returns { onion, port, stop }.
// The control connection is KEPT OPEN for the serve's lifetime: an ephemeral onion lives only while its control
// connection is open, so `stop()` (and any process exit that drops the socket) removes the onion automatically —
// nothing leaks past the session. `controlPort` overrides the auto-detected ports (used by tests).
async function publishOnion(localPort, opts) {
	opts = opts || {};
	const virtualPort = opts.virtualPort || 80;
	const ports = opts.controlPort ? [opts.controlPort] : CONTROL_PORTS;
	let sock = null, lastErr = null;
	for (const p of ports) { try { sock = await connectControl(p, opts.host, opts.timeoutMs); break; } catch (e) { lastErr = e; } }
	if (!sock) throw Object.assign(new Error('No running Tor was found (looked for a control port on ' + ports.join(' and ') + '). Start Tor — or open the Tor Browser — to use onion mode. ' + (lastErr && lastErr.message ? '' : '')), { code: 'NO_TOR' });
	try {
		await authenticate(sock);
		const r = await sendCmd(sock, 'ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=' + virtualPort + ',127.0.0.1:' + localPort);
		const id = (/ServiceID=([a-z2-7]{56})/.exec(r.lines.join(' ')) || [])[1];
		if (!id) throw new Error('Tor accepted the request but did not return an onion address.');
		sock.on('error', () => {}); // the socket is now kept open for the serve lifetime; ignore late errors so a Tor blip cannot crash us
		return { onion: id + '.onion', port: virtualPort, stop: () => { try { sock.destroy(); } catch (_) {} } };
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
	for (const p of SOCKS_PORTS) { try { const s = await connectControl(p, '127.0.0.1', 800); s.destroy(); return 'socks5h://127.0.0.1:' + p; } catch (_) {} }
	return null;
}
// Does a URL point at an onion address? (host ends in .onion) — used to decide whether a transfer needs the SOCKS route.
function isOnionUrl(u) { try { return /\.onion$/i.test(new URL(String(u)).hostname); } catch (_) { return /(^|\/\/|@)[a-z2-7]{16,56}\.onion(\b|[:/])/i.test(String(u || '')); } }

module.exports = { publishOnion, torAvailable, socksUrl, isOnionUrl, authenticate, sendCmd, connectControl, CONTROL_PORTS, SOCKS_PORTS };
