'use strict';
// lib/PortMap.js — automatic router port mapping via NAT-PMP (RFC 6886) and PCP (RFC 6887), zero-dependency.
//
// WHY: for a large share of home routers this opens a real WAN port straight through the NAT, giving a device a
// DIRECTLY reachable public address — no hole-punching, no relay. It is the single highest-leverage NAT-traversal
// step, and it is a tiny binary UDP exchange with the gateway, so it is pure Node and identical on
// macOS/Windows/Linux. PCP is NAT-PMP's standardized successor (adds IPv6 and longer lifetimes); we try PCP first and
// fall back to NAT-PMP, since a PCP-only or NAT-PMP-only router is common.
//
// SECURITY posture (this protocol is the "UPnProxy" abuse family, so be strict):
//   - Only ever map a WAN port to THIS machine's own LAN IP — never an arbitrary internal host.
//   - Request a SHORT lifetime and renew while serving; delete the mapping on stop. Never leave a permanent hole.
//   - A failure is never fatal: the caller falls through to hole-punch / relay. We never block on it.
// CROSS-PLATFORM / NON-BLOCKING: dgram only; the gateway is the default route (found without a native module); every
// timer is unref'd and every failure resolves (never rejects), so a silent/hostile gateway can never hang a caller.

const dgram = require('dgram');
const os = require('os');
const { execFile } = require('child_process');

const NATPMP_PORT = 5351;       // the gateway port both NAT-PMP and PCP listen on
const DEFAULT_LIFETIME = 3600;  // seconds; short-ish, renewed while serving, deleted on stop
const OP_TIMEOUT_MS = 2500;     // per-attempt timeout — a router that does not speak the protocol just never replies

// ── Gateway discovery (the default route) ──────────────────────────────────────────────────────────
// Node has no built-in "default gateway" API, so read it from the OS route table with a bounded, read-only command
// (never a shell string — execFile with an arg array). Each platform's parse is tiny; all fail closed to null.
function defaultGatewayV4() {
	return new Promise((resolve) => {
		const done = (v) => resolve(v && /^\d{1,3}(\.\d{1,3}){3}$/.test(v) && !v.startsWith('0.') ? v : null);
		const to = setTimeout(() => done(null), 1500); if (to.unref) to.unref();
		const finish = (v) => { clearTimeout(to); done(v); };
		try {
			if (process.platform === 'win32') {
				// "route print 0.0.0.0" → the gateway column on the default-route line.
				execFile('route', ['print', '0.0.0.0'], { timeout: 1500, windowsHide: true }, (err, out) => {
					if (err) return finish(null);
					const m = String(out).match(/\s0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})/);
					finish(m ? m[1] : null);
				});
			} else if (process.platform === 'darwin') {
				execFile('route', ['-n', 'get', 'default'], { timeout: 1500 }, (err, out) => {
					if (err) return finish(null);
					const m = String(out).match(/gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})/);
					finish(m ? m[1] : null);
				});
			} else {
				// Linux: `ip route` default line, or the classic /proc/net/route fallback.
				execFile('ip', ['route'], { timeout: 1500 }, (err, out) => {
					if (!err) { const m = String(out).match(/default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})/); if (m) return finish(m[1]); }
					finish(null);
				});
			}
		} catch (_) { finish(null); }
	});
}

// The primary non-internal IPv4 on the interface that reaches `gateway` (same /24 heuristic; falls back to the first
// LAN IPv4). PCP requires us to state the internal host we are mapping FOR, and we only ever map to our own address.
function localIPv4For(gateway) {
	const gwPrefix = String(gateway || '').split('.').slice(0, 3).join('.') + '.';
	let first = null;
	const ifs = os.networkInterfaces();
	for (const name of Object.keys(ifs || {})) {
		for (const a of ifs[name] || []) {
			if (a && a.family === 'IPv4' && !a.internal && a.address) {
				if (!first) first = a.address;
				if (a.address.startsWith(gwPrefix)) return a.address;
			}
		}
	}
	return first;
}

// One request/response exchange with the gateway on 5351. Sends `payload`, resolves the first datagram (or null on
// timeout/error). The socket is always closed. dgram only; never throws.
function exchange(gateway, payload, timeoutMs = OP_TIMEOUT_MS) {
	return new Promise((resolve) => {
		const sock = dgram.createSocket('udp4');
		let done = false;
		const finish = (v) => { if (done) return; done = true; clearTimeout(t); try { sock.close(); } catch (_) {} resolve(v); };
		const t = setTimeout(() => finish(null), timeoutMs); if (t.unref) t.unref();
		sock.on('error', () => finish(null));
		sock.on('message', (msg) => finish(msg));
		try { sock.send(payload, 0, payload.length, NATPMP_PORT, gateway); } catch (_) { finish(null); }
	});
}

// ── NAT-PMP (RFC 6886) ──────────────────────────────────────────────────────────────────────────────
// Map request: [ version=0, op=1(UDP)|2(TCP), reserved(2)=0, internalPort(2), suggestedExternalPort(2), lifetime(4) ].
// Response:    [ version=0, op=op+128, resultCode(2), epoch(4), internalPort(2), externalPort(2), lifetime(4) ].
function natpmpMapRequest(internalPort, external, lifetime, tcp) {
	const b = Buffer.alloc(12);
	b.writeUInt8(0, 0); b.writeUInt8(tcp ? 2 : 1, 1); b.writeUInt16BE(0, 2);
	b.writeUInt16BE(internalPort, 4); b.writeUInt16BE(external || 0, 6); b.writeUInt32BE(lifetime, 8);
	return b;
}
function natpmpParse(msg, tcp) {
	if (!msg || msg.length < 16 || msg.readUInt8(0) !== 0 || msg.readUInt8(1) !== (tcp ? 130 : 129)) return null;
	if (msg.readUInt16BE(2) !== 0) return null; // non-zero result code = router refused
	return { externalPort: msg.readUInt16BE(10), lifetime: msg.readUInt32BE(12) };
}

// ── PCP (RFC 6887) ──────────────────────────────────────────────────────────────────────────────────
// MAP request (24-byte header + 36-byte MAP opcode). We fill the client's internal IP as an IPv4-mapped IPv6 address
// and a random 96-bit nonce; the gateway echoes the nonce so a response can be tied to our request.
function pcpMapRequest(internalIP, internalPort, external, lifetime, tcp, nonce) {
	const hdr = Buffer.alloc(24);
	hdr.writeUInt8(2, 0);            // version 2 (PCP)
	hdr.writeUInt8(1, 1);            // opcode 1 = MAP, R=0 (request)
	hdr.writeUInt32BE(lifetime, 4);
	// client IP at bytes 8..23 as IPv4-mapped IPv6 (::ffff:a.b.c.d)
	hdr.writeUInt16BE(0xffff, 18);
	const parts = String(internalIP).split('.').map(Number);
	if (parts.length === 4 && parts.every((n) => n >= 0 && n <= 255)) { hdr[20] = parts[0]; hdr[21] = parts[1]; hdr[22] = parts[2]; hdr[23] = parts[3]; }
	const map = Buffer.alloc(36);
	nonce.copy(map, 0, 0, 12);       // mapping nonce (echoed in the response)
	map.writeUInt8(tcp ? 6 : 17, 12); // protocol: 6=TCP, 17=UDP
	map.writeUInt16BE(internalPort, 16);
	map.writeUInt16BE(external || 0, 18);
	// suggested external IP (bytes 20..35): all-zero = "any"
	return Buffer.concat([hdr, map]);
}
function pcpParse(msg, nonce) {
	if (!msg || msg.length < 60 || msg.readUInt8(0) !== 2) return null;
	if ((msg.readUInt8(1) & 0x7f) !== 1 || (msg.readUInt8(1) & 0x80) === 0) return null; // must be a MAP RESPONSE
	if (msg.readUInt8(3) !== 0) return null; // result code != SUCCESS
	if (msg.slice(24, 36).compare(nonce.slice(0, 12)) !== 0) return null; // nonce must match our request
	const lifetime = msg.readUInt32BE(4);
	const externalPort = msg.readUInt16BE(42);
	// external IP is the IPv4-mapped IPv6 at bytes 44..59
	const ip = msg.slice(56, 60);
	const externalIP = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + ip[3];
	return { externalPort, externalIP, lifetime };
}

// NAT-PMP "get external address" (opcode 0). Request [ version=0, op=0 ]; response
// [ version=0, op=128, resultCode(2), epoch(4), externalIP(4) ]. Used to learn the WAN IP after a NAT-PMP map (the
// map response itself does not carry it, unlike PCP).
function natpmpExtRequest() { const b = Buffer.alloc(2); b.writeUInt8(0, 0); b.writeUInt8(0, 1); return b; }
function natpmpExtParse(msg) {
	if (!msg || msg.length < 12 || msg.readUInt8(0) !== 0 || msg.readUInt8(1) !== 128 || msg.readUInt16BE(2) !== 0) return null;
	return msg[8] + '.' + msg[9] + '.' + msg[10] + '.' + msg[11];
}
// Is this a PUBLIC IPv4 — i.e. worth advertising as an internet-reachable candidate? Rejects private (RFC 1918),
// CGNAT (100.64/10), loopback, link-local, and the unspecified/broadcast ends. A double-NAT / CGNAT external address
// is not publicly reachable, so a port mapping there is useless and must not be advertised.
function isPublicIPv4(ip) {
	const m = String(ip || '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	if (!m) return false;
	const o = [+m[1], +m[2], +m[3], +m[4]];
	if (o.some((n) => n > 255)) return false;
	if (o[0] === 10 || o[0] === 127 || o[0] === 0 || o[0] >= 224) return false;
	if (o[0] === 192 && o[1] === 168) return false;
	if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
	if (o[0] === 169 && o[1] === 254) return false;
	if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false; // CGNAT (RFC 6598)
	return true;
}

// Try to map an external WAN port to `internalPort` on this machine (TCP by default — the serve is TCP). Returns
// { externalPort, externalIP?, lifetime, protocol, gateway, internalIP, internalPort } on success, or null. PCP first
// (richer, returns the external IP), then NAT-PMP (with a follow-up query for the external IP). Never throws; a
// router that speaks neither simply yields null.
async function mapPort(internalPort, { lifetime = DEFAULT_LIFETIME, tcp = true, gateway: gwOverride } = {}) {
	if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535) return null;
	const gateway = gwOverride || await defaultGatewayV4(); // gwOverride is for tests; production always discovers the real gateway
	if (!gateway) return null;
	const internalIP = localIPv4For(gateway);
	if (!internalIP) return null;
	// PCP
	const nonce = require('crypto').randomBytes(12);
	const pcpResp = await exchange(gateway, pcpMapRequest(internalIP, internalPort, 0, lifetime, tcp, nonce));
	const pcp = pcpParse(pcpResp, nonce);
	if (pcp && pcp.externalPort) return { externalPort: pcp.externalPort, externalIP: pcp.externalIP && pcp.externalIP !== '0.0.0.0' ? pcp.externalIP : null, lifetime: pcp.lifetime, protocol: tcp ? 'tcp' : 'udp', gateway, internalIP, internalPort };
	// NAT-PMP
	const npResp = await exchange(gateway, natpmpMapRequest(internalPort, 0, lifetime, tcp));
	const np = natpmpParse(npResp, tcp);
	if (np && np.externalPort) {
		let externalIP = null;
		try { externalIP = natpmpExtParse(await exchange(gateway, natpmpExtRequest())); } catch (_) {}
		return { externalPort: np.externalPort, externalIP: externalIP && externalIP !== '0.0.0.0' ? externalIP : null, lifetime: np.lifetime, protocol: tcp ? 'tcp' : 'udp', gateway, internalIP, internalPort };
	}
	return null;
}

// Delete a mapping (lifetime 0), best-effort — used on stop so no permanent hole is left. Never throws.
async function unmapPort(internalPort, { tcp = true } = {}) {
	const gateway = await defaultGatewayV4();
	if (!gateway) return;
	const internalIP = localIPv4For(gateway) || '0.0.0.0';
	const nonce = require('crypto').randomBytes(12);
	try { await exchange(gateway, pcpMapRequest(internalIP, internalPort, 0, 0, tcp, nonce), 1500); } catch (_) {}
	try { await exchange(gateway, natpmpMapRequest(internalPort, 0, 0, tcp), 1500); } catch (_) {}
}

// Keep a mapping alive: map now, then renew at ~half the granted lifetime, and delete on stop. Returns
// { externalPort, externalIP, gateway, stop } once the first map succeeds, or null if it could not be mapped at all.
async function keepMapped(internalPort, { lifetime = DEFAULT_LIFETIME, tcp = true } = {}) {
	const first = await mapPort(internalPort, { lifetime, tcp });
	if (!first) return null;
	let stopped = false, timer = null;
	const schedule = (secs) => { if (stopped) return; timer = setTimeout(renew, Math.max(30, Math.floor(secs / 2)) * 1000); if (timer.unref) timer.unref(); };
	async function renew() { if (stopped) return; const r = await mapPort(internalPort, { lifetime, tcp }); schedule((r && r.lifetime) || lifetime); }
	schedule(first.lifetime || lifetime);
	const stop = async () => { if (stopped) return; stopped = true; if (timer) clearTimeout(timer); await unmapPort(internalPort, { tcp }); };
	return { externalPort: first.externalPort, externalIP: first.externalIP, gateway: first.gateway, internalPort, stop };
}

module.exports = { mapPort, unmapPort, keepMapped, defaultGatewayV4, localIPv4For, isPublicIPv4, NATPMP_PORT, DEFAULT_LIFETIME };
// Test-only: the pure NAT-PMP / PCP wire codecs, so their round-trip and (security-critical) rejection paths can be
// exercised without a real router.
module.exports._proto = { natpmpMapRequest, natpmpParse, natpmpExtRequest, natpmpExtParse, pcpMapRequest, pcpParse };
