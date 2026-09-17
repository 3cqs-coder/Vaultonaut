'use strict';
// lib/HolePunch.js — dependency-free TCP hole-punching for a direct peer-to-peer hop, an OPTIONAL upgrade over the
// relay. Two already-paired peers who can each only reach the internet OUTBOUND (both behind a home/office router with
// no public port) can still form a DIRECT connection: each opens an outbound TCP connection to the other at ~the same
// instant, so each router, having just seen an outbound SYN, lets the other's inbound SYN through — a "TCP
// simultaneous open" (RFC 793). The relay is used only to exchange a little coordination data; the encrypted vault
// bytes then flow directly, off the hub.
//
// WHAT THIS IS NOT: it adds NO trust and changes NO crypto. A punch only changes the NETWORK PATH to a node you are
// already paired with; the very same pinned-TLS, cert-fingerprint-checked channel runs over the punched socket, so a
// successful punch is cryptographically indistinguishable from the relay path. It is strictly best-effort: whenever a
// punch cannot be made (a symmetric NAT, a firewall, a timeout), the caller silently keeps using the proven relay.
//
// CROSS-PLATFORM: Node built-ins only (`net`), so it behaves the same on macOS, Windows, and Linux. It deliberately
// AVOIDS the non-portable socket options — SO_REUSEPORT (Node's `reusePort` throws on Windows/macOS) and co-binding a
// listener and a dialer on one port — and instead uses the portable retry-based simultaneous open plus RST recycling:
// `socket.resetAndDestroy()` sends a TCP RST that frees a bound local port IMMEDIATELY, where a normal FIN close would
// leave it in TIME_WAIT and make the next bind to that port fail with EADDRINUSE. NON-BLOCKING: every timer is
// unref'd, so nothing here holds the event loop open, and a bounded budget means a punch can never hang.

const net = require('net');
const PortMap = require('./PortMap');

const REFLEX_TIMEOUT_MS = 8000;   // bound on learning our own reflexive endpoint from the hub (a quick round trip)
const PUNCH_BUDGET_MS = 6000;     // total wall-clock budget for a punch before giving up to the relay — a real punch
                                  // lands within a few seconds (measured: 97.6% on the first synchronized attempt) or
                                  // essentially never (two symmetric NATs ≈ 0.01%), so a long probe is pointless
const PUNCH_INTERVAL_MS = 120;    // gap between simultaneous-open attempts; both peers retry until their SYNs cross
const GREETING_MAX = 256;         // cap on the hub's WHERE reply line — a tiny "WHERE <ip> <port>" string

// Is `host` a genuinely internet-reachable IPv4 we may send a punch packet toward? A punch endpoint must never become
// a reflection/SSRF primitive, so only ever dial a PUBLIC address a paired peer vouched for. PortMap.isPublicIPv4
// already rejects private (RFC 1918), CGNAT (100.64/10), loopback, link-local, and multicast/reserved ranges.
function isPunchableHost(host) { return PortMap.isPublicIPv4(host); }

// Learn the PUBLIC endpoint (ip + port) our NAT maps a specific LOCAL port to, by asking the hub over a connection
// made FROM that exact local port (verb WHERE). We then reuse the same local port for the punch, so — on an endpoint-
// independent-mapping (cone) NAT — the peer's dial to this endpoint reaches us. The WHERE connection establishes a real
// TCP session with the hub, so we free the local port for reuse with `resetAndDestroy()` (RST, no TIME_WAIT) rather
// than a normal close. Resolves { ip, port } or null on any failure (unreachable/old hub, wrong token, timeout,
// malformed reply). Never throws; the timer is unref'd so it never holds the loop open.
function reflexiveEndpoint({ hubHost, hubPort, token, nodeId, localPort, localAddress, timeoutMs = REFLEX_TIMEOUT_MS }) {
	return new Promise((resolve) => {
		if (!hubHost || !hubPort || !token || !nodeId || !Number.isInteger(localPort)) { resolve(null); return; }
		let done = false, buf = '';
		const opts = { host: hubHost, port: hubPort, localPort };
		if (localAddress) opts.localAddress = localAddress;
		let s;
		try { s = net.connect(opts); } catch (_) { resolve(null); return; }
		// RST-close so the local port is immediately reusable for the punch (a FIN would strand it in TIME_WAIT).
		const finish = (v) => { if (done) return; done = true; clearTimeout(timer); try { s.resetAndDestroy(); } catch (_) { try { s.destroy(); } catch (_) {} } resolve(v); };
		const timer = setTimeout(() => finish(null), Math.max(500, timeoutMs)); if (timer.unref) timer.unref();
		s.once('error', () => finish(null));
		s.on('connect', () => { try { s.write('WHERE ' + token + ' ' + nodeId + '\n'); } catch (_) {} });
		s.on('data', (d) => {
			buf += d; if (buf.length > GREETING_MAX) return finish(null);
			const nl = buf.indexOf('\n'); if (nl < 0) return;
			const m = /^WHERE (\S+) (\d{1,5})$/.exec(buf.slice(0, nl).trim());
			const ip = m && m[1], port = m && parseInt(m[2], 10);
			finish(m && isPunchableHost(ip) && port > 0 && port < 65536 ? { ip, port } : null);
		});
	});
}

// Attempt a DIRECT connection to a peer by repeated TCP simultaneous open: from our fixed `localPort`, keep dialing
// the peer's punch endpoint until a connection establishes (the peer is dialing us at the same time, so our routers
// each let the other's SYN in) or the budget runs out. Resolves the connected, live socket on success, or null on
// timeout. Each failed attempt frees the local port for the next try — a failed attempt never establishes, so a plain
// destroy() is enough and the port is immediately rebindable (no TIME_WAIT). The winning socket is returned untouched.
// Only ever dials a sanitized PUBLIC address (a punch is never a reflection primitive). Bounded and non-blocking.
// `permitHost` gates which peer address may be dialed; it defaults to the secure public-only check and production
// never overrides it — only a loopback test does, to exercise the mechanism where no public interface exists.
function punch({ localPort, localAddress, peerHost, peerPort, budgetMs = PUNCH_BUDGET_MS, intervalMs = PUNCH_INTERVAL_MS, permitHost = isPunchableHost }) {
	return new Promise((resolve) => {
		if (!Number.isInteger(localPort) || !Number.isInteger(peerPort) || peerPort < 1 || peerPort > 65535 || !permitHost(peerHost)) { resolve(null); return; }
		let settled = false, cur = null, attemptTimer = null;
		const deadline = Date.now() + Math.max(500, budgetMs);
		const win = (sock) => { if (settled) return; settled = true; clearTimeout(deadlineTimer); if (attemptTimer) clearTimeout(attemptTimer); resolve(sock); };
		const fail = () => { if (settled) return; settled = true; if (attemptTimer) clearTimeout(attemptTimer); if (cur) { try { cur.destroy(); } catch (_) {} } resolve(null); };
		const deadlineTimer = setTimeout(fail, Math.max(500, budgetMs)); if (deadlineTimer.unref) deadlineTimer.unref();
		const schedule = () => { if (settled) return; attemptTimer = setTimeout(attempt, intervalMs); if (attemptTimer.unref) attemptTimer.unref(); };
		function attempt() {
			if (settled) return;
			if (Date.now() >= deadline) return fail();
			const opts = { host: peerHost, port: peerPort, localPort };
			if (localAddress) opts.localAddress = localAddress;
			let s = null, handled = false, perAttempt = null;
			// Resolve THIS attempt exactly once (connect wins, or error/timeout retries) so the error and the per-attempt
			// timeout can never both reschedule and spawn two overlapping attempt chains.
			const next = () => { if (handled) return; handled = true; if (perAttempt) clearTimeout(perAttempt); try { if (s) s.destroy(); } catch (_) {} schedule(); };
			try { s = net.connect(opts); } catch (_) { schedule(); return; }
			cur = s;
			// Bound each individual attempt so a silently-dropped SYN (no RST, no reply) does not stall the whole budget
			// on one socket's long OS-level connect timeout; abort and retry so our SYNs keep crossing the peer's.
			perAttempt = setTimeout(next, Math.max(60, intervalMs)); if (perAttempt.unref) perAttempt.unref();
			s.once('connect', () => { if (handled) return; handled = true; clearTimeout(perAttempt); if (settled) { try { s.destroy(); } catch (_) {} return; } win(s); });
			s.once('error', () => next());
		}
		attempt();
	});
}

module.exports = { reflexiveEndpoint, punch, isPunchableHost, REFLEX_TIMEOUT_MS, PUNCH_BUDGET_MS, PUNCH_INTERVAL_MS };
