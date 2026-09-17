'use strict';
// lib/LanDiscovery.js — zero-dependency LAN peer discovery for direct, server-less device-to-device transport.
//
// WHAT IT IS: a tiny UDP-broadcast announce/listen protocol so two Vaultonaut devices on the SAME network find each
// other with nothing to configure. A serving node periodically broadcasts a small packet — { nodeId, port, fp } —
// and a peer that already holds that node's connect code (so it is already authorized) hears it, matches the node's
// TLS-cert fingerprint, and connects DIRECTLY to the serve port over the existing pinned-TLS WebDAV channel. No
// relay, no hole-punch, no servers.
//
// WHAT IT IS NOT: it adds NO trust. An announcement only reveals the *address* of a node; a peer connects only to a
// node it already paired with (matched by the cert fingerprint of the `ca` it stored from the connect code), and the
// existing --ca-cert pin still guards the actual transfer. The packet never mentions vaults, names, or contents, so
// a passive listener on the LAN learns only that "a Vaultonaut node with fingerprint X is at address Y:port".
//
// CROSS-PLATFORM: Node built-ins only (`dgram`, `crypto`) — identical on macOS/Windows/Linux, no native module, no
// spawned binary. It binds 0.0.0.0 and sends to the global broadcast address AND loopback, so same-host discovery
// works even where subnet broadcast is restricted. Every socket error (e.g. a Windows firewall blocking broadcast)
// degrades SILENTLY — discovery simply finds nothing and the caller falls back to the relay, never breaking.
// NON-BLOCKING: all timers are unref'd so discovery never holds the event loop open, and nothing here is *Sync.

const dgram = require('dgram');
const crypto = require('crypto');

// A fixed UDP port for the protocol; low enough to be memorable, distinct from the UI (7420) / relay (7443) ports.
const DISCOVERY_PORT = 7421;
const MAGIC = 'VDLAN1';            // protocol + version tag; bump the digit for an incompatible packet change
const ANNOUNCE_INTERVAL_MS = 3000; // re-announce cadence, so a peer that starts listening later still finds a node
const MAX_PACKET = 512;            // hard cap on an accepted datagram — an announcement is tiny; anything larger is junk
// Freshness window for the optional per-packet timestamp (`ts`): a packet whose clock is more than this far from ours
// is treated as stale and dropped. It bounds trivial replay of a captured announcement and tolerates modest clock
// skew between two LAN devices. Generous, because discovery adds no trust — the cert-fingerprint pin, not this check,
// is what guards the actual connection; this only avoids following a stale address.
const MAX_SKEW_MS = 30000;
const SEEN_MAX = 512;              // cap on remembered recent nonces, so the de-dup map can never grow unbounded
// Default send targets: the global broadcast address (reaches the LAN) and loopback (reaches another process on THIS
// host even if broadcast is firewalled). Subnet-directed broadcast is not required for the common same-Wi-Fi case.
const DEFAULT_TARGETS = ['255.255.255.255', '127.0.0.1'];

// The SHA-256 fingerprint of a cert PEM (e.g. "AB:CD:…"), used to match an announcement to a stored peer's `ca`.
// Returns null on any parse failure — a caller treats "no fingerprint" as "cannot match", i.e. fail closed.
function certFp(certPem) {
	try { return new crypto.X509Certificate(certPem).fingerprint256; } catch (_) { return null; }
}

// Announce this node's presence on the LAN. `nodeId` is the stable serve node id, `port` the serve's TCP port, `fp`
// the serve cert's fingerprint (so a peer can verify which node it is without any secret). Returns { stop }. Safe to
// call when broadcast is unavailable — it just never reaches anyone. Never throws.
function announce({ nodeId, port, fp = null, intervalMs = ANNOUNCE_INTERVAL_MS, discoveryPort = DISCOVERY_PORT, targets = DEFAULT_TARGETS }) {
	if (typeof nodeId !== 'string' || !Number.isInteger(port)) throw new Error('announce needs { nodeId: string, port: integer }');
	const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
	let timer = null, stopped = false;
	// Each datagram carries a fresh timestamp and random nonce so a listener can drop a stale replay and collapse the
	// duplicate copies we intentionally send (broadcast + loopback). Both are additive: an older/minimal listener that
	// does not understand them simply ignores the extra fields, and a listener that does enforces them only when present.
	const packet = () => Buffer.from(JSON.stringify({ m: MAGIC, id: nodeId, port, fp: fp || undefined, ts: Date.now(), n: crypto.randomBytes(8).toString('hex') }), 'utf8');
	function stop() {
		if (stopped) return; stopped = true;
		if (timer) { clearInterval(timer); timer = null; }
		try { sock.close(); } catch (_) {}
	}
	// A send error to one target (e.g. broadcast blocked) must not kill the others or the interval.
	function sendOnce() {
		if (stopped) return;
		const b = packet();
		for (const t of targets) { try { sock.send(b, 0, b.length, discoveryPort, t); } catch (_) {} }
	}
	sock.on('error', () => stop()); // bind/permission failure → give up silently; caller degrades to the relay
	sock.bind(() => {                // ephemeral local port; we only send
		if (stopped) return;
		try { sock.setBroadcast(true); } catch (_) {}
		sendOnce();
		timer = setInterval(sendOnce, Math.max(500, intervalMs));
		if (timer.unref) timer.unref();  // never hold the process open just to announce
	});
	return { stop };
}

// Listen for announcements. `onPeer({ nodeId, host, port, fp })` fires for each valid packet; `host` is the SENDER's
// address (from the datagram, not the packet body — so it cannot be spoofed within the payload). Returns { stop }.
// Never throws; a malformed or oversized packet is ignored.
function browse(onPeer, { discoveryPort = DISCOVERY_PORT } = {}) {
	const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
	let stopped = false;
	// Recently-seen nonces → expiry time, so a replayed or intentionally-duplicated (broadcast + loopback) datagram is
	// processed at most once within the freshness window. Bounded: pruned on each hit and hard-capped at SEEN_MAX.
	const seen = new Map();
	function fresh(o) {
		// Backward compatible: a packet without a timestamp/nonce (an older or minimal sender) is accepted as before.
		if (typeof o.ts === 'number' && Math.abs(Date.now() - o.ts) > MAX_SKEW_MS) return false; // stale/replayed
		if (typeof o.n === 'string') {
			const now = Date.now();
			for (const [k, exp] of seen) { if (exp <= now) seen.delete(k); } // prune expired
			if (seen.has(o.n)) return false;                                 // duplicate within the window
			if (seen.size >= SEEN_MAX) { const first = seen.keys().next().value; if (first !== undefined) seen.delete(first); }
			seen.set(o.n, now + MAX_SKEW_MS);
		}
		return true;
	}
	function stop() { if (stopped) return; stopped = true; seen.clear(); try { sock.close(); } catch (_) {} }
	sock.on('error', () => stop()); // e.g. the port is unavailable → discovery simply finds nothing
	sock.on('message', (msg, rinfo) => {
		if (stopped || !msg || msg.length > MAX_PACKET) return;
		let o; try { o = JSON.parse(msg.toString('utf8')); } catch (_) { return; }
		if (!o || o.m !== MAGIC || typeof o.id !== 'string' || !Number.isInteger(o.port) || o.port < 1 || o.port > 65535) return;
		if (!fresh(o)) return; // drop a stale replay or a duplicate copy of a packet we already delivered
		try { onPeer({ nodeId: o.id, host: rinfo.address, port: o.port, fp: typeof o.fp === 'string' ? o.fp : null }); } catch (_) {}
	});
	sock.bind(discoveryPort, () => { try { sock.setBroadcast(true); } catch (_) {} });
	return { stop };
}

// One-shot lookup: resolve the first announcement for which `match(peer)` is truthy, within `timeoutMs`, else null.
// Used at connect time to find a paired node's CURRENT LAN address (matched by cert fingerprint) before falling back
// to the stored/relay address. Always resolves (never rejects); tears down its socket and timer on either path.
function find(match, { timeoutMs = 2500, discoveryPort = DISCOVERY_PORT } = {}) {
	return new Promise((resolve) => {
		let done = false;
		const finish = (val) => { if (done) return; done = true; clearTimeout(timer); b.stop(); resolve(val); };
		const b = browse((peer) => { let ok = false; try { ok = !!match(peer); } catch (_) {} if (ok) finish(peer); }, { discoveryPort });
		const timer = setTimeout(() => finish(null), Math.max(200, timeoutMs));
		if (timer.unref) timer.unref();
	});
}

module.exports = { announce, browse, find, certFp, DISCOVERY_PORT, MAGIC, ANNOUNCE_INTERVAL_MS, MAX_PACKET, MAX_SKEW_MS };
