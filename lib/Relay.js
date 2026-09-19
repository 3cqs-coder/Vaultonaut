'use strict';
// lib/Relay.js — Tier 2 turn-key relay. Reach a node that is behind NAT (no public IP, no port
// forwarding) through a small self-hosted HUB on a machine with a public address (a cheap VPS). Both
// the node and the client reach the hub OUTBOUND, so neither needs an open inbound port. The hub
// splices a client connection to one of the node's pre-opened worker connections; the node then pipes
// that to its own local (loopback) WebDAV serve. Dependency-free — raw TCP over Node's `net`, modeled
// on the in-house relay-tunnel pattern.
//
// Design notes:
//   • The CLIENT needs no relay code at all: the hub gives each node a public port, and the client
//     simply mirrors to http://<hub>:<port>/ like any other peer. All the tunnelling lives on the node
//     and the hub.
//   • No multiplexing framing: each client TCP connection consumes one whole worker connection (a
//     simple splice). The node keeps a small pool of spare workers and replenishes as they are used.
//   • Resilient: the node reconnects to the hub with exponential backoff if the link drops, and keeps
//     the worker pool topped up. Non-blocking throughout.
//   • Security posture: only CIPHERTEXT ever crosses the relay (the vault's password and plaintext
//     never transit — zero-knowledge holds regardless of the hub). A shared token gates who may
//     register/connect. The token and the serve's basic-auth credential travel in the clear over the
//     hub link, so for an UNTRUSTED network run the hub over a VPN or behind a TLS terminator; the
//     encrypted vault contents are safe either way.

const net = require('net');
const crypto = require('crypto');
const Common = require('./Common');
const Tunnel = require('./Tunnel'); // the stream multiplexer; the optional relay-mux path carries many client streams over one node link

const GREETING_MAX = 512;         // a greeting line is tiny; cap it so a stray client can't buffer forever
const GREETING_TIMEOUT_MS = 8000; // a handshake must complete promptly; a silent/dribbling peer is dropped
const WORKER_WAIT_MS = 10000;     // how long the hub holds a client while waiting for a free worker
const DEFAULT_POOL = 8;           // spare worker connections the node keeps ready
const MAX_WAITERS = 64;           // cap on clients queued for a node's workers, so a connection flood can't grow the backlog (or amplify into local serve connections) without limit
const MAX_WORKERS = 64;           // cap on pooled worker connections per node, so a token holder can't grow memory/file descriptors without limit (a node keeps only DEFAULT_POOL ready; this is generous headroom)
const MAX_PENDING = 256;          // cap on UNAUTHENTICATED sockets in the greeting window at once, so an accept flood can't exhaust the public hub's file descriptors before auth
const MAX_ACTIVE_SPLICES = 256;   // cap on CONCURRENT live spliced connections per node, so a hostile hub (node side) or a client flood (hub side) can't accumulate unbounded loopback-serve connections/file descriptors: the queue and pool caps above bound only what is WAITING/IDLE, not what is established, so track and bound the established splices too
const RECONNECT_BASE_MS = 2000, RECONNECT_MAX_MS = 30000;
const SPLICE_IDLE_MS = 5 * 60 * 1000; // drop a spliced connection after this long with NO data in either direction, so an unauthenticated client that reaches a node's public port and then idles cannot tie up a pooled worker (and its downstream local serve connection) indefinitely; generous so a real pause between requests is fine, and reset on any activity (below) so a slow-but-active transfer is never cut
const MIN_TOKEN_LEN = 16;          // the shared token is the ONLY control-plane gate on a public hub, so refuse to run with a guessably-short one (16 random chars ≈ 80+ bits; the auto-generated token is 20 hex)
const MAX_NODES = 256;             // cap on TOTAL registered nodes, so one token holder cannot register enough distinct node ids to exhaust the public port range and its listening sockets/file descriptors
const MAX_NODES_PER_IP = 16;       // cap on registered nodes from a single source IP, so one host cannot monopolize the hub's port range even under the total cap
const AUTH_FAIL_WINDOW_MS = 60000; // window over which failed-auth attempts from one source IP are counted
const AUTH_FAIL_MAX = 20;          // failed auths from one IP within the window before that IP is blocked — brute-forcing the shared token is then rate-limited to this many tries per cooldown
const AUTH_BLOCK_MS = 5 * 60 * 1000; // how long a source IP that trips the failed-auth ceiling is refused before it may try again
const AUTH_TRACK_MAX = 4096;       // cap on how many source IPs the failed-auth tracker holds at once, so the tracker itself cannot be grown without bound by a spoofed-source flood
const SIGNAL_MAX = 1024;           // cap on a single relayed signaling blob (opaque to the hub — endpoints + a nonce; small), so the SIGNAL routing path cannot be used to shovel bulk data through the control plane
const SIGNAL_TIMEOUT_MS = 10000;   // how long the hub holds a client's SIGNAL waiting for the node's reply before giving up — a hole-punch coordination round trip is quick or it is abandoned to the relay
const SIGNAL_MAX_PENDING = 128;    // cap on in-flight SIGNAL exchanges awaiting a node reply at once, so the signaling path cannot be flooded to grow hub memory
const SIGNAL_MAX_PENDING_PER_NODE = 8; // cap on in-flight SIGNALs targeting ONE node, so a single hostile paired client cannot fill the global pending pool and deny hole-punch signaling to every other node's clients

// Read a single newline-terminated ASCII greeting from a socket, then hand back the socket plus any
// bytes that arrived after the newline (there should be none before the handshake completes). A handshake
// DEADLINE bounds it: if no complete greeting arrives in time, the socket is destroyed and the callback
// gets an error. This is the watchdog for two attacks TCP keepalive cannot stop — a slowloris dribbling
// bytes to hold a public-hub file descriptor open, and a hub (or peer) that accepts the socket but never
// sends its line, which would otherwise park a node's worker/control socket forever. Destroying the socket
// also makes each caller's error/close path run (freeing the pool slot, resuming the reconnect loop).
function readGreeting(sock, cb) {
	let buf = Buffer.alloc(0); let done = false;
	const finish = (err, line, rest) => { if (done) return; done = true; clearTimeout(timer); sock.removeListener('data', onData); cb(err, line, rest); };
	const onData = (chunk) => {
		if (done) return;
		buf = Buffer.concat([buf, chunk]);
		const nl = buf.indexOf(0x0a);
		if (nl >= 0) finish(null, buf.slice(0, nl).toString('utf8').trim(), buf.slice(nl + 1));
		else if (buf.length > GREETING_MAX) finish(new Error('greeting too long'));
	};
	const timer = setTimeout(() => { if (!done) { finish(new Error('greeting timed out')); try { sock.destroy(); } catch (_) {} } }, GREETING_TIMEOUT_MS);
	if (timer.unref) timer.unref();
	sock.on('data', onData);
	sock.once('error', () => finish(new Error('closed')));
	sock.once('close', () => finish(new Error('closed')));
}

// Read newline-delimited lines from a socket CONTINUOUSLY (unlike readGreeting's one-shot line), invoking onLine for
// each complete line — trimmed, without the newline. Used AFTER the one-shot greeting to carry the optional post-
// registration signaling frames on the persistent control socket, on both the hub and node sides. Each buffered
// partial line is bounded: a run of more than `max` bytes with no newline is dropped rather than buffered forever, so
// a peer cannot grow memory on the control plane. An optional `initial` buffer (any bytes read alongside the greeting)
// is processed first. Returns a detach function. Never throws (a throwing onLine is swallowed so one bad frame cannot
// tear the reader down).
function readLines(sock, onLine, { max = GREETING_MAX, initial = null } = {}) {
	let buf = initial && initial.length ? Buffer.from(initial) : Buffer.alloc(0);
	const pump = () => {
		let nl;
		while ((nl = buf.indexOf(0x0a)) >= 0) { const line = buf.slice(0, nl).toString('utf8').trim(); buf = buf.slice(nl + 1); try { onLine(line); } catch (_) {} }
		if (buf.length > max) buf = Buffer.alloc(0); // over-long partial line with no newline → drop, never buffer without bound
	};
	const onData = (chunk) => { buf = Buffer.concat([buf, chunk]); pump(); };
	sock.on('data', onData);
	if (buf.length) pump();
	return () => { try { sock.removeListener('data', onData); } catch (_) {} };
}

// Constant-time token check. The hub is designed to run on a public host, so authenticate the shared
// token without leaking its length or shared-prefix through comparison timing: hash both sides to a
// fixed 32 bytes and compare those. Mirrors the timing-safe comparisons used elsewhere in the tool.
function tokenMatch(presented, expected) {
	return Common.timingSafeEqualHashed(presented, expected);
}

// The reconnect delay for the Nth attempt (1-based): exponential backoff, capped at RECONNECT_MAX_MS, with EQUAL
// JITTER. Many nodes can lose the same hub at the same instant (a hub restart or a shared-uplink blip); without jitter
// they would all back off by the identical schedule and reconnect in synchronized waves, hammering the hub just as it
// comes back. Equal jitter keeps half the delay deterministic — so backoff still grows and a retry is never near-
// instant — and randomizes the other half, spreading reconnects evenly across [cap/2, cap]. `rnd` is injectable so a
// test can pin the randomness.
function reconnectDelay(attempt, rnd = Math.random) {
	const cap = Math.min(RECONNECT_BASE_MS * Math.pow(2, Math.min(Math.max(1, attempt) - 1, 6)), RECONNECT_MAX_MS);
	const half = cap / 2;
	return Math.floor(half + rnd() * half);
}

// A per-node authentication tag that binds a nodeId to a secret only that node holds, so a node identity cannot be
// hijacked by another party that merely knows the shared hub token. The node derives tag = HMAC-SHA256(nodeAuth,
// nodeId); the hub records the tag on a node's first registration and, while that node is live, refuses any HELLO
// or WORKER for the same nodeId whose tag does not match — instead of blindly evicting the live node. The tag is
// deterministic in (nodeAuth, nodeId), so a node reconnecting after a flaky link presents the same tag and is
// correctly recognized as itself. The nodeAuth secret is stable per served vault (persisted), never transmitted.
function nodeTag(nodeAuth, nodeId) {
	return crypto.createHmac('sha256', String(nodeAuth)).update('node:' + String(nodeId)).digest('hex');
}

// A per-node SIGNAL credential: a secret that authorizes coordinating a hole-punch to ONE specific node (its SIGNAL
// and WHERE verbs), and nothing else — never registering a node or affecting any other node. It is derived from the
// same per-node secret as the tag but over a distinct label, so it cannot be confused with the tag, and it is handed
// to a paired client inside that node's connect code. Giving a client this credential lets it upgrade its relayed
// session to a direct one WITHOUT ever holding the hub's registration token, keeping the blast radius to that node.
function signalCredential(nodeAuth, nodeId) {
	return crypto.createHmac('sha256', String(nodeAuth)).update('signal:' + String(nodeId)).digest('hex');
}

// Bidirectionally splice two sockets; destroy both when either ends, or after an idle period with no data in
// EITHER direction. The idle timer is reset on data from either side (a socket's own setTimeout resets only on
// reads, which would wrongly cut a one-directional download, so track activity from both 'data' events instead).
// Pure Node timers and streams — cross-platform, no dependency. `idleMs` is overridable so a test can exercise it
// quickly; the internal callers use the generous default.
function splice(a, b, idleMs = SPLICE_IDLE_MS, onEnd = null) {
	let dead = false, idle = null;
	const kill = () => { if (dead) return; dead = true; if (idle) clearTimeout(idle); try { a.destroy(); } catch (_) {} try { b.destroy(); } catch (_) {} if (onEnd) { try { onEnd(); } catch (_) {} } }; // onEnd fires exactly once, so a caller can count concurrent live splices and release its slot
	const arm = () => { if (dead) return; if (idle) clearTimeout(idle); idle = setTimeout(kill, idleMs); if (idle.unref) idle.unref(); }; // never keep the event loop alive for a pending idle timeout
	a.on('error', kill); b.on('error', kill); a.on('close', kill); b.on('close', kill);
	a.on('data', arm); b.on('data', arm); // any data in either direction resets the idle clock (a slow-but-active transfer is never cut; only a fully idle connection is reaped)
	arm();
	a.pipe(b); b.pipe(a);
}

// ── Hub ─────────────────────────────────────────────────────────────────────────────────────────
// Run the relay hub. Nodes connect to `controlPort` and register; clients connect to the per-node
// public port the hub assigns. Returns { close } to stop it.
function runHub({ controlPort = Common.DEFAULT_RELAY_PORT, token, host = '0.0.0.0', portRange = Common.DEFAULT_RELAY_DATA_PORT_RANGE, onLog, maxActiveSplices = MAX_ACTIVE_SPLICES, maxNodes = MAX_NODES, maxNodesPerIp = MAX_NODES_PER_IP, mux } = {}) {
	// Relay multiplexing: carry every client connection for a node as a logical STREAM over ONE persistent node link,
	// instead of a whole fresh worker TCP per client (fewer VPS handshakes, no worker-pool churn). It is NEGOTIATED and
	// additive — used only when BOTH the node and the hub support it, and either side transparently falls back to the
	// classic worker-pool splice otherwise — so it never affects an older peer. On by default; opt out with
	// VAULTONAUT_RELAY_MUX=0 (or mux:false). The mux carries the same already-encrypted, pinned-TLS bytes the splice
	// does, so it is cryptographically identical.
	const muxEnabled = mux != null ? !!mux : (process.env.VAULTONAUT_RELAY_MUX !== '0');
	if (!token) throw new Error('A relay token is required (share it with your nodes).');
	// The token is the ONLY thing standing between the public internet and node registration, so refuse to run with
	// one short enough to brute-force. Combined with the per-IP failed-auth throttle below, this keeps the control
	// plane from being guessed open.
	if (String(token).length < MIN_TOKEN_LEN) throw new Error('The relay token is too short to be safe on a public hub (needs at least ' + MIN_TOKEN_LEN + ' characters). Use a longer, random token — for example run the hub with no token and it will generate a strong one for you.');
	const log = (m) => { try { if (onLog) onLog(m); } catch (_) {} };
	const nodes = new Map(); // nodeId -> { publicServer, publicPort, workers, control, authTag, ip }
	// In-flight hole-punch SIGNAL exchanges: sid -> { client, timer }. A client's SIGNAL is parked here awaiting the
	// target node's SIGNALREPLY (routed back over the node's control socket). Bounded by SIGNAL_MAX_PENDING and each
	// entry self-expires, so the signaling path cannot grow hub memory.
	const signals = new Map();
	const signalsPerNode = new Map(); // target nodeId -> count of its currently-pending signals (bounds one client denying signaling to all nodes)
	// Remove a pending signal by id: clear its timer, decrement the per-node counter, and optionally send a final line
	// to the waiting client. Central so every teardown path (reply, timeout, socket close, forward error, hub close)
	// stays consistent and the per-node counter can never leak.
	function dropSignal(sid, endMsg) {
		const e = signals.get(sid); if (!e) return null;
		signals.delete(sid);
		try { clearTimeout(e.timer); } catch (_) {}
		if (e.node) { const c = (signalsPerNode.get(e.node) || 1) - 1; if (c > 0) signalsPerNode.set(e.node, c); else signalsPerNode.delete(e.node); }
		if (endMsg && e.client) { try { e.client.end(endMsg); } catch (_) {} }
		return e;
	}
	const span = portRange[1] - portRange[0] + 1;
	const nodesPerIp = new Map(); // source IP -> count of its currently-registered nodes (bounds port-range monopolization per host)
	// Per-source-IP failed-auth throttle. A correct constant-time token check does not, by itself, stop an attacker
	// serially reconnecting to brute-force the token (MAX_PENDING bounds only CONCURRENT pre-auth sockets). Track
	// recent failures per IP and refuse a source that trips the ceiling for a cooldown. The map is pruned and hard-
	// capped so the tracker itself cannot be grown without bound by a spoofed-source flood.
	const authFails = new Map(); // ip -> { count, first, until }
	function ipBlocked(ip) { const e = authFails.get(ip); return !!(e && e.until && Date.now() < e.until); }
	function noteAuthFail(ip) {
		if (!ip) return;
		const now = Date.now();
		let e = authFails.get(ip);
		if (!e || now - e.first > AUTH_FAIL_WINDOW_MS) { e = { count: 0, first: now, until: 0 }; authFails.set(ip, e); }
		e.count++;
		if (e.count >= AUTH_FAIL_MAX) { e.until = now + AUTH_BLOCK_MS; log('blocking ' + ip + ' after repeated relay auth failures'); }
		if (authFails.size > AUTH_TRACK_MAX) { for (const [k, v] of authFails) { if (!(v.until && now < v.until)) authFails.delete(k); if (authFails.size <= AUTH_TRACK_MAX) break; } }
	}
	function noteAuthOk(ip) { if (ip) authFails.delete(ip); } // a genuine node clears its slate
	const sweep = setInterval(() => { const now = Date.now(); for (const [k, v] of authFails) if (!(v.until && now < v.until) && now - v.first > AUTH_FAIL_WINDOW_MS) authFails.delete(k); }, AUTH_FAIL_WINDOW_MS);
	if (sweep.unref) sweep.unref();

	// A stable public port per node id (a hash into the range), so a node keeps the same public
	// address across reconnects and its clients' saved peer URLs stay valid. Falls back to the next
	// free port only if the preferred one is taken by a different live node.
	function allocPort(nodeId) {
		const preferred = portRange[0] + (parseInt(Common.sha256Hex(nodeId).slice(0, 8), 16) % span);
		for (let i = 0; i < span; i++) {
			const p = portRange[0] + ((preferred - portRange[0] + i) % span);
			if (![...nodes.values()].some(n => n.publicPort === p)) return p;
		}
		return null;
	}

	// Route a node's SIGNALREPLY (its hole-punch answer, keyed by the sid the hub assigned) back to the client that is
	// parked waiting on that sid. The blob stays opaque to the hub. Unknown/expired sids are simply ignored.
	function deliverSignalReply(sid, blob) {
		const e = dropSignal(sid); if (!e) return;
		try { e.client.end('SIGNAL ' + blob + '\n'); } catch (_) {}
	}

	function dropNode(nodeId) {
		const n = nodes.get(nodeId); if (!n) return;
		nodes.delete(nodeId);
		if (n.detachControl) { try { n.detachControl(); } catch (_) {} }
		if (n.ip) { const c = (nodesPerIp.get(n.ip) || 1) - 1; if (c > 0) nodesPerIp.set(n.ip, c); else nodesPerIp.delete(n.ip); }
		try { n.publicServer.close(); } catch (_) {}
		for (const w of n.workers) { try { w.destroy(); } catch (_) {} }
		if (n.muxLink) { try { n.muxLink.stop(); } catch (_) {} }
		try { n.control.destroy(); } catch (_) {}
		log('node "' + nodeId + '" disconnected');
	}

	// Drop a client connection that opens a mux stream and then goes silent, matching the splice path's idle reaper: an
	// unauthenticated public-port client cannot tie up a stream (and its downstream local-serve connection) forever.
	// Reset on any activity, so a slow-but-active transfer is never cut. The timer is unref'd.
	function guardIdle(sock, idleMs = SPLICE_IDLE_MS) {
		let t = null;
		const arm = () => { if (t) clearTimeout(t); t = setTimeout(() => { try { sock.destroy(); } catch (_) {} }, idleMs); if (t.unref) t.unref(); };
		sock.on('data', arm); sock.once('close', () => { if (t) clearTimeout(t); });
		arm();
	}

	// A mux-negotiated node's single data link. Verify it belongs to a live node (same per-node tag, exactly like a
	// WORKER), then carry every subsequent client for that node as a stream over it. If clients were waiting for a
	// worker, drain them onto the mux now. Replaces any prior link for this node (a reconnect on a flaky mux socket).
	function attachMux(sock, nodeId, tag) {
		const n = nodes.get(nodeId);
		if (!n) { try { sock.destroy(); } catch (_) {} return; }
		if (!tokenMatch(String(tag || ''), String(n.authTag || ''))) { try { sock.destroy(); } catch (_) {} return; }
		if (n.muxLink) { try { n.muxLink.stop(); } catch (_) {} n.muxLink = null; }
		const mux = Tunnel.muxClient(sock, { onDown: () => { if (n.muxLink === mux) n.muxLink = null; } });
		n.muxLink = mux;
		while (n.waiters.length) {
			if (n.active + mux.count() >= maxActiveSplices) break;
			const waiter = n.waiters.shift();
			guardIdle(waiter.client); mux.openStream(waiter.client);
		}
	}

	function registerNode(control, nodeId, tag, ip, signalCred, wantMux) {
		const existing = nodes.get(nodeId);
		if (existing) {
			// A registration already holds this nodeId. Only the SAME node (proving the same per-node tag) may replace
			// it — the flaky-link reconnect the relay is built for. A different party that merely knows the shared
			// token but not this node's secret is REFUSED, never allowed to evict the live node and seize its stable
			// public port. A legacy node that registered without a tag (empty stored tag) keeps the old replace-on-
			// reconnect behavior, but every current node sends a tag, so a live tagged node cannot be hijacked.
			const sameNode = tokenMatch(String(tag || ''), String(existing.authTag || ''));
			if (!sameNode) { try { control.end('ERR nodeid in use\n'); } catch (_) {} return; }
			dropNode(nodeId); // same node reconnecting — replace its old registration
		} else if (nodes.size >= maxNodes) {
			// Total-node ceiling: refuse a brand-new node id once the hub is full, so one token holder cannot register
			// enough distinct ids to consume the whole public port range and its listening sockets.
			try { control.end('ERR hub full\n'); } catch (_) {} return;
		} else if (ip && (nodesPerIp.get(ip) || 0) >= maxNodesPerIp) {
			// Per-source-IP ceiling: one host cannot monopolize the port range even under the total cap.
			try { control.end('ERR too many nodes from this host\n'); } catch (_) {} return;
		}
		const publicPort = allocPort(nodeId);
		if (publicPort == null) { try { control.end('ERR no free ports\n'); } catch (_) {} return; }
		const n = { publicPort, workers: [], control, waiters: [], active: 0, authTag: String(tag || ''), signalCred: String(signalCred || ''), ip: ip || null, muxWanted: !!wantMux, muxLink: null };
		if (ip) nodesPerIp.set(ip, (nodesPerIp.get(ip) || 0) + 1);
		// The per-node public listener clients connect to. Each client is carried as a stream over the node's mux link
		// when one is established, else spliced to a spare worker (the classic path).
		const publicServer = net.createServer((client) => {
			// Bound CONCURRENT established connections (splices + mux streams), not just the waiter/worker queues: refuse a
			// new client once this node already has MAX_ACTIVE_SPLICES live connections, so a flood cannot accumulate
			// unbounded loopback-serve connections on the node. A splice slot is released when it ends; a mux stream is
			// counted live by the mux link.
			const established = n.active + (n.muxLink ? n.muxLink.count() : 0);
			if (established >= maxActiveSplices) { try { client.destroy(); } catch (_) {} return; }
			// Prefer the mux link: carry this client as one stream over the single node link. An idle guard drops an
			// unauthenticated client that opens a stream and then sits silent, matching the splice path's idle reaper.
			if (n.muxLink && !n.muxLink.down()) { guardIdle(client); n.muxLink.openStream(client); return; }
			const w = n.workers.shift();
			if (w) { try { w.write('GO\n'); } catch (_) {} n.active++; splice(client, w, SPLICE_IDLE_MS, () => { n.active--; }); return; }
			// No spare worker right now — hold the client briefly for one to arrive. Bound the backlog: a flood of
			// connections (before any WebDAV auth) must not grow this queue without limit, nor amplify into unbounded
			// local serve connections as workers are consumed. Over the cap, drop the newest client at once.
			if (n.waiters.length >= MAX_WAITERS) { try { client.destroy(); } catch (_) {} return; }
			const waiter = { client, at: Date.now() };
			n.waiters.push(waiter);
			const wait = setTimeout(() => { const i = n.waiters.indexOf(waiter); if (i >= 0) { n.waiters.splice(i, 1); try { client.destroy(); } catch (_) {} } }, WORKER_WAIT_MS);
			if (wait.unref) wait.unref(); // never keep the event loop alive for a pending waiter timeout
			client.once('close', () => { clearTimeout(wait); const i = n.waiters.indexOf(waiter); if (i >= 0) n.waiters.splice(i, 1); }); // clear the timer on early close so it doesn't linger per connection
		});
		// Only tear down if THIS registration is still the current one for the node id. A node on a flaky link often
		// reconnects on a NEW socket before the hub sees the old one's FIN; registerNode then replaces the old
		// registration (dropNode above) and installs this new `n`. The OLD socket's destroy then fires its close/error
		// handlers LATE — without this identity guard they would resolve dropNode by id and tear down the freshly
		// reconnected node, causing reconnect churn on exactly the unreliable links this relay exists to serve.
		const isCurrent = () => nodes.get(nodeId) === n;
		publicServer.on('error', () => { if (isCurrent()) dropNode(nodeId); });
		publicServer.listen(publicPort, host, () => log('node "' + nodeId + '" registered on public port ' + publicPort));
		n.publicServer = publicServer;
		nodes.set(nodeId, n);
		// Confirm registration, appending MUX when the node asked for it and the hub honors it — the node then opens a
		// MUXCONN. An older node ignores the extra token; a node whose request the hub declines gets a plain OK and uses
		// the worker pool. Either way the greeting stays one bounded line.
		try { control.write('OK ' + publicPort + (n.muxWanted ? ' MUX' : '') + '\n'); } catch (_) {}
		// After OK, keep reading the node's control socket for pushed frames. A node that supports hole-punch answers a
		// forwarded SIGNAL with `SIGNALREPLY <sid> <blob>`; the hub routes that blob back to the waiting client. A node
		// that never uses hole-punch simply never sends these lines, so this is inert for a relay-only node.
		n.detachControl = readLines(control, (line) => {
			const sp1 = line.indexOf(' '); if (sp1 < 0) return;
			if (line.slice(0, sp1) !== 'SIGNALREPLY') return;
			const rest = line.slice(sp1 + 1); const sp2 = rest.indexOf(' '); if (sp2 < 0) return;
			deliverSignalReply(rest.slice(0, sp2), rest.slice(sp2 + 1));
		}, { max: SIGNAL_MAX });
		control.once('close', () => { if (isCurrent()) dropNode(nodeId); });
		control.once('error', () => { if (isCurrent()) dropNode(nodeId); });
	}

	function addWorker(worker, nodeId, tag) {
		const n = nodes.get(nodeId);
		if (!n) { worker.destroy(); return; }
		// A worker must prove the SAME per-node tag as the node's live registration, so a token holder cannot attach
		// worker connections to (and thus carry client traffic for) a node identity that is not theirs.
		if (!tokenMatch(String(tag || ''), String(n.authTag || ''))) { try { worker.destroy(); } catch (_) {} return; }
		// If a client is already waiting, splice immediately; otherwise pool the worker.
		const waiter = n.waiters.shift();
		if (waiter) {
			// A waiting client is present. If the node is already at its concurrent-splice ceiling, drop both rather
			// than establish another live connection (the client waited past the point we can safely serve it).
			if (n.active >= maxActiveSplices) { try { waiter.client.destroy(); } catch (_) {} try { worker.destroy(); } catch (_) {} return; }
			try { worker.write('GO\n'); } catch (_) {} n.active++; splice(waiter.client, worker, SPLICE_IDLE_MS, () => { n.active--; }); return;
		}
		// Bound the pool: a token holder must not be able to open unlimited WORKER connections and grow the hub's
		// memory and file descriptors without limit. Over the cap, drop the surplus worker rather than pool it.
		if (n.workers.length >= MAX_WORKERS) { try { worker.destroy(); } catch (_) {} return; }
		n.workers.push(worker);
		worker.once('close', () => { const i = n.workers.indexOf(worker); if (i >= 0) n.workers.splice(i, 1); });
	}

	// Cap the number of sockets sitting in the UNAUTHENTICATED greeting window at once. Each greeting is already
	// bounded in size (GREETING_MAX) and time (GREETING_TIMEOUT_MS), but nothing bounded how MANY an attacker could
	// open simultaneously — on a public hub an accept flood of connections that each stall for the full timeout
	// would exhaust the process's file descriptors and stop legitimate nodes and clients from connecting. Over the
	// ceiling, drop the newest accept immediately (a real hub never has this many handshakes genuinely in flight).
	let pending = 0;
	const server = net.createServer((sock) => {
		if (pending >= MAX_PENDING) { try { sock.destroy(); } catch (_) {} return; }
		const ip = sock.remoteAddress || '';
		// Refuse a source that has recently tripped the failed-auth ceiling, BEFORE spending a greeting slot on it, so
		// a token brute-force is throttled to AUTH_FAIL_MAX tries per cooldown rather than unbounded serial reconnects.
		if (ipBlocked(ip)) { try { sock.destroy(); } catch (_) {} return; }
		pending++;
		let counted = true;
		const releasePending = () => { if (counted) { counted = false; pending--; } }; // leaves the pre-auth window exactly once (greeting resolved, or the socket closed first)
		sock.once('close', releasePending);
		sock.setKeepAlive(true, 30000);
		readGreeting(sock, (err, line) => {
			releasePending(); // past the pre-auth window now; a registered node/worker manages its own lifetime and is bounded by MAX_WAITERS/MAX_WORKERS
			if (err) { try { sock.destroy(); } catch (_) {} return; }
			const parts = line.split(' ');
			const verb = parts[0], tok = parts[1], nodeId = parts[2], tag = parts[3];
			// Registration and worker verbs (HELLO/WORKER/WHOAMI) are gated by the shared hub TOKEN. The hole-punch
			// coordination verbs (SIGNAL/WHERE) additionally accept the NAMED node's per-node SIGNAL CREDENTIAL, so a
			// paired client that holds only that node's connect code can coordinate a punch to it without ever holding
			// the registration token — the credential authorizes signaling THAT node and nothing else.
			const mainOk = !!nodeId && tokenMatch(tok, token);
			let scopedOk = false, nodeAbsent = false;
			if (!mainOk && nodeId && (verb === 'SIGNAL' || verb === 'WHERE')) {
				const n = nodes.get(nodeId);
				if (!n) nodeAbsent = true;                                          // cannot authenticate a scoped credential against an absent node
				else scopedOk = !!(n.signalCred && tokenMatch(tok, n.signalCred));
			}
			if (!mainOk && !scopedOk) {
				// A scoped verb whose target node is simply absent (mid-reconnect on a flaky link — the very case the
				// relay exists for) is NOT a credential failure, so it is answered "no node" WITHOUT charging the
				// brute-force throttle; a legitimate client is never IP-blocked because a node briefly dropped. Anything
				// else — a genuinely wrong token or a wrong credential against a PRESENT node — is charged as before.
				if (!nodeAbsent) noteAuthFail(ip);
				try { sock.end(nodeAbsent ? 'ERR no node\n' : 'ERR auth\n'); } catch (_) {}
				return;
			}
			noteAuthOk(ip); // a valid credential from this source — clear any accumulated failure count
			// Registration and worker attachment require the main token specifically (a scoped signal credential must
			// never register or attach workers), so refuse them when only the scoped credential matched.
			if ((verb === 'HELLO' || verb === 'WORKER' || verb === 'MUXCONN') && !mainOk) { try { sock.end('ERR auth\n'); } catch (_) {} return; }
			// A node advertises multiplexing by appending a `MUX` token to HELLO (always the last field, after the tag and
			// signal credential — so it can never be mistaken for one of them). The hub honors it only when mux is enabled;
			// an older hub simply does not look for it and serves the node with the classic worker pool.
			if (verb === 'HELLO') registerNode(sock, nodeId, tag, ip, parts[4], muxEnabled && parts.includes('MUX'));
			else if (verb === 'WORKER') addWorker(sock, nodeId, tag);
			// MUXCONN: the single data link a mux-negotiated node opens; the hub carries each client connection for that
			// node as a stream over it. Main-token authed like HELLO/WORKER (gated above); tag-checked in attachMux.
			else if (verb === 'MUXCONN') attachMux(sock, nodeId, tag);
			// WHOAMI: a node asks the hub what public source address it is seen from — the reflexive address it can then
			// advertise as a direct-connect candidate (Phase-2 public-address hint). Token-authed like the rest; the hub
			// reveals only the IP it already observes (::ffff: unwrapped) and closes. An OLDER hub does not know this verb
			// and simply closes the socket, so a newer node degrades to "no reflexive address" — additive and compatible.
			else if (verb === 'WHOAMI') { try { sock.end('IP ' + (String(ip || '').replace(/^::ffff:/, '') || '0.0.0.0') + '\n'); } catch (_) {} }
			// WHERE: like WHOAMI, but returns the observed IP AND source PORT (`WHERE <ip> <port>`). A peer that connects
			// FROM the exact local port it will hole-punch from learns the PUBLIC endpoint its NAT maps that port to, which
			// it then advertises to the other peer as its punch address. Token-authed; the hub only ever reports the
			// endpoint it already observes. Additive alongside WHOAMI — an older hub does not know WHERE and closes, so a
			// newer peer degrades to "no reflexive endpoint" and falls back to the relay.
			else if (verb === 'WHERE') { try { sock.end('WHERE ' + (String(ip || '').replace(/^::ffff:/, '') || '0.0.0.0') + ' ' + (sock.remotePort || 0) + '\n'); } catch (_) {} }
			// SIGNAL: a client asks the hub to forward a hole-punch offer to a live node and to relay the node's answer
			// back. The offer is the 4th greeting field (same slot as a node's tag) — a small, opaque, space-free base64
			// blob (the client's reflexive endpoint + a nonce) — so the whole request is one bounded greeting line; the
			// hub never inspects it and never carries vault data on this path. Bounded by SIGNAL_MAX_PENDING and a per-
			// exchange timeout. An OLDER hub does not know this verb and simply closes, so a newer client falls back to
			// the relay — additive and compatible.
			else if (verb === 'SIGNAL') {
				const blob = tag; // parts[3]
				if (!blob || blob.length > SIGNAL_MAX || /\s/.test(blob)) { try { sock.destroy(); } catch (_) {} return; }
				const target = nodes.get(nodeId);
				if (!target) { try { sock.end('ERR no node\n'); } catch (_) {} return; }
				if (signals.size >= SIGNAL_MAX_PENDING || (signalsPerNode.get(nodeId) || 0) >= SIGNAL_MAX_PENDING_PER_NODE) { try { sock.end('ERR busy\n'); } catch (_) {} return; }
				const sid = crypto.randomBytes(6).toString('hex');
				const timer = setTimeout(() => dropSignal(sid, 'ERR timeout\n'), SIGNAL_TIMEOUT_MS); if (timer.unref) timer.unref();
				signals.set(sid, { client: sock, timer, node: nodeId });
				signalsPerNode.set(nodeId, (signalsPerNode.get(nodeId) || 0) + 1);
				sock.once('close', () => dropSignal(sid));
				// Stamp the SIGNAL SENDER's OBSERVED public source IP into the forwarded frame. The node punches only
				// toward this address, never one the client merely names — so a paired client cannot make the node fire
				// SYNs at an unrelated victim (a reflection primitive). On a cone NAT the client's reflexive IP equals
				// this observed source IP, so real punches still succeed.
				const observedIp = (String(ip || '').replace(/^::ffff:/, '') || '0.0.0.0');
				try { target.control.write('SIGNAL ' + sid + ' ' + observedIp + ' ' + blob + '\n'); }
				catch (_) { dropSignal(sid, 'ERR node unreachable\n'); }
			}
			else { try { sock.destroy(); } catch (_) {} }
		});
	});
	server.on('error', (e) => log('hub error: ' + (e && e.message)));
	server.listen(controlPort, host, () => log('relay hub listening on ' + host + ':' + controlPort + ' (public ports ' + portRange[0] + '-' + portRange[1] + ')'));
	return { close: () => { try { clearInterval(sweep); } catch (_) {} for (const [, e] of signals) { try { clearTimeout(e.timer); } catch (_) {} try { e.client.destroy(); } catch (_) {} } signals.clear(); signalsPerNode.clear(); try { server.close(); } catch (_) {} for (const id of [...nodes.keys()]) dropNode(id); } };
}

// ── Node registration ────────────────────────────────────────────────────────────────────────────
// Register a locally-served vault with a hub so it is reachable at http://<hubHost>:<publicPort>/.
// `localPort` is the vault's loopback WebDAV serve. Returns { publicPort, stop } once the hub assigns
// a port. Reconnects with backoff if the hub link drops, and keeps the worker pool topped up.
function registerNode({ hubHost, hubPort, token, nodeId, nodeAuth, localPort, pool = DEFAULT_POOL, onEvent, onSignal = null, maxActiveSplices = MAX_ACTIVE_SPLICES, mux }) {
	if (!hubHost || !hubPort || !token || !nodeId || !localPort) throw new Error('hubHost, hubPort, token, nodeId and localPort are required.');
	const emit = (type, extra) => { try { if (onEvent) onEvent({ type, ...extra }); } catch (_) {} };
	// Per-node authentication tag: proves to the hub that reconnections and worker connections for this nodeId come
	// from the same node (the holder of nodeAuth), so no other party that merely knows the shared token can hijack
	// this node's identity. Empty when no nodeAuth is supplied (legacy/tests), which sends the classic 3-field greeting.
	const tag = nodeAuth ? nodeTag(nodeAuth, nodeId) : '';
	// The per-node SIGNAL credential the hub records so a paired client (holding only this node's connect code) can
	// coordinate a hole-punch to it without the registration token. Sent only on HELLO, as a 5th field after the tag,
	// so positions stay fixed (both derive from nodeAuth, so a node either sends tag+cred together or neither).
	const sigCred = nodeAuth ? signalCredential(nodeAuth, nodeId) : '';
	// Request multiplexing (negotiated; the hub confirms with `OK <port> MUX` or declines with a plain OK). Only when a
	// per-node tag is present, so MUX is always the LAST HELLO field (after tag+cred) and can never be misread as one of
	// them; a tagless legacy/test node uses the worker pool. On by default; opt out with VAULTONAUT_RELAY_MUX=0 / mux:false.
	const wantMux = !!tag && (mux != null ? !!mux : (process.env.VAULTONAUT_RELAY_MUX !== '0'));
	const greet = (verb) => verb === 'HELLO'
		? 'HELLO ' + token + ' ' + nodeId + (tag ? ' ' + tag + ' ' + sigCred : '') + (wantMux ? ' MUX' : '') + '\n'
		: verb + ' ' + token + ' ' + nodeId + (tag ? ' ' + tag : '') + '\n';
	let stopped = false, control = null, attempt = 0, detachControl = null;
	const workers = new Set();
	let muxSock = null, muxProxyStop = null; // the mux data link and its de-framing proxy, when the hub negotiated mux
	let activeSplices = 0; // CONCURRENT established client<->local-serve splices; bounded by MAX_ACTIVE_SPLICES

	// Handle a hole-punch SIGNAL the hub forwarded on the control socket: `SIGNAL <sid> <srcIp> <blob>`, where srcIp is
	// the sender's public source address the hub observed. Only meaningful when the caller supplied an onSignal handler
	// (hole-punch enabled); otherwise the frame is ignored. The handler gets `srcIp` (so it punches only toward the real
	// sender, never an address the client merely named) and a `reply(blob)` that routes the node's answer back.
	function handleControlLine(line) {
		if (!onSignal) return;
		const parts = line.split(' ');
		if (parts[0] !== 'SIGNAL' || parts.length < 4) return;
		const sid = parts[1], srcIp = parts[2], blob = parts[3];
		if (!sid || !srcIp || !blob) return;
		const reply = (b) => { try { if (control && !control.destroyed) control.write('SIGNALREPLY ' + sid + ' ' + String(b) + '\n'); } catch (_) {} };
		try { onSignal({ sid, srcIp, blob, reply, localPort }); } catch (_) {}
	}

	function openWorker() {
		if (stopped) return;
		const w = net.connect(hubPort, hubHost);
		workers.add(w);
		w.once('error', () => { workers.delete(w); try { w.destroy(); } catch (_) {} });
		w.once('close', () => { workers.delete(w); if (!stopped) { const t = setTimeout(topUp, 200); if (t.unref) t.unref(); } }); // replace a consumed/closed worker (unref: a pending top-up must not hold the loop open at stop)
		w.on('connect', () => { try { w.write(greet('WORKER')); } catch (_) {} });
		// Wait for GO, then connect to the local serve and splice.
		readGreeting(w, (err, line, rest) => {
			if (err || line !== 'GO' || stopped) { try { w.destroy(); } catch (_) {} return; }
			workers.delete(w); // this worker is now carrying a client; replace it in the pool
			// Bound CONCURRENT live splices. A hostile or MITM'd hub could otherwise write GO on every worker with no
			// real client behind it, and each GO would open a fresh loopback serve connection plus a replacement worker,
			// accumulating without limit until the 5-minute idle reaper. Above the ceiling, drop this worker and open
			// neither a local connection nor a replacement (topUp is paused too), so established connections stay bounded.
			if (activeSplices >= maxActiveSplices) { try { w.destroy(); } catch (_) {} return; }
			{ const t = setTimeout(topUp, 0); if (t.unref) t.unref(); } // unref: the replacement top-up must not by itself keep the loop alive
			const local = net.connect(localPort, '127.0.0.1');
			// Queue any bytes already read from the client (during the greeting) onto the local socket BEFORE the
			// splice starts piping more from the worker — Node flushes queued writes first on connect, so the
			// first WebDAV request can't be reordered behind later bytes. Writing to a still-connecting socket
			// buffers in order.
			if (rest && rest.length) { try { local.write(rest); } catch (_) {} }
			local.once('error', () => { try { w.destroy(); } catch (_) {} });
			activeSplices++;
			splice(w, local, SPLICE_IDLE_MS, () => { activeSplices--; if (!stopped) { const t = setTimeout(topUp, 0); if (t.unref) t.unref(); } }); // free the slot on end, and resume replenishing if it had paused at the ceiling
		});
	}
	// Only replenish the worker pool while we are actually registered (a public port is assigned). If
	// the hub is unreachable, ready.publicPort is null, so worker sockets are NOT respawned in a fixed
	// 200ms churn during the outage — they resume once the control link reconnects.
	function topUp() { if (stopped || ready.publicPort == null || activeSplices >= maxActiveSplices) return; while (workers.size < pool) openWorker(); } // pause replenishing at the concurrent-splice ceiling so a GO flood can't churn the pool; a finishing splice resumes it

	// Mux path: open ONE data link (MUXCONN) and hand it to the multiplexer's node end, which de-frames each client
	// stream the hub opens into a fresh connection to the local serve — no worker pool needed. The mux link is tied to
	// the control session: if it drops, tear the control link down so the whole session reconnects and re-negotiates.
	function openMux() {
		if (stopped) return;
		closeMux(); // never stack two
		const m = net.connect(hubPort, hubHost);
		muxSock = m;
		m.on('connect', () => { try { m.write(greet('MUXCONN')); } catch (_) {} });
		const proxy = Tunnel.nodeProxy(m, { localServePort: localPort });
		muxProxyStop = proxy.stop;
		m.once('error', () => { try { m.destroy(); } catch (_) {} });
		m.once('close', () => { if (muxSock === m) { muxSock = null; muxProxyStop = null; } if (!stopped && control && !control.destroyed) { try { control.destroy(); } catch (_) {} } });
	}
	function closeMux() {
		if (muxProxyStop) { try { muxProxyStop(); } catch (_) {} muxProxyStop = null; }
		if (muxSock) { try { muxSock.destroy(); } catch (_) {} muxSock = null; }
	}

	function connectControl() {
		if (stopped) return;
		control = net.connect(hubPort, hubHost);
		control.setKeepAlive(true, 30000);
		control.on('connect', () => { try { control.write(greet('HELLO')); } catch (_) {} });
		readGreeting(control, (err, line, rest) => {
			if (stopped) return;
			// On ANY greeting failure (timed out, too long, or the socket closed) tear the control socket down so
			// its 'close' handler schedules a reconnect. Some readGreeting error paths (e.g. "greeting too long")
			// do NOT destroy the socket themselves, so without this the link could sit idle forever, never
			// reconnecting after a malformed hub greeting.
			if (err) { try { control.destroy(); } catch (_) {} return; }
			// Accept an optional trailing ` MUX`: the hub appends it only when it agreed to multiplex (and only in reply to
			// our own MUX request). A plain OK — an older hub, or one with mux disabled — leaves us on the worker pool.
			const m = /^OK (\d+)( MUX)?$/.exec(line);
			if (!m) { emit('error', { error: line || 'hub refused the registration' }); scheduleReconnect(); try { control.destroy(); } catch (_) {} return; }
			attempt = 0;
			ready.publicPort = parseInt(m[1], 10);
			const hubMux = !!m[2];
			// After OK, keep reading the control socket for hub-pushed hole-punch SIGNAL frames (only acted on when an
			// onSignal handler is set). `rest` carries any bytes that arrived alongside the OK line. Detach a previous
			// reader first so a reconnect never stacks readers.
			if (detachControl) { try { detachControl(); } catch (_) {} detachControl = null; }
			detachControl = readLines(control, handleControlLine, { max: SIGNAL_MAX, initial: rest });
			emit('up', { publicPort: ready.publicPort, mux: hubMux });
			if (readyResolve) { readyResolve(ready.publicPort); readyResolve = null; }
			// Mux path: open the single data link and de-frame each stream to the local serve. Worker path otherwise.
			if (hubMux) openMux(); else topUp();
		});
		control.once('close', () => { ready.publicPort = null; if (detachControl) { try { detachControl(); } catch (_) {} detachControl = null; } closeMux(); if (!stopped) { emit('down'); scheduleReconnect(); } });
		control.once('error', () => {});
	}
	function scheduleReconnect() {
		if (stopped) return;
		attempt++;
		const delay = reconnectDelay(attempt);
		emit('reconnecting', { attempt, delay });
		clearTimeout(reconnectTimer);
		reconnectTimer = setTimeout(connectControl, delay);
		if (reconnectTimer.unref) reconnectTimer.unref(); // never keep the process alive just to reconnect
	}

	const ready = { publicPort: null };
	let readyResolve = null, reconnectTimer = null;
	const readyPromise = new Promise((resolve) => { readyResolve = resolve; });
	// stop is available SYNCHRONOUSLY (not gated behind the ready promise), so a caller that times out
	// waiting for registration can still tear the node down — otherwise a hub that is unreachable (or
	// answers after the timeout) would leave the control-reconnect loop and worker pool running forever.
	const stop = () => {
		stopped = true;
		try { clearTimeout(reconnectTimer); } catch (_) {}
		if (detachControl) { try { detachControl(); } catch (_) {} detachControl = null; }
		closeMux();
		try { control && control.destroy(); } catch (_) {}
		for (const w of workers) { try { w.destroy(); } catch (_) {} }
		workers.clear();
	};
	connectControl();
	return { ready: readyPromise.then((publicPort) => ({ publicPort })), stop };
}

// A short, stable-ish node id (a random handle for this served vault on the hub).
function nodeId() { return crypto.randomBytes(5).toString('hex'); }

// One-shot request/reply over a THROWAWAY control connection to the hub, shared by the reflexive and signaling probes
// (WHOAMI / WHERE / SIGNAL) so their connect → write → read-one-line → parse → teardown logic lives in ONE place —
// three near-identical copies invited a fix to land in only two of them. It connects (optionally binding a specific
// local port for a hole-punch probe), writes `request`, reads a single newline-terminated reply line bounded by
// `maxLine`, and resolves `parse(line)` — or null on any failure (unreachable/old hub, timeout, oversized/malformed
// reply). `rst: true` closes with a TCP RST (resetAndDestroy) so a bound local port is IMMEDIATELY reusable, where a
// normal FIN close would strand it in TIME_WAIT. Never throws; the timeout is unref'd so it never holds the loop open.
function hubQuery({ hubHost, hubPort, request, parse, timeoutMs = 8000, localPort, localAddress, rst = false, maxLine = GREETING_MAX }) {
	return new Promise((resolve) => {
		if (!hubHost || !hubPort || !request || typeof parse !== 'function') { resolve(null); return; }
		let done = false, buf = '';
		const opts = { host: hubHost, port: hubPort };
		if (Number.isInteger(localPort)) opts.localPort = localPort;
		if (localAddress) opts.localAddress = localAddress;
		let s; try { s = net.connect(opts); } catch (_) { resolve(null); return; }
		const finish = (v) => { if (done) return; done = true; clearTimeout(timer); try { if (rst) s.resetAndDestroy(); else s.destroy(); } catch (_) { try { s.destroy(); } catch (_) {} } resolve(v); };
		const timer = setTimeout(() => finish(null), Math.max(500, timeoutMs)); if (timer.unref) timer.unref();
		s.once('error', () => finish(null));
		s.on('connect', () => { try { s.write(request + '\n'); } catch (_) {} });
		s.on('data', (d) => { buf += d; if (buf.length > maxLine) return finish(null); const nl = buf.indexOf('\n'); if (nl < 0) return; let v = null; try { v = parse(buf.slice(0, nl).trim()); } catch (_) { v = null; } finish(v); });
	});
}

// Ask the hub what public address this node is seen from — its REFLEXIVE address, used as a direct-connect candidate.
// Resolves the observed IP string, or null on any failure. Never throws; the timeout is unref'd.
function reflexiveAddress({ hubHost, hubPort, token, nodeId: nid, timeoutMs = 8000 }) {
	if (!token || !nid) return Promise.resolve(null);
	return hubQuery({ hubHost, hubPort, timeoutMs, request: 'WHOAMI ' + token + ' ' + nid, parse: (line) => { const m = /^IP (\S+)$/.exec(line); return m ? m[1] : null; } });
}

// Client side of the SIGNAL exchange: send `SIGNAL <credential> <nodeId> <offerBlob>` and resolve the node's answer
// blob (the `SIGNAL <blob>` line the hub routes back), or null on any failure. The answer blob can be up to the hub's
// SIGNAL cap, so allow that much reply. Never throws; the timeout is unref'd.
function signalExchange({ hubHost, hubPort, credential, nodeId: nid, offerBlob, timeoutMs = SIGNAL_TIMEOUT_MS }) {
	if (!credential || !nid || !offerBlob) return Promise.resolve(null);
	return hubQuery({ hubHost, hubPort, timeoutMs, maxLine: SIGNAL_MAX + 32, request: 'SIGNAL ' + credential + ' ' + nid + ' ' + offerBlob, parse: (line) => { const sp = line.indexOf(' '); return sp >= 0 && line.slice(0, sp) === 'SIGNAL' ? line.slice(sp + 1) : null; } });
}
module.exports = { runHub, registerNode, reflexiveAddress, signalExchange, hubQuery, nodeId, nodeTag, signalCredential, splice, readLines, reconnectDelay, SPLICE_IDLE_MS, RECONNECT_BASE_MS, RECONNECT_MAX_MS, MIN_TOKEN_LEN, MAX_NODES, MAX_NODES_PER_IP, AUTH_FAIL_MAX, SIGNAL_MAX, SIGNAL_MAX_PENDING };
