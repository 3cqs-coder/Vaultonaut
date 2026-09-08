'use strict';
// lib/Relay.js — Tier 2 turn-key relay. Reach a node that is behind NAT (no public IP, no port
// forwarding) through a small self-hosted HUB on a machine with a public address (a cheap VPS). Both
// the node and the client reach the hub OUTBOUND, so neither needs an open inbound port. The hub
// splices a client connection to one of the node's pre-opened worker connections; the node then pipes
// that to its own local (loopback) WebDAV serve. Dependency-free — raw TCP over Node's `net`, modelled
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

const GREETING_MAX = 512;         // a greeting line is tiny; cap it so a stray client can't buffer forever
const GREETING_TIMEOUT_MS = 8000; // a handshake must complete promptly; a silent/dribbling peer is dropped
const WORKER_WAIT_MS = 10000;     // how long the hub holds a client while waiting for a free worker
const DEFAULT_POOL = 8;           // spare worker connections the node keeps ready
const MAX_WAITERS = 64;           // cap on clients queued for a node's workers, so a connection flood can't grow the backlog (or amplify into local serve connections) without limit
const MAX_WORKERS = 64;           // cap on pooled worker connections per node, so a token holder can't grow memory/file descriptors without limit (a node keeps only DEFAULT_POOL ready; this is generous headroom)
const RECONNECT_BASE_MS = 2000, RECONNECT_MAX_MS = 30000;

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

// Constant-time token check. The hub is designed to run on a public host, so authenticate the shared
// token without leaking its length or shared-prefix through comparison timing: hash both sides to a
// fixed 32 bytes and compare those. Mirrors the timing-safe comparisons used elsewhere in the tool.
function tokenMatch(presented, expected) {
	return Common.timingSafeEqualHashed(presented, expected);
}

// Bidirectionally splice two sockets; destroy both when either ends.
function splice(a, b) {
	let dead = false;
	const kill = () => { if (dead) return; dead = true; try { a.destroy(); } catch (_) {} try { b.destroy(); } catch (_) {} };
	a.on('error', kill); b.on('error', kill); a.on('close', kill); b.on('close', kill);
	a.pipe(b); b.pipe(a);
}

// ── Hub ─────────────────────────────────────────────────────────────────────────────────────────
// Run the relay hub. Nodes connect to `controlPort` and register; clients connect to the per-node
// public port the hub assigns. Returns { close } to stop it.
function runHub({ controlPort = 7443, token, host = '0.0.0.0', portRange = [20000, 20099], onLog } = {}) {
	if (!token) throw new Error('A relay token is required (share it with your nodes).');
	const log = (m) => { try { if (onLog) onLog(m); } catch (_) {} };
	const nodes = new Map(); // nodeId -> { publicServer, publicPort, workers: [], control }
	const span = portRange[1] - portRange[0] + 1;

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

	function dropNode(nodeId) {
		const n = nodes.get(nodeId); if (!n) return;
		nodes.delete(nodeId);
		try { n.publicServer.close(); } catch (_) {}
		for (const w of n.workers) { try { w.destroy(); } catch (_) {} }
		try { n.control.destroy(); } catch (_) {}
		log('node "' + nodeId + '" disconnected');
	}

	function registerNode(control, nodeId) {
		if (nodes.has(nodeId)) dropNode(nodeId); // a reconnecting node replaces its old registration
		const publicPort = allocPort(nodeId);
		if (publicPort == null) { try { control.end('ERR no free ports\n'); } catch (_) {} return; }
		const n = { publicPort, workers: [], control, waiters: [] };
		// The per-node public listener clients connect to. Each client is spliced to a spare worker.
		const publicServer = net.createServer((client) => {
			const w = n.workers.shift();
			if (w) { try { w.write('GO\n'); } catch (_) {} splice(client, w); return; }
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
		publicServer.on('error', () => dropNode(nodeId));
		publicServer.listen(publicPort, host, () => log('node "' + nodeId + '" registered on public port ' + publicPort));
		n.publicServer = publicServer;
		nodes.set(nodeId, n);
		try { control.write('OK ' + publicPort + '\n'); } catch (_) {}
		control.once('close', () => dropNode(nodeId));
		control.once('error', () => dropNode(nodeId));
	}

	function addWorker(worker, nodeId) {
		const n = nodes.get(nodeId);
		if (!n) { worker.destroy(); return; }
		// If a client is already waiting, splice immediately; otherwise pool the worker.
		const waiter = n.waiters.shift();
		if (waiter) { try { worker.write('GO\n'); } catch (_) {} splice(waiter.client, worker); return; }
		// Bound the pool: a token holder must not be able to open unlimited WORKER connections and grow the hub's
		// memory and file descriptors without limit. Over the cap, drop the surplus worker rather than pool it.
		if (n.workers.length >= MAX_WORKERS) { try { worker.destroy(); } catch (_) {} return; }
		n.workers.push(worker);
		worker.once('close', () => { const i = n.workers.indexOf(worker); if (i >= 0) n.workers.splice(i, 1); });
	}

	const server = net.createServer((sock) => {
		sock.setKeepAlive(true, 30000);
		readGreeting(sock, (err, line) => {
			if (err) { try { sock.destroy(); } catch (_) {} return; }
			const parts = line.split(' ');
			const verb = parts[0], tok = parts[1], nodeId = parts[2];
			if (!nodeId || !tokenMatch(tok, token)) { try { sock.end('ERR auth\n'); } catch (_) {} return; }
			if (verb === 'HELLO') registerNode(sock, nodeId);
			else if (verb === 'WORKER') addWorker(sock, nodeId);
			else { try { sock.destroy(); } catch (_) {} }
		});
	});
	server.on('error', (e) => log('hub error: ' + (e && e.message)));
	server.listen(controlPort, host, () => log('relay hub listening on ' + host + ':' + controlPort + ' (public ports ' + portRange[0] + '-' + portRange[1] + ')'));
	return { close: () => { try { server.close(); } catch (_) {} for (const id of [...nodes.keys()]) dropNode(id); } };
}

// ── Node registration ────────────────────────────────────────────────────────────────────────────
// Register a locally-served vault with a hub so it is reachable at http://<hubHost>:<publicPort>/.
// `localPort` is the vault's loopback WebDAV serve. Returns { publicPort, stop } once the hub assigns
// a port. Reconnects with backoff if the hub link drops, and keeps the worker pool topped up.
function registerNode({ hubHost, hubPort, token, nodeId, localPort, pool = DEFAULT_POOL, onEvent }) {
	if (!hubHost || !hubPort || !token || !nodeId || !localPort) throw new Error('hubHost, hubPort, token, nodeId and localPort are required.');
	const emit = (type, extra) => { try { if (onEvent) onEvent({ type, ...extra }); } catch (_) {} };
	let stopped = false, control = null, attempt = 0;
	const workers = new Set();

	function openWorker() {
		if (stopped) return;
		const w = net.connect(hubPort, hubHost);
		workers.add(w);
		w.once('error', () => { workers.delete(w); try { w.destroy(); } catch (_) {} });
		w.once('close', () => { workers.delete(w); if (!stopped) { const t = setTimeout(topUp, 200); if (t.unref) t.unref(); } }); // replace a consumed/closed worker (unref: a pending top-up must not hold the loop open at stop)
		w.on('connect', () => { try { w.write('WORKER ' + token + ' ' + nodeId + '\n'); } catch (_) {} });
		// Wait for GO, then connect to the local serve and splice.
		readGreeting(w, (err, line, rest) => {
			if (err || line !== 'GO' || stopped) { try { w.destroy(); } catch (_) {} return; }
			workers.delete(w); // this worker is now carrying a client; replace it in the pool
			{ const t = setTimeout(topUp, 0); if (t.unref) t.unref(); } // unref: the replacement top-up must not by itself keep the loop alive
			const local = net.connect(localPort, '127.0.0.1');
			// Queue any bytes already read from the client (during the greeting) onto the local socket BEFORE the
			// splice starts piping more from the worker — Node flushes queued writes first on connect, so the
			// first WebDAV request can't be reordered behind later bytes. Writing to a still-connecting socket
			// buffers in order.
			if (rest && rest.length) { try { local.write(rest); } catch (_) {} }
			local.once('error', () => { try { w.destroy(); } catch (_) {} });
			splice(w, local);
		});
	}
	// Only replenish the worker pool while we are actually registered (a public port is assigned). If
	// the hub is unreachable, ready.publicPort is null, so worker sockets are NOT respawned in a fixed
	// 200ms churn during the outage — they resume once the control link reconnects.
	function topUp() { if (stopped || ready.publicPort == null) return; while (workers.size < pool) openWorker(); }

	function connectControl() {
		if (stopped) return;
		control = net.connect(hubPort, hubHost);
		control.setKeepAlive(true, 30000);
		control.on('connect', () => { try { control.write('HELLO ' + token + ' ' + nodeId + '\n'); } catch (_) {} });
		readGreeting(control, (err, line) => {
			if (stopped) return;
			// On ANY greeting failure (timed out, too long, or the socket closed) tear the control socket down so
			// its 'close' handler schedules a reconnect. Some readGreeting error paths (e.g. "greeting too long")
			// do NOT destroy the socket themselves, so without this the link could sit idle forever, never
			// reconnecting after a malformed hub greeting.
			if (err) { try { control.destroy(); } catch (_) {} return; }
			const m = /^OK (\d+)$/.exec(line);
			if (!m) { emit('error', { error: line || 'hub refused the registration' }); scheduleReconnect(); try { control.destroy(); } catch (_) {} return; }
			attempt = 0;
			ready.publicPort = parseInt(m[1], 10);
			emit('up', { publicPort: ready.publicPort });
			if (readyResolve) { readyResolve(ready.publicPort); readyResolve = null; }
			topUp();
		});
		control.once('close', () => { ready.publicPort = null; if (!stopped) { emit('down'); scheduleReconnect(); } });
		control.once('error', () => {});
	}
	function scheduleReconnect() {
		if (stopped) return;
		attempt++;
		const delay = Math.min(RECONNECT_BASE_MS * Math.pow(2, Math.min(attempt - 1, 6)), RECONNECT_MAX_MS);
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
		try { control && control.destroy(); } catch (_) {}
		for (const w of workers) { try { w.destroy(); } catch (_) {} }
		workers.clear();
	};
	connectControl();
	return { ready: readyPromise.then((publicPort) => ({ publicPort })), stop };
}

// A short, stable-ish node id (a random handle for this served vault on the hub).
function nodeId() { return crypto.randomBytes(5).toString('hex'); }

module.exports = { runHub, registerNode, nodeId };
