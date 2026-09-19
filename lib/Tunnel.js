'use strict';
// lib/Tunnel.js — a tiny stream multiplexer + local proxy that lets ONE direct (hole-punched) TCP connection carry the
// MANY connections an engine opens to a WebDAV serve. The problem it solves: a hole-punch yields a single TCP socket,
// but rclone opens several connections to a `host:port`, and it opens its own sockets (we cannot hand it one). So the
// client runs a small LOCAL proxy that rclone connects to; each rclone connection becomes a framed STREAM over the one
// punched socket; the node end de-frames each stream back into a fresh connection to its loopback WebDAV serve.
//
// CRYPTO: the frames carry only the ALREADY-ENCRYPTED, certificate-pinned WebDAV bytes end to end. The tunnel never
// terminates, originates, or inspects TLS — exactly like the relay splice — so a punched path is cryptographically
// identical to the relay path (the same pinned handshake runs peer-to-peer over it). The multiplexer is therefore
// treated as UNTRUSTED transport: every frame length is bounded and any malformed frame tears the tunnel down (the
// inner pinned TLS is what authenticates the peer, never this framing).
//
// CROSS-PLATFORM / NON-BLOCKING: Node built-ins only (`net`), identical on macOS/Windows/Linux. Backpressure is
// honored (a slow punched link pauses the source so memory cannot grow without bound), a keepalive ping keeps the NAT
// mapping warm under its idle timeout, and the keepalive timer is unref'd so it never holds the event loop open.

const net = require('net');

const T = { OPEN: 1, DATA: 2, CLOSE: 3, PING: 4, PONG: 5 }; // frame types
const HEADER = 9;                 // 1 byte type + 4 bytes stream id + 4 bytes payload length
const MAX_FRAME = 128 * 1024;     // hard cap on a single frame's payload — a TLS record is ≤16 KiB, so this is generous
                                  // headroom while still bounding what a malformed/hostile frame can make us buffer
const KEEPALIVE_MS = 25000;       // ping cadence to keep the NAT mapping from idling out (well under common timeouts)
const MAX_MISSED_PONGS = 3;       // tear the tunnel down after this many pings with no reply — catches a peer whose NAT
                                  // mapping silently dropped (the socket looks open but nothing returns), which a plain
                                  // socket error/close would not detect for minutes
const MAX_STREAMS = 256;          // cap on concurrent logical streams over one tunnel, so a flood cannot exhaust fds
const AGG_BACKPRESSURE_BYTES = 4 * 1024 * 1024; // pause the shared punched socket only when the TOTAL bytes buffered
                                  // toward the many local sockets exceeds this — so one slow stream no longer stalls the
                                  // others (per-stream flow control), while memory across all streams stays bounded

// Reap a per-stream socket that goes idle for `ms` in BOTH directions (no bytes read AND none written since the last
// sample). Direction-agnostic by watching the socket's own byte counters, so a long transfer in EITHER direction keeps
// it alive while a genuinely silent stream is dropped. The relay passes SPLICE_IDLE_MS so a mux stream is bounded
// exactly like a spliced connection (a hostile peer cannot hold idle streams open). Off when ms is 0 — the hole-punch
// path, where the local engine manages its own connections and should not be reaped. The sampling timer is unref'd.
function armStreamIdle(sock, ms) {
	if (!ms || !sock) return;
	let last = -1;
	const timer = setInterval(() => {
		let cur = -1; try { cur = (sock.bytesRead || 0) + (sock.bytesWritten || 0); } catch (_) {}
		if (cur !== last) { last = cur; return; } // activity since the last sample — keep the stream
		try { clearInterval(timer); } catch (_) {} try { sock.destroy(); } catch (_) {}
	}, ms);
	if (timer.unref) timer.unref();
	sock.once('close', () => { try { clearInterval(timer); } catch (_) {} });
}

function encode(type, sid, payload) {
	const len = payload ? payload.length : 0;
	const b = Buffer.allocUnsafe(HEADER + len);
	b.writeUInt8(type, 0); b.writeUInt32BE(sid >>> 0, 1); b.writeUInt32BE(len, 5);
	if (len) payload.copy(b, HEADER);
	return b;
}

// A framed link over one socket: parses inbound frames (bounded; a violation tears it down), writes outbound frames
// with backpressure (a congested socket pauses the source and resumes on drain, so a slow link never grows memory),
// and runs its own keepalive — it pings on a cadence to keep the NAT mapping warm and tears the link down after a few
// unanswered pings, so a peer whose mapping silently dropped (socket still "open") is detected instead of lingering.
// PING/PONG is handled entirely here, so a caller's onFrame only ever sees OPEN/DATA/CLOSE. `onDown()` fires once.
function makeLink(sock, { onFrame, onDown }) {
	let buf = Buffer.alloc(0), down = false, missedPongs = 0, ka = null;
	const paused = new Set();   // OUTBOUND: source sockets paused because the punched socket is congested
	const active = new Set();   // INBOUND: local streams still draining buffered DATA — tracked for aggregate backpressure
	let aggPaused = false;       // is the shared punched socket currently paused for aggregate inbound backpressure?
	const die = () => { if (down) return; down = true; if (ka) { try { clearInterval(ka); } catch (_) {} } for (const s of paused) { try { s.resume(); } catch (_) {} } paused.clear(); active.clear(); try { sock.destroy(); } catch (_) {} try { onDown(); } catch (_) {} };
	// INBOUND aggregate backpressure: each stream buffers what its slow local socket cannot take yet, INDEPENDENTLY, so a
	// single slow consumer no longer stalls every other stream (the old design paused the whole shared socket on ANY one
	// congested stream — head-of-line blocking). Memory still stays bounded: when the TOTAL buffered across all streams
	// crosses the cap, the shared punched socket is paused (stops reads, applying backpressure to the peer) until enough
	// has drained, then resumed.
	const reassess = () => {
		if (down) return;
		let total = 0; for (const s of active) total += (s.writableLength || 0);
		if (!aggPaused && total > AGG_BACKPRESSURE_BYTES) { aggPaused = true; try { sock.pause(); } catch (_) {} }
		else if (aggPaused && total <= AGG_BACKPRESSURE_BYTES) { aggPaused = false; try { sock.resume(); } catch (_) {} }
	};
	const write = (type, sid, payload) => { let ok = true; try { ok = sock.write(encode(type, sid, payload)); } catch (_) { die(); return false; } return ok; };
	sock.on('data', (chunk) => {
		if (down) return;
		buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
		while (buf.length >= HEADER) {
			const type = buf.readUInt8(0), sid = buf.readUInt32BE(1), len = buf.readUInt32BE(5);
			if (len > MAX_FRAME) return die();               // oversized/hostile frame → fail closed
			if (buf.length < HEADER + len) break;            // wait for the rest of this frame
			const payload = len ? Buffer.from(buf.subarray(HEADER, HEADER + len)) : null; // COPY out of the accumulator so a forwarded frame never pins the whole concatenated buffer alive
			buf = buf.slice(HEADER + len);
			if (type === T.PING) { write(T.PONG, 0, null); continue; }     // keepalive handled here, invisible to onFrame
			if (type === T.PONG) { missedPongs = 0; continue; }            // peer is alive
			try { onFrame(type, sid, payload); } catch (_) { return die(); }
		}
	});
	sock.on('error', die); sock.on('close', die);
	sock.on('drain', () => { for (const s of paused) { try { s.resume(); } catch (_) {} } paused.clear(); });
	ka = setInterval(() => { if (down) return; if (missedPongs >= MAX_MISSED_PONGS) return die(); missedPongs++; write(T.PING, 0, null); }, KEEPALIVE_MS);
	if (ka.unref) ka.unref(); // never hold the event loop open just to ping
	return {
		// OUTBOUND flow control: writing a frame TO the punched socket. If it congests, pause the source (the local
		// socket the bytes came from) and resume it on the punched socket's drain, so memory cannot grow without bound.
		send(type, sid, payload, source) {
			if (down) return;
			if (write(type, sid, payload) === false && source) { try { source.pause(); } catch (_) {} paused.add(source); }
		},
		// INBOUND: deliver one DATA frame to a local stream. Write it (the stream buffers what it cannot send yet); if the
		// stream is now congested, track it so aggregate backpressure pauses the shared socket ONLY if the TOTAL buffered
		// across all streams grows too large — one slow stream no longer blocks the others. Cleans up on drain or close.
		deliver(stream, payload) {
			if (down || !stream) return;
			let okw = true; try { okw = stream.write(payload); } catch (_) { return; }
			if (!okw && !active.has(stream)) {
				active.add(stream);
				const clear = () => { if (active.delete(stream)) reassess(); };
				// On drain, also drop the paired 'close' listener — otherwise a stream that repeatedly congests and drains
				// (a long transfer over a slow consumer) stacks a new 'close' listener each time and leaks them.
				const onDrain = () => { stream.removeListener('close', clear); clear(); };
				stream.once('drain', onDrain); stream.once('close', clear);
			}
			reassess();
		},
		down: () => down,
		stop: die,
	};
}

// CLIENT end: listen on loopback and multiplex every accepted connection as a stream over the punched socket. rclone
// is pointed at the returned `port`. Returns { port, stop } once listening (or rejects if it cannot bind loopback).
// The reusable multiplexer CLIENT over one framed socket: it opens a logical STREAM for each caller-supplied socket and
// relays that socket's bytes both ways over the one shared link. Two callers use it: clientProxy() below wraps it with a
// loopback listener so an engine's many connections each become a stream (the hole-punch path), and the relay hub uses
// it directly to carry each incoming client connection as a stream over ONE node link (the relay mux path). It never
// opens a stream on its own — a stream exists only for a socket the caller hands to openStream().
function muxClient(muxSocket, { onDown, streamIdleMs = 0 } = {}) {
	const streams = new Map(); // sid -> caller socket
	let nextId = 1, stopped = false;
	const shutdown = () => {
		if (stopped) return; stopped = true;
		for (const s of streams.values()) { try { s.destroy(); } catch (_) {} }
		streams.clear();
		try { if (onDown) onDown(); } catch (_) {}
	};
	const link = makeLink(muxSocket, {
		onFrame: (type, sid, payload) => {
			const s = streams.get(sid); if (!s) return; // this end never receives OPEN (it does the opening); PING/PONG handled in makeLink
			if (type === T.DATA && payload) link.deliver(s, payload);
			else if (type === T.CLOSE) { streams.delete(sid); try { s.end(); } catch (_) {} }
		},
		onDown: shutdown,
	});
	return {
		down: () => stopped || link.down(),
		count: () => streams.size,
		// Carry `sock` as a new logical stream over the mux. Returns false (and destroys sock) when the mux is down or at
		// the stream cap, so a caller can bound established streams exactly as the loopback server and the hub do.
		openStream(sock) {
			if (stopped || link.down() || streams.size >= MAX_STREAMS) { try { sock.destroy(); } catch (_) {} return false; }
			const sid = nextId++; streams.set(sid, sock);
			link.send(T.OPEN, sid, null);
			sock.on('data', (d) => link.send(T.DATA, sid, d, sock));
			sock.on('close', () => { if (streams.delete(sid)) link.send(T.CLOSE, sid, null); });
			sock.on('error', () => { try { sock.destroy(); } catch (_) {} });
			armStreamIdle(sock, streamIdleMs); // reap a stream that goes silent both ways (relay path; no-op on the hole-punch path)
			return true;
		},
		stop: shutdown,
	};
}

// CLIENT end for the hole-punch path: listen on loopback and carry every accepted connection as a stream over the
// punched socket. rclone is pointed at the returned `port`. Returns { port, stop } once listening (or rejects if it
// cannot bind loopback).
function clientProxy(punchSocket, { onDown } = {}) {
	return new Promise((resolve, reject) => {
		let server = null;
		const mux = muxClient(punchSocket, { onDown: () => { try { if (server) server.close(); } catch (_) {} try { if (onDown) onDown(); } catch (_) {} } });
		server = net.createServer((sock) => { mux.openStream(sock); });
		server.on('error', (e) => { if (!mux.down()) { mux.stop(); reject(e); } });
		server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, stop: () => { try { server.close(); } catch (_) {} mux.stop(); } }));
	});
}

// NODE end: for each stream the client opens, connect to the loopback WebDAV serve and relay both ways. Returns
// { stop }. `localServePort` is the node's own serve port. Purely reactive — it never opens a stream itself.
function nodeProxy(punchSocket, { localServePort, localServeHost = '127.0.0.1', onDown, streamIdleMs = 0, maxStreams = MAX_STREAMS } = {}) {
	const cap = Math.min(MAX_STREAMS, maxStreams > 0 ? maxStreams : MAX_STREAMS); // honor a caller's lower ceiling (the relay's maxActiveSplices), never above the hard fd cap
	const streams = new Map(); // sid -> local serve socket
	let stopped = false;
	const shutdown = () => {
		if (stopped) return; stopped = true;
		for (const s of streams.values()) { try { s.destroy(); } catch (_) {} }
		streams.clear();
		try { if (onDown) onDown(); } catch (_) {}
	};
	const link = makeLink(punchSocket, {
		onFrame: (type, sid, payload) => {
			if (type === T.OPEN) {
				if (streams.has(sid) || streams.size >= cap) return;
				const local = net.connect(localServePort, localServeHost);
				streams.set(sid, local);
				local.on('data', (d) => link.send(T.DATA, sid, d, local));
				local.on('close', () => { if (streams.delete(sid)) link.send(T.CLOSE, sid, null); });
				local.on('error', () => { try { local.destroy(); } catch (_) {} });
				armStreamIdle(local, streamIdleMs); // reap a serve connection a hostile hub opens and then leaves silent (relay path)
				return;
			}
			const s = streams.get(sid); if (!s) return;
			if (type === T.DATA && payload) link.deliver(s, payload);
			else if (type === T.CLOSE) { streams.delete(sid); try { s.end(); } catch (_) {} }
		},
		onDown: shutdown,
	});
	void link; // makeLink runs the keepalive/liveness internally; nothing further to wire here
	return { stop: shutdown };
}

module.exports = { clientProxy, nodeProxy, muxClient, _codec: { encode, T, HEADER, MAX_FRAME }, KEEPALIVE_MS, MAX_STREAMS };
