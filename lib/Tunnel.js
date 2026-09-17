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
const MAX_STREAMS = 256;          // cap on concurrent logical streams over one tunnel, so a flood cannot exhaust fds

function encode(type, sid, payload) {
	const len = payload ? payload.length : 0;
	const b = Buffer.allocUnsafe(HEADER + len);
	b.writeUInt8(type, 0); b.writeUInt32BE(sid >>> 0, 1); b.writeUInt32BE(len, 5);
	if (len) payload.copy(b, HEADER);
	return b;
}

// A framed link over one socket: parses inbound frames (bounded; a violation tears it down) and writes outbound frames
// with backpressure — when the socket is congested the source is paused and resumed on drain, so a slow punched link
// can never grow memory without bound. Shared by both proxy ends. `onFrame(type, sid, payload)`; `onDown()` once.
function makeLink(sock, { onFrame, onDown }) {
	let buf = Buffer.alloc(0), down = false;
	const paused = new Set();   // OUTBOUND: source sockets paused because the punched socket is congested
	const holders = new Set();  // INBOUND: streams whose local socket is congested, holding back reads of the punched socket
	const die = () => { if (down) return; down = true; for (const s of paused) { try { s.resume(); } catch (_) {} } paused.clear(); holders.clear(); try { sock.destroy(); } catch (_) {} try { onDown(); } catch (_) {} };
	sock.on('data', (chunk) => {
		if (down) return;
		buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
		while (buf.length >= HEADER) {
			const type = buf.readUInt8(0), sid = buf.readUInt32BE(1), len = buf.readUInt32BE(5);
			if (len > MAX_FRAME) return die();               // oversized/hostile frame → fail closed
			if (buf.length < HEADER + len) break;            // wait for the rest of this frame
			const payload = len ? buf.slice(HEADER, HEADER + len) : null;
			buf = buf.slice(HEADER + len);
			try { onFrame(type, sid, payload); } catch (_) { return die(); }
		}
	});
	sock.on('error', die); sock.on('close', die);
	sock.on('drain', () => { for (const s of paused) { try { s.resume(); } catch (_) {} } paused.clear(); });
	return {
		// OUTBOUND flow control: writing a frame TO the punched socket. If it congests, pause the source (the local
		// socket the bytes came from) and resume it on the punched socket's drain, so memory cannot grow without bound.
		send(type, sid, payload, source) {
			if (down) return;
			let ok = true; try { ok = sock.write(encode(type, sid, payload)); } catch (_) { return die(); }
			if (ok === false && source) { try { source.pause(); } catch (_) {} paused.add(source); }
		},
		// INBOUND flow control: when a consumer (a local stream) cannot keep up with DATA arriving on the punched
		// socket, hold() pauses reading the punched socket until every congested stream has drained. Refcounted so it
		// resumes exactly once all holders release, and safe to release a stream that never held.
		hold(stream) { if (down) return; if (!holders.has(stream)) { holders.add(stream); try { sock.pause(); } catch (_) {} } },
		release(stream) { if (!holders.delete(stream)) return; if (holders.size === 0 && !down) { try { sock.resume(); } catch (_) {} } },
		down: () => down,
		stop: die,
	};
}

// Keep the NAT mapping warm and detect a dead peer: ping on a cadence; a link that stops draining/replying is torn
// down by its own socket error/close. Returns a stop() to clear the timer. The timer is unref'd.
function keepAlive(link) {
	const t = setInterval(() => link.send(T.PING, 0, null), KEEPALIVE_MS);
	if (t.unref) t.unref();
	return () => clearInterval(t);
}

// CLIENT end: listen on loopback and multiplex every accepted connection as a stream over the punched socket. rclone
// is pointed at the returned `port`. Returns { port, stop } once listening (or rejects if it cannot bind loopback).
function clientProxy(punchSocket, { onDown } = {}) {
	return new Promise((resolve, reject) => {
		const streams = new Map(); // sid -> local (rclone) socket
		let nextId = 1, stopped = false, stopKa = null;
		const shutdown = () => {
			if (stopped) return; stopped = true;
			if (stopKa) { try { stopKa(); } catch (_) {} }
			for (const s of streams.values()) { try { s.destroy(); } catch (_) {} }
			streams.clear();
			try { server.close(); } catch (_) {}
			try { if (onDown) onDown(); } catch (_) {}
		};
		const link = makeLink(punchSocket, {
			onFrame: (type, sid, payload) => {
				if (type === T.PING) return link.send(T.PONG, 0, null);
				if (type === T.PONG) return;
				const s = streams.get(sid); if (!s) return;
				if (type === T.DATA && payload) { if (s.write(payload) === false) { link.hold(s); s.once('drain', () => link.release(s)); } } // hold the punched socket while this stream is congested
				else if (type === T.CLOSE) { streams.delete(sid); link.release(s); try { s.end(); } catch (_) {} }
			},
			onDown: shutdown,
		});
		stopKa = keepAlive(link);
		const server = net.createServer((sock) => {
			if (link.down() || streams.size >= MAX_STREAMS) { try { sock.destroy(); } catch (_) {} return; }
			const sid = nextId++; streams.set(sid, sock);
			link.send(T.OPEN, sid, null);
			sock.on('data', (d) => link.send(T.DATA, sid, d, sock));
			sock.on('close', () => { link.release(sock); if (streams.delete(sid)) link.send(T.CLOSE, sid, null); });
			sock.on('error', () => { try { sock.destroy(); } catch (_) {} });
		});
		server.on('error', (e) => { if (!stopped) { shutdown(); reject(e); } });
		server.listen(0, '127.0.0.1', () => resolve({ port: server.address().port, stop: shutdown }));
	});
}

// NODE end: for each stream the client opens, connect to the loopback WebDAV serve and relay both ways. Returns
// { stop }. `localServePort` is the node's own serve port. Purely reactive — it never opens a stream itself.
function nodeProxy(punchSocket, { localServePort, localServeHost = '127.0.0.1', onDown } = {}) {
	const streams = new Map(); // sid -> local serve socket
	let stopped = false, stopKa = null;
	const shutdown = () => {
		if (stopped) return; stopped = true;
		if (stopKa) { try { stopKa(); } catch (_) {} }
		for (const s of streams.values()) { try { s.destroy(); } catch (_) {} }
		streams.clear();
		try { if (onDown) onDown(); } catch (_) {}
	};
	const link = makeLink(punchSocket, {
		onFrame: (type, sid, payload) => {
			if (type === T.PING) return link.send(T.PONG, 0, null);
			if (type === T.PONG) return;
			if (type === T.OPEN) {
				if (streams.has(sid) || streams.size >= MAX_STREAMS) return;
				const local = net.connect(localServePort, localServeHost);
				streams.set(sid, local);
				local.on('data', (d) => link.send(T.DATA, sid, d, local));
				local.on('close', () => { link.release(local); if (streams.delete(sid)) link.send(T.CLOSE, sid, null); });
				local.on('error', () => { try { local.destroy(); } catch (_) {} });
				return;
			}
			const s = streams.get(sid); if (!s) return;
			if (type === T.DATA && payload) { if (s.write(payload) === false) { link.hold(s); s.once('drain', () => link.release(s)); } } // hold the punched socket while the local serve is congested
			else if (type === T.CLOSE) { streams.delete(sid); link.release(s); try { s.end(); } catch (_) {} }
		},
		onDown: shutdown,
	});
	stopKa = keepAlive(link);
	return { stop: shutdown };
}

module.exports = { clientProxy, nodeProxy, _codec: { encode, T, HEADER, MAX_FRAME }, KEEPALIVE_MS, MAX_STREAMS };
