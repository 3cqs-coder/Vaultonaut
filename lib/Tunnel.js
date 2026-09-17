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
	const holders = new Set();  // INBOUND: streams whose local socket is congested, holding back reads of the punched socket
	const die = () => { if (down) return; down = true; if (ka) { try { clearInterval(ka); } catch (_) {} } for (const s of paused) { try { s.resume(); } catch (_) {} } paused.clear(); holders.clear(); try { sock.destroy(); } catch (_) {} try { onDown(); } catch (_) {} };
	const write = (type, sid, payload) => { let ok = true; try { ok = sock.write(encode(type, sid, payload)); } catch (_) { die(); return false; } return ok; };
	sock.on('data', (chunk) => {
		if (down) return;
		buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
		while (buf.length >= HEADER) {
			const type = buf.readUInt8(0), sid = buf.readUInt32BE(1), len = buf.readUInt32BE(5);
			if (len > MAX_FRAME) return die();               // oversized/hostile frame → fail closed
			if (buf.length < HEADER + len) break;            // wait for the rest of this frame
			const payload = len ? buf.slice(HEADER, HEADER + len) : null;
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
		// INBOUND flow control: when a consumer (a local stream) cannot keep up with DATA arriving on the punched
		// socket, hold() pauses reading the punched socket until every congested stream has drained. Refcounted so it
		// resumes exactly once all holders release, and safe to release a stream that never held.
		hold(stream) { if (down) return; if (!holders.has(stream)) { holders.add(stream); try { sock.pause(); } catch (_) {} } },
		release(stream) { if (!holders.delete(stream)) return; if (holders.size === 0 && !down) { try { sock.resume(); } catch (_) {} } },
		down: () => down,
		stop: die,
	};
}

// CLIENT end: listen on loopback and multiplex every accepted connection as a stream over the punched socket. rclone
// is pointed at the returned `port`. Returns { port, stop } once listening (or rejects if it cannot bind loopback).
function clientProxy(punchSocket, { onDown } = {}) {
	return new Promise((resolve, reject) => {
		const streams = new Map(); // sid -> local (rclone) socket
		let nextId = 1, stopped = false;
		const shutdown = () => {
			if (stopped) return; stopped = true;
			for (const s of streams.values()) { try { s.destroy(); } catch (_) {} }
			streams.clear();
			try { server.close(); } catch (_) {}
			try { if (onDown) onDown(); } catch (_) {}
		};
		const link = makeLink(punchSocket, {
			onFrame: (type, sid, payload) => {
				const s = streams.get(sid); if (!s) return; // OPEN never arrives at the client (it never opens streams inbound); PING/PONG handled in makeLink
				if (type === T.DATA && payload) { if (s.write(payload) === false) { link.hold(s); s.once('drain', () => link.release(s)); } } // hold the punched socket while this stream is congested
				else if (type === T.CLOSE) { streams.delete(sid); link.release(s); try { s.end(); } catch (_) {} }
			},
			onDown: shutdown,
		});
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
	void link; // makeLink runs the keepalive/liveness internally; nothing further to wire here
	return { stop: shutdown };
}

module.exports = { clientProxy, nodeProxy, _codec: { encode, T, HEADER, MAX_FRAME }, KEEPALIVE_MS, MAX_STREAMS };
