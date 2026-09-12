'use strict';
// lib/test/_exit.js — a Windows-safe exit for any test that started an HTTP server.
//
// Closing a server and then calling process.exit() right away tears the process down while socket handles — kept
// alive by fetch/undici, or by a lingering client connection — are still closing. On Windows that aborts the whole
// test runner with a libuv assertion:
//   Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c
// (POSIX tolerates the abrupt teardown, so it only bites Windows.) This destroys every live connection, waits for
// each server's own close callback so no handle is mid-close at exit, and only then exits. An unref'd fallback still
// exits if a close never calls back, so a wedged server can never hang the suite. The leading underscore keeps the
// battery runner from executing this file as a test.
//
// Usage:  const closeServersThenExit = require('./_exit');  …  closeServersThenExit(code, server1, server2);

module.exports = function closeServersThenExit(code, ...servers) {
	const list = servers.filter(Boolean);
	const fb = setTimeout(() => process.exit(code), 3000); if (fb.unref) fb.unref(); // never hang the suite on a stuck close
	let pending = list.length;
	if (!pending) return process.exit(code);
	const oneDone = () => { if (--pending === 0) process.exit(code); };
	for (const s of list) {
		try { if (typeof s.closeAllConnections === 'function') s.closeAllConnections(); } catch (_) {} // drop keep-alive sockets so close() completes now
		try { s.close(oneDone); } catch (_) { oneDone(); }
	}
};
