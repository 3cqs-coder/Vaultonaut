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

module.exports = async function closeServersThenExit(code, ...servers) {
	const fb = setTimeout(() => process.exit(code), 5000); if (fb.unref) fb.unref(); // never hang the suite on a stuck close
	// fetch() is undici, which keeps CLIENT sockets alive in a global connection pool. Closing only the server leaves
	// those open, so tearing them down at process.exit() hits the same Windows assertion — this is the piece a
	// server-only close missed. Close undici's global dispatcher too. The symbol is undici's own stable handle for it.
	try { const gd = globalThis[Symbol.for('undici.globalDispatcher.1')]; if (gd && typeof gd.close === 'function') await gd.close(); } catch (_) {}
	for (const s of servers.filter(Boolean)) {
		try { if (typeof s.closeAllConnections === 'function') s.closeAllConnections(); } catch (_) {} // drop keep-alive sockets so close() completes now
		try { await new Promise((r) => s.close(r)); } catch (_) {} // wait for the listener to fully close before exiting, so no handle is mid-close
	}
	process.exit(code);
};
