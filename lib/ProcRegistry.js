'use strict';
// lib/ProcRegistry.js — a single place that tracks every short-lived child process
// the tool spawns (the quick engine calls: obscure, cat, list, and so on), so none
// can hang or be orphaned. Two guarantees:
//
//   1. Never hang — each tracked process has a timeout; if it overruns it is
//      killed and the caller gets a clean error instead of waiting forever.
//   2. Never orphan — a one-time shutdown handler kills everything still tracked
//      when the host process exits (Ctrl+C, SIGTERM, normal exit), so a stopped
//      CLI or web server never leaves stray engine processes behind.
//
// The long-lived mount process is deliberately NOT tracked here: it is detached on
// purpose so the drive stays mounted after the command returns, and it is instead
// recorded in the state file so it can be unmounted later.

const tracked = new Set(); // Set<ChildProcess>
const shutdownTasks = [];  // async functions to run on graceful shutdown (e.g. lock vaults)
let handlersInstalled = false;
let shuttingDown = false;
let shutdownSignal = null;  // the signal that started the drain, so only a REPEAT of the SAME one forces an exit
let resilient = false;     // long-running processes flip this on: an uncaught error is logged, not fatal

// Make the current process resilient: a stray uncaughtException is LOGGED AND SURVIVED instead of
// exiting. Long-running processes (the web server, a served node, the guardian) call this so an
// unrelated error in a background job — an auto-sync, an auto-refresh, a notification — can never take
// the process down or eject the user's mounted disks mid-use. One-shot CLI commands leave it off, so a
// genuinely fatal error there still exits non-zero. Safe to call more than once.
function beResilient() { resilient = true; }

// Register an async task to run when the host process is asked to stop (Ctrl+C,
// SIGTERM). The long-running web server uses this to unmount — and therefore lock —
// every open vault before it exits, so stopping the service never leaves a vault
// mounted and exposed.
function onShutdown(fn) { if (typeof fn === 'function') shutdownTasks.push(fn); }

// Track a child process. It removes itself on exit/error, so finished work never
// lingers in the set. Returns the process for chaining.
function track(proc) {
	if (!proc) return proc;
	tracked.add(proc);
	const done = () => tracked.delete(proc);
	proc.once('close', done);
	proc.once('error', done);
	return proc;
}

// Kill every tracked process. Used by the shutdown handler.
function killAll(signal = 'SIGKILL') {
	let n = 0;
	for (const p of tracked) { try { p.kill(signal); n++; } catch (_) {} }
	tracked.clear();
	return n;
}

// Run the registered shutdown tasks (locking any open vaults), clean up in-flight
// engine calls, then exit. Runs the drain exactly once. A repeat of the SAME stop signal forces an immediate exit —
// the "user impatiently hit Ctrl+C twice" case, where they want to stop waiting for a slow drain. A DIFFERENT stop
// signal arriving during the drain (a closing terminal's SIGHUP alongside a service manager's SIGTERM, say) is a
// normal multi-source teardown, not impatience, so it is ignored rather than aborting an in-flight flush mid-write.
// A programmatic re-entry (no signal) is likewise ignored — the hard-timeout backstop below bounds a hung drain.
async function gracefulExit(code, sig) {
	if (shuttingDown) { if (sig && sig === shutdownSignal) { try { killAll('SIGKILL'); } catch (_) {} process.exit(code); } return; }
	shuttingDown = true;
	shutdownSignal = sig || null;
	// Hard fallback: if a shutdown task ever hangs (the mount teardown is engineered to fail-fast, but be safe),
	// still exit with the SAME code before the OS supervisor's stop-then-SIGKILL window elapses. This keeps a clean
	// stop (code 0) a CLEAN exit — otherwise a SIGKILL would be a non-zero death and, under launchd's
	// KeepAlive={SuccessfulExit:false}, relaunch a service the user deliberately stopped. Anything cut off is still
	// made safe by the SIGKILL of tracked engines plus the guardian locking the vaults.
	//
	// The cap is PLATFORM-AWARE. macOS launchd allows ~20s before it SIGKILLs, so the tight 15s cap is required there.
	// systemd, though, sets a long TimeoutStopSec in our unit precisely so a slow drain-on-stop finishes; cutting it at
	// 15s would abandon a legitimate flush (and report the unit "stopped" while a vault is still mounted). Under systemd
	// (NOTIFY_SOCKET) give the drain the room the unit allows and keep extending the stop timeout as it runs, so only a
	// genuinely hung task hits the (much larger) backstop.
	const systemd = !!process.env.NOTIFY_SOCKET;
	const hardMs = systemd ? 9 * 60 * 1000 : 15 * 1000;
	let extendTimer = null;
	if (systemd) { try { const S = require('./SdNotify'); S.extendTimeout(hardMs + 30000); extendTimer = setInterval(() => { try { S.extendTimeout(45000); } catch (_) {} }, 30000); if (extendTimer.unref) extendTimer.unref(); } catch (_) {} }
	const hard = setTimeout(() => { try { killAll('SIGKILL'); } catch (_) {} process.exit(code); }, hardMs);
	if (hard.unref) hard.unref();
	for (const fn of shutdownTasks) { try { await fn(); } catch (_) {} }
	if (extendTimer) clearInterval(extendTimer);
	clearTimeout(hard);
	killAll('SIGKILL');
	process.exit(code);
}

// A cooperative stop channel for the packaged desktop app. The native shell launches this backend as a child and,
// on quit, needs it to drain writes and lock vaults before exiting. On Unix the shell sends SIGTERM (handled below),
// but Windows has no equivalent signal a windowless child honors, so the shell instead writes a "quit" line on this
// process's stdin. Treat that exactly like SIGTERM — run the same one-shot graceful drain-and-lock. Only watched when
// the shell has piped our stdin (not a terminal), so a person running `ui --desktop` by hand keeps a normal console.
function watchStdinForQuit() {
	try {
		if (process.stdin.isTTY) return; // interactive terminal — leave stdin alone
		let buf = '';
		process.stdin.on('data', (d) => {
			buf += String(d);
			// Match a whole "quit" LINE, buffering across chunks, so a delivery split mid-word ("qu" + "it\n") still
			// triggers and a stray byte cannot mis-fire it. Bound the buffer so unexpected input can never grow it.
			let nl; while ((nl = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1); if (line === 'quit') return gracefulExit(0); }
			if (buf.length > 64) buf = buf.slice(-64);
		});
		process.stdin.on('error', () => {}); // a broken stdin pipe must never crash the long-running service
		process.stdin.resume();
	} catch (_) {}
}

// Install process-level handlers exactly once, so EVERY exit path first runs the
// shutdown tasks. A stop signal or a genuinely fatal uncaughtException locks open
// vaults and exits; a hard kill that cannot be caught in-process is covered by the
// external guardian. An unhandledRejection is only LOGGED — a single stray rejection
// somewhere in async code must not eject the user's mounted disks mid-use. Safe to
// call from both the CLI and the web server.
function installShutdownHandlers() {
	if (handlersInstalled) return;
	handlersInstalled = true;
	process.once('exit', () => { killAll('SIGKILL'); }); // synchronous safety net
	for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => gracefulExit(0, sig));
	process.on('uncaughtException', (e) => {
		try { console.error((resilient ? 'Uncaught error (continuing): ' : 'Fatal error: ') + (e && e.stack || e)); } catch (_) {}
		if (!resilient) gracefulExit(1); // one-shot commands exit; long-running processes survive and keep serving
	});
	process.on('unhandledRejection', (e) => { try { console.error('Unhandled rejection (continuing): ' + (e && e.stack || e)); } catch (_) {} });
}

module.exports = { track, killAll, onShutdown, installShutdownHandlers, watchStdinForQuit, gracefulExit, beResilient };
