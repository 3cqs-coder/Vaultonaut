'use strict';
// lib/SdNotify.js — minimal systemd readiness + watchdog notifications, for the Linux service only. On a
// systemd host that armed a watchdog (NOTIFY_SOCKET is set), it tells the service manager the service is READY,
// then sends periodic WATCHDOG keep-alive pings — but ONLY when a real health tick recently completed, so a
// wedged event loop stops the pings and systemd restarts the service (a dumb timer would keep pinging a hung
// process forever and defeat the whole point). It also signals STOPPING during a clean shutdown and can extend
// the timeout during a long, healthy drain so systemd never kills a legitimate flush.
//
// Off systemd — macOS, Windows, or any host with no NOTIFY_SOCKET — every function here is a NO-OP, so this is
// safe to call unconditionally from the cross-platform service. Node core cannot send an AF_UNIX DATAGRAM (its
// dgram is UDP-only, net is stream-only), so the message is delivered via the OS-provided `systemd-notify(1)`,
// which exists wherever a systemd watchdog does — no npm dependency, and nothing spawned on a non-systemd host.

const { spawn } = require('child_process');

// A monotonic millisecond clock (never wall-clock — a clock jump must not affect liveness reasoning).
function monoMs() { return Number(process.hrtime.bigint() / 1000000n); }

function enabled() { return !!process.env.NOTIFY_SOCKET; }
// systemd only honors a keep-alive from the process it is watching. If WATCHDOG_PID names another process (the
// var was inherited by a child), we must stay silent rather than keep an unrelated process's watchdog alive.
function pidMatches() { const w = process.env.WATCHDOG_PID; return !w || Number(w) === process.pid; }
// Half of the watchdog window systemd asked for (its recommended ping period), in ms — or 0 if no watchdog.
function watchdogIntervalMs() { const us = Number(process.env.WATCHDOG_USEC); return us > 0 ? Math.floor(us / 2000) : 0; }

// Fire-and-forget a systemd notification. Best-effort by design: a missing systemd-notify or a spawn error must
// never surface into the service's loop.
function notify(state) {
	if (!enabled()) return;
	try { const c = spawn('systemd-notify', [state], { stdio: 'ignore' }); c.on('error', () => {}); if (c.unref) c.unref(); } catch (_) {}
}
function ready() { notify('READY=1'); }
function stopping() { notify('STOPPING=1'); }
function extendTimeout(ms) { if (Number(ms) > 0) notify('EXTEND_TIMEOUT_USEC=' + Math.round(Number(ms) * 1000)); }

// The progress-binding decision, kept PURE so it can be tested without systemd: ping only if a healthy tick
// completed within `windowMs`. A frozen stamp (a wedged tick) -> false -> no ping -> systemd restarts us.
function shouldPing(lastHealthyMonoMs, nowMonoMs, windowMs) { return Number.isFinite(lastHealthyMonoMs) && (nowMonoMs - lastHealthyMonoMs) <= windowMs; }

// Arm the watchdog. `getLastHealthyMonoMs()` returns the monotonic time (from monoMs()) of the last COMPLETED
// healthy tick; the service updates it at the end of each tick. Sends READY once, then pings on systemd's
// cadence only while the last healthy tick is recent. Returns a stop() function. A no-op off systemd.
function startWatchdog(getLastHealthyMonoMs, { windowMs } = {}) {
	if (!enabled()) return () => {};
	ready(); // Type=notify requires READY=1 or `systemctl start` hangs — send it whenever notify is on
	const interval = watchdogIntervalMs();
	if (interval <= 0) return () => {}; // notify without a watchdog: readiness only, no keep-alive pings
	const win = windowMs || interval; // require a healthy tick within ~one ping period
	const timer = setInterval(() => {
		try { if (pidMatches() && shouldPing(Number(getLastHealthyMonoMs()), monoMs(), win)) notify('WATCHDOG=1'); } catch (_) {}
	}, interval);
	if (timer.unref) timer.unref();
	return () => { try { clearInterval(timer); } catch (_) {} };
}

module.exports = { monoMs, enabled, pidMatches, watchdogIntervalMs, ready, stopping, extendTimeout, shouldPing, startWatchdog };
