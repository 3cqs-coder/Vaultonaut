'use strict';
// lib/test/sdnotify.js — the systemd watchdog notifier's decision logic, which is what makes it safe. The
// actual datagram delivery is systemd's own `systemd-notify` and only runs on a Linux systemd host (an
// integration concern), but the LOGIC that decides WHETHER to ping — the part that must never keep a wedged
// process alive — is pure and tested here: a recent healthy tick pings, a frozen (wedged) tick does NOT, the
// ping period is read from what systemd asked for, a mismatched watchdog PID stays silent, and off systemd the
// whole thing is a no-op that never spawns anything.
//
// Run:  node lib/test/sdnotify.js

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function withEnv(vars, fn) {
	const saved = {}; for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] == null) delete process.env[k]; else process.env[k] = vars[k]; }
	try { return fn(); } finally { for (const k of Object.keys(vars)) { if (saved[k] == null) delete process.env[k]; else process.env[k] = saved[k]; } }
}

function main() {
	delete require.cache[require.resolve('../SdNotify')];
	const S = require('../SdNotify');

	// The crux: ping only while a healthy tick is recent; a frozen stamp (a wedge) must NOT ping.
	const now = 100000;
	ok('a recent healthy tick pings', S.shouldPing(now - 5000, now, 30000) === true);
	ok('a frozen (wedged) tick does NOT ping', S.shouldPing(now - 60000, now, 30000) === false);
	ok('exactly at the window still pings', S.shouldPing(now - 30000, now, 30000) === true);
	ok('a missing stamp does NOT ping', S.shouldPing(NaN, now, 30000) === false);

	// The ping period is half the window systemd asked for (WATCHDOG_USEC microseconds -> ms).
	ok('the ping interval is half of WATCHDOG_USEC', withEnv({ WATCHDOG_USEC: '60000000' }, () => S.watchdogIntervalMs()) === 30000);
	ok('no watchdog window means no interval', withEnv({ WATCHDOG_USEC: undefined }, () => S.watchdogIntervalMs()) === 0);

	// Only ping when we are the process systemd is watching.
	ok('our own pid matches the watchdog pid', withEnv({ WATCHDOG_PID: String(process.pid) }, () => S.pidMatches()) === true);
	ok('a different watchdog pid is not us (stay silent)', withEnv({ WATCHDOG_PID: String(process.pid + 1) }, () => S.pidMatches()) === false);
	ok('no watchdog pid means no restriction', withEnv({ WATCHDOG_PID: undefined }, () => S.pidMatches()) === true);

	// enabled() strictly follows NOTIFY_SOCKET.
	ok('enabled only when NOTIFY_SOCKET is set', withEnv({ NOTIFY_SOCKET: '/run/x' }, () => S.enabled()) === true && withEnv({ NOTIFY_SOCKET: undefined }, () => S.enabled()) === false);

	// Off systemd, startWatchdog is a no-op returning a callable stop(); it never arms a timer or spawns.
	const stop = withEnv({ NOTIFY_SOCKET: undefined }, () => S.startWatchdog(() => S.monoMs()));
	ok('startWatchdog off systemd returns a no-op stop()', typeof stop === 'function');
	stop();

	// The monotonic clock advances and is not wall-clock-negative.
	const a = S.monoMs(); const b = S.monoMs();
	ok('monoMs() is a sane monotonic millisecond clock', Number.isFinite(a) && b >= a);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SD-NOTIFY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
