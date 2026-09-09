'use strict';
// lib/test/scheduledue.js — the "is this schedule due now?" gate (Vault.isBackupDue → isScheduleDue). Pure and
// local-time based, so it is tested directly with fixed Dates (no engine, no vault). It pins the two behaviors that
// matter for a data-safety product: an INTERVAL schedule catches up a missed run, and a DAILY schedule does too —
// a daily job missed across local midnight (machine asleep, or the vault mounted so the tick was skipped) is caught
// up at the next opportunity instead of silently losing a full day, while still running at most once per scheduled
// instant and never double-running when it already ran today.
//
// Run:  node lib/test/scheduledue.js

const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// A local Date builder so the tests read clearly (year, monthIndex, day, hour, minute).
const D = (y, m, d, h, mn) => new Date(y, m, d, h, mn, 0, 0);
const daily = (h, mn, lastRunAt) => ({ mode: 'daily', hour: h, minute: mn, dest: '/backup', lastRunAt: lastRunAt ? lastRunAt.toISOString() : null });
const interval = (hours, lastRunAt) => ({ mode: 'interval', intervalHours: hours, dest: '/backup', lastRunAt: lastRunAt ? lastRunAt.toISOString() : null });
const due = (sched, now) => vdisk.isBackupDue(sched, now);

function main() {
	// --- interval: catches up a missed run ---
	ok('interval with no last run is due', due(interval(1, null), D(2026, 0, 10, 12, 0)) === true);
	ok('interval within the window is not due', due(interval(24, D(2026, 0, 10, 12, 0)), D(2026, 0, 10, 13, 0)) === false);
	ok('interval past the window (a missed run) is due', due(interval(24, D(2026, 0, 9, 12, 0)), D(2026, 0, 11, 12, 0)) === true);

	// --- daily: normal cases (unchanged behavior) ---
	ok('daily never-run is NOT due before its first scheduled time (no premature run)', due(daily(23, 30, null), D(2026, 0, 10, 8, 0)) === false);
	ok('daily never-run becomes due at its first scheduled time', due(daily(23, 30, null), D(2026, 0, 10, 23, 35)) === true);
	ok('daily after today\'s time, not yet run today, is due', due(daily(23, 30, D(2026, 0, 9, 23, 30)), D(2026, 0, 10, 23, 35)) === true);
	ok('daily already run today is not due again', due(daily(23, 30, D(2026, 0, 10, 23, 30)), D(2026, 0, 10, 23, 40)) === false);
	ok('daily before today\'s time, having run yesterday on time, is NOT due (no premature run)', due(daily(9, 0, D(2026, 0, 9, 9, 0)), D(2026, 0, 10, 8, 0)) === false);

	// --- daily: THE FIX — a run missed across local midnight is caught up ---
	// Last ran day 8 at 23:30; day 9's 23:30 was missed (asleep); now is day 10 at 00:10 (just after midnight).
	ok('daily catches up a run missed across midnight', due(daily(23, 30, D(2026, 0, 8, 23, 30)), D(2026, 0, 10, 0, 10)) === true);
	// But if it DID run yesterday, it must not fire again before today's time.
	ok('daily does not re-run before today\'s time when it ran yesterday', due(daily(23, 30, D(2026, 0, 9, 23, 30)), D(2026, 0, 10, 0, 10)) === false);
	// Month-boundary catch-up (day 0 of a month rolls to the previous month correctly).
	ok('daily catch-up works across a month boundary', due(daily(23, 30, D(2026, 0, 30, 23, 30)), D(2026, 1, 1, 0, 10)) === true);

	// --- daily: DST transitions. The gate compares LOCAL calendar days (sameLocalDay) and rebuilds the scheduled
	// instant from the local hour/minute, never "now minus 24h". That keeps it correct across a daylight-saving
	// change and guards against anyone rewriting the daily branch as a naive `now - last >= 24h` delta, which would
	// skip a day every spring-forward (only 23 wall-clock hours elapse) and double-run every fall-back (25 hours). The
	// checks use the US 2026 transition dates but assert only calendar-day logic, so they hold in any local zone.
	// Spring-forward day (clocks jump 02:00->03:00 on 2026-03-08). Ran the day before at 09:00; now is 09:05 the next
	// day. Only ~23 wall-clock hours have elapsed, but it is a new local day and past the time, so it must be due.
	ok('daily is due the morning after spring-forward (a new local day, not 24h elapsed)', due(daily(9, 0, D(2026, 2, 7, 9, 0)), D(2026, 2, 8, 9, 5)) === true);
	// ...and having run on the spring-forward day, it must not fire again later that same day.
	ok('daily does not re-run later on the spring-forward day once it has run', due(daily(9, 0, D(2026, 2, 8, 9, 0)), D(2026, 2, 8, 18, 0)) === false);
	// Fall-back day (clocks fall 02:00->01:00 on 2026-11-01, a 25-hour local day). Ran at 09:00; later that same day
	// ~25 wall-clock hours of the day remain, yet it already ran today, so it must NOT fire a second time.
	ok('daily does not double-run on the fall-back day', due(daily(9, 0, D(2026, 10, 1, 9, 0)), D(2026, 10, 1, 23, 30)) === false);
	// ...and the morning after fall-back it is due again (new local day, past the time).
	ok('daily is due the morning after fall-back', due(daily(9, 0, D(2026, 10, 1, 9, 0)), D(2026, 10, 2, 9, 5)) === true);

	// off / missing dest
	ok('an off schedule is never due', due({ mode: 'off', dest: '/backup' }, D(2026, 0, 10, 23, 40)) === false);
	ok('a schedule with no destination is not due', vdisk.isBackupDue(daily(23, 30, null), D(2026, 0, 10, 23, 40)) === true && vdisk.isBackupDue({ mode: 'daily', hour: 23, minute: 30 }, D(2026, 0, 10, 23, 40)) === false);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SCHEDULE-DUE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
