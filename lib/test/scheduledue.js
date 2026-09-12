'use strict';
// lib/test/scheduledue.js — the "is this schedule due now?" gate (Vault.isBackupDue → isScheduleDue). Pure and
// evaluated in UTC, so it is tested directly with fixed UTC Dates (no engine, no vault) and is deterministic in any
// timezone. It pins the two behaviors that matter for a data-safety product: an INTERVAL schedule catches up a missed
// run, and a DAILY schedule does too — a daily job missed across UTC midnight (machine asleep, or the vault mounted so
// the tick was skipped) is caught up at the next opportunity instead of silently losing a full day, while still
// running at most once per scheduled instant and never double-running when it already ran today. Evaluating in UTC
// (rather than machine-local time) is what keeps a schedule firing at the SAME absolute moment after a vault moves to
// a machine in another timezone, and keeps sync/mirror cadences uniform across peers; it also removes daylight-saving
// entirely (a UTC day is always exactly 24 hours), so there is no spring-forward skip or fall-back double-run to guard.
//
// Run:  node lib/test/scheduledue.js

const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// A UTC Date builder so the tests read clearly (year, monthIndex, day, hour, minute) and are timezone-independent —
// the gate reads the daily hour/minute as UTC, so `now` and `lastRunAt` are built as UTC instants to match.
const D = (y, m, d, h, mn) => new Date(Date.UTC(y, m, d, h, mn, 0, 0));
const daily = (h, mn, lastRunAt) => ({ mode: 'daily', hour: h, minute: mn, dest: '/backup', lastRunAt: lastRunAt ? lastRunAt.toISOString() : null });
const interval = (hours, lastRunAt) => ({ mode: 'interval', intervalHours: hours, dest: '/backup', lastRunAt: lastRunAt ? lastRunAt.toISOString() : null });
const due = (sched, now) => vdisk.isBackupDue(sched, now);

function main() {
	// --- interval: catches up a missed run (absolute elapsed time, timezone-independent) ---
	ok('interval with no last run is due', due(interval(1, null), D(2026, 0, 10, 12, 0)) === true);
	ok('interval within the window is not due', due(interval(24, D(2026, 0, 10, 12, 0)), D(2026, 0, 10, 13, 0)) === false);
	ok('interval past the window (a missed run) is due', due(interval(24, D(2026, 0, 9, 12, 0)), D(2026, 0, 11, 12, 0)) === true);

	// --- daily (UTC time of day): normal cases ---
	ok('daily never-run is NOT due before its first scheduled time (no premature run)', due(daily(23, 30, null), D(2026, 0, 10, 8, 0)) === false);
	ok('daily never-run becomes due at its first scheduled time', due(daily(23, 30, null), D(2026, 0, 10, 23, 35)) === true);
	ok('daily after today\'s time, not yet run today, is due', due(daily(23, 30, D(2026, 0, 9, 23, 30)), D(2026, 0, 10, 23, 35)) === true);
	ok('daily already run today is not due again', due(daily(23, 30, D(2026, 0, 10, 23, 30)), D(2026, 0, 10, 23, 40)) === false);
	ok('daily before today\'s time, having run yesterday on time, is NOT due (no premature run)', due(daily(9, 0, D(2026, 0, 9, 9, 0)), D(2026, 0, 10, 8, 0)) === false);

	// --- daily: THE FIX — a run missed across UTC midnight is caught up ---
	// Last ran day 8 at 23:30 UTC; day 9's 23:30 was missed (asleep); now is day 10 at 00:10 UTC (just after midnight).
	ok('daily catches up a run missed across midnight', due(daily(23, 30, D(2026, 0, 8, 23, 30)), D(2026, 0, 10, 0, 10)) === true);
	// But if it DID run yesterday, it must not fire again before today's time.
	ok('daily does not re-run before today\'s time when it ran yesterday', due(daily(23, 30, D(2026, 0, 9, 23, 30)), D(2026, 0, 10, 0, 10)) === false);
	// Month-boundary catch-up (day 0 of a month rolls to the previous month correctly, via Date.UTC).
	ok('daily catch-up works across a month boundary', due(daily(23, 30, D(2026, 0, 30, 23, 30)), D(2026, 1, 1, 0, 10)) === true);
	// Year-boundary catch-up (Dec 31 -> Jan 1 rolls the year back correctly).
	ok('daily catch-up works across a year boundary', due(daily(23, 30, D(2025, 11, 30, 23, 30)), D(2026, 0, 1, 0, 10)) === true);

	// The daily branch rebuilds the scheduled instant from the stored hour/minute, never a naive "now - last >= 24h"
	// delta. Ran today at 09:00 UTC; later the same UTC day it must not fire again even though far more than a day's
	// worth of the day remains, and it must not fire a second time within the same day regardless of elapsed hours.
	ok('daily does not re-run later the same UTC day once it has run', due(daily(9, 0, D(2026, 2, 8, 9, 0)), D(2026, 2, 8, 23, 0)) === false);
	ok('daily is due again the next UTC day after the time', due(daily(9, 0, D(2026, 2, 8, 9, 0)), D(2026, 2, 9, 9, 5)) === true);

	// off / missing dest
	ok('an off schedule is never due', due({ mode: 'off', dest: '/backup' }, D(2026, 0, 10, 23, 40)) === false);
	ok('a schedule with no destination is not due', vdisk.isBackupDue(daily(23, 30, null), D(2026, 0, 10, 23, 40)) === true && vdisk.isBackupDue({ mode: 'daily', hour: 23, minute: 30 }, D(2026, 0, 10, 23, 40)) === false);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SCHEDULE-DUE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
