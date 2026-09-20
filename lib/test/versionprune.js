'use strict';
// lib/test/versionprune.js — the version-prune decision must ALWAYS keep the newest snapshot, so an unattended
// prune can never delete a vault's last recovery point. This exercises versionsToPrune directly against the count,
// age, and size caps (existing version tests only ever create one snapshot and never trigger pruning). See
// lib/Vault.js (versionsToPrune).
//
// Run:  node lib/test/versionprune.js

const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { if (!cond) { console.log('  FAIL ' + name); failures++; } else { console.log('  ok   ' + name); } }

// Five valid version-stamp folder names, oldest → newest (format YYYY-MM-DDTHH-MM-SS-mmmZ).
const NAMES = [
	'2026-01-01T00-00-00-000Z',
	'2026-01-02T00-00-00-000Z',
	'2026-01-03T00-00-00-000Z',
	'2026-01-04T00-00-00-000Z',
	'2026-01-05T00-00-00-000Z',
];
const NEWEST = NAMES[NAMES.length - 1];
const shuffled = [NAMES[3], NAMES[0], NAMES[4], NAMES[1], NAMES[2]]; // order must not matter; it sorts internally

async function main() {
	// Count cap: keep the 2 newest, doom the 3 oldest; the newest is never doomed.
	let doomed = await Vault.versionsToPrune(shuffled, { keep: 2 }, async () => 0);
	ok('count cap dooms the 3 oldest', doomed.has(NAMES[0]) && doomed.has(NAMES[1]) && doomed.has(NAMES[2]));
	ok('count cap keeps the 2 newest', !doomed.has(NAMES[3]) && !doomed.has(NAMES[4]));
	ok('count cap never dooms the newest', !doomed.has(NEWEST));

	// Age cap with every snapshot older than the cutoff: everything is over-age, but the newest still survives.
	doomed = await Vault.versionsToPrune(NAMES, { maxAgeDays: 1 }, async () => 0);
	ok('age cap keeps the newest even when ALL snapshots are past the cutoff', !doomed.has(NEWEST));
	ok('age cap dooms the older over-age snapshots', doomed.has(NAMES[0]) && doomed.has(NAMES[3]));

	// Size cap where the newest snapshot alone exceeds the whole budget: it must still be retained.
	doomed = await Vault.versionsToPrune(NAMES, { maxSizeMB: 1 }, async () => 2 * 1024 * 1024); // each snapshot = 2 MB > 1 MB budget
	ok('size cap keeps the newest even when it alone exceeds the budget', !doomed.has(NEWEST));
	ok('size cap dooms the older snapshots that overflow the budget', doomed.has(NAMES[0]));

	// Combined caps still keep exactly one recovery point.
	doomed = await Vault.versionsToPrune(NAMES, { keep: 1, maxAgeDays: 1, maxSizeMB: 1 }, async () => 5 * 1024 * 1024);
	ok('with every cap active, the newest is still kept', !doomed.has(NEWEST));
	ok('with every cap active, at least one snapshot survives', doomed.size < NAMES.length);

	// A single snapshot is never pruned, whatever the policy.
	doomed = await Vault.versionsToPrune([NEWEST], { keep: 0, maxAgeDays: 1, maxSizeMB: 0.000001 }, async () => 9 * 1024 * 1024);
	ok('a lone snapshot is never pruned', doomed.size === 0);

	// No snapshots → nothing to prune, no error.
	doomed = await Vault.versionsToPrune([], { keep: 1 }, async () => 0);
	ok('an empty set prunes nothing', doomed.size === 0);

	// Non-stamp names are ignored (not pruned, not crashed on).
	doomed = await Vault.versionsToPrune(['not-a-stamp', '.versions', NAMES[0], NEWEST], { keep: 1 }, async () => 0);
	ok('non-stamp names are ignored and the newest stamp is kept', !doomed.has(NEWEST) && !doomed.has('not-a-stamp'));

	// The tests above exercise the pure prune DECISION. This guards the settings→policy MAPPING that feeds it
	// (versionsPolicy), which no functional test covers because it is internal: a flipped default or a renamed key
	// would silently change how much history everyone keeps, with no failing test. Pin the four invariants at the
	// source: history is on unless versionsKeep is exactly 0, the count defaults to 10, and the two optional caps are
	// coerced through nonNegNum (a non-positive or non-numeric cap becomes 0 = off, never a persisted NaN/negative).
	{
		const fs = require('fs'), path = require('path');
		const vault = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
		const at = vault.indexOf('function versionsPolicy(');
		const body = at >= 0 ? vault.slice(at, at + 400) : '';
		ok('versionsPolicy exists and reads settings.versionsKeep', /const k = settings && settings\.versionsKeep/.test(body));
		ok('history is on unless versionsKeep is exactly 0 (strict), and the count defaults to 10', /on: k !== 0/.test(body) && /\? k : 10/.test(body));
		ok('the age and size caps are coerced through nonNegNum (no NaN or negative)', /maxAgeDays: nonNegNum\(settings && settings\.versionsMaxAgeDays\)/.test(body) && /maxSizeMB: nonNegNum\(settings && settings\.versionsMaxSizeMB\)/.test(body));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VERSION-PRUNE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
