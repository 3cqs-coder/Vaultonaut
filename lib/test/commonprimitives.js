'use strict';
// lib/test/commonprimitives.js — behavioral tests for the data-integrity primitives in Common.js that the rest of
// the app leans on but that were previously only checked for EXPORT, not behavior: writeJsonAtomic (the atomic,
// optionally-durable writer used for the manifest and every ledger), serialQueue / serialQueueByKey (the no-
// interleave guarantee protecting read-modify-write on state/settings/ledger files), pollUntil (the bounded wait
// behind unmount/shutdown), renameWithRetry (which must never mask a non-lock error), and isProcessAlive (which
// must not report a non-positive pid as alive). These are the crown-jewel helpers; a regression here is a data or
// liveness bug, so lock the contracts down.
//
// Run:  node lib/test/commonprimitives.js   (no engine, no network)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const isWin = process.platform === 'win32';

async function testWriteJsonAtomic(dir) {
	const p = path.join(dir, 'sub', 'file.json'); // a nested path also exercises the mkdir-parents step

	// Atomic write + read-back.
	await Common.writeJsonAtomic(p, { a: 1, b: 'x' });
	ok('writeJsonAtomic writes valid JSON that reads back', JSON.stringify(JSON.parse(await fsp.readFile(p, 'utf8'))) === JSON.stringify({ a: 1, b: 'x' }));

	// chmod:true tightens the mode exactly (chmod is not umask-masked, unlike the open mode). POSIX only.
	if (!isWin) {
		await Common.writeJsonAtomic(p, { secret: true }, { mode: 0o600, chmod: true, fsync: true });
		ok('writeJsonAtomic + chmod applies 0o600', (fs.statSync(p).mode & 0o777) === 0o600);
	}

	// Failure path: a value JSON.stringify cannot serialize must leave the DESTINATION untouched and clean up the
	// temp — never a torn/half file, and never a stray temp sibling. Seed a known-good file first, then fail a write.
	await Common.writeJsonAtomic(p, { good: 1 });
	const circular = {}; circular.self = circular; // JSON.stringify throws on a circular reference
	let threw = false;
	try { await Common.writeJsonAtomic(p, circular); } catch (_) { threw = true; }
	ok('writeJsonAtomic rejects an unserializable value', threw);
	ok('writeJsonAtomic left the destination intact on failure', JSON.parse(await fsp.readFile(p, 'utf8')).good === 1);
	const leftovers = (await fsp.readdir(path.dirname(p))).filter(n => n !== 'file.json');
	ok('writeJsonAtomic left no temp file behind on failure', leftovers.length === 0);

	// Concurrent writes to the SAME path must not collide on the temp (unique temp per write) — both settle, the
	// result is one of the two whole values (never a torn mix), and no temp sibling survives.
	await Promise.all([
		Common.writeJsonAtomic(p, { who: 'A', n: 1 }, { fsync: true }),
		Common.writeJsonAtomic(p, { who: 'B', n: 2 }, { fsync: true }),
	]);
	const after = JSON.parse(await fsp.readFile(p, 'utf8'));
	ok('concurrent writeJsonAtomic yields one whole value', (after.who === 'A' && after.n === 1) || (after.who === 'B' && after.n === 2));
	ok('concurrent writeJsonAtomic left no temp behind', (await fsp.readdir(path.dirname(p))).filter(n => n !== 'file.json').length === 0);
}

async function testSerialQueue() {
	// No interleave: each task does a read-modify-write with an await in the middle. Without serialization the reads
	// would all see the same start value and updates would be lost; serialized, the final value is exact.
	const run = Common.serialQueue();
	let shared = 0;
	const order = [];
	const tasks = [];
	for (let i = 0; i < 20; i++) {
		tasks.push(run(async () => {
			const seen = shared;
			await new Promise(r => setTimeout(r, Math.random() * 5)); // a real interleave window
			shared = seen + 1;
			order.push(i);
		}));
	}
	await Promise.all(tasks);
	ok('serialQueue prevents lost updates across 20 tasks', shared === 20);
	ok('serialQueue runs tasks in submission order', order.join(',') === Array.from({ length: 20 }, (_, i) => i).join(','));

	// Error isolation: a rejecting task propagates to ITS caller but must not wedge the queue for later tasks.
	const run2 = Common.serialQueue();
	let ranAfter = false;
	let caught = false;
	const bad = run2(async () => { throw new Error('boom'); });
	const good = run2(async () => { ranAfter = true; return 'ok'; });
	try { await bad; } catch (_) { caught = true; }
	ok('serialQueue rejects the failing task to its own caller', caught);
	ok('serialQueue keeps running later tasks after a rejection', (await good) === 'ok' && ranAfter);
}

async function testSerialQueueByKey() {
	const run = Common.serialQueueByKey();
	// Same key serializes (no lost updates); different keys are independent and may overlap.
	const counters = { a: 0, b: 0 };
	const tasks = [];
	for (let i = 0; i < 10; i++) {
		for (const key of ['a', 'b']) {
			tasks.push(run(key, async () => { const seen = counters[key]; await new Promise(r => setTimeout(r, Math.random() * 4)); counters[key] = seen + 1; }));
		}
	}
	await Promise.all(tasks);
	ok('serialQueueByKey serializes each key independently', counters.a === 10 && counters.b === 10);

	// A rejection on one key must not wedge that key or any other.
	const run2 = Common.serialQueueByKey();
	let caught = false, later = false, otherKey = false;
	try { await run2('k', async () => { throw new Error('x'); }); } catch (_) { caught = true; }
	await run2('k', async () => { later = true; });
	await run2('other', async () => { otherKey = true; });
	ok('serialQueueByKey isolates a rejection and keeps the key usable', caught && later && otherKey);
}

async function testPollUntil() {
	// Becomes true partway through, within the timeout.
	let ticks = 0;
	const became = await Common.pollUntil(async () => (++ticks >= 3), { timeoutMs: 1000, stepMs: 10 });
	ok('pollUntil resolves true once the predicate is truthy', became === true);
	// Never becomes true -> false at the timeout (and it actually stops, does not hang).
	const timedOut = await Common.pollUntil(async () => false, { timeoutMs: 40, stepMs: 10 });
	ok('pollUntil resolves false on timeout', timedOut === false);
	// Already-true on the first check.
	ok('pollUntil resolves true immediately when already satisfied', (await Common.pollUntil(() => true, { timeoutMs: 1000, stepMs: 10 })) === true);
}

async function testRenameWithRetry(dir) {
	const from = path.join(dir, 'r-from'); const to = path.join(dir, 'r-to');
	await fsp.writeFile(from, 'data');
	await Common.renameWithRetry(from, to);
	ok('renameWithRetry moves the file', fs.existsSync(to) && !fs.existsSync(from) && fs.readFileSync(to, 'utf8') === 'data');
	// A non-lock error (a missing source) must reject immediately — the retry loop must never mask it or spin.
	let rejected = false;
	const t0 = Date.now();
	try { await Common.renameWithRetry(path.join(dir, 'does-not-exist'), to); } catch (_) { rejected = true; }
	ok('renameWithRetry rethrows a non-lock error', rejected);
	ok('renameWithRetry does not spin on a non-lock error', Date.now() - t0 < 1000);
}

function testIsProcessAlive() {
	ok('isProcessAlive true for the current process', Common.isProcessAlive(process.pid) === true);
	ok('isProcessAlive false for a non-positive pid (0)', Common.isProcessAlive(0) === false);
	ok('isProcessAlive false for a negative pid', Common.isProcessAlive(-1) === false);
	// An almost-certainly-dead high pid. (Not guaranteed free, but reliable enough for a smoke check.)
	ok('isProcessAlive false for an unused high pid', Common.isProcessAlive(0x3fffffff) === false);
}

function testSuspiciousMassDeletion() {
	const s = Common.suspiciousMassDeletion;
	// A total wipe at ANY count is suspicious.
	ok('a total wipe of 1 file is suspicious', s(1, 1) === true);
	ok('a total wipe of 3 files is suspicious', s(3, 3) === true);
	// Below ten files, a partial (non-total) deletion is NOT flagged (only a full wipe is).
	ok('deleting 8 of 9 is not flagged (under ten, not a full wipe)', s(9, 8) === false);
	// Ten-plus: 90% or more trips it, just under does not.
	ok('deleting 9 of 10 (90%) is suspicious', s(10, 9) === true);
	ok('deleting 8 of 10 (80%) is not', s(10, 8) === false);
	// Twenty-plus: more than half trips it.
	ok('deleting 11 of 20 (>50%) is suspicious', s(20, 11) === true);
	ok('deleting 10 of 20 (exactly 50%) is not', s(20, 10) === false);
	// Degenerate inputs are safe (never flag).
	ok('zero total is never suspicious', s(0, 0) === false && s(0, 5) === false);
	ok('zero deletions is never suspicious', s(100, 0) === false);
}

async function testFailureBackoff() {
	const b = Common.failureBackoff({ threshold: 3, maxDelayMs: 1000, maxEntries: 4 });
	const now = 1000;
	// Not blocked until the threshold of consecutive failures is reached.
	b.fail('a', now); b.fail('a', now);
	ok('not blocked before the threshold', b.blocked('a', now) === false);
	b.fail('a', now); // 3rd failure hits the threshold
	ok('blocked once the threshold is reached', b.blocked('a', now) === true);
	// The block expires after the (capped) backoff window.
	ok('block expires after the backoff window', b.blocked('a', now + 2000) === false);
	// A success clears the count so the next failure starts over.
	b.clear('a');
	b.fail('a', now); b.fail('a', now);
	ok('clear() resets the count (still unblocked after 2 fresh fails)', b.blocked('a', now) === false);
	// Keys are independent.
	ok('a different key is unaffected', b.blocked('b', now) === false);
	// The map is hard-capped: flooding distinct still-blocked keys never grows it without bound.
	const c = Common.failureBackoff({ threshold: 1, maxDelayMs: 100000, maxEntries: 4 });
	for (let i = 0; i < 50; i++) c.fail('k' + i, now); // each is immediately blocked (threshold 1), none expired
	let live = 0; for (let i = 0; i < 50; i++) if (c.blocked('k' + i, now)) live++;
	ok('the backoff map is hard-capped under a flood of distinct keys', live <= 4);
}

async function main() {
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vaultonaut-primitives-'));
	try {
		await testWriteJsonAtomic(dir);
		await testSerialQueue();
		await testSerialQueueByKey();
		await testPollUntil();
		await testRenameWithRetry(dir);
		testIsProcessAlive();
		testSuspiciousMassDeletion();
		await testFailureBackoff();
	} finally {
		try { await fsp.rm(dir, { recursive: true, force: true }); } catch (_) {}
	}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL COMMON-PRIMITIVE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
