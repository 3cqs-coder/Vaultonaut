'use strict';
// lib/test/freshcache.js — Common.freshCache: a stale-while-revalidate async cache with in-flight dedup.
// It backs the /api/state poll so a vault on a wedged drive can't hang the poll or start a fresh
// thread-pinning read every few seconds. The subtle parts (return-stale-immediately, one-compute-per-key,
// wait-for-the-first-read-at-most-once) are what these checks pin down.
//
// Run:  node lib/test/freshcache.js

const Common = require('../Common');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	console.log('[a fast source returns its value on the first get]');
	{
		const get = Common.freshCache(async (k) => 'v:' + k, { firstWaitMs: 1000 });
		ok('first get resolves to the computed value', (await get('a')) === 'v:a');
	}

	console.log('[a slow source returns pending, then the value once it settles — waiting at most once]');
	{
		let release; const gate = new Promise(r => { release = r; });
		let calls = 0;
		const get = Common.freshCache(async () => { calls++; await gate; return 'ready'; }, { firstWaitMs: 80 });
		ok('the first get returns pending (undefined) after the brief wait', (await get('x')) === undefined);
		ok('the compute was started exactly once', calls === 1);
		ok('a later get stays pending WITHOUT re-waiting or re-computing', (await get('x')) === undefined && calls === 1);
		release(); await sleep(20);
		ok('the value appears on a later get once the compute settles', (await get('x')) === 'ready');
	}

	console.log('[concurrent gets share a single compute (in-flight dedup)]');
	{
		let calls = 0;
		const get = Common.freshCache(async () => { calls++; await sleep(30); return 'z'; }, { firstWaitMs: 500 });
		await Promise.all([get('k'), get('k'), get('k')]); // only the first waits; all share one in-flight compute
		ok('three simultaneous gets triggered exactly one compute', calls === 1);
		await sleep(40);
		ok('the value is available once the shared compute settles', (await get('k')) === 'z');
	}

	console.log('[stale-while-revalidate: return the cached value at once, refresh in the background]');
	{
		let n = 0;
		const get = Common.freshCache(async () => { n++; return 'n' + n; }, { firstWaitMs: 500 });
		ok('first value is computed and returned', (await get('s')) === 'n1');
		ok('a later get returns the cached value immediately (stale)', (await get('s')) === 'n1');
		await sleep(10);
		ok('the background refresh has updated the value by the next get', (await get('s')) === 'n2');
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FRESH-CACHE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
