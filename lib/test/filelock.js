'use strict';
// lib/test/filelock.js — the shared cross-process advisory file lock (lib/FileLock.js) that now serializes the vault
// lock, the tamper/rollback ledger, and the mount-state file. Checks the properties every one of those relies on:
// two holders of the same key are mutually exclusive, a crashed/stale holder is reclaimed, and release removes the
// lock only when it is still OURS (never a newer holder's). No engine, no network.
//
// Run:  node -r ./lib/test/_setup.js lib/test/filelock.js

const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const FileLock = require('../FileLock');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
	const key = 'test-filelock-' + crypto.randomBytes(6).toString('hex');
	const p = FileLock.lockPathFor(key);

	// Deterministic key -> path, so two processes serialize on the SAME file.
	ok('lockPathFor is deterministic for a key', FileLock.lockPathFor(key) === p);

	// Mutual exclusion: two withLock sections on the same key must never interleave.
	{
		let active = 0, maxActive = 0; const order = [];
		const section = (id) => FileLock.withLock(p, async () => {
			active++; maxActive = Math.max(maxActive, active); order.push(id + 'in');
			await sleep(40);
			order.push(id + 'out'); active--;
		});
		await Promise.all([section('A'), section('B')]);
		ok('two holders of the same key never overlap (serialized)', maxActive === 1);
		ok('each critical section completes before the next starts', /^(Ain Aout Bin Bout|Bin Bout Ain Aout)$/.test(order.join(' ')));
		ok('the lock file is removed after the last release', !fs.existsSync(p));
	}

	// Stale reclaim: a lock whose timestamp is older than the TTL (a crashed holder that never released) is reclaimed
	// by a new acquirer rather than blocking forever.
	{
		await fsp.mkdir(path.dirname(p), { recursive: true });
		await fsp.writeFile(p, JSON.stringify({ v: 1, pid: 999999, host: os.hostname(), at: Date.now() - (FileLock.TTL_MS + 5000), nonce: 'stale-holder' }));
		const h = await FileLock.acquire(p);
		ok('a stale (expired) lock is reclaimed by a new acquirer', !!h.nonce && h.nonce !== 'stale-holder');
		await FileLock.release(p, h.nonce);
		ok('the reclaimed lock is released cleanly', !fs.existsSync(p));
	}

	// release removes only OUR lock: if the file was replaced by a NEW holder while we held our nonce, our release
	// must leave that new holder's lock in place (never yank a lock out from under its owner).
	{
		const mine = await FileLock.acquire(p);
		await fsp.writeFile(p, FileLock.record('someone-else')); // a fresh record with a different nonce and a live pid — not stale
		await FileLock.release(p, mine.nonce);
		ok("release does not remove a different holder's lock", fs.existsSync(p));
		await fsp.rm(p, { force: true });
	}

	// Orphaned reclaim/heartbeat temp cleanup: a crash mid-rename can leave a `*.reclaim.*` / `*.beat.*` file behind,
	// and nothing else visits data/locks/. sweepStaleTemps removes only those, and only once they are older than the
	// stale window, so a temp a live operation is still using is never swept, and a real .lock is never touched.
	{
		const dir = path.dirname(p);
		await fsp.mkdir(dir, { recursive: true });
		const oldReclaim = path.join(dir, 'x.lock.reclaim.' + crypto.randomBytes(6).toString('hex'));
		const oldBeat = path.join(dir, 'y.lock.beat.' + crypto.randomBytes(6).toString('hex'));
		const freshBeat = path.join(dir, 'z.lock.beat.' + crypto.randomBytes(6).toString('hex'));
		const realLock = FileLock.lockPathFor('sweep-keep-' + crypto.randomBytes(4).toString('hex'));
		await fsp.writeFile(oldReclaim, 'x'); await fsp.writeFile(oldBeat, 'y'); await fsp.writeFile(freshBeat, 'z');
		await fsp.writeFile(realLock, FileLock.record('keep-me'));
		const old = new Date(Date.now() - (FileLock.TEMP_STALE_MS + 60000)); // comfortably past the stale window
		await fsp.utimes(oldReclaim, old, old); await fsp.utimes(oldBeat, old, old);
		await FileLock.sweepStaleTemps(dir);
		ok('an old orphaned .reclaim temp is swept', !fs.existsSync(oldReclaim));
		ok('an old orphaned .beat temp is swept', !fs.existsSync(oldBeat));
		ok('a FRESH temp (a live op may still be using it) is NOT swept', fs.existsSync(freshBeat));
		ok('a real .lock file is never touched by the temp sweep', fs.existsSync(realLock));
		for (const f of [freshBeat, realLock]) await fsp.rm(f, { force: true });
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FILE-LOCK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
