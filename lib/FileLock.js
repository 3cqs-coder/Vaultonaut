'use strict';
// lib/FileLock.js — a tiny cross-process advisory file lock. One lock file per key under data/locks/, carrying a
// nonce plus the holder's pid/host/timestamp: a holder that crashes or whose pid is reused is detected as STALE (by
// a TTL and a same-host liveness check) and reclaimed atomically, and a long-lived holder refreshes its timestamp on
// a heartbeat so it is never judged stale mid-operation. ONE proven implementation shared by every cross-process
// serialization in the app — the vault lock (Vault.withVaultLock, which layers its own lease fence on top), the
// tamper/rollback ledger, and the mount-state file — so they can never drift on how "who holds this?" is decided.
// Pure Node (fs + crypto), cross-platform: the atomic create-or-fail (`wx`) and rename-aside reclaim work the same
// on macOS, Linux, and Windows (renameWithRetry rides out a transient Windows lock).

const fsp = require('fs').promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const Common = require('./Common');

const TTL_MS = 30 * 1000;   // a lock not refreshed within this is stale (a crashed or reused-pid holder)
const BEAT_MS = 10 * 1000;  // a held lock refreshes its timestamp this often, so a live long op stays valid

// The lock file path for a KEY (any stable string — e.g. a resolved file path). The key is hashed so the lock name
// is filesystem-safe and fixed-length regardless of the key. Every caller under the same data dir that passes the
// same key gets the same lock file, which is exactly what serializes them across processes.
function lockPathFor(key) {
	const h = crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 32);
	return path.join(Common.dataDir(), 'locks', h + '.lock');
}
function record(nonce) { return JSON.stringify({ v: 1, pid: process.pid, host: os.hostname(), at: Date.now(), nonce }); }
function stale(held) {
	if (!held) return true;
	if (Date.now() - (held.at || 0) > TTL_MS) return true;                                        // not refreshed in time
	if (held.host === os.hostname() && held.pid && !Common.isProcessAlive(held.pid)) return true; // same machine, holder gone
	return false;
}
// The current holder record at lock path p, or null if absent/unreadable/torn.
async function readHolder(p) { try { return JSON.parse(await fsp.readFile(p, 'utf8')); } catch (_) { return null; } }

// Reclaim and heartbeat rename a temp file into place (`p + '.reclaim.' + nonce` / `p + '.beat.' + nonce`). A crash
// in the tiny window between creating that temp and renaming/removing it leaves it behind, and nothing else visits
// data/locks/ — so over a long-lived install those orphans would slowly accumulate. This best-effort, THROTTLED,
// age-gated sweep removes them: the age gate is far beyond any live rename window, so a temp a running operation is
// still using can never be swept. Detached and bounded — it never blocks or fails an acquire, and it swallows every
// error (a missing dir, a racing remove). Kept here, beside the code that creates the temps, so the two can't drift.
const TEMP_RE = /\.(reclaim|beat)\.[0-9a-f]+$/;
const TEMP_STALE_MS = 5 * 60 * 1000;
const SWEEP_EVERY_MS = 60 * 1000;
let lastSweep = 0;
async function sweepStaleTemps(dir) {
	let names; try { names = await fsp.readdir(dir); } catch (_) { return; }
	const now = Date.now();
	for (const n of names) {
		if (!TEMP_RE.test(n)) continue;
		const f = path.join(dir, n);
		try { const st = await fsp.stat(f); if (now - st.mtimeMs > TEMP_STALE_MS) await fsp.rm(f, { force: true }); } catch (_) {}
	}
}

// Acquire the lock at file path p. Creates data/locks/ if needed, waits a short while for a live holder to finish
// (then throws with code VAULT_LOCKED rather than hanging), and reclaims a stale holder atomically. Returns
// { p, nonce } — pass both to refresh/release.
async function acquire(p) {
	try { await fsp.mkdir(path.dirname(p), { recursive: true }); } catch (_) {}
	// Opportunistically clear any orphaned reclaim/heartbeat temp files (throttled, detached, best-effort so it never
	// slows or blocks the acquire itself).
	if (Date.now() - lastSweep > SWEEP_EVERY_MS) { lastSweep = Date.now(); sweepStaleTemps(path.dirname(p)).catch(() => {}); }
	const nonce = crypto.randomBytes(12).toString('hex');
	const deadline = Date.now() + 12000; // wait a short while for a brief holder, then refuse rather than hang
	for (;;) {
		let fh = null;
		try { fh = await fsp.open(p, 'wx'); } catch (e) { if (e.code !== 'EEXIST') throw e; }
		if (fh) { try { await fh.write(record(nonce)); } finally { await fh.close(); } return { p, nonce }; }
		// Held by someone. Read it. An empty or torn file is a BIRTH in progress (another acquirer created it but has
		// not written the record yet) — wait briefly rather than reclaiming a lock that is about to be valid.
		let raw = null; try { raw = await fsp.readFile(p, 'utf8'); } catch (_) { continue; } // vanished -> retry create
		let held = null; try { held = JSON.parse(raw); } catch (_) {}
		if (!held) {
			let ageMs = Infinity; try { ageMs = Date.now() - (await fsp.stat(p)).mtimeMs; } catch (_) { continue; }
			if (ageMs < 3000) { await Common.sleep(60); continue; } // just born; give the writer a moment
		}
		if (stale(held)) {
			// Reclaim atomically: rename the stale file aside (only one racer's rename can move a given file; the loser
			// gets ENOENT and retries). Confirm the moved file really was stale before discarding it — if a fresh lock
			// slipped in between the read and the rename, put it back and wait rather than dropping it.
			const aside = p + '.reclaim.' + nonce;
			try {
				await Common.renameWithRetry(p, aside); // ENOENT (the race loser) still throws, preserving the atomic reclaim
				let moved = null; try { moved = JSON.parse(await fsp.readFile(aside, 'utf8')); } catch (_) {}
				if (stale(moved)) { await fsp.rm(aside, { force: true }); }
				else { try { await Common.renameWithRetry(aside, p); } catch (_) { await fsp.rm(aside, { force: true }); } }
			} catch (_) {} // lost the reclaim race -> retry
			continue;
		}
		if (Date.now() > deadline) { const err = new Error('This is busy with another operation. Wait for it to finish, then try again.'); err.code = 'VAULT_LOCKED'; throw err; }
		await Common.sleep(150);
	}
}
// Refresh a held lock's timestamp ATOMICALLY (temp + rename), and only while we still own it — so a reader can never
// observe a torn record, and a beat can never resurrect a lock that was already reclaimed and replaced.
async function refresh(p, nonce) {
	try {
		let cur = null; try { cur = JSON.parse(await fsp.readFile(p, 'utf8')); } catch (_) {}
		if (!cur || cur.nonce !== nonce) return; // no longer ours — do not touch a new holder's file
		const tmp = p + '.beat.' + nonce;
		await fsp.writeFile(tmp, record(nonce));
		await Common.renameWithRetry(tmp, p); // atomic replace; readers never see a half-written record
	} catch (_) {}
}
// Release the lock — remove it only if it is still OURS (a reclaimed-and-replaced lock now carries a different nonce
// and must not be removed from under its new owner).
async function release(p, nonce) {
	try { const cur = JSON.parse(await fsp.readFile(p, 'utf8')); if (cur && cur.nonce === nonce) await fsp.rm(p, { force: true }); } catch (_) {}
}
// Hold the lock for the duration of fn: acquire, keep it fresh with an unref'd heartbeat (so a rare long hold is
// never judged stale and stolen), then release. A short read-modify-write finishes before the first beat, so it
// writes nothing extra. The vault lock does not use this — it composes acquire/refresh/release itself so it can also
// maintain its in-memory lease fence.
async function withLock(p, fn) {
	const { nonce } = await acquire(p);
	const beat = setInterval(() => { refresh(p, nonce); }, BEAT_MS);
	if (beat.unref) beat.unref();
	try { return await fn(); }
	finally { clearInterval(beat); await release(p, nonce); }
}

module.exports = { lockPathFor, record, stale, readHolder, acquire, refresh, release, withLock, sweepStaleTemps, TTL_MS, BEAT_MS, TEMP_STALE_MS };
