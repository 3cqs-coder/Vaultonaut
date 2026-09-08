'use strict';
// lib/Watchdog.js — runtime health watch for mounted vaults.
//
// The macOS mount is a hard NFS mount (FUSE-T): a wedged engine or a stuck operation makes the
// drive stop responding while it still LOOKS mounted, so the file manager spins. This watch
// probes each tracked mount with a strictly bounded stat and classifies it, so the interface can
// surface a stuck drive as a one-click recovery instead of leaving the user to reboot — which is
// never the right answer.
//
// Design (mirrors the platform's self-policing style): self-contained, WARN-ONLY (it only
// observes and reports — it never tears a drive down on its own, so a healthy-but-busy drive is
// safe), and it NEVER throws, so it can never disturb a mount.
//
// Two safety properties keep the watch from ever becoming the thing that freezes the app — a
// stat on a wedged hard-NFS mount pins a worker thread until the mount is force-released, and a
// timeout bounds the RESULT but cannot cancel the underlying stat, so pinned threads accumulate:
//   • Per mount, it NEVER launches a second stat while one is still pending, so a single wedged
//     mount can pin at most one thread.
//   • Across mounts, it never lets more than MAX_OUTSTANDING probes be in flight at once, so no
//     number of simultaneously-wedged mounts can exhaust the worker-thread pool — the app always
//     keeps threads free for its own file reads. Mounts skipped this pass keep their last known
//     health and are re-probed once a slot frees.
// A healthy mount answers a stat in single-digit milliseconds almost always, but a drive under a
// heavy WRITE (especially the SMB backend) can occasionally miss the timeout on a single probe while
// it is perfectly fine. So a missed probe is NOT reported immediately: a drive is only classified
// 'unresponsive' after it has failed probes CONTINUOUSLY for a grace period. A busy copy produces
// isolated slow probes interleaved with fast ones, which never reaches the grace window; a truly
// wedged drive keeps failing and crosses it. This removes the false "not responding" flash during a
// large copy without weakening detection of a real wedge (surfaced within the grace window).
//
//   refresh(mounts) -> { snapshot, changes }   // probe + update the cache; report transitions
//   snapshot()       -> { <mountpoint>: health }  // cached; instant; no probing
//
// 'dead' = the engine process is gone (a stale mount); the periodic self-heal clears these
// automatically. 'unresponsive' = the engine is alive but the drive does not answer (wedged);
// this is surfaced for the one-click Force unmount, never torn down here.

const fsp = require('fs').promises;
const Common = require('./Common');
const Rclone = require('./Rclone');

const PROBE_MS = 3000;              // wide margin over a healthy mount's single-digit-millisecond stat
const MAX_OUTSTANDING = 2;          // never pin more than this many worker threads on wedged mounts (pool is small)
const UNRESPONSIVE_GRACE_MS = 12000; // must fail probes continuously for this long before it counts as wedged
const STALE_PROBE_MS = 60000;       // if a mount cannot get a probe slot for this long (pool saturated by other wedged mounts), note once that its shown health may be out of date

const cache = new Map();   // mountpoint -> 'healthy' | 'unresponsive' | 'dead'
const pending = new Map(); // mountpoint -> the raw stat promise still in flight (may stay pending)
const failingSince = new Map(); // mountpoint -> timestamp it first started failing probes (cleared on a good stat)
const lastProbed = new Map();   // mountpoint -> timestamp of its last COMPLETED probe (not a skip)
const staleNoted = new Set();   // mountpoints already logged as stale, so the note fires once per stale spell

// Start, or reuse, a single bounded stat for a mount. Returns 'ok' (answered), 'fail' (answered
// with an error — e.g. the mount is gone/stale), 'timeout' (did not answer in time), or 'skip'
// (the outstanding-probe cap was reached — do not launch a new stat; keep the last known health).
function probe(mp) {
	if (!pending.has(mp)) {
		if (pending.size >= MAX_OUTSTANDING) return Promise.resolve('skip'); // protect the worker-thread pool
		const p = fsp.stat(mp).then(() => 'ok', () => 'fail');
		pending.set(mp, p);
		// Clear the slot only when THIS stat settles, so a still-stuck stat keeps blocking new ones.
		p.finally(() => { if (pending.get(mp) === p) pending.delete(mp); });
	}
	return Common.withTimeout(pending.get(mp), PROBE_MS).catch(() => 'timeout');
}

// Probe every tracked mount (bounded, parallel), update the cache, and return the new snapshot
// plus the list of mounts whose health changed since last time (for one-time logging). Never throws.
async function refresh(mounts, nowArg) {
	const list = Array.isArray(mounts) ? mounts : [];
	const now = Number.isFinite(nowArg) ? nowArg : Date.now(); // injectable clock for tests; production always passes one argument

	const livePoints = new Set(list.map(m => m.mountpoint));
	for (const mp of [...cache.keys()]) if (!livePoints.has(mp)) { cache.delete(mp); failingSince.delete(mp); lastProbed.delete(mp); staleNoted.delete(mp); } // forget unmounted
	// Also release the outstanding-probe slot of any DEPARTED mount. Its stat may never settle (a mount torn out of
	// state while its FUSE layer stays wedged), and if that straggler kept its slot it would permanently count against
	// MAX_OUTSTANDING and silently disable health probing for every live mount. The stat's own `.finally` no-ops after
	// this delete (it checks the entry is still itself), so this cannot clobber a new probe for a re-appeared mount.
	for (const mp of [...pending.keys()]) if (!livePoints.has(mp)) pending.delete(mp);

	const changes = [];
	await Promise.all(list.map(async (m) => {
		const mp = m.mountpoint;
		if (!lastProbed.has(mp)) lastProbed.set(mp, now); // first sight — start the staleness clock so a new mount is never instantly "stale"
		let result;
		try { result = await probe(mp); } catch (_) { result = 'timeout'; }
		if (result === 'skip') {
			// The pool was saturated by other (wedged) mounts, so this mount kept its last known health. If it has
			// gone unprobed for too long, note it ONCE — its shown status may be out of date until a slot frees.
			if (now - (lastProbed.get(mp) || now) >= STALE_PROBE_MS && !staleNoted.has(mp)) {
				staleNoted.add(mp);
				Common.warn('Could not check the health of ' + (m.volname || mp) + ' recently — the system is busy with other unresponsive drives, so its shown status may be out of date.');
			}
			return; // leave this mount's last known health untouched
		}
		lastProbed.set(mp, now); staleNoted.delete(mp); // a completed probe (ok/fail/timeout) refreshes the clock and re-arms the note
		// The engine being gone is decisive: a stale record whose mount point still stats as a
		// plain directory must NOT read healthy, or the self-heal would never clear it. Identity is
		// checked via the control socket, so a recycled pid is not mistaken for a live engine.
		// Reuse the mountpoint probe we just did (result) instead of letting engineAlive re-stat the same mount —
		// a second stat on a wedged mount would pin another threadpool slot beyond this watch's outstanding cap.
		const engineAlive = await Rclone.engineAlive(m, result);
		let next;
		if (!engineAlive) { next = 'dead'; failingSince.delete(mp); }
		else if (result === 'ok') { next = 'healthy'; failingSince.delete(mp); } // answered — clear any failing streak
		else {
			// Missed this probe. Only surface "not responding" once it has been failing CONTINUOUSLY for
			// the grace window — an isolated slow probe during a large copy stays healthy — while a mount
			// already flagged stays flagged until it answers again.
			const since = failingSince.get(mp) || now;
			failingSince.set(mp, since);
			next = (now - since >= UNRESPONSIVE_GRACE_MS || cache.get(mp) === 'unresponsive') ? 'unresponsive' : 'healthy';
		}
		const prev = cache.get(mp) || 'healthy';
		cache.set(mp, next);
		if (prev !== next) changes.push({ mountpoint: mp, name: m.volname || '', from: prev, to: next });
	}));

	return { snapshot: snapshot(), changes };
}

// The last known health per mountpoint (cached — instant, does no I/O). Safe to call anywhere,
// including on the request path, without risk of blocking on a wedged mount.
function snapshot() { return Object.fromEntries(cache); }

module.exports = { refresh, snapshot };
