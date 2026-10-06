'use strict';
// lib/DisperseProcess.js — runs the CPU-heavy Reed–Solomon encode/decode for Tier 3 dispersal in an isolated
// child PROCESS, so it can never block the event loop or a mounted drive's health checks AND its large working
// set is fully isolated: Reed–Solomon is non-streaming, so it must hold the whole packed archive (up to the
// multi-GB cap) plus the full shard set in memory at once. In a child process that memory is its own address
// space — it never counts against the shared web/background service and the OS reclaims all of it the instant
// this process exits, so no single dispersal and no sequence of them can drive the app to an out-of-memory kill
// (a worker THREAD, by contrast, shares the service's heap, so an over-large job would take the whole service
// down with it). The big archive is read/written to files here (never posted across the process boundary), so
// the whole blob stays in this process's memory. Progress is streamed as { percent, label }; the coding math
// lives in Disperse.js.
//
// Ops (job.op / .args):
//   encode { archivePath, files, n, k }        -> split the archive into n shard files
//   decode { shardPaths, archivePath }         -> rebuild the archive from k+ shard files
//   repair { shardPaths, targets, n, k }        -> re-create the listed shard files from the survivors

const fs = require('fs/promises');
const path = require('path');
const Disperse = require('./Disperse');
const WorkerRun = require('./WorkerRun');
const Common = require('./Common');

// Read the survivor shards one at a time, emitting progress per shard. The per-shard tick matters for more
// than the UI: shard folders live on OTHER nodes / removable / network drives, so a read can stall on a
// yanked drive; the parent runs this process under the idle watchdog, and the steady progress lets that
// watchdog tell a genuine stall (no more ticks) from a slow-but-working read of a large shard.
async function readShards(shardPaths, progress, base, label) {
	// Reconstruction needs any k shards of ONE dispersal. Retain only shards whose in-frame hash checks out
	// (Disperse.shardInfo(...).good), grouped by geometry, and stop the instant one geometry group has k
	// distinct-index shards — enough to rebuild. This is what defeats a starvation attack: a bit-rotten or
	// deliberately-planted junk shard fails its hash, so it is skipped and NEVER retained, and thus can't fill
	// a byte budget and crowd out the good shards that would rebuild the set. Two bounds keep a hostile folder
	// from exhausting the worker: wasted (bad) reads are capped, and retained good bytes are capped at ~two
	// archives (one real dispersal's k shards sum to ~one archive). Each read is itself size-bounded by readShard.
	const ARCH = Disperse.MAX_ARCHIVE_BYTES + 256 * Disperse.HEADER;
	const NULL_READ_COST = 1024 * 1024; // charge each unreadable/mis-declared file ~1 MiB toward the junk budget, so a folder full of tiny junk files is bounded to ~a few thousand reads rather than walked in full
	const groups = new Map();
	let junkRead = 0, keptBytes = 0;
	for (let i = 0; i < shardPaths.length; i++) {
		if (junkRead >= 4 * ARCH || keptBytes >= 2 * ARCH) break;
		const b = await Disperse.readShard(shardPaths[i]); // bounded read; null if unreadable/mis-declared
		progress({ percent: base + Math.floor((i + 1) / shardPaths.length * 20), label });
		if (!b) { junkRead += NULL_READ_COST; continue; } // count a junk file toward the budget so the loop can't run unbounded over a hostile folder
		const info = Disperse.shardInfo(b);
		if (!info || !info.good) { junkRead += b.length; continue; } // bit-rot / forged-without-a-valid-hash: skip, don't charge the good budget
		const key = (info.id || 'v1') + ':' + info.k + ':' + info.m + ':' + info.origLen + ':' + info.shardLen; // group by dispersal id (v2) + geometry, so a foreign dispersal's shards never join this set
		let g = groups.get(key); if (!g) { g = new Map(); groups.set(key, g); }
		if (!g.has(info.idx)) { g.set(info.idx, b); keptBytes += b.length; }
	}
	// Pick the LARGEST consistent group (the majority dispersal) — the documented defense against cross-split mixing.
	// Deliberately NOT "the first group in path order to reach k": if the folder holds two dispersals (a foreign/planted
	// set, or leftovers from a re-disperse with a different geometry), returning the first-to-k could hand back the
	// MINORITY set and reconstruct the wrong (but internally consistent) archive, diverging from what inspect reports.
	// Reading every shard first is still bounded by the junk/kept-byte budgets above, and this now matches
	// Disperse.largestGroup and inspect so decode, repair, and inspect never disagree on which set wins.
	let best = [];
	for (const g of groups.values()) if (g.size > best.length) best = [...g.values()];
	return best;
}

// A time-throttled liveness heartbeat for the CPU-bound Reed-Solomon coding phase. This child is bounded by a
// progress-IDLE watchdog, but the GF math does no I/O and so reports nothing while it runs — without a heartbeat a
// large but perfectly-healthy encode/decode/reconstruct can go silent long enough (past the idle timeout) to be killed
// as "unresponsive", which made big or highly-redundant dispersals fail with a misleading storage error. This returns a
// zero-arg function cheap enough to call in the tight inner loop that merely re-emits the progress line at most every
// ~2s, feeding the watchdog. It reports no true percentage — the real per-shard progress is emitted around the math.
function makeBeat(progress, percent, label) {
	let last = Date.now();
	return () => { const now = Date.now(); if (now - last >= 2000) { last = now; try { progress({ percent, label }); } catch (_) {} } };
}

async function encode({ archivePath, files, n, k }, progress) {
	// Enforce the archive-size cap HERE, before the whole-file read, so the "Reed–Solomon is non-streaming, so the
	// packed archive is bounded" invariant is local to this process rather than resting on the orchestrator alone. RS
	// coding holds the whole blob (plus the shard set) in memory, so an over-budget archive would balloon this
	// process's memory; failing fast with a clear message beats a generic ERR_FS_FILE_TOO_LARGE or an out-of-memory kill.
	const st = await fs.stat(archivePath);
	const mib = (b) => (b / (1024 * 1024)).toFixed(1) + ' MiB';
	if (st.size > Disperse.MAX_ARCHIVE_BYTES) throw new Error('The packed archive is ' + mib(st.size) + ', larger than the ' + mib(Disperse.MAX_ARCHIVE_BYTES) + ' dispersal limit.');
	const bytes = await fs.readFile(archivePath);
	progress({ percent: 45, label: 'Splitting into shards' });
	const shards = Disperse.encodeShards(bytes, n, k, { onTick: makeBeat(progress, 45, 'Splitting into shards') }); // heartbeat so the CPU-bound parity math is not read as a wedge
	const temps = [];
	try {
		for (let i = 0; i < n; i++) {
			await fs.mkdir(path.dirname(files[i]), { recursive: true });
			// Write each shard atomically (temp beside the target, then rename), so a failure mid-run never leaves
			// a slot EMPTY — a plain overwrite that failed partway would leave a torn/zero-length file. With rename a
			// slot always holds a WHOLE shard: its new one or its prior one, never nothing.
			// LIMITATION (a --force RE-disperse, where files[i] are the SAME paths as existing shards): the new set gets
			// a fresh dispersal id, so the new shards form a DIFFERENT group from any surviving old shards — the two
			// cannot be combined to rebuild (blending two different packed archives would RS-decode to garbage, so a
			// fresh id is correct). A multi-file SET swap is not atomic on a plain filesystem, so if a --force is
			// interrupted partway, slots split between the old and new groups. For a redundant geometry (k <= n-k) one
			// of the two groups still has >= k and the set stays recoverable; for a LOW-redundancy geometry (k > n-k) a
			// mid-force interruption can leave BOTH groups below k. The ORIGINAL vault is untouched, so this risks the
			// durability copy, not the only copy — re-running the disperse completes the new set. The rollback removes
			// only leftover temps, never a placed shard; a fresh disperse's partial set is cleaned by the orchestrator
			// (which knows every target was empty). A hard crash or watchdog
			// terminate() bypasses this, but still cannot empty a slot — at worst it leaves a stray temp file.
			const tmp = files[i] + '.tmp-' + process.pid + '-' + Date.now() + '-' + i;
			temps.push(tmp);
			await fs.writeFile(tmp, shards[i]);
			await Common.fsyncPath(tmp); // durability: flush the shard's data BEFORE the rename, so a power loss can't leave a zero-length shard in a slot that held a good one (a --force re-disperse writes over the same paths)
			await Common.renameWithRetry(tmp, files[i]);
			temps.pop();
			progress({ percent: 45 + Math.floor((i + 1) / n * 50), label: 'Writing shard ' + (i + 1) + ' of ' + n });
		}
	} catch (e) {
		for (const t of temps) { try { await fs.rm(t, { force: true }); } catch (_) {} }
		throw e;
	}
	return { shards: files };
}

async function decode({ shardPaths, archivePath }, progress) {
	const bufs = await readShards(shardPaths, progress, 15, 'Reading shards');
	progress({ percent: 45, label: 'Rebuilding the vault' });
	const bytes = Disperse.decodeShards(bufs, makeBeat(progress, 45, 'Rebuilding the vault')); // heartbeat during the CPU-bound reconstruct; throws clearly if fewer than k good shards
	await fs.writeFile(archivePath, bytes);
	return { ok: true };
}

async function repair({ shardPaths, targets, n, k }, progress) {
	const bufs = await readShards(shardPaths, progress, 20, 'Reading surviving shards');
	progress({ percent: 45, label: 'Rebuilding from good shards' });
	const bytes = Disperse.decodeShards(bufs, makeBeat(progress, 45, 'Rebuilding from good shards'));
	// Rebuild missing shards in the SAME framing as the survivors — same dispersal id for a v2 set (or v1 framing
	// for an old v1 set) — so the rebuilt shards REJOIN the surviving group. Minting a fresh id here would split the
	// set into two groups, and a later reconstruction would draw from only the largest group, silently reducing
	// fault tolerance below n-k even though every shard still reads as "good". The shard payloads are deterministic
	// per index, so with the id preserved a rebuilt shard is byte-identical to the original it replaces.
	const grp = Disperse.dominantGroup(bufs);
	const framing = grp && grp.id ? { id: Buffer.from(grp.id, 'hex') } : { version: (grp && grp.version) === 1 ? 1 : 2 };
	// Re-encode with the geometry of the group we ACTUALLY decoded, not the parent's independently-chosen majority: if
	// the two ever disagreed, rebuilt shards carrying one group's id/origLen with the other's n/k would match no group
	// and never rejoin the set (a silently ineffective repair). Deriving n/k from `grp` keeps the rebuilt shards in the
	// same group as the survivors. Falls back to the parent's n/k only when the group carries no geometry.
	const useK = (grp && grp.k) || k;
	const useN = (grp && typeof grp.m === 'number' && typeof grp.k === 'number') ? (grp.k + grp.m) : n;
	const fresh = Disperse.encodeShards(bytes, useN, useK, { ...framing, onTick: makeBeat(progress, 60, 'Rebuilding missing shards') }); // deterministic per index, framed to match the survivors; heartbeat during the parity math
	let repaired = 0;
	for (const t of targets) {
		if (t.idx >= fresh.length) continue;
		// Write each rebuilt shard atomically (temp beside the target, then rename), matching the codebase's
		// write discipline: a crash mid-write leaves the old bad/missing shard as it was rather than a
		// half-written file that could later read as a valid-but-wrong shard. Rename within the same directory
		// is atomic on every supported platform.
		await fs.mkdir(path.dirname(t.path), { recursive: true });
		const tmp = t.path + '.tmp-' + process.pid + '-' + Date.now();
		try { await fs.writeFile(tmp, fresh[t.idx]); await Common.fsyncPath(tmp); await Common.renameWithRetry(tmp, t.path); } // fsync the rebuilt shard's data before the rename, so a crash can't replace a bad shard with a zero-length one
		catch (e) { try { await fs.rm(tmp, { force: true }); } catch (_) {} throw e; }
		repaired++;
	}
	return { repaired };
}

// Inspect a set of shard files in the child process: reading + SHA-256-verifying each shard's full payload (up
// to ~2 GiB) would otherwise stall the web event loop, especially on the scheduled repair tick. Each read is
// size-bounded (Disperse.readShard) and time-bounded (60s), and a per-shard progress tick feeds the parent's
// idle watchdog so a wedged removable/network drive fails fast instead of hanging. Returns the same summary
// shape the caller expects: { total, good, k, n, recoverable, shards:[{path, ok, idx, k, n}] }.
async function inspect({ shardPaths }, progress) {
	const paths = Array.isArray(shardPaths) ? shardPaths : [];
	const infos = [];
	for (let i = 0; i < paths.length; i++) {
		const p = paths[i];
		let info = null;
		try { const b = await Common.withTimeout(Disperse.readShard(path.resolve(p)), 60000); info = b ? Disperse.shardInfo(b) : null; } catch (_) {}
		const fromName = Disperse.shardIdxFromName(p);
		infos.push({ path: p, ok: !!(info && info.good), idx: info ? info.idx : (fromName ? fromName.idx : null), k: info ? info.k : null, n: info ? (info.k + info.m) : (fromName ? fromName.n : null), id: info ? info.id : null });
		progress({ percent: Math.floor((i + 1) / paths.length * 100), label: 'Inspecting shard ' + (i + 1) + ' of ' + paths.length });
	}
	const good = infos.filter(x => x.ok);
	// Derive k/n and recoverability from the MAJORITY geometry among good shards, not just the first one — a
	// foreign-geometry shard (from a different dispersal) must not set the shape and make repair re-encode
	// wrongly (this mirrors decodeShards rebuilding from the largest consistent group). `good` stays the total
	// count for display; recoverability counts DISTINCT indices within the majority group.
	const byGeom = new Map();
	for (const g of good) { const key = (g.id || 'v1') + ':' + g.k + ':' + g.n; const arr = byGeom.get(key) || []; arr.push(g); byGeom.set(key, arr); }
	let best = [];
	for (const arr of byGeom.values()) if (arr.length > best.length) best = arr;
	const k = best.length ? best[0].k : null;
	const n = best.length ? best[0].n : (infos.find(x => x.n != null) || {}).n || null;
	const distinct = new Set(best.map(g => g.idx)).size;
	return { total: infos.length, good: good.length, k, n, recoverable: k != null && distinct >= k, shards: infos };
}

WorkerRun.runProcessChild({ encode, decode, repair, inspect }, { label: 'dispersal' });
