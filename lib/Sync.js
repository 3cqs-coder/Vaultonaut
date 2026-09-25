'use strict';
// lib/Sync.js — Tier 1 "Mirror": the engine mechanics for a two-way, zero-knowledge sync of a
// vault's encrypted folder to a second place. Only ciphertext travels — the destination (a local
// drive/share or an SFTP server) never sees the key or plaintext. This module is deliberately thin:
// it knows how to run the bundled engine's bidirectional sync and where to keep its state. The
// policy around it — resolving destinations, anti-clobber guards, "must be unmounted", recording the
// remembered destination — lives in Vault.js, next to the one-way backup it mirrors.
//
// Design choices that keep this safe and robust:
//   • The engine's own state (its per-pair file listings) lives in the app data dir, OUTSIDE the
//     vault, so it never becomes part of what is synced.
//   • The first sync must be PRIMED (an explicit baseline pass): one side is declared authoritative
//     and the other is made to match. Everything after is a true two-way merge.
//   • Conflicts (the same file changed on both sides between runs) are never silently overwritten —
//     both versions are kept, and surfaced through the existing sync-artifact check.
//   • Resilient/recover flags let an interrupted run pick up cleanly rather than wedge.

const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const Common = require('./Common');
const Rclone = require('./Rclone');

// The cross-machine write-lease file, kept at the destination root and managed directly (never synced).
const LEASE_FILE = '.vaultlease.json';

// The top-level folder that holds version snapshots (prior copies of overwritten/deleted files). Single-sourced
// here because both the one-way backup (in Vault.js) and this two-way mirror use the exact same name and layout,
// and the bisync filter above must match it byte-for-byte. The format is STABLE — do not rename it, or existing
// snapshot folders would stop being found.
const VERSIONS_DIR = '.versions';

// A stable per-(vault, destination) folder for the engine's sync state. Keyed by a hash of both
// endpoints so re-pointing a vault at a different destination starts a fresh, independent baseline.
function workdirFor(vaultAbs, destKey) {
	const h = crypto.createHash('sha256').update(vaultAbs + '\x00' + destKey).digest('hex').slice(0, 16);
	return path.join(Common.dataDir(), 'sync', h);
}

// Has this pair been primed yet? bisync writes its listing files into the workdir on a successful
// run; their absence means we still need the initial baseline pass. This is polled for every mirror-
// configured vault on each background state refresh, so it is stat-keyed like the other poll reads
// (the manifest and recovery-index probes): the "primed" answer only changes when a .lst file is ADDED
// (a first prime) or the workdir is REMOVED (clearState) — both change the directory's mtime — so a
// cheap stat gates the readdir, which then runs only when the workdir actually changed. Content updates
// to existing .lst files do not change the answer and correctly do not invalidate the cache.
const baselineCache = new Map(); // workdir -> { mtimeMs, primed }
async function hasBaseline(workdir) {
	let st;
	try { st = await fsp.stat(workdir); } catch (_) { baselineCache.delete(workdir); return false; } // no workdir yet -> not primed
	const cached = baselineCache.get(workdir);
	if (cached && cached.mtimeMs === st.mtimeMs) return cached.primed;
	let primed = false;
	try { primed = (await fsp.readdir(workdir)).some(f => f.endsWith('.lst')); } catch (_) { primed = false; }
	baselineCache.set(workdir, { mtimeMs: st.mtimeMs, primed });
	if (baselineCache.size > 64) baselineCache.delete(baselineCache.keys().next().value); // bound (one entry per mirror pair; generous headroom)
	return primed;
}

// Remove a pair's sync state (when a vault stops mirroring, or before a fresh prime).
async function clearState(workdir) { try { await fsp.rm(workdir, { recursive: true, force: true }); } catch (_) {} }

// Run one bidirectional sync between path1 (the local vault) and path2 (the destination). When
// `resync` is set it is the priming pass (path1 is authoritative and path2 is made to match).
// Returns { ok, conflicts, tail } — `conflicts` is true when the engine preserved both sides of a
// clash, so the caller can point the user at the sync-artifact check.
async function runBisync(bin, { path1, path2, configPath, workdir, resync, onProgress, caPath, proxyEnv, backupDir1, backupDir2, primeArchive2, bwlimit, timeoutMs = 12 * 60 * 60 * 1000 }) {
	await fsp.mkdir(workdir, { recursive: true });
	if (onProgress) onProgress({ label: resync ? 'Priming the mirror' : 'Comparing both sides' });
	// A PRIME makes the destination AUTHORITATIVELY match this source, but `bisync --resync` alone does NOT do that:
	// since rclone v1.66 a resync builds a SUPERSET — files that exist ONLY at the destination are copied BACK into
	// path1 (the local vault). After a key rotation, which renames every ciphertext, the destination is entirely
	// old-key, so that back-copy would merge stale, undecryptable old-key files into the local vault (polluting it and
	// tripping the foreign-file scan). So first make the destination match path1 with a one-way `sync`, archiving any
	// destination-only files into the version store via --backup-dir (never hard-deleting them), THEN run the
	// `bisync --resync` below over two already-matching trees — which copies nothing back. The one-way sync is skipped
	// unless priming (a steady-state run is a true two-way merge). Verified against the bundled engine.
	if (resync) {
		const syncArgs = ['sync', path1, path2,
			'--filter', '- /' + LEASE_FILE,
			'--filter', '- /' + VERSIONS_DIR + '/**',
			'--transfers', '8', '--checkers', '8'];
		if (primeArchive2) syncArgs.push('--backup-dir', primeArchive2); // archive the destination's now-absent (e.g. old-key) files rather than delete them, so a prime can never destroy the only off-site copy
		if (bwlimit) syncArgs.push('--bwlimit', bwlimit);
		if (caPath) syncArgs.push('--ca-cert', caPath);
		if (onProgress) { onProgress({ label: 'Priming the mirror (matching the destination)' }); syncArgs.push('--stats', '1s', '--stats-one-line', '--stats-log-level', 'NOTICE'); }
		const onLineS = onProgress ? (line) => { const pm = /,\s*(\d+)%\s*,/.exec(line); if (pm) onProgress({ percent: Math.min(99, parseInt(pm[1], 10)), label: 'Priming the mirror (matching the destination)' }); } : undefined;
		const dropLineS = onProgress ? (line) => /Transferred:/.test(line) : undefined;
		const sres = await Rclone.run(bin, syncArgs, { configPath, env: proxyEnv, timeoutMs, onLine: onLineS, dropLine: dropLineS });
		if (sres.status !== 0) { const so = (sres.stdout || '') + '\n' + (sres.stderr || ''); return { ok: false, status: sres.status, conflicts: false, needsResync: false, tail: tail(so) }; }
	}
	const args = [
		'bisync', path1, path2,
		'--workdir', workdir,
		'--conflict-resolve', 'none',      // never auto-pick a winner…
		'--conflict-suffix', 'sync-conflict', // …keep both, with a clear suffix the artifact check knows
		'--resilient', '--recover',        // an interrupted run recovers instead of wedging
		// The cross-machine write lease lives at the destination root and is managed directly (not synced), so
		// exclude it. Also exclude any top-level VERSION store: on the destination side the version snapshots
		// live in path2's `.versions/` (see below), and it must never be treated as content to sync back — in
		// bisync an unfiltered backup-dir inside a path would be re-propagated as new files, RESURRECTING old
		// versions into the live mirror. The pattern is root-anchored, so it never touches a user file deeper in.
		'--filter', '- /' + LEASE_FILE,
		'--filter', '- /' + VERSIONS_DIR + '/**',
		'--transfers', '8', '--checkers', '8',
	];
	if (bwlimit) args.push('--bwlimit', bwlimit); // cap sync throughput; accepts a plain rate or an off-peak timetable
	// Version capture (best-effort history, off unless the caller passes the dirs). --backup-dir1 keeps prior
	// versions of files overwritten/deleted ON path1 (it lives OUTSIDE the vault, on the same local disk, so it
	// never pollutes the live vault, needs no filter, and is invisible to mount/tamper/pack); --backup-dir2 does
	// the same for the destination, inside path2's `.versions/` (excluded by the filter above). Each backup dir
	// must be on the same remote as its path — path1 is always local here, path2 is whatever the mirror targets.
	// Kept on the steady-state pass so an overwritten or deleted file's prior version is preserved on each side. A
	// prime's authoritative overwrite of the destination is handled by the one-way sync above (which archives the
	// destination's cleared files to primeArchive2), so the destination is never destructively re-primed. rclone
	// supports these since v1.66.
	if (backupDir1) args.push('--backup-dir1', backupDir1);
	if (backupDir2) args.push('--backup-dir2', backupDir2);
	if (resync) args.push('--resync'); // establish (or re-establish) the baseline
	else {
		// SAFETY: on a steady-state run, require the vault manifest to be present at BOTH roots before syncing.
		// If a side's contents have vanished — an unmounted or emptied destination drive, or a hostile peer that
		// deleted its own copy — bisync would otherwise read the absence as deletions and propagate them back,
		// removing the local vault's encrypted files AND their recovery parity together (unrecoverable). With
		// this guard bisync ABORTS instead, failing closed. Skipped on the priming pass (path1 is authoritative
		// there, so there is no back-propagation to guard, and the destination is being established). vault.json
		// is present in every vault and is itself mirrored, so it is a reliable both-sides sentinel.
		args.push('--check-access', '--check-filename', 'vault.json');
	}
	// Pin the deletion safety cap EXPLICITLY (not the engine's unversioned default) as a second backstop, on BOTH
	// passes: on a steady-state run it bounds a catastrophic wipe if a side is emptied, and on a RE-prime it stops
	// an authoritative-but-silently-shrunken source from mirror-deleting the destination's still-good copies (the
	// destination is the only off-site copy — priming must not empty it to match a damaged source). A first prime
	// deletes nothing at an empty destination, so the cap is a no-op there. 50% keeps intentional propagation working.
	// NOTE: in bisync, --max-delete is a PERCENTAGE (0-100), not a file count as it is in plain `rclone sync` — so
	// `50` means "abort if >50% of a side would be deleted". Do not "fix" this to --max-delete-percent (that flag is
	// for `sync`, not `bisync`).
	args.push('--max-delete', '50');
	if (caPath) args.push('--ca-cert', caPath); // pin a relay peer's TLS certificate
	// Live progress: ask the engine for periodic one-line stats and translate them into { percent, label }.
	// bisync has compare phases with no transfer percentage, so a missing percent just keeps the phase label.
	let onLine, dropLine;
	if (onProgress) {
		// Surface periodic one-line stats at NOTICE level rather than full `-v`: progress still streams,
		// but without the extra INFO chatter that could otherwise perturb the conflict/resync heuristics
		// below (which scan the engine's output).
		args.push('--stats', '1s', '--stats-one-line', '--stats-log-level', 'NOTICE');
		const phase = resync ? 'Priming the mirror' : 'Syncing both sides';
		onLine = (line) => {
			const pm = /,\s*(\d+)%\s*,/.exec(line); // "Transferred: X / Y, NN%, ..."
			if (pm) { onProgress({ percent: Math.min(99, parseInt(pm[1], 10)), label: phase }); }
		};
		// Keep the once-a-second stats lines OUT of the retained output: they must not bury the real
		// error/conflict message in the diagnostic tail, nor accumulate over a long sync.
		dropLine = (line) => /Transferred:/.test(line);
	}
	const r = await Rclone.run(bin, args, { configPath, env: proxyEnv, timeoutMs, onLine, dropLine });
	const out = (r.stdout || '') + '\n' + (r.stderr || '');
	const conflicts = /conflict/i.test(out);
	// bisync signals "critical" (needs a fresh --resync) distinctly from a transient failure; surface
	// that clearly so the caller can offer to re-prime rather than showing an opaque error.
	const needsResync = /resync|critical|cannot find prior|run.*--resync/i.test(out) && !resync;
	return { ok: r.status === 0, status: r.status, conflicts, needsResync, tail: tail(out) };
}

// Last ~600 chars of engine output, trimmed — enough context for an error without a wall of logs.
function tail(s) {
	const t = String(s || '').trim();
	return t.length > 600 ? '…' + t.slice(-600) : t;
}

module.exports = { workdirFor, hasBaseline, clearState, runBisync, LEASE_FILE, VERSIONS_DIR };
