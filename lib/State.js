'use strict';
// lib/State.js — a tiny async, atomic store for two things the tool needs to
// remember between separate runs and for the web UI:
//   • mounts — vaults currently mounted (so status and unmount can find them)
//   • vaults — known vault folders the user has created or added (so the UI can
//              list them without re-typing paths)
//
// Every mutation is a read-modify-write, and the web server is concurrent, so all
// mutations are serialized behind an in-process lock — otherwise two overlapping
// writes could drop each other's change and leave a mount untracked (and therefore
// never auto-locked). The write itself is atomic (temp file + rename) and private
// (0600), so a crash can never leave a half-written, unreadable, or world-readable
// state file.
//
// Mutations are serialized both IN-PROCESS (a queue) and ACROSS PROCESSES (a shared file lock on this file), so the
// CLI and the background service running at once can never lose each other's update in the read-modify-write window.
// The guardian (which mutates state only once the service is already dead) and the reap-on-startup backstop
// (unmountOrphans) remain as a second line of defense.

const fsp = require('fs').promises;
const path = require('path');
const Common = require('./Common');
const FileLock = require('./FileLock'); // cross-process lock so the CLI and the service can't drop each other's mount-state writes
const Brand = require('./Brand');

// Serialize mutations: each waits for the previous to finish before its own
// read-modify-write, so no update is lost. (Shared serial-queue contract.)
const _stateQueue = Common.serialQueue();
// Serialize mutations IN-PROCESS (the queue) AND across processes (a shared file lock on the mount-state file), so
// the CLI and the background service — which the user may run at the same time — can never clobber each other's
// whole-file read-modify-write and drop a mount row. Dropping a `State.add` would leave a mounted, decrypted vault
// untracked, so it would never be auto-locked; the lock closes that window. Mirrors how settings.json is serialized.
function withLock(fn) { return _stateQueue(() => FileLock.withLock(FileLock.lockPathFor('mount-state'), fn)); }

const STATE_MAX_BYTES = 16 * 1024 * 1024; // size cap for the control file, matching the manifest/sidecar readers

// In-flight de-dup of the read-only state read. The web UI polls /api/state every few seconds, and each poll reads
// state.json once; with --data-dir on a network or removable mount that wedges, an un-deduped read would start a
// fresh hanging read every poll, stacking until the libuv threadpool is exhausted (a process-wide freeze). Sharing
// one pending read pins at most ONE threadpool thread no matter how many polls pile up. This is used ONLY by the
// unlocked read-only path; the serialized mutation path always reads fresh under its lock (below), so a
// read-modify-write can never build on a concurrent read that started before its own prior write.
let readInflight = null; // { path, promise } | null
function readStateTextDeduped() {
	const p = Common.statePath();
	if (readInflight && readInflight.path === p) return readInflight.promise;
	const promise = Common.readFileCapped(p, STATE_MAX_BYTES, 'utf8');
	readInflight = { path: p, promise };
	promise.then(() => {}, () => {}).finally(() => { if (readInflight && readInflight.promise === promise) readInflight = null; });
	return promise;
}

// `repair` is passed only by the serialized mutation path (below). A corrupt file is moved aside ONLY under
// that lock — never from an unlocked read-only accessor, which could otherwise rename a file a concurrent
// mutation just healed. Unlocked readers simply start empty on a corrupt file and let the next write fix it.
async function readState(repair = false) {
	let raw;
	// The mutation path (repair=true) reads fresh so its read-modify-write sees the latest content; the unlocked
	// read-only path shares one in-flight read so a wedged data dir can never stack reads across polls.
	try { raw = repair ? await Common.readFileCapped(Common.statePath(), STATE_MAX_BYTES, 'utf8') : await readStateTextDeduped(); }
	catch (_) { return { mounts: [], vaults: [] }; } // no state file yet (first run), unreadable, or over-cap — start fresh
	try {
		const data = JSON.parse(raw);
		// Spread `data` first so any fields a newer build added (beyond mounts/vaults/schemaVersion)
		// are carried through and written back untouched, never dropped on a downgrade.
		return { ...data, mounts: Array.isArray(data.mounts) ? data.mounts : [], vaults: Array.isArray(data.vaults) ? data.vaults : [] };
	} catch (_) {
		// The file EXISTS but is corrupt. Move it aside instead of letting the next write silently clobber
		// it — otherwise the user's known-vaults list is lost AND a still-live mount becomes invisible to
		// orphan reaping and auto-lock (an exposure gap, not just a UI loss). Start fresh from the moved-aside
		// copy preserved for recovery; the boot-time state_readable self-check also surfaces this in the UI.
		if (repair) {
			const saved = Common.statePath() + '.corrupt-' + Date.now();
			// Preserve the corrupt original BEFORE the caller's fresh write overwrites it (move, or copy if the move
			// fails on a lock or cross-device link) — never let the write clobber it with no surviving copy. Mount state
			// is rebuildable, so proceed either way; only the message differs. Shared with the settings and ledger asides.
			const preserved = await Common.preserveCorruptFile(Common.statePath(), saved);
			if (preserved) Common.warn('The mount-state file was unreadable and has been moved to "' + saved + '"; a fresh one was started. A vault that was mounted may need to be unmounted by hand. The old file is preserved for recovery.');
			else Common.warn('The mount-state file was unreadable and a copy could not be preserved; a fresh one was started. A vault that was mounted may need to be unmounted by hand.');
		}
		return { mounts: [], vaults: [] };
	}
}

async function writeState(state) {
	state.schemaVersion = Common.schemaVersionFor('mount state', state); // stamp/preserve the schema version
	await Common.writeJsonAtomic(Common.statePath(), state, { mode: 0o600, chmod: true });
}

// ---- mounts ----
async function readAll() { return (await readState()).mounts; }
// Both mounts and known vaults from ONE read of the state file — the UI poll needs both, and reading them
// separately parses state.json twice per poll.
async function readMountsAndVaults() { const s = await readState(); return { mounts: s.mounts, vaults: s.vaults }; }

// Like readAll(), but returns null when the state file EXISTS yet cannot be trusted (unreadable or corrupt),
// as opposed to an empty array for a genuinely empty or first-run state. A DESTRUCTIVE sweep uses this to FAIL
// SAFE: when the mount list can't be trusted, it must not mistake a LIVE mount's resources for a leak and tear
// them down. Read-only; it never repairs (repair happens only under the mutation lock).
async function readAllOrNull() {
	let raw;
	try { raw = await fsp.readFile(Common.statePath(), 'utf8'); }
	catch (e) { return (e && e.code === 'ENOENT') ? [] : null; } // absent -> genuinely empty; unreadable -> untrusted
	try { const data = JSON.parse(raw); return Array.isArray(data.mounts) ? data.mounts : []; }
	catch (_) { return null; } // present but corrupt -> untrusted
}

function add(entry) {
	return withLock(async () => {
		const s = await readState(true);
		s.mounts = s.mounts.filter(m => !Common.samePath(m.mountpoint, entry.mountpoint));
		s.mounts.push(entry);
		await writeState(s);
	});
}

function remove(mountpoint) {
	return withLock(async () => {
		const s = await readState(true);
		s.mounts = s.mounts.filter(m => !Common.samePath(m.mountpoint, mountpoint));
		await writeState(s);
	});
}

// Locate a tracked mount by full mountpoint path, full vault path, or a bare name — the
// last of these matches the mountpoint's folder name or the vault's name (with or without
// the ".vault" suffix), so a user or the CLI can recover a mount with just "Test" instead
// of the full path. Exact-path matches are tried first so a name can never shadow a path.
async function find(target) {
	const s = await readState();
	const name = String(target == null ? '' : target).trim();
	const stripVault = (p) => path.basename(p).replace(Brand.vaultExtRe, '');
	// Fold the bare-name comparison the same way the exact-path branch (Common.samePath) folds, so a name typed
	// in a different case still matches on Windows (which is case-insensitive), matching the exact-path behavior.
	const foldedName = Common.foldPath(name);
	return s.mounts.find(m => Common.samePath(m.mountpoint, target) || Common.samePath(m.vault, target))
		|| (name && s.mounts.find(m => Common.foldPath(path.basename(m.mountpoint)) === foldedName || Common.foldPath(stripVault(m.vault)) === foldedName))
		|| null;
}

// ---- known vaults ----
async function listVaults() { return (await readState()).vaults; }

function addVault(vaultDir) {
	const abs = path.resolve(vaultDir);
	return withLock(async () => {
		const s = await readState(true);
		if (!s.vaults.some(v => Common.samePath(v, abs))) { s.vaults.push(abs); await writeState(s); }
	});
}

function removeVault(vaultDir) {
	return withLock(async () => {
		const s = await readState(true);
		s.vaults = s.vaults.filter(v => !Common.samePath(v, vaultDir));
		await writeState(s);
	});
}

module.exports = { readState, readAll, readAllOrNull, readMountsAndVaults, add, remove, find, listVaults, addVault, removeVault };
