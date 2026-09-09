'use strict';
// lib/Vault.js — the core, non-blocking orchestration: create a portable encrypted
// vault, mount it as a real-time drive, unmount it, list it without mounting, and
// report status. Everything here is async and delegates the actual cryptography to
// the bundled encryption engine, so this code never touches key material directly.
//
// A vault is a self-contained, portable directory:
//   <name>.vault/
//     vault.json     non-secret manifest: format version + crypt settings + a
//                    RANDOM per-vault salt (a salt is not secret; storing it is
//                    correct and is what makes two vaults with the same password
//                    derive different keys — defeating precomputation attacks).
//     data/          the encrypted files (encrypted names and contents).
// Copy the whole folder to another machine or OS and it opens with the password.

const fsp = require('fs').promises;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const Common = require('./Common');
const Rclone = require('./Rclone');
const RcloneSetup = require('./RcloneSetup');
const RamCache = require('./RamCache');
const Driver = require('./Driver');
const State = require('./State');
const Kdf = require('./Kdf');
const Integrity = require('./Integrity');
const Recovery = require('./Recovery');
const Net = require('./Net');
const Brand = require('./Brand');
const Sync = require('./Sync');
const Serve = require('./Serve');
const Relay = require('./Relay');
const Cert = require('./Cert');
const UiAuth = require('./UiAuth');
const RecoveryKit = require('./RecoveryKit');
const Attest = require('./Attest');
const Decoy = require('./Decoy');
const Travel = require('./Travel');
const Emergency = require('./Emergency');
// Every settings sub-store keyed by a vault's absolute path. Centralized so that forgetting a vault (or hiding
// it for travel) can scrub ALL of its plaintext traces from this app's state — not just some — and so a new
// path-keyed store added later is covered by adding it here once. (repairSchedules is keyed by a schedule id,
// not a vault path, so it is deliberately NOT in this list.)
const VAULT_PATH_KEYED = ['mountPrefs', 'backupDests', 'backupSchedules', 'scrubSchedules', 'syncDests', 'syncLast', 'favorites', 'serveCreds', 'serveNodeIds'];
const Disperse = require('./Disperse');
const Shamir = require('./Shamir');
const FileLock = require('./FileLock'); // shared cross-process file lock (the vault lock, ledger, and mount state all use it)
const WorkerRun = require('./WorkerRun');
const MiniSearch = require('minisearch');
const SearchDefs = require('./SearchDefs');

const MANIFEST = 'vault.json';
const MANIFEST_BAK = '.vault.bak'; // redundant copy of the manifest (holds the salt/KDF params)
// The complete set of files that hold key material for a vault, named ONCE so crypto-erase overwrites and
// then verifies exactly the same list. If the layout ever externalizes wrapped-key material into another file
// (a separate keyfile, a per-member slot sidecar), add it here and both the shred pass and the survivor check
// pick it up together — they can never drift out of sync.
const KEY_MATERIAL_FILES = [MANIFEST, MANIFEST_BAK];
// The manifest is a small JSON object (format, salt, KDF params, a handful of key slots) — kilobytes even
// with many slots. It travels inside a shareable vault, so bound the read: a hostile multi-GB vault.json
// must never be pulled into memory before it is even parsed. Hugely generous versus any real manifest.
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
// A cap for reading a signed snapshot back through the engine. The zero-knowledge model treats a remote as
// untrusted, so a hostile or MITM'd remote could answer a small-file read by streaming a huge object and exhaust
// the long-running service's heap before any parse. This engine read also serves LOCAL vaults, so the ceiling is
// set well above any realistic snapshot (a per-file record is ~130 bytes, so 256 MiB is roughly two million files)
// — a legitimate vault never reaches it, while a malicious remote is still bounded. On overflow the engine child
// is killed; readSnapshot detects the truncated-at-cap result and reports it as UNREADABLE (not a false "snapshot
// removed" tamper), so an over-cap read is never mistaken for deletion.
const MAX_REMOTE_SNAPSHOT_BYTES = 256 * 1024 * 1024;
// A cap for the STDOUT of an engine directory LISTING (`lsf`). A listing can run against a remote whose contents
// are attacker-chosen (a peer version store, a shared bucket), and `lsf` prints one line per entry, so a store
// with a huge or pathologically-named file set could otherwise stream gigabytes into the long-running service's
// heap before the timeout fires. One entry is well under a kilobyte, so 128 MiB admits a listing of hundreds of
// thousands of files while still bounding a bomb; on overflow the engine child is killed and the non-zero status
// makes the caller treat the listing as empty/absent (fail-safe). One constant so every `lsf` call is capped the
// same way and none drifts back to unbounded.
const MAX_LISTING_BYTES = 128 * 1024 * 1024;
const CIPHER_SUBDIR = 'data';

// A tiny known token written through the encryption at create time. The engine's
// crypt has no built-in password check, so we add one: reading this file back and
// getting the expected token proves the password is correct (and that the vault is
// intact). It is hidden from listings and is the only reliable way to reject a
// wrong password even when the vault is otherwise empty.
// One self-explanatory wrong-password message, shared by every unlock path, so a locked-out user always sees the
// same clear next step instead of a dead end. It names the ways back in that this tool provides; the recovery
// command lists what THIS vault actually has enrolled.
const WRONG_PASSWORD_MSG = 'Could not open the vault — wrong password. If you have forgotten it, you can still get in another way: a recovery key or keyfile you added, or your Recovery Kit. Run "' + Brand.cli + ' keys <vault>" to see the keys and recovery methods this vault has.';
// The ONE way to build a wrong-secret error, so every site reports it the same shape: the message plus a stable
// `wrongPassword` flag a UI can branch on to offer recovery. Open/unlock paths use the default (full recovery
// guidance); a change/operation path passes its own contextual message (e.g. "The current password is incorrect.").
function wrongPasswordError(msg = WRONG_PASSWORD_MSG) { return Object.assign(new Error(msg), { wrongPassword: true }); }
const CANARY_NAME = '.vaultcheck';
const CANARY_TOKEN = 'virtual-disk vault check v1\n';

// Tamper-detection snapshot. Because the vault is stored as many separately-encrypted
// files (which keeps it portable and cloud-sync friendly), removing or replacing one of
// them is easy and, on its own, invisible. A snapshot records the full set of files with
// a content hash of each, signed with a key derived from the password, and is written
// THROUGH the encryption so it lives as one more encrypted file inside the vault. A later
// audit re-scans and reports exactly what was added, removed, or modified. The signature
// means no one without the password can forge a snapshot that hides a change.
const SNAPSHOT_NAME = '.vaultsnapshot';
// On-disk baseline record version. New baselines are written at 4, which binds the seal state and deep flag
// into the signature (see Integrity.signingInput). Version 3 records are still read and verified (the signed
// input is version-gated), and upgrade to 4 the next time the baseline is (re)written.
const BASELINE_VERSION = 4;
// Marks that a read-WRITE keyholder had a live mount session that started from a given baseline.
// Written (encrypted, inside the vault) at mount and removed on a clean unmount, so if it is still
// present at the next mount the previous session ended abnormally (crash / hard kill / power loss)
// rather than being changed offline by someone without the key — which lets those in-session writes
// be accepted instead of reported as tampering. See the session-marker helpers below.
const SESSION_NAME = '.vaultsession';
// The internal bookkeeping objects that live INSIDE the ciphertext store (vault:) alongside the user's own
// files — the canary, the snapshot baseline, the session marker, and their staged ".new" temporaries. They must
// never appear in a user-facing listing or be counted as a user file. Single-sourced here so every consumer of
// `rclone lsf` output agrees on what is "a user file"; parseLsf drops them, and the count and listing paths all
// route through it, so a listing and a count can never disagree (a past drift hid these from counts but not from
// the driver-free file listing).
const INTERNAL_VAULT_OBJECTS = new Set([CANARY_NAME, SNAPSHOT_NAME, SNAPSHOT_NAME + '.new', SESSION_NAME, SESSION_NAME + '.new']);
// Parse `rclone lsf` stdout into a clean array of names: drop blank lines and, unless asked otherwise, the
// internal bookkeeping objects above. One place, so a listing and a count never disagree about what to hide.
function parseLsf(stdout, { excludeInternal = true } = {}) {
	const names = String(stdout || '').split(/\r?\n/).filter(Boolean);
	// Use the SAME "is this a user file?" predicate the signed tamper baseline uses (isIgnoredVaultPath), so a
	// listing and a count can never disagree with the baseline about what counts — including OS-junk files (a
	// cloud-synced folder's .DS_Store, Thumbs.db, and the like), which the baseline excludes but a bare
	// internal-objects check would leave in, making the user-facing count differ from the signed one.
	return excludeInternal ? names.filter(n => !isIgnoredVaultPath(n)) : names;
}
const SNAPSHOT_HASH = 'SHA-1'; // engine hash name; hashes the DECRYPTED content of each file

// Engine stderr patterns that indicate a genuine decryption/integrity failure (as
// opposed to any line merely containing the word "error").
const INTEGRITY_FAIL = /failed to authenticate|bad password|corrupt|checksum|decrypt/i;
// A benign engine notice: a file or directory whose encrypted NAME can't be decoded — a foreign entry,
// or a sync tool's conflicted-copy of an encrypted blob — is skipped by name. It is NOT a decryption
// failure of vault CONTENT and must not read as corruption (the word "undecryptable" happens to contain
// "decrypt"). Both the "file name" and "dir name" variants are benign here; the tamper check surfaces
// foreign entries and the sync scan reports conflicted copies separately as leftovers to resolve.
const BENIGN_SKIP = /Skipping undecryptable (?:file|dir) name/i;
// The engine-stderr lines that signal a real content integrity failure (ignoring the benign notice).
// One source for "what counts as a real failure", used both to decide and to report the offending lines.
function integrityFailureLines(stderr) {
	return String(stderr || '').split(/\r?\n/).filter(l => !BENIGN_SKIP.test(l) && INTEGRITY_FAIL.test(l));
}
// True only when engine stderr shows a real content integrity failure, ignoring the benign notice.
function hasIntegrityFailure(stderr) { return integrityFailureLines(stderr).length > 0; }

// The highest on-disk vault format this build understands. A vault written by a
// newer version is refused with a clear message rather than being misread — this
// is the core of the "future-proof" contract: the format is versioned and
// self-describing, so old data always stays openable and new data never gets
// silently corrupted by an older reader.
const SUPPORTED_FORMAT = 5; // 5 = dual-key capability slots (write-seed / read-key), signed baselines
const MIN_FORMAT = 5;       // the oldest format this build can open — older vaults are incompatible (no backward compat)
// UPGRADE INVARIANT: when SUPPORTED_FORMAT is next raised (to 6+), do NOT raise MIN_FORMAT in lock-step and add a
// read/migration branch in parseManifest for the old layout — otherwise every existing vault at the previous
// format becomes unopenable after the user updates. MIN_FORMAT moves forward only once a genuine migration exists.

// Resolve a vault location. A bare name (no path separator) is placed under the
// default vaults folder in the project's data directory, so all vaults are kept
// together in one place; a name or path with a separator is used as given. A
// ".vault" suffix is added to bare names for a tidy, recognizable folder.
function resolveVaultDir(input) {
	if (!input) throw new Error('A vault name or path is required.');
	const hasSep = input.includes('/') || input.includes('\\');
	if (hasSep || path.isAbsolute(input)) return path.resolve(input);
	const name = Brand.vaultExtRe.test(input) ? input : input + Brand.vaultExt; // case-insensitive, matching how the suffix is stripped
	return path.join(Common.vaultsDir(), name);
}

// A stable, filesystem-safe tag for a vault's resolved path — the key for its PER-MACHINE breadcrumbs (the lock
// file, the recovery-exclude sidecar, the mirror-version store) under the app data dir. One definition so those
// paths are always derived the same way and stay byte-stable if the derivation ever changes.
function vaultDirTag(abs) { return Common.sha256Hex(resolveVaultDir(abs)).slice(0, 16); }

// Normalize a mount target. On Windows a bare drive letter ("X:") is drive-RELATIVE
// to path.resolve (it would resolve against the current directory on X:), so map it to
// the drive root ("X:\"); every other path resolves normally.
function normalizeMountpoint(mp) {
	if (process.platform === 'win32' && /^[A-Za-z]:$/.test(mp)) return mp.toUpperCase() + '\\';
	return path.resolve(mp);
}
// A Windows drive-letter mount target, for which the " (n)" fresh-path fallback is not
// a valid path.
function isDriveLetter(mp) { return process.platform === 'win32' && /^[A-Za-z]:\\?$/.test(mp); }

// Files the OS drops into a folder on its own (Finder/Explorer). They are not real
// user content, and a mount folder that holds only these should still be treated as
// empty — otherwise the FUSE driver refuses to mount over a "non-empty" directory.
// OS-dropped noise that BOTH the mount-empty check (isMountJunk) and the tamper-ignore set (IGNORED_BASENAME,
// far below) treat as junk — single-sourced here so a new common name can't be added to one and missed by the
// other. Each scope adds its own extras: the mount-empty check also ignores macOS's ".localized"; the
// tamper-ignore set also ignores the extra macOS/FUSE/NFS metadata and wildcards it builds from this core.
const OS_JUNK_COMMON = ['.DS_Store', '.Spotlight-V100', '.Trashes', '.fseventsd', 'Thumbs.db', 'desktop.ini'];
const MOUNT_JUNK = new Set([...OS_JUNK_COMMON, '.localized']);
const MOUNT_JUNK_LC = new Set([...MOUNT_JUNK].map(n => n.toLowerCase()));
// Whether a directory entry is OS-dropped junk. On the case-insensitive filesystems (Windows, macOS) the OS and
// apps write these under varying case (Desktop.ini, THUMBS.DB), so match case-insensitively there; Linux is
// case-sensitive, so match exactly to avoid ever removing a real file that only differs in case.
function isMountJunk(name) {
	if (MOUNT_JUNK.has(name)) return true;
	return (process.platform === 'win32' || process.platform === 'darwin') && MOUNT_JUNK_LC.has(name.toLowerCase());
}

// Every filesystem probe on a MOUNT PATH is time-bounded: a user-chosen custom mount point can sit on a network
// or removable drive that is wedged or disconnected, where a plain readdir/mkdir never returns — and because
// mounts are serialized, one such hang would block EVERY vault's mount. A timeout makes the op fail fast (the
// mount is then retried or reported) instead of stalling the queue. The default mount root is local, so this
// only ever matters for a custom path.
const MOUNT_FS_TIMEOUT_MS = 10000; // generous for a slow-but-working drive, but bounds a genuine wedge
async function boundedMountFs(promise, mp) {
	try { return await Common.withTimeout(promise, MOUNT_FS_TIMEOUT_MS); }
	catch (e) { if (/timed out/.test(e && e.message || '')) throw new Error('The mount location "' + mp + '" is not responding — is the drive or network share connected? Choose a location on a connected drive, or reconnect it, then try again.'); throw e; }
}

// The real (non-junk) entries in a directory, or null if it does not exist / isn't one / does not answer in time.
async function dirRealEntries(p) {
	let ents;
	try { ents = await Common.withTimeout(fsp.readdir(p), MOUNT_FS_TIMEOUT_MS); } catch (_) { return null; }
	return ents.filter(n => !isMountJunk(n));
}

// Remove only OS-dropped junk from a mount folder so the driver sees it as empty. Never
// touches real files — a folder with real content is handled by freeMountpoint instead.
async function cleanMountpointJunk(p) {
	let ents;
	try { ents = await Common.withTimeout(fsp.readdir(p), MOUNT_FS_TIMEOUT_MS); } catch (_) { return; }
	for (const n of ents) { if (isMountJunk(n)) { try { await fsp.rm(path.join(p, n), { recursive: true, force: true }); } catch (_) {} } }
}

// Is a mount point already occupied — a live mount now, claimed by an existing state
// entry, or a directory that holds real (non-junk) content? Used so two DIFFERENT
// vaults never collide on one path, and so a folder left non-empty by real files is
// avoided (a folder holding only OS junk is treated as free and cleaned before mount).
async function mountpointInUse(p) {
	if (await Rclone.isMounted(p)) return true;
	const all = await State.readAll();
	if (all.some(m => Common.samePath(m.mountpoint, p))) return true;
	const real = await dirRealEntries(p);
	return Array.isArray(real) && real.length > 0;
}

// Choose a mount point that is not already in use, so mounting a second vault whose
// default path collides with an already-mounted one (e.g. two vaults that share a
// display name) lands on a distinct path — "<name> (2)", "<name> (3)", … — instead of
// silently mounting over, and untracking, the first. A drive letter can't be
// uniquified this way, so it is returned as-is for the attempt loop to handle.
async function freeMountpoint(preferred) {
	// A drive letter cannot be uniquified with a " (n)" suffix; if it is taken, fail with
	// a clear message rather than returning an in-use path.
	if (isDriveLetter(preferred)) {
		if (await mountpointInUse(preferred)) throw new Error('The drive letter ' + preferred + ' is already in use.');
		return preferred;
	}
	if (!(await mountpointInUse(preferred))) return preferred;
	for (let n = 2; n <= 99; n++) {
		const cand = preferred + ' (' + n + ')';
		if (!(await mountpointInUse(cand))) return cand;
	}
	throw new Error('Could not find a free mount point near ' + preferred + '.');
}

// Strip the vault-folder extension (case-insensitive) from a basename, using the configured suffix.
function stripVaultExt(base) { return base.replace(Brand.vaultExtRe, ''); }
function displayName(vaultDir) { return stripVaultExt(path.basename(vaultDir)); }
function cipherDirOf(vaultDir) { return path.join(path.resolve(vaultDir), CIPHER_SUBDIR); }
function defaultMountRoot() { return path.join(os.homedir(), Brand.mountDirName); }

// The tracked live-mount record for a resolved vault path, or undefined. `state` may be passed in
// to reuse a snapshot the caller already read (avoids re-reading the state file in a loop).
async function liveMountFor(abs, state) { return (state || await State.readAll()).find(m => Common.samePath(m.vault, abs)); }
// Is this vault actually mounted right now? Finds its state row, then confirms the mountpoint really answers. It
// deliberately does NOT swallow an isMounted error — a caller that needs a safety guarantee (assertUnmounted,
// mountpointFor) must let that propagate and abort rather than proceed on an unknown state. The schedule ticks,
// which only want to SKIP a mounted vault, wrap the call in their own `.catch(() => false)` so an uncertain probe
// means "not mounted, go ahead" for them.
async function isVaultMounted(abs, state) { const live = await liveMountFor(abs, state); return !!(live && live.mountpoint && (await Rclone.isMounted(live.mountpoint))); }
// Refuse an operation that needs the on-disk store settled while the vault is still mounted, since
// the working cache can hold unflushed writes. `action` completes the sentence "Unmount the vault …".
async function assertUnmounted(abs, action) {
	if (await isVaultMounted(abs)) throw new Error('Unmount the vault ' + action + '.');
}
function parseManifest(txt) {
	const manifest = JSON.parse(txt);
	// A manifest must be a JSON OBJECT. A body that parses to null, a number, a string, or an array is damaged (or
	// from an incompatible version); reject it with the same friendly guidance below, instead of letting a null
	// throw a raw "Cannot read properties of null" TypeError that then surfaces to the user as an internal error.
	if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
		const e = new Error('This vault\'s manifest is not readable, so it cannot be opened — it was created by an incompatible version, or the manifest is damaged. Create a new vault and copy your files into it.');
		e.olderFormat = true;
		throw e;
	}
	// Format floor: this build's dual-key vaults are format 5. An OLDER format is incompatible (its key
	// slots wrap a raw master, not a capability bundle), so refuse it CLEARLY here instead of failing
	// later as a baffling "wrong password". No backward compatibility is provided. A valid manifest
	// ALWAYS carries a numeric format (every write sets it), so a missing/non-numeric one means the
	// manifest is from an incompatible version or is damaged — reject it the same way rather than
	// letting it slip past both bounds.
	if (typeof manifest.format !== 'number' || !Number.isFinite(manifest.format)) {
		const e = new Error('This vault\'s manifest has no valid format number, so it cannot be opened — it was created by an incompatible version, or the manifest is damaged. Create a new vault and copy your files into it.');
		e.olderFormat = true;
		throw e;
	}
	if (manifest.format < MIN_FORMAT) {
		const e = new Error('This vault was created by an older, incompatible version of the tool (format ' +
			manifest.format + '; this build needs format ' + MIN_FORMAT + ' or newer). It cannot be opened — create a new vault and copy your files into it.');
		e.olderFormat = true;
		throw e;
	}
	if (manifest.format > SUPPORTED_FORMAT) {
		const e = new Error('This vault was created by a newer version of the tool (format ' +
			manifest.format + '; this build supports up to ' + SUPPORTED_FORMAT + '). Please update to open it.');
		e.newerFormat = true; // a VALID but too-new manifest — must never be downgraded from a backup
		throw e;
	}
	if (!manifest.crypt || !manifest.crypt.salt) throw new Error('Vault manifest is missing crypt settings; the vault may be corrupt.');
	// DATA-CONFIDENTIALITY INVARIANT: file and directory names are ALWAYS encrypted. Every vault this build creates
	// sets filename_encryption='standard' and directory_name_encryption=true, and there is deliberately no option to
	// weaken them. A manifest whose name-encryption fields have been altered to a weaker mode (corruption or hand
	// tampering) would build a config that no longer matches the on-disk ciphertext — refuse it here with a clear
	// message rather than letting it surface later as a baffling "files unreadable" failure. This enforces the
	// invariant structurally on every read, in addition to being fixed at creation.
	if (manifest.crypt.filename_encryption !== 'standard' || manifest.crypt.directory_name_encryption === false) {
		throw new Error('This vault\'s manifest requests weaker file-name encryption than this tool allows, so it was refused — it was altered or is corrupt. File and directory names are always encrypted.');
	}
	// A format-5 vault carries its key material as wrapped key slots (or the single-slot wrappedKey shape). A
	// manifest that claims format 5 but has NO key wrapping — e.g. a crafted one shaped like a pre-format-5
	// direct-derive vault — is refused here, so unlock can never fall through to a legacy key path that this
	// format no longer uses. Every vault this build creates has slots, so a legitimate manifest always passes.
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault\'s manifest has no key slots and was refused — it may be corrupt or was created by an incompatible version.');
	return manifest;
}

// Read the manifest resiliently. The salt and key-derivation parameters live here,
// so losing this one file would otherwise make the vault unrecoverable. A redundant
// backup copy (.vault.bak) is kept alongside it; if the primary is genuinely missing
// or corrupt it is restored from the backup (and vice-versa), so no single accidental
// deletion can brick the vault. A primary that is merely a NEWER format is never
// downgraded from a stale backup — that error is surfaced so the user updates.
async function readManifest(vaultDir) {
	const abs = path.resolve(vaultDir);
	const p = path.join(abs, MANIFEST);
	const bak = path.join(abs, MANIFEST_BAK);
	let manifest, primaryOk = false, firstErr;
	try { manifest = parseManifest(await Common.readFileCapped(p, MAX_MANIFEST_BYTES, 'utf8')); primaryOk = true; }
	catch (e) {
		if (e.newerFormat) throw e; // valid newer primary: do not fall back / downgrade
		firstErr = e;
		try { manifest = parseManifest(await Common.readFileCapped(bak, MAX_MANIFEST_BYTES, 'utf8')); }
		catch (bakErr) {
			if (bakErr.newerFormat) throw bakErr;
			if (await exists(bak)) throw bakErr;                              // backup exists but is corrupt — report that
			throw firstErr.code === 'ENOENT' ? new Error('No vault found at ' + abs) : firstErr;
		}
	}
	// Self-heal (best-effort, never fatal for a reader): restore the primary only when
	// it genuinely failed (missing/corrupt, not newer-format), and ensure the backup.
	try {
		if (!primaryOk) {
			// This reader does NOT hold the vault lock (it is called from inside AND outside it). Before overwriting
			// the primary with the copy we read from the backup, re-read the primary: another process may have written
			// a fresh primary under the lock in the window since our failed read above, and clobbering that fresh copy
			// with our older backup content would drop its change. So heal only while the primary is STILL unreadable.
			// This narrows the race to the atomic-rename gap; the backup already holds a good copy either way.
			let stillBad = false;
			try { parseManifest(await Common.readFileCapped(p, MAX_MANIFEST_BYTES, 'utf8')); } catch (_) { stillBad = true; }
			if (stillBad) await Common.writeJsonAtomic(p, manifest);
		}
		if (!(await exists(bak))) await Common.writeJsonAtomic(bak, manifest);
	} catch (_) {}
	return manifest;
}

// A stat-keyed manifest read for the frequent dashboard POLL only. The poll re-reads every vault's manifest every
// few seconds, but a manifest changes only on a rare key/membership/tamper operation — so stat the primary and reuse
// the last parsed object when its mtime and size are unchanged, turning a full read+parse into a single stat on the
// common case (the same trick recoveryStatus already uses for its index). Falls back to the authoritative
// readManifest (with its self-heal) on any change, a stat miss, or the first read. NEVER used on the mount/unmount
// or any operational path — those always take readManifest. The returned object is shared, so callers must read it,
// never mutate it (the poll's buildState only reads fields). Keyed the same way readManifest resolves, so a removed
// vault's entry is dropped in removeKnownVault.
const pollManifestCache = new Map(); // resolved vaultDir -> { mtimeMs, size, manifest }
async function readManifestForPoll(vaultDir) {
	const abs = path.resolve(vaultDir);
	let st = null;
	try { st = await fsp.stat(path.join(abs, MANIFEST)); } catch (_) {}
	if (st) {
		const c = pollManifestCache.get(abs);
		if (c && c.mtimeMs === st.mtimeMs && c.size === st.size) return c.manifest;
		const manifest = await readManifest(abs);
		pollManifestCache.set(abs, { mtimeMs: st.mtimeMs, size: st.size, manifest });
		return manifest;
	}
	pollManifestCache.delete(abs); // primary missing/unreadable — no valid cache entry; let readManifest self-heal or throw
	return readManifest(abs);
}

async function exists(p) { try { await fsp.access(p); return true; } catch (_) { return false; } }
// Does a folder hold a vault? A vault is identified by its manifest, and a vault can legitimately exist with ONLY
// the backup copy present (the primary lost or mid-write), so both names count. One helper so that rule lives in a
// single place and every "is this a vault?" check stays consistent.
async function looksLikeVault(dir) { return (await exists(path.join(dir, MANIFEST))) || (await exists(path.join(dir, MANIFEST_BAK))); }

// The unlock secret derived from a keyfile: the base64 SHA-256 of the file's bytes. Used as a key
// slot's secret, so possession of the exact file opens the vault. The browser computes the same
// digest client-side (the file never leaves the user's machine); this is the command-line path.
// The base64 SHA-256 "slot secret" derived from raw bytes — the value a keyfile or a reconstructed threshold
// secret unlocks with. One helper so the keyfile path and the threshold-key path can never drift to different
// encodings (which would silently stop one class of vault from opening).
function slotSecretFromBytes(bytes) { return Common.sha256(bytes).toString('base64'); }
async function keyfileDigestFromFile(filePath) {
	const buf = await fsp.readFile(filePath);
	return slotSecretFromBytes(buf);
}

// Whether the vault folder at destDir is the SAME vault as the one described by srcManifest. Two
// vaults are the same iff they share the stable crypt salt (set once at creation, never altered by
// a password change). Reads the destination manifest RAW — no readManifest self-heal — so an
// identity check (e.g. before a mirroring backup) never modifies the destination.
async function sameVaultIdentity(destDir, srcManifest) {
	const want = srcManifest && srcManifest.crypt && srcManifest.crypt.salt;
	if (!want) return false;
	for (const f of [MANIFEST, MANIFEST_BAK]) {
		try { const m = JSON.parse(await Common.readFileCapped(path.join(destDir, f), MAX_MANIFEST_BYTES, 'utf8')); if (m && m.crypt && m.crypt.salt === want) return true; } catch (_) {}
	}
	return false;
}
// Read a vault's manifest RAW — the first readable of vault.json / vault.json.bak, parsed, with NO self-heal.
// Unlike readManifest it never writes anything back, so it is safe on a folder that must stay untouched, such as
// a backup source we are only inspecting. Returns null if neither manifest is readable.
async function readManifestRaw(dir) {
	for (const f of [MANIFEST, MANIFEST_BAK]) {
		try { return JSON.parse(await Common.readFileCapped(path.join(dir, f), MAX_MANIFEST_BYTES, 'utf8')); } catch (_) {}
	}
	return null;
}

// The off-site (SFTP/WebDAV) equivalent: is the REMOTE folder empty/fresh, or does it already hold THIS same
// vault? Reads the remote vault.json over the engine and compares its salt to the source. FAIL-OPEN by design:
// only a confirmed, readable manifest with a DIFFERENT salt returns false (a foreign vault to refuse); a missing
// or unreadable remote manifest (fresh destination, or a transient read error) returns true so a legitimate
// backup is never blocked — the >50%-deletion and source-intact guards remain the backstops in that case.
// Read a vault manifest from a REMOTE store: rclone cat of the primary copy, then the backup copy, returning the
// first that parses — or, with requireSalt, the first that parses AND carries a salt — else null. One place for the
// "cat the remote manifest" I/O (its timeout, byte cap, and primary→backup fallback), so the overwrite-safety and
// backup-verify paths can never drift on it; each caller keeps its own salt comparison on top.
async function readRemoteManifest(bin, configPath, remotePath, caPath, { requireSalt = false } = {}) {
	for (const f of [MANIFEST, MANIFEST_BAK]) {
		try {
			const r = await Rclone.run(bin, ['cat', remotePath + '/' + f, ...caArgs(caPath)], { configPath, timeoutMs: 60000, maxOutBytes: MAX_MANIFEST_BYTES });
			if (r && r.status === 0 && r.stdout) { const m = JSON.parse(r.stdout); if (m && (!requireSalt || (m.crypt && m.crypt.salt))) return m; }
		} catch (_) {} // missing / unreadable / unparseable -> try the backup copy, then give up
	}
	return null;
}
async function remoteVaultSafeToOverwrite(bin, cfg, remoteVaultPath, srcManifest, caPath) {
	const want = srcManifest && srcManifest.crypt && srcManifest.crypt.salt;
	if (!want) return true;
	const m = await readRemoteManifest(bin, cfg, remoteVaultPath, caPath, { requireSalt: true });
	return m ? m.crypt.salt === want : true; // no confirmed foreign vault found -> safe to write this vault's copy
}

// Create a new encrypted vault. `password` is used only to prove the settings
// work; it is never written anywhere. Returns { vault, cipherDir }.
// A KDF security level is optional (absent = the default 'standard'), but an explicitly chosen one MUST be a known
// level. A bad or drifted value used to fall through Kdf.defaultParams to 'standard' silently — a hidden security
// downgrade. Fail closed so a typo, a stale UI option, or a bad API body is rejected up front, never quietly
// weakened. Validated against the one source of truth (Kdf.LEVELS) that the CLI and the UI options also derive from.
function assertKdfLevel(level) {
	if (level != null && level !== '' && !Kdf.LEVELS[level]) throw new Error('Unknown security level "' + level + '". Choose one of: ' + Object.keys(Kdf.LEVELS).join(', ') + '.');
}
async function create(vaultDir, { password, level, cloud, worm } = {}) {
	if (!password) throw new Error('A password is required to create a vault.');
	assertKdfLevel(level);
	// A CLOUD vault keeps its manifest and key slots in this local folder but puts its encrypted store on a
	// remote backend (cloud = { remoteId, remotePath }); only ciphertext ever reaches the cloud.
	const isCloud = !!(cloud && cloud.remoteId);
	// WORM (Object Lock / tamper-proof) mode makes each uploaded object version immutable for a retention window
	// — strong protection against ransomware and accidental or malicious deletion. It works only on an S3 or
	// S3-compatible backend (the only kind rclone can set Object Lock on; Backblaze B2 qualifies via its S3
	// endpoint). Normalized here; validated against the actual backend type below.
	if (worm && !(Number(worm.retainDays) > 0)) throw new Error('Tamper-proof (WORM) mode needs a retention period of at least one day (set how many days each version stays locked).');
	if (worm && !isCloud) throw new Error('Tamper-proof (WORM) mode is only for cloud vaults on S3 or S3-compatible storage.');
	const wormCfg = worm ? { mode: String(worm.mode).toLowerCase() === 'compliance' ? 'compliance' : 'governance', retainDays: Math.max(1, Math.round(Number(worm.retainDays))) } : null;
	// File AND directory names are ALWAYS encrypted (standard EME) — never optional. A vault
	// must not leak even a hint of its structure to anyone who can see the encrypted store, so
	// there is deliberately no setting to weaken or disable name encryption.
	const filenameEnc = 'standard';
	const dirNameEnc = true;
	// The byte→name encoding is derived from the backend and fixed for the life of the vault: base32768 for
	// UTF-16-length backends (OneDrive/Dropbox/…), otherwise the default base32. Resolved once the cloud remote
	// (and its type) is known below.
	let filenameEncoding;
	const abs = resolveVaultDir(vaultDir);
	// Refuse on ANY sign of an existing vault, not just the primary manifest. The backup
	// manifest or the encrypted data can survive a deleted vault.json (exactly the state
	// readManifest heals from), and writing a fresh random key over them would orphan that
	// data forever. This upholds the rule that the tool can never make a vault unopenable.
	if (await looksLikeVault(abs)) {
		throw new Error('A vault already exists at ' + abs);
	}
	if (!isCloud) {
		const existingData = await dirRealEntries(cipherDirOf(abs));
		if (Array.isArray(existingData) && existingData.length > 0) {
			throw new Error('The folder at ' + abs + ' already contains data — refusing to create a vault over it.');
		}
	}

	// Whether the target folder already existed before we touched it. If create fails, the
	// rollback must only remove what WE made — never a pre-existing folder or its contents.
	const preExisted = await exists(abs);

	await Rclone.sweepStaleConfigs();
	const bin = await ensureEngine();
	const cipherDir = cipherDirOf(abs);
	if (isCloud) {
		// The cloud remote must be configured on this machine, and the target path must be empty — never
		// create a vault over existing objects. List the RAW backend path (ciphertext) and refuse if non-empty.
		const entry = await getCloudRemoteRaw(cloud.remoteId);
		if (!entry) throw new Error('That cloud storage is not set up on this computer. Add it under Cloud storage first.');
		if (wormCfg && String(entry.type).toLowerCase() !== 's3') throw new Error('Tamper-proof (WORM) mode needs an S3 or S3-compatible remote (Amazon S3, or Backblaze B2 through its S3 endpoint). It is not available on "' + entry.type + '".');
		filenameEncoding = cloudFilenameEncoding(entry.type);
		const key = await machineCredKey();
		const probeCfg = await Rclone.writeEphemeralConfig(await backendSectionText(bin, 'backend', entry, key));
		try {
			const spec = backendRemoteSpec(cloud.remotePath);
			const r = await Rclone.run(bin, ['lsf', spec, '--max-depth', '1'], { configPath: probeCfg, timeoutMs: 30000, maxOutBytes: MAX_LISTING_BYTES });
			// A not-yet-existing target directory is EXPECTED for a new vault (the crypt store is created on
			// first write), so treat "directory not found" as empty. Any OTHER failure (auth, network) is real.
			if (r.status !== 0) { if (!/not found|doesn't exist|directory not found/i.test(String(r.stderr || ''))) throw new Error('Could not reach the cloud storage: ' + engineTail(r)); }
			else if (String(r.stdout || '').split(/\r?\n/).filter(Boolean).length > 0) throw new Error('That cloud location already contains data — choose an empty path, or a different one.');
		} finally { await Rclone.removeConfig(probeCfg); }
		if (wormCfg) {
			await assertEngineObjectLock(bin);
			// Backblaze (and some other S3-compatible providers) reject inline Object-Lock headers on PUT, so their
			// lock must be applied with a follow-up call after each upload; Amazon S3 accepts the inline headers.
			if (/backblaze/i.test(String((entry.opts || {}).provider || ''))) wormCfg.setAfterUpload = true;
			// Create the bucket with Object Lock enabled (which also turns on the versioning Object Lock requires),
			// BEFORE the canary write, so the bucket is lock-capable and every object — the canary included — is
			// born immutable. Object Lock can ONLY be turned on when a bucket is created, and the engine cannot read
			// the lock state back, so a PRE-EXISTING bucket cannot be confirmed tamper-proof — creating a WORM vault
			// on one would falsely label it locked. So a WORM vault requires a brand-new, dedicated bucket: probe
			// the bucket root first and refuse if it already exists.
			const bucket = String(cloud.remotePath || '').replace(/^\/+/, '').split('/')[0];
			if (!bucket) throw new Error('A tamper-proof (WORM) vault needs a bucket name in its remote path (for example "my-vault-bucket" or "my-vault-bucket/folder").');
			const lockCfg = await Rclone.writeEphemeralConfig(await backendSectionText(bin, 'backend', entry, key));
			try {
				const probe = await Rclone.run(bin, ['lsf', 'backend:' + bucket, '--max-depth', '1'], { configPath: lockCfg, timeoutMs: 30000, maxOutBytes: MAX_LISTING_BYTES });
				const bucketAbsent = probe.status !== 0 && /not found|doesn't exist|no such|does not exist|404/i.test(String(probe.stderr || ''));
				if (!bucketAbsent) throw new Error('The bucket "' + bucket + '" already exists, so it cannot be confirmed to have Object Lock — Object Lock can only be turned on when a bucket is created, and it cannot be read back afterward. Use a brand-new bucket name for a tamper-proof vault (or create the bucket with Object Lock enabled in your provider console, then point a normal cloud vault at it).');
				const mk = await Rclone.run(bin, ['mkdir', 'backend:' + bucket, '--s3-bucket-object-lock-enabled'], { configPath: lockCfg, timeoutMs: 60000 });
				if (mk.status !== 0) throw new Error('Could not create the bucket "' + bucket + '" with Object Lock enabled: ' + engineTail(mk) + '\nUse a brand-new bucket name for a tamper-proof vault.');
			} finally { await Rclone.removeConfig(lockCfg); }
		}
	} else {
		await fsp.mkdir(cipherDir, { recursive: true });
	}

	// Random per-vault salt -> stored (obscured) in the manifest as the engine's
	// second password. Not secret; its job is to make key derivation unique so two
	// vaults with the same passphrase still have different keys.
	const salt = crypto.randomBytes(32).toString('base64');
	const saltObscured = await Rclone.obscure(bin, salt);

	// Key wrapping: the engine's data key is derived from a RANDOM master secret, not
	// from the password directly. The master secret is wrapped (encrypted) with a key
	// derived from the password via Argon2id. This is what makes a password change instant
	// and safe — changing the password only re-wraps this small blob, so the data key never
	// changes and not a single file is re-encrypted.
	// Dual-key (capability) design: the root secret is a random WRITE SEED (the write-cap). The read
	// key the engine actually uses is derived from it by one-way hashing, and the Ed25519 signing key
	// is derived from it too. So a WRITE holder reproduces both the read key and the signing key, while
	// a READ-ONLY holder is given only the read key and can never climb back to the write seed — it can
	// decrypt and verify, but cannot produce an authentic (signed) write. A read-write key slot wraps
	// the write seed; a read-only slot wraps just the read key.
	const writeSeed = crypto.randomBytes(32).toString('base64');
	const master = Integrity.readKeyFromSeed(writeSeed, saltObscured); // the engine's data key (read key)
	const engineSecret = master; // the engine is handed the read key
	const verifyPub = Integrity.signKeysFromSeed(writeSeed).pub; // public verify key — safe to publish
	// The password becomes the vault's first (read-write) KEY SLOT: the write seed wrapped under an
	// Argon2id key derived from it. More slots (passwords, recovery, read-only) can be added later, each
	// wrapping a capability, so adding/changing/revoking access never re-encrypts a file.
	const firstSlot = await makeSlot({ cap: 'rw', key: writeSeed }, password, 'password', 'Primary', level);

	const manifest = {
		format: SUPPORTED_FORMAT,
		tool: Brand.slug,
		createdAt: new Date().toISOString(),
		// The engine and scheme are recorded so a future version can recognize and,
		// if needed, migrate vaults written by this one. The on-disk crypto is
		// authenticated (each chunk carries an integrity tag), so tampering or
		// bit-rot in the encrypted store is detected on read.
		engine: 'rclone',
		scheme: 'rclone-crypt-v1',
		// The verify (public) key is published at creation so every reader — including a read-only
		// holder, before any snapshot exists — can check that a baseline was signed by the write holder.
		integrity: { scheme: Integrity.SCHEME, pubkey: verifyPub },
		crypt: {
			filename_encryption: filenameEnc,
			directory_name_encryption: dirNameEnc !== false,
			...(filenameEncoding ? { filename_encoding: filenameEncoding } : {}),
			salt: saltObscured,
			keySlots: [firstSlot], // each slot wraps a capability (write seed, or just the read key)
			...(isCloud ? { backend: { remoteId: cloud.remoteId, remotePath: String(cloud.remotePath || ''), ...(wormCfg ? { worm: wormCfg } : {}) } } : {})
		}
	};
	await persistManifest(abs, manifest); // primary + redundant backup copy
	await markAsPackage(abs); // macOS: present the .vault as a single item in Finder

	// Self-test and canary: build a config from the derived secret + salt, make sure
	// the crypt remote initializes, then write the password-check token through the
	// encryption so future opens can verify the passphrase. The vault is registered
	// and kept only once this succeeds; on failure the half-created directory is
	// rolled back so no unusable, canary-less vault is left behind.
	const passwordObscured = await Rclone.obscure(bin, engineSecret);
	const cryptOpts = cryptOptsOf(manifest, passwordObscured);
	let cfgText;
	if (isCloud) { const t = await cloudCryptTargetText(bin, manifest); cfgText = t.backendText + Rclone.cryptRemoteSection('vault', { cipherDir: t.remoteSpec, ...cryptOpts }); }
	else cfgText = Rclone.buildConfig({ cipherDir, ...cryptOpts });
	const cfg = await Rclone.writeEphemeralConfig(cfgText);
	try {
		// A local store's dir already exists (mkdir above), so list it to prove the config decrypts. A cloud
		// store's dir does not exist until the first write, so skip the pre-list there — the canary write below
		// creates and initializes it, and its success proves the config round-trips just as well.
		if (!isCloud) {
			const r = await Rclone.run(bin, ['lsf', 'vault:'], { configPath: cfg, maxOutBytes: MAX_LISTING_BYTES });
			if (r.status !== 0) throw new Error('The vault self-test failed, so the vault was not created — the encryption engine could not read back what it just wrote. Check the location is writable and try again. Engine: ' + engineTail(r));
		}
		const w = await Rclone.run(bin, ['rcat', 'vault:' + CANARY_NAME], { configPath: cfg, input: CANARY_TOKEN });
		if (w.status !== 0) throw new Error('Could not initialize the vault. Check the location is writable and has enough free space, then try again. Engine: ' + engineTail(w));
	} catch (e) {
		// For a cloud vault, best-effort remove the canary we may have written to the remote, so the target
		// path is left empty for a retry (targeted delete of one known file — never a blind purge of the path).
		if (isCloud) { try { const t = await cloudCryptTargetText(bin, manifest); const rc = await Rclone.writeEphemeralConfig(t.backendText + Rclone.cryptRemoteSection('vault', { cipherDir: t.remoteSpec, ...cryptOpts })); try { await Rclone.run(bin, ['deletefile', 'vault:' + CANARY_NAME], { configPath: rc, timeoutMs: 30000 }); } finally { await Rclone.removeConfig(rc); } } catch (_) {} }
		await Rclone.removeConfig(cfg);
		// Roll back only what this call created. If the folder did not exist before, we
		// made all of it, so remove it whole. If it DID exist, remove strictly the files
		// we wrote (the manifest, its backup, and the encrypted data subdir) and never the
		// folder itself or any other content the user may have had there.
		try {
			if (!preExisted) {
				await fsp.rm(abs, { recursive: true, force: true });
			} else {
				// Remove strictly the manifest files we wrote. Leaving a partial encrypted
				// canary in data/ is harmless (unopenable without a manifest) and far safer
				// than risking any pre-existing content in the folder.
				for (const p of [path.join(abs, MANIFEST), path.join(abs, MANIFEST_BAK)]) {
					try { await fsp.rm(p, { force: true }); } catch (_) {}
				}
			}
		} catch (_) {}
		throw e;
	}
	await Rclone.removeConfig(cfg);
	await State.addVault(abs); // remember it only once it is proven usable

	// Also return the master and manifest so a caller that immediately writes to the vault (e.g.
	// importFolder) can reuse them instead of re-reading and re-deriving the key (a second Argon2id).
	// The vault's identity is established at creation (from the published verify key), so it can be recorded
	// out of band from day one — the durable anchor for a later proof bundle and for "is this really my vault?".
	return { vault: abs, cipherDir, master, manifest, identity: Integrity.identity(verifyPub) };
}

// Import an existing folder into a NEW vault in one step: create the vault, then copy the folder's
// contents into it, encrypting on the way in (through the engine's crypt remote — no mount needed).
// The ORIGINAL files are never touched or deleted; the caller tells the user to remove them when
// ready. `create` refuses if a vault already exists at the target, so this never overwrites one.
async function importFolder(vaultDir, { password, sourceDir, level } = {}) {
	if (!sourceDir) throw new Error('A folder to import is required.');
	assertKdfLevel(level);
	const src = path.resolve(sourceDir);
	const st = await fsp.stat(src).catch(() => null);
	if (!st || !st.isDirectory()) throw new Error('The folder to import does not exist: ' + src);
	const created = await create(vaultDir, { password, level }); // refuses over an existing vault (no overwrite)
	const abs = created.vault;
	const manifest = created.manifest;       // reuse the just-written manifest and derived master —
	const master = created.master;           // no second read or Argon2id derivation for this vault
	const bin = await ensureEngine();
	let count = 0;
	await withVaultConfig(bin, abs, password, manifest, master, async (cfg) => {
		const r = await Rclone.run(bin, ['copy', src, 'vault:', '--transfers', '8', '--checkers', '8'], { configPath: cfg, timeoutMs: 12 * 60 * 60 * 1000 });
		if (r.status !== 0) throw new Error('The vault was created but importing the folder failed: ' + engineTail(r) + ' — you can mount it and copy the files in manually.');
		const l = await Rclone.run(bin, ['lsf', '-R', '--files-only', 'vault:'], { configPath: cfg, maxOutBytes: MAX_LISTING_BYTES });
		if (l.status === 0) count = parseLsf(l.stdout).length;
	});
	return { vault: abs, source: src, count };
}

// Change a vault's password WITHOUT re-encrypting any data. Because the data key comes
// from a random master secret (wrapped under the password), we simply recover the master
// with the current password and re-wrap it under the new one, with a fresh KDF salt. The
// master secret and the encrypted files are untouched, so this is instant and works on a
// vault of any size — and is safe to do whether the vault is mounted or not (a live mount
// already holds the master and is unaffected). Returns { ok, vault }.
// Cross-machine compare-and-swap for a whole-manifest write. The vault lock serializes writers on ONE machine, but
// a vault on a shared or removable drive can be opened from two machines with independent, per-machine lock files;
// without a backstop, two concurrent edits could each build a new manifest from the same starting state and the
// second would silently clobber the first's change (both carry a valid signature, since both were signed by the
// same write/owner key, so the seal check would not notice). Two monotonic counters track this: crypt.slotEpoch for
// passphrase-family KEY-SLOT changes and members.epoch for MEMBERSHIP changes. A slot change bumps only slotEpoch
// and a membership change bumps only members.epoch — BUT both rewrite the WHOLE manifest (each carries the other's
// section forward), so each must guard BOTH counters. Checking only its own would let a slot op racing a membership
// op (or vice-versa) pass its CAS and write back the other's now-stale section, silently reverting it. So right
// before writing we re-read the on-disk manifest and refuse if EITHER counter moved since the caller read it. Like
// any epoch CAS this narrows the window rather than eliminating it (a synced remote also preserves both edits as
// sync-conflict copies). Both counters are plain UNSIGNED and deliberately NOT part of manifestSealInput: the slot
// set and roster themselves stay covered by their signatures (the security boundary; the epochs only detect a
// concurrent change), and folding a counter into a seal input would change every existing vault's seal.
async function assertManifestEpochs(abs, manifest) {
	let cur; try { cur = await readManifest(abs); } catch (_) { return; } // unreadable re-read -> fall through; persistManifest's lease fence still guards the write
	const slotOf = (mf) => Number(((mf || {}).crypt || {}).slotEpoch) || 0;
	const rosterOf = (mf) => (mf && mf.members && typeof mf.members.epoch === 'number') ? mf.members.epoch : 0;
	if (slotOf(cur) !== slotOf(manifest)) throw new Error('This vault\'s keys were changed at the same time (from another window or another computer). Reload the vault and make your change again.');
	if (rosterOf(cur) !== rosterOf(manifest)) throw new Error('The membership roster changed at the same time (it is now at epoch ' + rosterOf(cur) + ', not ' + rosterOf(manifest) + '). Reload the vault and make your change again.');
}
// Seal + persist a key-slot change under the slot-epoch CAS. `manifest` is the one read inside the caller's lock;
// `slots` is the new slot list. Mirrors commitMembership's shape for the roster.
async function persistSlotChange(abs, manifest, slots, writeSeed) {
	const prevEpoch = Number((manifest.crypt || {}).slotEpoch) || 0;
	const m = resealManifest(withKeySlots(manifest, slots), writeSeed);
	m.crypt.slotEpoch = prevEpoch + 1; // set AFTER reseal — the epoch is intentionally outside the signed seal input
	await assertManifestEpochs(abs, manifest); // CAS on BOTH counters, so a concurrent membership change is not clobbered
	await persistManifest(abs, m);
	return m;
}
async function changePassword(vaultDir, { oldPassword, newPassword } = {}) {
	if (!oldPassword || !newPassword) throw new Error('Both the current and the new password are required.');
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent slot change is never lost
		if (!hasKeyWrapping(manifest.crypt)) {
			// A legacy vault derives its key straight from the password, so there is no wrapped
			// master to re-wrap; its password cannot be changed in place without re-encrypting.
			throw new Error('This vault predates password change. Create a new vault (whose password can be changed) and copy your files into it.');
		}
		// Recover the master with the CURRENT password (whichever slot it opens). A wrong password
		// matches no slot, so the vault is left completely unchanged.
		const r = await unwrapMaster(oldPassword, manifest.crypt);
		if (!r) throw wrongPasswordError('The current password is incorrect.');
		if (!r.writeSeed) throw new Error('A read-only credential cannot change the vault — unlock with a read-write password.');
		// Re-wrap the SAME master under the new password, replacing only the slot the old password
		// opened (keeping its id/kind/label). Every other key slot, and every file, is untouched.
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		const i = slots.findIndex(s => s.id === r.slotId);
		// Preserve this slot's existing security level on a password change — never silently downgrade it.
		const fresh = await makeSlot(capBundle(r), newPassword, slots[i].kind || 'password', slots[i].label, Kdf.levelOf(slots[i].kdf));
		slots[i] = { ...fresh, id: slots[i].id };
		await persistSlotChange(abs, manifest, slots, r.writeSeed); // cross-machine slot-epoch CAS, then persist
		return { ok: true, vault: abs };
	});
}

// --- Key slots: extra passwords, a recovery key, and revocable access ---
// All operate on the master key's wrapping only, so they are instant and never re-encrypt a
// file. Slot metadata (id, kind, label, time) is not secret; the wrapped keys are useless
// without a password. Listing needs no password; adding/removing requires unlocking the vault.

// List a vault's key slots (metadata only; no password needed).
// Whether a vault currently has a forgot-password safety net: a recovery-key slot, or a non-stale owner recovery
// (Shamir) set. Used both to detect what a rotation is about to drop and to suppress the post-rotation reminder
// once the owner has restored one.
function hasRecoveryCredential(manifest) {
	try {
		if (keySlotsOf((manifest && manifest.crypt) || {}).some(s => s.kind === 'recovery')) return true;
		const rec = manifest && manifest.members && manifest.members.recovery;
		return !!(rec && (rec.keyGeneration || 1) >= ((manifest.members.keyGeneration) || 1)); // owner recovery, not stale
	} catch (_) { return false; }
}
async function listKeys(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	// Member slots are NOT listed here — they are team membership, managed only through the owner-signed roster
	// (see listMembers / removeMember). Showing them as removable "keys" would let a write member drop a member
	// outside the owner path and invalidate the roster signature.
	// Rollback flag: this machine has seen a HIGHER slot epoch than the manifest now carries, so an older manifest
	// (which could re-list a removed extra password, keyfile, or read-only slot) was restored. Local, best-effort.
	let rolledBack = false;
	try { rolledBack = (await Integrity.slotEpochSeen(Integrity.vaultId(manifest))) > (Number((manifest.crypt || {}).slotEpoch) || 0); } catch (_) {}
	// A rotation removed this vault's recovery credential and it has not been restored — nudge the owner to add one
	// so a forgotten password is not a lockout. Suppressed the moment a recovery key or owner recovery exists again.
	let recoveryReminder = false;
	try { recoveryReminder = !hasRecoveryCredential(manifest) && !!(await Integrity.recoveryDroppedAt(Integrity.vaultId(manifest))); } catch (_) {}
	return { vault: abs, level: vaultLevel(manifest), rolledBack, recoveryReminder, slots: keySlotsOf(manifest.crypt).filter(s => s.kind !== 'member').map(s => ({ id: s.id, kind: s.kind || 'password', label: s.label || 'Password', createdAt: s.createdAt || null, ...(s.keyfileName ? { keyfileName: s.keyfileName } : {}) })) };
}

// The biometric (device) key slots of a vault, with the WebAuthn descriptor the browser needs
// to run the unlock ceremony (a credential id and PRF salt — neither is secret). No password
// needed; used to offer "Unlock with Touch ID" only on a device that has been enrolled.
function deviceDescriptors(manifest) {
	if (!manifest || !manifest.crypt) return [];
	return keySlotsOf(manifest.crypt)
		.filter(s => s.kind === 'device' && s.webauthn && s.webauthn.credentialId && s.webauthn.prfSalt)
		.map(s => ({ id: s.id, label: s.label || 'This device', credentialId: s.webauthn.credentialId, prfSalt: s.webauthn.prfSalt }));
}

// Add a key slot that opens the vault with `newSecret` (a password, a recovery key, or a
// device's biometric key). Requires the current password to recover the master. Refuses a
// secret that already opens the vault, so slots never silently duplicate. `extra` carries
// slot-specific non-secret metadata (e.g. a device slot's WebAuthn descriptor).
// Add a new slot. `bundle` is the capability to wrap ({cap:'rw'|'ro', key}); a normal added key is
// read-write (same authority as the adder), a read-only key wraps just the read key.
async function addKeyInternal(abs, manifest, bundle, newSecret, kind, label, extra, sealWith) {
	if (await unwrapMaster(newSecret, manifest.crypt)) throw new Error('That key already opens this vault.');
	const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
	// A new key matches the vault's existing security level, so every slot stays consistent.
	const slot = { ...(await makeSlot(bundle, newSecret, kind, label, vaultLevel(manifest))), ...(extra || {}) };
	slots.push(slot);
	await persistSlotChange(abs, manifest, slots, sealWith); // keep the manifest seal current + cross-machine slot-epoch CAS
	return { slot, count: slots.length };
}

// Shared head for every "add a key" operation: unlock the vault with the current password to
// recover the master, then add a new slot for `secret`. Each public wrapper does its own input
// validation and result shaping; this owns the recover-then-add sequence they all share.
async function addKeyByPassword(vaultDir, password, { secret, kind, label, extra, readOnly } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent slot change is never lost
		if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates key slots. Create a new vault to use them.');
		const r = await unwrapMaster(password, manifest.crypt);
		if (!r) throw wrongPasswordError('The current password is incorrect.');
		// Authorizing a new key requires WRITE access — a read-only credential cannot grant access.
		if (!r.writeSeed) throw new Error('A read-only credential cannot add or change keys — unlock with a read-write password.');
		// The new slot is read-write by default (same authority as the adder), or read-only when asked.
		const bundle = readOnly ? { cap: 'ro', key: r.master } : { cap: 'rw', key: r.writeSeed };
		const { slot, count } = await addKeyInternal(abs, manifest, bundle, secret, kind, label, extra, r.writeSeed);
		return { ok: true, vault: abs, slotId: slot.id, count };
	});
}

async function addKey(vaultDir, { password, newPassword, label } = {}) {
	if (!password || !newPassword) throw new Error('The current password and a new password are required.');
	return addKeyByPassword(vaultDir, password, { secret: newPassword, kind: 'password', label: label || 'Password' });
}

// Add a recovery key: a strong, random key that also opens the vault. It is returned ONCE for
// the user to store safely and is never written anywhere in plaintext — only its wrapped slot
// is kept. Entered later exactly like a password, it recovers a forgotten primary.
async function addRecoveryKey(vaultDir, { password, label } = {}) {
	if (!password) throw new Error('The current password is required to add a recovery key.');
	const recoveryKey = Integrity.groupB32(crypto.randomBytes(20)); // ~160 bits, human-transcribable
	const r = { ...(await addKeyByPassword(vaultDir, password, { secret: recoveryKey, kind: 'recovery', label: label || 'Recovery key' })), recoveryKey };
	try { await Integrity.clearRecoveryDropped(Integrity.vaultId(await readManifest(resolveVaultDir(vaultDir)))); } catch (_) {} // the safety net is restored — drop the post-rotation reminder
	return r;
}

// Add a biometric (device) key slot for Touch ID / Windows Hello unlock. The browser derives
// `deviceKey` from the platform authenticator via WebAuthn PRF (released only after the
// fingerprint/face check) and passes it here; it becomes a normal key slot, wrapping the same
// master. The WebAuthn descriptor (credential id + PRF salt — not secret) is stored so the
// browser can reproduce the same key at unlock time. Requires the current password to authorize.
async function addDeviceKey(vaultDir, { password, deviceKey, webauthn, label } = {}) {
	if (!password) throw new Error('The current password is required to set up biometric unlock.');
	if (!deviceKey || !webauthn || !webauthn.credentialId || !webauthn.prfSalt) throw new Error('Biometric enrollment data is incomplete.');
	const extra = { webauthn: { credentialId: String(webauthn.credentialId), prfSalt: String(webauthn.prfSalt) } };
	return addKeyByPassword(vaultDir, password, { secret: deviceKey, kind: 'device', label: label || 'This device', extra });
}

// Add a keyfile slot: a chosen file (e.g. one kept on a USB stick) becomes an unlock credential.
// The caller passes the file's SHA-256 digest — the file itself never leaves the user's machine, and
// only a non-secret NAME hint is stored, so the vault never reveals which file is needed and the
// file cannot be reconstructed from it. The keyfile then opens the vault on its own (an ALTERNATIVE
// credential; the password still works unless you remove its slot, so you are never locked out).
// Requires the current password to authorize.
async function addKeyfile(vaultDir, { password, keyfileDigest, keyfileName, readOnly } = {}) {
	if (!password) throw new Error('The current password is required to add a keyfile.');
	if (!keyfileDigest) throw new Error('No keyfile was provided.');
	const name = [...String(keyfileName || 'keyfile')].slice(0, 120).join(''); // cap by code points, not UTF-16 units, so an emoji/surrogate pair at the boundary is never split into a lone half
	return addKeyByPassword(vaultDir, password, { secret: String(keyfileDigest), kind: 'keyfile', label: name, extra: { keyfileName: name }, readOnly: !!readOnly });
}

// Remove a key slot by id. You must unlock with a DIFFERENT key than the one being removed, so
// you are always left with at least one key you have proven you can use — you can never lock
// yourself out. The last remaining slot can never be removed.
async function removeKey(vaultDir, { password, slotId } = {}) {
	if (!password || !slotId) throw new Error('A current password and the key id to remove are required.');
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent slot change is never lost
		if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault has no key slots to remove.');
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		if (slots.length <= 1) throw new Error('A vault must keep at least one key — this is the only one.');
		if (!slots.some(s => s.id === slotId)) throw new Error('No key with id "' + slotId + '" exists in this vault.');
		if (slots.some(s => s.id === slotId && s.kind === 'member')) throw new Error('That is a team member, not a key — remove it from the Members list (an owner action), not here.');
		const r = await unwrapMaster(password, manifest.crypt);
		if (!r) throw wrongPasswordError('The password is incorrect.');
		if (!r.writeSeed) throw new Error('A read-only credential cannot remove keys — unlock with a read-write password.');
		// On a TEAM vault, removing a key changes who can access the vault, so it is an OWNER action — the same
		// class as changing membership. Requiring owner authority here means a non-owner read-write password can't
		// strip the owner's key, and (since a caller can never remove the slot they unlocked with, below) the vault
		// can never be left with no owner via this path. Solo vaults have no owner concept and are unaffected.
		if (manifest.members && manifest.members.ownerPubKey && !r.ownerSeed) throw new Error('Only an owner can remove a key on a team vault — unlock with an owner credential. (Removing a key changes who can open the vault, so it is an owner action, like changing membership.)');
		if (r.slotId === slotId) throw new Error('Unlock with a different key to remove this one, so you are never left without a working key.');
		await persistSlotChange(abs, manifest, slots.filter(s => s.id !== slotId), r.writeSeed); // keep the manifest seal current + cross-machine slot-epoch CAS
		return { ok: true, vault: abs, removedId: slotId, count: slots.length - 1 };
	});
}

// Ensure a mount-capable engine is available and return its path.
async function ensureEngine() {
	const info = await RcloneSetup.ensure();
	if (!info.ok || !info.rclone) throw new Error('The encryption engine is not available and could not be downloaded. Run "' + Brand.cli + ' setup" while online.');
	return info.rclone;
}

// A vault's crypto uses key-wrapping if it has key SLOTS (format 4+) or a single wrapped
// master (format 3). Older vaults derive the engine key straight from the passphrase.
function hasKeyWrapping(crypt) { return !!(crypt && (crypt.wrappedKey || (Array.isArray(crypt.keySlots) && crypt.keySlots.length))); }

// The vault's list of key slots. A format-3 single wrappedKey is presented as one implicit
// slot so every code path can treat a vault uniformly as a list of slots, each of which wraps
// the SAME master secret under a different password's Argon2id key.
function keySlotsOf(crypt) {
	if (Array.isArray(crypt.keySlots) && crypt.keySlots.length) return crypt.keySlots;
	if (crypt.wrappedKey && crypt.kdf) return [{ id: 'primary', kind: 'password', label: 'Primary', kdf: crypt.kdf, wrappedKey: crypt.wrappedKey }];
	return [];
}

// Recover the master secret by trying each slot with the given secret (a password or a
// recovery key). Returns { master, slotId } for the first slot whose authenticated unwrap
// succeeds, or null if none do (a wrong password). Cost is at most one Argon2id derivation per
// slot, and vaults have only a handful of slots.
// Unlock a vault with a secret: try each slot, and on the one that opens, return the recovered
// capability — the read key (master) always, plus the write seed when the slot holds a read-write
// capability (null for a read-only slot). Callers use the presence of the write seed to decide whether
// this credential may sign/change the vault.
// Unicode NFC is the canonical form for hashing a passphrase (RFC 8265): a non-ASCII password then derives the
// SAME key no matter how the OS or keyboard produced it (macOS input can arrive decomposed), so the same vault
// unlocks on any platform. A no-op for an ASCII password, a recovery key, or a keyfile digest.
function nfcPassword(secret) { return String(secret == null ? '' : secret).normalize('NFC'); }
// The passphrase forms to TRY when unlocking, in order: canonical NFC first, then the forms a vault created
// BEFORE canonicalization might hold — decomposed NFD, and the raw input as typed. Deduped, so an ASCII secret
// (or a recovery key) yields exactly ONE form and pays no extra cost. Because the RAW form is always included,
// unlock can never fail to open a vault that opens today — this change adds forms, it never removes one — so it
// is a zero-regression migration; new slots are written NFC (see makeSlot), so a re-key moves a vault forward.
function passphraseForms(secret) { const raw = String(secret == null ? '' : secret); return [...new Set([raw.normalize('NFC'), raw.normalize('NFD'), raw])]; }
async function unwrapMaster(secret, crypt) {
	// Try each distinct normalization form; the first that opens a slot wins (a correct NFC password returns on
	// its first form, so the extra forms cost nothing in the common case — they matter only for a legacy vault
	// whose non-ASCII password was stored in another form).
	for (const form of passphraseForms(secret)) {
		const r = await unwrapMasterOneForm(form, crypt);
		if (r) return r;
	}
	return null;
}
async function unwrapMasterOneForm(secret, crypt) {
	// Cap how many slots an unlock attempt will try: a vault has at most a handful, but a HOSTILE shared
	// vault could list thousands to multiply the (already per-derivation-bounded) Argon2id cost into a DoS.
	for (const slot of keySlotsOf(crypt).slice(0, 64)) {
		if (slot.kind === 'member') continue; // member slots are opened with a private key (see openMemberSlot), not a passphrase
		let wrapKey;
		try { wrapKey = await Kdf.deriveKey(secret, slot.kdf); } catch (_) { continue; }
		let raw;
		try { raw = Kdf.unwrapSecret(slot.wrappedKey, wrapKey); } catch (_) { continue; } // wrong secret for this slot
		let b; try { b = JSON.parse(raw); } catch (_) { continue; }
		if (!b || !b.key) continue;
		if (b.cap === 'ro') return { master: b.key, writeSeed: null, ownerSeed: null, capability: 'ro', slotId: slot.id };
		// read-write: the stored key IS the write seed; derive the read key from it. An owner's slot additionally
		// carries the owner seed (team-management authority); a plain read-write slot has none.
		return { master: Integrity.readKeyFromSeed(b.key, crypt.salt), writeSeed: b.key, ownerSeed: b.ownerSeed || null, capability: 'rw', slotId: slot.id };
	}
	return null;
}

// Build a new key slot: the master wrapped under a fresh Argon2id key derived from `secret`.
// The capability bundle to re-wrap when copying a recovered credential into a new slot (a password
// change, or an added key), preserving whether it is read-write or read-only.
// Preserve the recovered capability when re-wrapping the SAME slot (a password change): read-only vs read-write,
// AND owner standing — dropping the owner seed here would silently demote an owner on a password change (and could
// leave a team vault with no owner). Only used by changePassword, which re-keys one existing slot in place.
function capBundle(r) { return r.capability === 'ro' ? { cap: 'ro', key: r.master } : { cap: 'rw', key: r.writeSeed, ...(r.ownerSeed ? { ownerSeed: r.ownerSeed } : {}) }; }

// A key slot wraps a CAPABILITY bundle — { cap: 'rw', key: <write seed> } for a read-write credential,
// or { cap: 'ro', key: <read key> } for a read-only one — under an Argon2id key derived from the secret.
async function makeSlot(bundle, secret, kind, label, level) {
	const kdf = Kdf.defaultParams(level); // level defaults to 'standard' inside defaultParams
	return {
		// The slot's `kind` ('readonly' for a read-only credential) is the non-secret label the UI/CLI show;
		// the actual capability is the encrypted bundle inside wrappedKey, read only after unlocking.
		id: crypto.randomBytes(6).toString('hex'), kind, label: label || (kind === 'recovery' ? 'Recovery key' : 'Password'),
		createdAt: new Date().toISOString(), kdf, wrappedKey: Kdf.wrapSecret(JSON.stringify({ v: 1, ...bundle }), await Kdf.deriveKey(nfcPassword(secret), kdf)) // new slots are written from the canonical NFC form (a no-op for a recovery key/keyfile), so a vault is cross-platform-consistent
	};
}

// A vault's current security level, taken from its primary key slot, so new keys and re-wraps match
// the level the vault was created with (never silently downgrading it).
function vaultLevel(manifest) {
	const slots = keySlotsOf((manifest && manifest.crypt) || {});
	return slots.length ? Kdf.levelOf(slots[0].kdf) : 'standard';
}

// Persist a normalized slot list into a manifest: migrate a format-3 vault to format-4 key slots (dropping
// the single top-level wrappedKey/kdf). The per-slot fields are an explicit ALLOWLIST, NOT a `...s` spread:
// key slots are the vault's most sensitive structure, so only vetted fields are ever written — this is a
// deliberate security guard against a transient/secret field ever leaking into the on-disk slot. The
// trade-off is that a FUTURE build adding a new persistable per-slot field must add it to this list (it is
// intentionally NOT auto-carried the way unknown top-level/crypt fields are). Everywhere the slot secret
// itself lives in local variables (unwrapMaster returns a separate object; slots are never given a secret).
// UPGRADE CHECKLIST: per-slot fields here are an ALLOWLIST, not a spread — a security guard so no transient or
// secret field ever leaks into the persisted slot. Top-level and crypt-level unknown fields ARE preserved, but a
// new PER-SLOT field is not auto-carried. So any future per-slot field MUST bump SUPPORTED_FORMAT (so an older
// build refuses the vault instead of silently stripping the field on its next key op) AND be added to both slot
// allowlists below (the member branch and the passphrase-family branch).
function withKeySlots(manifest, slots) {
	const crypt = { ...manifest.crypt, keySlots: slots.map(s => (s.kind === 'member'
		// A MEMBER slot wraps the capability by SEALING it to a member's public key (X-Wing), not with an
		// Argon2id KDF — so it carries `sealed`, `role`, `memberId`, and the public-key fingerprint instead of
		// `kdf`/`wrappedKey`. Its allowlist is separate and just as strict: only these vetted fields are written.
		? { id: s.id, kind: s.kind, label: s.label, createdAt: s.createdAt, role: s.role, owner: !!s.owner, memberId: s.memberId, pub: s.pub, pubFp: s.pubFp, sealed: s.sealed }
		: { id: s.id, kind: s.kind, label: s.label, createdAt: s.createdAt, kdf: s.kdf, wrappedKey: s.wrappedKey, ...(s.webauthn ? { webauthn: s.webauthn } : {}), ...(s.keyfileName ? { keyfileName: s.keyfileName } : {}) })) };
	delete crypt.wrappedKey; delete crypt.kdf; // superseded by keySlots
	return { ...manifest, format: SUPPORTED_FORMAT, crypt };
}

// Write the manifest and its redundant backup. Both hold the same content, so a crash between
// the two writes never loses the vault — at worst one copy lags by one change.
async function persistManifest(abs, manifest) {
	// FENCE: if this write is happening under a held vault lease, confirm we STILL own that lease right before
	// writing. A pure-filesystem advisory lease can, in rare races (a reclaimed birth window, a wall-clock jump,
	// an event-loop stall past the lease's time-to-live), be judged stale and taken by another process while our
	// operation was still running. This check makes the manifest write depend on OWNING the lease, not on the
	// lease being perfectly race-free: a lost lease aborts the write cleanly instead of clobbering the change the
	// new holder made. It only guards writes made under the lock (heldLeases has the entry); other writers are
	// untouched.
	await assertStillHoldLease(abs);
	// The manifest is the ONLY copy of the salt/KDF params — losing it bricks the vault permanently. Write both
	// copies POWER-LOSS DURABLY, primary first: fsync makes the primary durable before the backup write begins,
	// so a crash can never catch BOTH copies un-flushed and leave the vault unopenable.
	await Common.writeJsonAtomic(path.join(abs, MANIFEST), manifest, { fsync: true });
	await Common.writeJsonAtomic(path.join(abs, MANIFEST_BAK), manifest, { fsync: true });
	// Anchor a team vault's members epoch as it is written (monotonic, local-only), so a later rollback to an
	// older, still validly-signed manifest — which would silently re-list a removed member — is detected on read.
	// This is the one choke point every roster mutation persists through (directly or via updateManifestFields);
	// rotate anchors its own bump in the finalize. Best-effort — never fail a manifest write on the anchor.
	try { if (manifest && manifest.members && typeof manifest.members.epoch === 'number') await Integrity.noteMembersEpoch(Integrity.vaultId(manifest), manifest.members.epoch); } catch (_) {}
	// Anchor the KEY-SLOT epoch the same way, so restoring an older manifest that re-lists a removed extra password,
	// keyfile, or read-only slot is detected on read (listKeys.rolledBack, surfaced by the boot self-check).
	try { const c = manifest && manifest.crypt; if (c && typeof c.slotEpoch === 'number') await Integrity.noteSlotEpoch(Integrity.vaultId(manifest), c.slotEpoch); } catch (_) {}
}

// The ONE safe way to update a SUBSET of an existing vault's manifest (its snapshot, integrity, or other
// non-credential fields) after work that may have taken time. It takes the vault lock, RE-READS a fresh manifest
// INSIDE the lock — so the key slots and members reflect any change another process just committed under the same
// lock — lets `apply(fresh)` mutate ONLY the intended fields, then persists atomically (where the persist fence is
// also active). ALWAYS use this instead of a bare persistManifest of a manifest read earlier, for any partial
// update that could otherwise write back a stale copy and silently drop a concurrent key or membership change.
// That read-early / persist-late pattern is precisely what can corrupt or lose a vault's access, so it must never
// be reimplemented by hand. (Whole-manifest writers that already read inside their own lock — the key/member
// mutators, rotate — are unaffected; new partial-update code belongs here.) Returns the fresh, persisted manifest.
async function updateManifestFields(abs, apply) {
	return withVaultLock(abs, async () => {
		const fresh = await readManifest(abs);
		await apply(fresh);
		await persistManifest(abs, fresh);
		return fresh;
	});
}

// Turn the user passphrase into the secret the engine receives: unwrap the master key with it
// (trying each key slot), or, for legacy vaults with no wrapping, derive the key straight from
// the passphrase. A wrong password fails closed here — no slot unwraps.
// Unlock a vault to the FULL credential — the read key (master) plus the write seed when the secret
// opens a read-write slot (null for a read-only slot) — deriving the expensive KDF just once. Callers
// that need only the read key use enginePassword (a thin wrapper), so there is one unlock path.
async function unlockCredential(passphrase, manifest) {
	const crypt = manifest && manifest.crypt;
	if (hasKeyWrapping(crypt)) {
		const r = await unwrapMaster(passphrase, crypt);
		if (!r) { throw wrongPasswordError(); }
		return { master: r.master, writeSeed: r.writeSeed, ownerSeed: r.ownerSeed || null, capability: r.capability };
	}
	if (crypt && crypt.kdf) return { master: await Kdf.deriveSecret(passphrase, crypt.kdf), writeSeed: null, capability: 'rw' }; // legacy direct-derive
	return { master: passphrase, writeSeed: null, capability: 'rw' };
}
async function enginePassword(passphrase, manifest) { return (await unlockCredential(passphrase, manifest)).master; }
// Prove a password grants READ-WRITE access, for an irreversible or standing-security change (permanent delete,
// removing self-heal recovery data). The manifest must already be read — readManifest guarantees key slots exist, so
// unwrapMaster is authoritative and needs no engine. Rejects a wrong or empty password and a read-only credential
// (which carries no write seed). Returns the recovered credential. Shared so every such gate verifies identically.
async function assertWriteCredential(manifest, password) {
	const cred = await unwrapMaster(password, manifest && manifest.crypt);
	if (!cred) throw wrongPasswordError('The password is incorrect.');
	if (cred.capability !== 'rw') throw new Error('A read-only password cannot make this change. Use the full read-write password.');
	return cred;
}
// Prove a password can OPEN a vault (read-only OR read-write), for an operation that copies or serves the vault's
// ciphertext. Reads the manifest and verifies via the same unlockCredential the mount path uses (readManifest
// guarantees key slots exist, so it is authoritative and needs no engine). The Argon2id derivation runs in a
// short-lived worker thread (see Kdf), so this never blocks the event loop. Returns the recovered credential.
async function assertReadable(vaultDir, password) {
	const manifest = await readManifest(resolveVaultDir(vaultDir));
	return await unlockCredential(password, manifest); // throws wrongPasswordError if it does not open the vault
}

// --- Read-only capabilities (Tier 3 / dual-key sharing) -------------------------------------------
// Add a READ-ONLY password: a credential that opens the vault for reading but can never change it or
// grant access. Authorizing it requires a read-write password (only an owner can hand out read access).
async function addReadOnlyKey(vaultDir, { password, readOnlyPassword, label } = {}) {
	if (!password || !readOnlyPassword) throw new Error('The current read-write password and a new read-only password are required.');
	return addKeyByPassword(vaultDir, password, { secret: readOnlyPassword, kind: 'readonly', label: label || 'Read-only', readOnly: true });
}

// --- Team / multi-user vaults ---------------------------------------------------------------------
// A vault is shared with several people, each holding their own member keypair (the same X-Wing contact keypair
// as emergency access). A MEMBER SLOT wraps the vault capability by SEALING it to that member's PUBLIC key, so
// only their private key opens it — no shared password. Membership is a signed roster (see rosterSealInput):
// the members meta carries a monotonic epoch (anti-rollback) and the OWNER public key, and only an owner (who
// holds the owner seed) can change membership. Read vs read-write is the existing capability split; owner adds a
// third tier (can manage membership) enforced by the separate owner-key roster signature. Everything reuses the
// existing slot list, the sealed-share primitive, the write-authority signing, and rotate.

// Domain-separation labels for the sealed-box reuse. Each distinct use of Emergency.seal binds its own label, so
// a blob minted for one purpose cannot be opened as another even if their formats ever overlapped. The seal and
// open of each pair MUST pass the same label; the emergency dead-man switch uses the default (no label).
const SEAL_CTX = { member: 'member-cap', recovery: 'owner-recovery', share: 'share-bundle' };
// The capability a member/device slot should carry for a given standing: an owner gets the write seed plus the
// owner seed, a read-write member the write seed, a read member only the read key. Single-sourced so add-member,
// add-device, promote/demote, and rotate's re-seal all agree (they take the write/read/owner keys from `keys`).
function memberBundle({ role, owner } = {}, keys = {}) {
	if (owner) return { cap: 'rw', key: keys.writeSeed, ownerSeed: keys.ownerSeed };
	if (role === 'write') return { cap: 'rw', key: keys.writeSeed };
	return { cap: 'ro', key: keys.master };
}
// Build a member slot: the capability bundle sealed to the member's public key.
function memberCapSlot(bundle, memberPubB64, { role, owner, memberId, label } = {}) {
	return {
		id: crypto.randomBytes(6).toString('hex'), kind: 'member',
		label: label || 'Member', createdAt: new Date().toISOString(),
		// An owner is implicitly read-write. `owner` is non-secret display/counting metadata (covered by the roster
		// signature, so it cannot be forged); the actual authority is the owner seed sealed inside the bundle.
		role: owner ? 'write' : (role === 'write' ? 'write' : 'read'),
		owner: !!owner,
		memberId: memberId || crypto.randomBytes(6).toString('hex'),
		pub: String(memberPubB64).trim(),      // the member's PUBLIC key (not secret) — kept so rotate can re-seal to them
		pubFp: memberFingerprint(memberPubB64),
		sealed: Emergency.seal(String(memberPubB64).trim(), JSON.stringify({ v: 1, ...bundle }), SEAL_CTX.member),
	};
}
// Open a member slot with the member's private key. Returns the recovered capability, or null if this key does
// not open this slot (fail-closed: a wrong key or an altered slot throws inside Emergency.open → caught → null).
function openMemberSlot(memberPrivB64, slot) {
	if (!slot || slot.kind !== 'member' || !slot.sealed) return null;
	let b; try { b = JSON.parse(Emergency.open(String(memberPrivB64).trim(), slot.sealed, SEAL_CTX.member)); } catch (_) { return null; }
	if (!b || !b.key) return null;
	if (b.cap === 'ro') return { master: b.key, writeSeed: null, ownerSeed: null, capability: 'ro', slotId: slot.id, memberId: slot.memberId, role: slot.role };
	return { master: Integrity.readKeyFromSeed(b.key, slot._salt), writeSeed: b.key, ownerSeed: b.ownerSeed || null, capability: 'rw', slotId: slot.id, memberId: slot.memberId, role: slot.role };
}
// Unlock a vault with a member PRIVATE key: try each member slot and return the first that opens (with the read
// key, and the write seed / owner seed when present), or null. The read key needs the vault salt, so it is
// injected per attempt.
async function unlockByMemberKey(memberPrivB64, manifest) {
	const salt = manifest && manifest.crypt && manifest.crypt.salt;
	for (const slot of keySlotsOf((manifest && manifest.crypt) || {}).slice(0, 256)) {
		if (slot.kind !== 'member') continue;
		const r = openMemberSlot(memberPrivB64, { ...slot, _salt: salt });
		if (r) return r;
	}
	return null;
}

// Turn a solo vault into a team vault: mint the OWNER key, publish it, and grant the current password holder the
// owner seed (so they can manage membership) — all under one owner. Idempotent-ish: refuses if already a team.
async function enableTeam(vaultDir, { password, ownerLabel } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent change is never lost
		if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates key slots and cannot be a team vault. Create a new vault.');
		if (!(manifest.integrity && manifest.integrity.pubkey)) throw new Error('Take a snapshot first (mount the vault once, or run "snapshot") so the vault has a signed identity before enabling team access.');
		if (manifest.members && manifest.members.ownerPubKey) throw new Error('This vault is already a team vault.');
		const r = await unwrapMaster(password, manifest.crypt);
		if (!r) throw wrongPasswordError('The password is incorrect.');
		if (!r.writeSeed) throw new Error('Enabling team access needs a read-write password.');
		const ownerSeed = crypto.randomBytes(32).toString('base64');
		const ownerPubKey = Integrity.signKeysFromSeed(ownerSeed).pub;
		// Re-wrap the password holder's slot to also carry the owner seed, so they become the first owner.
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		const ownerSlot = slots.find(s => s.id === r.slotId);
		ownerSlot.wrappedKey = Kdf.wrapSecret(JSON.stringify({ v: 1, cap: 'rw', key: r.writeSeed, ownerSeed }), await Kdf.deriveKey(nfcPassword(password), ownerSlot.kdf)); // canonical NFC, matching makeSlot
		// COVERAGE NOTE: this re-wraps a passphrase slot WITHOUT going through persistSlotChange, so it does not bump
		// or compare-and-swap crypt.slotEpoch (the withKeySlots spread preserves whatever epoch was there, so the
		// counter is never corrupted). That is intentional: enable-team is a one-time setup step with its own
		// cross-machine re-check just below (a second enable is refused), and racing it against a plain add/remove-key
		// on another machine is the same pre-existing shared-drive limitation the slot-epoch CAS narrows but does not
		// eliminate. Not worth threading the slot CAS through this one-shot path.
		let m = withKeySlots(manifest, slots);
		m.members = { epoch: 1, keyGeneration: 1, ownerPubKey };
		m = resealManifest(m, r.writeSeed);   // the owner slot's wrappedKey changed → refresh the write-seed seal
		m = resealRoster(m, ownerSeed);        // sign the (empty) roster with the new owner key
		// The lock serializes this on THIS machine; for a vault on a shared drive opened from two machines the
		// lock does not reach across, so re-check that a team was not enabled meanwhile before overwriting — else
		// the second enable would silently strip the first owner's owner seed. Cheap belt-and-suspenders.
		{ let cur = null; try { cur = await readManifest(abs); } catch (_) {} if (cur && cur.members && cur.members.ownerPubKey) throw new Error('This vault just became a team vault (enabled elsewhere). Reload it, then manage members.'); }
		await persistManifest(abs, m);
		void ownerLabel;
		return { ok: true, vault: abs, ownerFingerprint: Integrity.identity(ownerPubKey) };
	});
}

// Recover the owner seed (and write seed) for an owner action, from a password or a member private key.
async function ownerCredential(manifest, { password, memberKey } = {}) {
	let r = null;
	if (password) r = await unwrapMaster(password, manifest.crypt);
	else if (memberKey) r = await unlockByMemberKey(memberKey, manifest);
	if (!r) throw new Error('The password or member key is incorrect.');
	if (!r.ownerSeed) throw new Error('Only an owner can change membership — unlock with an owner credential.');
	return r;
}

// Add a member by their public key (read or read-write). Only an owner may. TOFU: the caller is expected to have
// verified the member's public-key fingerprint out of band first.
async function addMember(vaultDir, { password, memberKey, memberPub, role, label } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault yet — enable team access first.');
		const pub = String(memberPub || '').trim();
		if (!pub) throw new Error('The member\'s public key is required (they make one with "share-keypair").');
		const r = await ownerCredential(manifest, { password, memberKey });
		const wantOwner = role === 'owner';
		const wantWrite = wantOwner || role === 'write';
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		if (slots.some(s => s.kind === 'member' && s.pub === pub)) throw new Error('That key is already a member of this vault (use "add device" to give an existing member another device).');
		// A read member carries only the read key; a write member the write seed; an OWNER also carries the owner seed
		// (so they can manage membership too). The owner seed is the same shared roster-signing secret every owner holds.
		const bundle = memberBundle({ role: wantWrite ? 'write' : 'read', owner: wantOwner }, r);
		const slot = memberCapSlot(bundle, pub, { role: wantWrite ? 'write' : 'read', owner: wantOwner, label });
		slots.push(slot);
		const { epoch } = await commitMembership(abs, manifest, slots, r.ownerSeed);
		return { ok: true, vault: abs, memberId: slot.memberId, slotId: slot.id, role: slot.role, owner: slot.owner, fingerprint: slot.pubFp, epoch };
	});
}

// Promote a member to owner (grant the owner seed) or demote an owner back to a plain member. Only an owner may.
// Re-seals the member's slot to their (stored) public key with — or without — the owner seed. SOFT by default:
// a demoted owner keeps the owner seed they already held until an owner-key rotation, so a demotion that must
// truly cut off owner power should be followed by rotate-owner-key (see rotateOwnerKey). Reuses memberCapSlot.
async function setMemberOwner(vaultDir, { password, memberKey, memberId, owner: makeOwner } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		if (!memberId) throw new Error('A member id is required (see "members").');
		const r = await ownerCredential(manifest, { password, memberKey });
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		const target = slots.find(s => s.kind === 'member' && s.memberId === memberId);
		if (!target) throw new Error('No member with that id.');
		if (!makeOwner) {
			// Demotion must never remove the LAST owner. Owners = the creator (the password slot that holds the owner
			// seed, always an owner and not in the member list) plus member slots flagged owner. Since the creator is a
			// permanent owner, there is always at least one; still guard against demoting the last member-owner when no
			// password owner exists (defensive — the creator path always does).
			const memberOwners = slots.filter(s => s.kind === 'member' && s.owner).length;
			if (target.owner && memberOwners <= 1 && !ownerHasPasswordSlot(manifest)) throw new Error('This is the last owner — promote another member to owner first.');
		}
		const bundle = memberBundle({ role: 'write', owner: !!makeOwner }, r);
		const fresh = memberCapSlot(bundle, target.pub, { role: 'write', owner: !!makeOwner, memberId: target.memberId, label: target.label });
		const remaining = slots.filter(s => s !== target);
		remaining.push(fresh);
		await commitMembership(abs, manifest, remaining, r.ownerSeed);
		return { ok: true, vault: abs, memberId, owner: !!makeOwner, softDemote: !makeOwner };
	});
}

// Enroll an additional DEVICE for an existing member: a new member slot sharing that person's memberId, role, and
// owner standing, sealed to the new device's public key. So a person can use several devices, and losing one does
// not require re-inviting them. Only an owner may enroll a device (the roster is owner-signed). Reuses memberCapSlot.
async function addDevice(vaultDir, { password, memberKey, memberId, devicePub, label } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		const pub = String(devicePub || '').trim();
		if (!pub) throw new Error('The new device\'s public key is required (they make one with "share-keypair").');
		if (!memberId) throw new Error('The member id to add a device to is required (see "members").');
		const r = await ownerCredential(manifest, { password, memberKey });
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		const existing = slots.find(s => s.kind === 'member' && s.memberId === memberId);
		if (!existing) throw new Error('No member with that id.');
		if (slots.some(s => s.kind === 'member' && s.pub === pub)) throw new Error('That device key is already enrolled in this vault.');
		const bundle = memberBundle({ role: existing.role, owner: existing.owner }, r);
		const slot = memberCapSlot(bundle, pub, { role: existing.role, owner: existing.owner, memberId, label: label || existing.label });
		slots.push(slot);
		await commitMembership(abs, manifest, slots, r.ownerSeed);
		return { ok: true, vault: abs, memberId, slotId: slot.id, fingerprint: slot.pubFp };
	});
}
// Revoke ONE device (a single member slot) while keeping the person's other devices. Defaults to HARD (rotate) so
// the removed device's key is worthless for future content — the same honest model as removeMember. Refuses to
// remove a person's LAST device (that is removeMember) or the last owner.
async function removeDevice(vaultDir, { password, memberKey, slotId, rotate: doRotate = true, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Check the certain rotate preconditions (owner password present, vault unmounted) BEFORE dropping the slot, so a
	// predictable failure never leaves the device soft-removed while the re-encryption that fully revokes it never
	// ran. A crash between the drop and rotate's journal is caught by the pendingRotation flag surfaced elsewhere.
	if (doRotate) {
		if (!password) throw new Error('Fully revoking a device re-encrypts the vault, which needs the owner password.');
		await assertUnmounted(abs, 'before removing a device (it re-encrypts the whole vault)');
	}
	// The slot drop + roster re-sign runs under the lock; the rotate that follows a hard remove takes its own
	// lock (never nested), and the soft state persisted here makes an interrupted hard remove resumable.
	await withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		if (!slotId) throw new Error('A device (slot) id is required (see "members").');
		const r = await ownerCredential(manifest, { password, memberKey });
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		const target = slots.find(s => s.kind === 'member' && s.id === slotId);
		if (!target) throw new Error('No device with that id.');
		const sameMember = slots.filter(s => s.kind === 'member' && s.memberId === target.memberId);
		if (sameMember.length <= 1) throw new Error('That is the member\'s only device — remove the member instead.');
		if (target.owner && slots.filter(s => s.kind === 'member' && s.owner).length <= 1 && !ownerHasPasswordSlot(manifest)) throw new Error('That is the last owner device — promote another owner first.');
		const remaining = slots.filter(s => s !== target);
		// Mark the roster rotation-pending BEFORE the rotate (below), so a hard remove interrupted between this commit
		// and the rotate is resumable — matching removeMember. A successful rotate clears the flag either way; a soft
		// remove (no rotate) leaves it set, which is correct.
		await commitMembership(abs, manifest, remaining, r.ownerSeed, { pendingRotation: true });
	});
	if (doRotate) { if (!password) throw new Error('Fully revoking a device re-encrypts the vault, which needs the owner password.'); await rotate(abs, { password, reason: 'device removed', onProgress }); return { ok: true, vault: abs, removed: slotId, revoked: true }; }
	return { ok: true, vault: abs, removed: slotId, revoked: false, pendingRotation: true };
}

// Does a passphrase-family slot carry the owner seed (i.e. is the creator/a password holder an owner)? Best-effort
// structural check used only for the last-owner guard; it cannot read sealed bundles, so it errs toward "yes" when
// a non-member read-write slot exists (the creator's slot), which is the vault-creation default.
function ownerHasPasswordSlot(manifest) {
	return keySlotsOf((manifest && manifest.crypt) || {}).some(s => s.kind !== 'member' && (s.kind === 'password' || s.kind === 'primary' || !s.kind));
}

// Commit a membership change under the vault lock: install the new key slots, bump the roster epoch (merging any
// extra members fields such as pendingRotation or a recovery record), re-sign the roster with the owner seed, enforce
// the cross-machine epoch CAS, and persist. One place, so every membership mutation bumps the epoch, re-seals, AND
// asserts the CAS — a new mutation site cannot silently omit the rollback/tamper backstop. The caller must already
// hold withVaultLock and have read `manifest` inside it. Returns the persisted manifest and the new epoch.
async function commitMembership(abs, manifest, slots, ownerSeed, membersPatch = {}) {
	let m = withKeySlots(manifest, slots);
	const epoch = (m.members.epoch || 0) + 1;
	m.members = { ...m.members, ...membersPatch, epoch };
	m = resealRoster(m, ownerSeed); // membership changed → re-sign the roster with the owner key
	await assertManifestEpochs(abs, manifest); // CAS on BOTH counters, so a concurrent key-slot change is not clobbered
	await persistManifest(abs, m);
	return { m, epoch };
}

// --- N-of-M owner recovery (Shamir) ---------------------------------------------------------------
// Split the owner's full capability (write seed + owner seed) across n trustees so any k can restore owner
// access if the owners are lost. Each share is SEALED to a trustee's public key, so only they can hold it, and
// stored in the manifest (ciphertext, safe to travel with the vault). Reconstruction is SELF-VERIFYING: the
// recovered write seed must re-derive the published content verify key AND the recovered owner seed the published
// owner key — so a wrong/corrupt share (plain Shamir does not detect one) or a share from a superseded key
// generation is caught and refused rather than silently yielding a bad key.
const OWNER_RECOVERY_MIN = 2;
async function setupOwnerRecovery(vaultDir, { password, memberKey, trustees, k } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		const list = (trustees || []).filter(t => t && t.pub);
		const n = list.length;
		const kk = Number(k);
		if (n < OWNER_RECOVERY_MIN) throw new Error('Provide at least ' + OWNER_RECOVERY_MIN + ' trustees (each with a public key).');
		if (!Number.isInteger(kk) || kk < OWNER_RECOVERY_MIN || kk > n) throw new Error('The threshold must be between ' + OWNER_RECOVERY_MIN + ' and ' + n + ' (got ' + k + ').');
		const r = await ownerCredential(manifest, { password, memberKey });
		const secret = Buffer.from(JSON.stringify({ v: 1, writeSeed: r.writeSeed, ownerSeed: r.ownerSeed }), 'utf8');
		const shares = Shamir.split(secret, n, kk);
		const sealedTrustees = list.map((t, i) => ({ label: t.label || ('Trustee ' + (i + 1)), fp: memberFingerprint(t.pub), sealed: Emergency.seal(String(t.pub).trim(), shares[i], SEAL_CTX.recovery) }));
		await commitMembership(abs, manifest, keySlotsOf(manifest.crypt).map(s => ({ ...s })), r.ownerSeed, { recovery: { v: 1, k: kk, n, createdAt: new Date().toISOString(), keyGeneration: manifest.members.keyGeneration || 1, trustees: sealedTrustees } });
		try { await Integrity.clearRecoveryDropped(Integrity.vaultId(manifest)); } catch (_) {} // owner recovery restored — drop the post-rotation reminder
		return { ok: true, vault: abs, k: kk, n, trustees: sealedTrustees.map(t => ({ label: t.label, fingerprint: t.fp })) };
	});
}
// A trustee opens their sealed recovery share with their private key, yielding the plaintext Shamir share to hand
// to whoever is performing recovery. Returns null if this key holds no share here.
async function getRecoveryShare(vaultDir, trusteePrivKey) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const rec = manifest.members && manifest.members.recovery;
	if (!rec || !Array.isArray(rec.trustees)) return null;
	for (const t of rec.trustees) {
		let share; try { share = Emergency.open(String(trusteePrivKey).trim(), t.sealed, SEAL_CTX.recovery); } catch (_) { continue; }
		if (share) return { share, k: rec.k, n: rec.n, label: t.label };
	}
	return null;
}
// Recover owner access from k trustee shares: reconstruct the owner capability, VERIFY it against the vault's
// published keys, and (given a new password) install a fresh owner slot so the recoverer regains owner + write
// access. Fail-closed on a wrong/insufficient/stale set of shares.
async function recoverOwner(vaultDir, { shares, newPassword, label } = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		if (!Array.isArray(shares) || !shares.length) throw new Error('Provide the recovery shares from the trustees.');
		if (!newPassword) throw new Error('Choose a new owner password to regain access with.');
		// The self-verify below trusts the vault's PUBLISHED keys (integrity.pubkey, members.ownerPubKey). Anchor
		// them first: refuse if the write-seed manifest seal or the owner-signed roster does not verify, so recovery
		// can never validate reconstructed keys against a manifest that was rewritten. Enforcing these here is what
		// makes the owner-signed roster a real gate, not just an advisory flag. (A fully self-consistent identity
		// swap is a DIFFERENT vault — caught out of band by the recorded origin identity, not by an in-vault check.)
		{ const seal = checkManifestSeal(manifest); if (seal.sealed && !seal.ok) throw new Error('This vault\'s manifest fails its integrity signature (it was altered), so owner recovery is refused until the tampering is resolved.'); }
		if (!verifyRoster(manifest)) throw new Error('This vault\'s membership roster fails its owner signature (it was altered), so owner recovery is refused until the tampering is resolved.');
		let secret; try { secret = Shamir.combine(shares); } catch (e) { throw new Error('Could not combine the shares: ' + e.message); }
		let b; try { b = JSON.parse(secret.toString('utf8')); } catch (_) { throw new Error('The shares did not reconstruct a valid recovery secret (a share may be wrong, or too few were provided).'); }
		// SELF-VERIFY against the published keys — this is what turns plain (non-verifying) Shamir into a safe recovery.
		const okWrite = b && b.writeSeed && (() => { try { return Integrity.signKeysFromSeed(b.writeSeed).pub === manifest.integrity.pubkey; } catch (_) { return false; } })();
		const okOwner = b && b.ownerSeed && (() => { try { return Integrity.signKeysFromSeed(b.ownerSeed).pub === manifest.members.ownerPubKey; } catch (_) { return false; } })();
		if (!okWrite || !okOwner) throw new Error('The reconstructed keys do not match this vault (a wrong or corrupted share, or shares from a superseded key generation). Recovery refused.');
		// Install a new owner password slot carrying the recovered capability.
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		if (await unwrapMaster(newPassword, manifest.crypt)) throw new Error('That password already opens this vault — choose a different new password.');
		slots.push(await makeSlot({ cap: 'rw', key: b.writeSeed, ownerSeed: b.ownerSeed }, newPassword, 'password', label || 'Recovered owner', vaultLevel(manifest)));
		let m = withKeySlots(manifest, slots);
		m = resealManifest(m, b.writeSeed); // a new passphrase slot changed the write-seed seal
		// COVERAGE NOTE: this adds a passphrase slot WITHOUT persistSlotChange, so it does not bump or CAS
		// crypt.slotEpoch (the withKeySlots spread preserves the existing epoch, so the counter is never corrupted).
		// Intentional: owner recovery is a rare emergency that must SUCCEED once the trustee shares self-verify above
		// — bouncing it on a slot-epoch mismatch would be worse than the rare shared-drive race it would catch, and a
		// concurrent cross-machine owner-recovery is not a realistic scenario. Its real gate is the Shamir
		// self-verification, not the concurrency counter.
		await persistManifest(abs, m);
		return { ok: true, vault: abs, recovered: true };
	});
}

// List the vault's members (public metadata only) plus the roster state. Needs no secret.
async function listMembers(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!(manifest.members && manifest.members.ownerPubKey)) return { vault: abs, team: false, members: [] };
	// One PERSON (memberId) may hold several DEVICE keys — each is a member slot sharing the memberId. Group them
	// so the roster reads as people with their devices; a device can be enrolled or revoked without touching the
	// person's other devices. The flat fields (memberId, label, role, owner, fingerprint) are kept for callers that
	// treat a member as a single entry — for the common one-device member they are unchanged.
	const byMember = new Map();
	for (const s of keySlotsOf(manifest.crypt).filter(s => s.kind === 'member')) {
		if (!byMember.has(s.memberId)) byMember.set(s.memberId, { memberId: s.memberId, label: s.label, role: s.role, owner: !!s.owner, devices: [] });
		const p = byMember.get(s.memberId);
		p.devices.push({ slotId: s.id, label: s.label, fingerprint: s.pubFp, addedAt: s.createdAt });
		if (s.owner) p.owner = true; if (s.role === 'write') p.role = 'write'; // a person's standing is the strongest across their devices
	}
	const members = [...byMember.values()].map(p => ({ ...p, fingerprint: p.devices[0].fingerprint, deviceCount: p.devices.length }));
	// Recovery shares encode the write seed, which rotation changes, so a recovery set up BEFORE the last key
	// rotation can no longer restore access (recoverOwner fails closed against the new keys). Flag that so the UI
	// can tell the owner to re-run owner-recovery.
	const recovery = manifest.members.recovery ? { k: manifest.members.recovery.k, n: manifest.members.recovery.n, stale: (manifest.members.recovery.keyGeneration || 1) < (manifest.members.keyGeneration || 1), trustees: (manifest.members.recovery.trustees || []).map(t => ({ label: t.label, fingerprint: t.fp })) } : null;
	const epoch = manifest.members.epoch || 0;
	// ROLLBACK detection: this machine anchored a higher members-epoch than the manifest now on disk carries, so an
	// older (still validly-signed) manifest was restored — which can silently re-list a removed member. Surface it
	// so the owner knows a rotation is owed; independent of the roster signature check (the old roster is validly signed).
	let rolledBack = false;
	try { const vid = Integrity.vaultId(manifest); rolledBack = (await Integrity.membersEpochSeen(vid)) > epoch; } catch (_) {}
	// Whether a key rotation is OWED: set by a soft remove (rotate:false — a deliberate "drop from the roster but do
	// not re-encrypt yet" choice) and, transiently, by a hard remove before its rotate completes (rotate clears it on
	// success). Either way the vault is still under the old key until a rotation runs, so a soft-removed member's key
	// still opens it — informational for the UI, NOT an alarm (a soft remove is intentional), so it is only reported
	// here, not raised as a self-check warning.
	const rotationPending = !!manifest.members.pendingRotation;
	return { vault: abs, team: true, epoch, keyGeneration: manifest.members.keyGeneration || 0, ownerFingerprint: Integrity.identity(manifest.members.ownerPubKey), rosterValid: verifyRoster(manifest), rolledBack, rotationPending, memberOwners: members.filter(m => m.owner).length, recovery, members };
}

// Remove a member. Defaults to HARD remove (true revocation): drop the member's slot, then rotate so the vault is
// re-encrypted under a fresh key and the remaining members are re-sealed to it — the removed member's key is then
// worthless for any future content. Soft remove ({ rotate: false }) only drops the slot and re-signs the roster;
// it is NOT revocation (the master key is unchanged, so a copy the member already kept still decrypts) and exists
// only to batch departures — it marks the roster pendingRotation so a later rotate finishes the job.
async function removeMember(vaultDir, { password, memberKey, memberId, rotate: doRotate = true, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// A HARD remove re-encrypts (rotate) right after dropping the slot. Check rotate's certain preconditions — the
	// owner password is present and the vault is unmounted — BEFORE dropping the slot, so a predictable failure (the
	// common one: removing a member while the vault is still mounted) can never leave the member soft-removed yet
	// still able to decrypt because the re-encryption never ran. A rarer failure (a crash between the drop and
	// rotate's journal) is caught by the pendingRotation flag, which listMembers and the boot self-check now surface.
	if (doRotate) {
		if (!password) throw new Error('Fully revoking a member re-encrypts the vault, which needs the owner password.');
		await assertUnmounted(abs, 'before removing a member (it re-encrypts the whole vault)');
	}
	// The slot drop + roster re-sign runs under the lock; the rotate that follows a hard remove takes its own
	// lock (never nested), and the soft state persisted here makes an interrupted hard remove resumable.
	await withVaultLock(abs, async () => {
		const manifest = await readManifest(abs); // read INSIDE the lock so a concurrent membership change is never lost
		if (!(manifest.members && manifest.members.ownerPubKey)) throw new Error('This vault is not a team vault.');
		if (!memberId) throw new Error('A member id to remove is required (see "members").');
		const r = await ownerCredential(manifest, { password, memberKey });
		const slots = keySlotsOf(manifest.crypt).map(s => ({ ...s }));
		if (!slots.some(s => s.kind === 'member' && s.memberId === memberId)) throw new Error('No member with that id.');
		const remaining = slots.filter(s => !(s.kind === 'member' && s.memberId === memberId));
		await commitMembership(abs, manifest, remaining, r.ownerSeed, { pendingRotation: true }); // soft state first, so an interrupted hard remove is resumable
	});
	if (doRotate) {
		if (!password) throw new Error('Fully revoking a member re-encrypts the vault, which needs the owner password.');
		await rotate(abs, { password, reason: 'member removed', onProgress }); // re-encrypts + re-seals the remaining members; clears pendingRotation
		return { ok: true, vault: abs, removed: memberId, revoked: true };
	}
	return { ok: true, vault: abs, removed: memberId, revoked: false, pendingRotation: true };
}

// A shareable READ CAPABILITY: a self-describing token carrying the read key and the crypt parameters,
// so a recipient can open a COPY of the vault read-only without a password and without the write seed.
// It grants read + verify, never write. Non-secret except for the read key it contains, which is the
// whole point (it is read access). Format: "vdrc1." + base64url(JSON).
const READCAP_PREFIX = 'vdrc1';
function makeReadCapToken(payload) { return READCAP_PREFIX + '.' + Buffer.from(JSON.stringify(payload)).toString('base64url'); }
function parseReadCap(token) {
	const s = String(token || '').trim();
	if (s.length > 8192) return null; // a read cap is small (prefix + a short base64url JSON) — cap the input before decoding/parsing
	const dot = s.indexOf('.');
	if (dot < 0 || s.slice(0, dot) !== READCAP_PREFIX) return null;
	try { const p = JSON.parse(Buffer.from(s.slice(dot + 1), 'base64url').toString('utf8')); return (p && p.master) ? p : null; }
	catch (_) { return null; }
}
// Mint a read capability. Requires the full READ-WRITE password: only the write key can sign the share
// registry, so a read link is always recorded there — the owner can see it in the access list and revoke it.
// Allowing a read-only credential to mint would produce a link the owner could neither see nor revoke (the
// roster cannot be signed without the write key), so a read-only password is refused. Each cap carries a share
// id and, optionally, an EXPIRY the recipient's tool enforces. Honest limit: expiry and revocation are policy
// the recipient's tool applies, not cryptography; a recipient who keeps their own copy of the ciphertext and the
// read key can ignore them. Cutting off a leaked read key for good means rotating the vault's keys (a separate op).
// Days → an absolute expiry timestamp (ms), or null for "never" (absent or a non-positive value). One helper so
// read-cap and web-read-cap compute an expiry identically.
function expiryFromDays(expiryDays) {
	const days = Number(expiryDays);
	return (Number.isFinite(days) && days > 0) ? Date.now() + Math.round(days * 24 * 60 * 60 * 1000) : null;
}
async function makeReadCap(vaultDir, { password, label, expiryDays } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault does not support read capabilities.');
	const cred = await unlockCredential(password, manifest);
	if (cred.capability !== 'rw') throw new Error('A read link can only be created with the full read-write password, so it is recorded in the access list and stays revocable. A read-only password cannot create one.');
	const c = manifest.crypt;
	const sid = crypto.randomBytes(8).toString('hex');
	const exp = expiryFromDays(expiryDays);
	const token = makeReadCapToken({ v: 1, sid, master: cred.master, salt: c.salt, fn: c.filename_encryption, dn: c.directory_name_encryption !== false, pub: (manifest.integrity || {}).pubkey || null, exp });
	// Record it in the signed roster. Fail-closed: if the roster cannot be written, do NOT return a capability that
	// would be untracked and therefore unrevocable — the caller retries rather than unknowingly leaking access.
	await recordShare(abs, cred.writeSeed, { sid, label: label || 'Read link', perm: 'read', exp });
	return { token, sid, exp };
}

// Portable, offline recipient share: seal a read capability to a recipient's PUBLIC key, so only their private
// key can open it. Unlike a read link — which the recipient redeems against a running instance — this produces a
// small self-contained bundle you can hand over by any means (email, a file, a message). It carries ONLY the
// sealed read cap; the recipient still obtains the vault's ciphertext separately (a pack, a copy, or the cloud
// store), then mounts it read-only with the recovered cap. Pure reuse: makeReadCap mints the read-only grant, and
// Emergency seals it with the post-quantum hybrid (X25519 + ML-KEM-768) so a key harvested today stays unopenable.
async function shareSeal(vaultDir, { password, recipientPub, label, expiryDays } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const pub = String(recipientPub || '').trim();
	if (!pub) throw new Error('A recipient public key is required — the recipient makes one with "' + Brand.cli + ' share-keypair".');
	const manifest = await readManifest(abs);
	const { token, sid, exp } = await makeReadCap(abs, { password, label: label || 'Sealed share', expiryDays });
	const sealed = Emergency.seal(pub, token, SEAL_CTX.share); // only the recipient's private key can open it; fail-closed on the far side
	let identity = null; try { identity = Integrity.vaultId(manifest); } catch (_) {}
	const bundle = { v: 1, app: Brand.name, kind: 'share', vault: displayName(abs), identity, pq: Emergency.isPostQuantum(), exp: exp || null, sealed };
	return { bundle, sid, exp: exp || null, pq: bundle.pq };
}

// Recipient side: open a share bundle with the recipient's PRIVATE key, recovering the read cap inside. The cap
// then mounts a copy of the vault read-only ("mount <copy> --read-cap <token>"). Fail-closed: a wrong key or an
// altered bundle throws (the seal's AEAD tag), never returns a bad cap.
function shareOpen(bundle, privateKey) {
	let b; try { b = (typeof bundle === 'string') ? JSON.parse(bundle) : bundle; } catch (_) { throw new Error('That file is not a readable share bundle.'); }
	if (!b || b.kind !== 'share' || !b.sealed) throw new Error('That is not a share bundle.');
	const token = Emergency.open(String(privateKey || '').trim(), b.sealed, SEAL_CTX.share); // throws on wrong key / tampering
	return { token, vault: b.vault || null, identity: b.identity || null, exp: b.exp || null, pq: !!b.pq };
}

// A WEB read capability: the same read grant as above, but shaped for a browser decryptor that has no
// engine. It carries the read key and the DE-OBSCURED salt (revealed here so the browser needs no engine
// to un-obscure it) plus the filename mode, which is everything the portable reader needs to open the
// vault's files entirely on the device. It grants read only, exactly like a normal read capability, and is
// recorded in the signed roster the same way so an owner can see and revoke it. The read key it carries is
// the very same secret a normal read capability already holds — the salt is a non-secret KDF input — so a
// web capability exposes nothing a read capability does not. Format: "vdwrc1." + base64url(JSON).
const WEB_READCAP_PREFIX = 'vdwrc1';
async function makeWebReadCap(vaultDir, { password, label, expiryDays, record = true } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault does not support read capabilities.');
	if (isCloudVault(manifest)) throw new Error('Web access is not yet supported for cloud vaults.');
	const c = manifest.crypt;
	if ((c.filename_encryption || 'standard') !== 'standard') throw new Error('Web access supports the standard filename mode only.');
	const cred = await unlockCredential(password, manifest);
	if (!cred) throw wrongPasswordError('The password is incorrect.');
	// A RECORDED grant (a phone session, a shared read link) keeps the same two guarantees makeReadCap enforces, so
	// it is never untracked or unrevocable: it can only be minted with the read-write password (so it is written to
	// the signed roster the owner sees), and that roster write is fail-closed. An UNRECORDED, ephemeral grant
	// (record:false) is the local in-app viewer: it lives only in this process's memory and dies on restart, hands
	// nothing to another party, and so needs no roster entry — and a read-only password may create it.
	if (record && cred.capability !== 'rw') throw new Error('Web and mobile access can only be created with the full read-write password, so the grant is recorded in the access list and stays revocable. A read-only password cannot create one.');
	const sid = crypto.randomBytes(8).toString('hex');
	const exp = expiryFromDays(expiryDays);
	let salt = '';
	try { salt = c.salt ? Rclone.reveal(c.salt) : ''; } catch (_) { salt = ''; }
	const payload = { v: 1, sid, key: cred.master, salt, fn: c.filename_encryption || 'standard', dn: c.directory_name_encryption !== false, pub: (manifest.integrity || {}).pubkey || null, exp };
	const token = WEB_READCAP_PREFIX + '.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
	if (record) await recordShare(abs, cred.writeSeed, { sid, label: label || 'Mobile access', perm: 'read', exp });
	return { token, sid, exp };
}

// Prepare the pieces a mobile-access session needs: the web read capability (decryption material the phone
// will hold), the vault's stable id, its ciphertext root (the ONLY directory the session may read from,
// resolved here so the web layer never has to know the vault's internal layout), and a display name. The
// caller (the web server) mints the short-lived bearer token and holds the in-memory session; nothing here
// is persisted. Read-only by construction — a web read capability can never write.
async function mobilePrepare(vaultDir, { password, expiryDays, record = true } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	// record:false is the local in-app viewer — an ephemeral, in-memory grant that is NOT written to the access
	// roster (so repeat viewing never litters the "who has access" list). A phone session keeps record:true.
	const web = await makeWebReadCap(abs, { password, label: 'Mobile access', expiryDays, record });
	return {
		vaultId: (manifest.integrity || {}).pubkey || abs,
		cipherRoot: cipherDirOf(abs),
		webCap: web.token,
		sid: web.sid,
		name: displayName(abs),
	};
}

// Turn a read capability into the read-only credential used to mount. Verifies it matches this vault and
// that it has not expired (the recipient-side enforcement of a share expiry).
function readCapCredential(token, manifest) {
	const cap = parseReadCap(token);
	if (!cap) throw new Error('That read capability is not valid — copy it again.');
	if (manifest.integrity && manifest.integrity.pubkey && cap.pub && manifest.integrity.pubkey !== cap.pub) throw new Error('This read capability is for a different vault.');
	if (cap.exp && Date.now() > Number(cap.exp)) throw new Error('This read link expired on ' + new Date(Number(cap.exp)).toLocaleString() + '. Ask the owner for a new one.');
	return { master: cap.master, writeSeed: null, capability: 'ro' };
}

// ---- Share registry (a signed roster of who has access) ----
//
// A small, write-key-signed list of the read links (and read-only keys) an owner has handed out, stored
// beside the vault so it travels with it. It lets the owner see who has access, set an expiry, and mark a
// share revoked. The signature (by the write key, verified against the published key) means a reader can
// trust the roster but cannot forge it. Revocation here is a record plus an end to any live in-app viewer session
// the share started on this machine — it does NOT block a node already serving the vault's ciphertext, and does
// NOT reach a copy or read link someone already holds; only re-encrypting the vault (rotate) does that.
const SHARES_NAME = 'shares.json';
function sharesPath(vaultDir) { return path.join(path.resolve(vaultDir), SHARES_NAME); }
// The signed message over the roster. It binds a monotonic EPOCH so an older, still-validly-signed roster cannot
// be restored in place of a newer one (a rollback that would un-revoke a share). `legacy` reproduces the original
// pre-epoch message, used only to accept a roster written before this field existed until its next write re-signs
// it — the epoch anchor, not the signature, is what actually catches a rollback, so the legacy path is safe.
// The signed message binds, in order: the format VERSION, the monotonic EPOCH, and the share rows. Binding the
// version means a forged "newer version" (an attacker editing the file to a high number to block revocation)
// breaks the signature and is caught, instead of being taken at face value. Two older shapes are still ACCEPTED on
// verify, so a roster written before a field was signed is not falsely flagged until its next write re-signs it in
// the current shape: `noVersion` is the epoch-but-no-version shape, and `legacy` the original pre-epoch shape.
function sharesSigInput(store, { legacy = false, noVersion = false } = {}) {
	const shares = ((store && store.shares) || []).map(s => [s.sid, s.perm || 'read', s.label || '', s.createdAt || '', s.exp || '', s.revoked ? 1 : 0].join('|')).join('\n');
	const tag = 'vault-shares-v1', epoch = String((store && store.epoch) || 0);
	if (legacy) return tag + '\n' + shares;                       // pre-epoch (oldest)
	if (noVersion) return tag + '\n' + epoch + '\n' + shares;     // epoch-bound, pre-version
	return tag + '\nver=' + String(Number((store && store.version) || 1)) + '\n' + epoch + '\n' + shares; // current: version + epoch + rows
}
// Whether a roster's signature verifies against `pub`, accepting the current shape or either older one (so an
// un-migrated roster is not falsely flagged). Shared by listShares (to report sigOk) and the write path (to decide
// whether a claimed higher version is genuine or forged).
function sharesSigVerifies(store, pub) {
	if (!(pub && store && store.sig)) return false;
	try {
		return Integrity.verify(pub, sharesSigInput(store), store.sig)
			|| Integrity.verify(pub, sharesSigInput(store, { noVersion: true }), store.sig)
			|| (store.epoch == null && Integrity.verify(pub, sharesSigInput(store, { legacy: true }), store.sig));
	} catch (_) { return false; }
}
const SHARES_VERSION = 1;      // the share-roster format this build reads and writes
// Refuse to REWRITE a signed sidecar whose on-disk format is newer than this build understands, so an older build
// can never silently re-sign a future format under the old rules — dropping fields the new build added, or
// downgrading a binding a revocation depends on. This is the same "refuse a newer version, leave it untouched"
// discipline the manifest and recovery-index readers already enforce. Returns the version to stamp on the write.
function assertSidecarVersion(store, supported, label) {
	const v = Number((store && store.version) || 1);
	if (v > supported) throw new Error('This vault\'s ' + label + ' was written by a newer version of ' + Brand.name + ' (format v' + v + '; this build understands v' + supported + '). Update ' + Brand.name + ' to change or verify it.');
	return supported;
}
// Read a signed, list-shaped sidecar (the share roster, the succession log, the attestation chain): one size-capped
// JSON read with the same "a valid list, or the default empty shape" fallback, folded into one place instead of
// three near-identical copies. A read or parse error yields the default — these are unlocked, best-effort reads,
// and the write paths (under the vault lock) are what move a corrupt file aside. `extra` carries any non-list
// default fields (e.g. the roster's `sig`). Uses the shared corrupt-tolerant reader (16 MB cap) rather than a
// second hand-rolled cap, so the size ceiling lives in one place.
async function readSidecarList(p, key, version, extra) {
	const j = await Common.readJsonCorruptAside(p).catch(() => null); // .catch keeps the prior swallow-any-error contract (readJsonCorruptAside rethrows a real I/O error)
	// Carry the on-disk version into the fallback default so a future build that restructures this sidecar (its list
	// key no longer a bare array) is not treated as a version-1 file — which would let the newer-file write guard be
	// bypassed and the newer file overwritten under old rules. A missing/invalid version falls back to the default.
	return (j && Array.isArray(j[key])) ? j : Object.assign({ version: (j && Number(j.version)) || version, [key]: [] }, extra || {});
}
async function readShares(abs) {
	return readSidecarList(sharesPath(abs), 'shares', SHARES_VERSION, { sig: null });
}
// Sign and persist the roster, advancing its epoch PAST the highest one this machine has anchored — so a write
// always re-establishes monotonicity even after an attacker rolled the file back — then record the new epoch as
// the anchor. `vid` is the stable (salt-derived) vault id; when absent the epoch still advances locally.
async function writeSharesSigned(abs, store, writeSeed, vid) {
	// Self-clean on every write: drop entries that have EXPIRED (dead by their own time limit) so the roster never
	// accumulates stale grants without anyone lifting a finger. REVOKED entries are deliberately kept — a revoke is
	// an intentional act, the rollback anchor protects the recorded revocation, and the owner should be able to see
	// what was cut off; clear those explicitly with pruneShares / "Remove revoked & expired" when wanted.
	if (Array.isArray(store.shares)) { const now = Date.now(); store.shares = store.shares.filter(s => !(s.exp && now > Number(s.exp))); }
	// Refuse to downgrade a GENUINELY newer-format roster — but only when its signature actually verifies as that
	// version. A forged or corrupt "newer version" on a roster whose signature does NOT verify is untrusted, so the
	// owner (who holds the write seed, hence the vault's own signing key) can rewrite it cleanly instead of being
	// blocked — closing a filesystem-write denial-of-modification where a bumped version alone stalled revocation.
	// The version this build writes is bound into the signature (sharesSigInput), so a future genuine bump is caught.
	const claimed = Number((store && store.version) || 1);
	if (claimed > SHARES_VERSION) {
		let pub = null; try { pub = Integrity.signKeysFromSeed(writeSeed).pub; } catch (_) {}
		if (sharesSigVerifies(store, pub)) throw new Error('This vault\'s share roster was written by a newer version of ' + Brand.name + ' (format v' + claimed + '; this build understands v' + SHARES_VERSION + '). Update ' + Brand.name + ' to change it.');
	}
	store.version = SHARES_VERSION; // stamp the version this build writes (bound into the signature below)
	const anchor = vid != null ? await Integrity.sharesEpochSeen(vid) : 0;
	store.epoch = Math.max(Number(store.epoch) || 0, anchor) + 1;
	try { store.sig = Integrity.sign(Integrity.signKeysFromSeed(writeSeed).priv, sharesSigInput(store)); } catch (_) { store.sig = null; }
	await Common.writeJsonAtomic(sharesPath(abs), store, { fsync: true }); // durable, matching the other signed sidecars
	if (vid != null) { try { await Integrity.noteSharesEpoch(vid, store.epoch); } catch (_) {} }
}
async function recordShare(abs, writeSeed, { sid, label, perm, exp } = {}) {
	// Serialize the whole read-modify-write of the signed roster under the vault lock — cross-process, and the same
	// lock rotate holds while it rewrites shares.json. Without it, a concurrent mint/revoke (two tabs, a CLI and the
	// web app, or a mint racing a rotation) could both read the old roster and the later write drop the other's
	// change — a lost revocation would leave a share the owner believes revoked still honored by a served node.
	await withVaultLock(abs, async () => {
		const store = await readShares(abs);
		const vid = Integrity.vaultId(await readManifest(abs));
		store.shares.push({ sid, label: label || 'Share', perm: perm || 'read', createdAt: new Date().toISOString(), exp: exp || null, revoked: false });
		await writeSharesSigned(abs, store, writeSeed, vid);
	});
}
// List the roster, verifying its signature against the vault's published key so an altered roster is
// flagged. Marks each share expired/active. No password needed (the roster holds no secret).
async function listShares(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const store = await readShares(abs);
	const pub = (manifest.integrity || {}).pubkey || null;
	// Verify the roster signature against the vault's published key, accepting the current shape or an older one so
	// an un-migrated roster is not falsely flagged (it re-signs in the current shape on its next write).
	const sigOk = sharesSigVerifies(store, pub);
	// Detect a ROLLBACK: this machine anchored a higher epoch than the roster now on disk, so an older (still
	// validly signed) roster was restored — which could un-revoke a share. Independent of the signature check.
	let rolledBack = false;
	try { const anchor = await Integrity.sharesEpochSeen(Integrity.vaultId(manifest)); rolledBack = anchor > 0 && (Number(store.epoch) || 0) < anchor; } catch (_) {}
	const now = Date.now();
	const shares = store.shares.map(s => ({ sid: s.sid, label: s.label, perm: s.perm || 'read', createdAt: s.createdAt || null, exp: s.exp || null, revoked: !!s.revoked, expired: !!(s.exp && now > Number(s.exp)) }));
	return { vault: abs, shares, sigOk: (shares.length ? sigOk : true) && !rolledBack, rolledBack };
}
// Mark a share revoked (needs the write password) and end any live in-app viewer session it started in THIS
// process. It is a record, not an enforced cut-off: a node already serving the vault's ciphertext keeps serving,
// and a copy or read link the recipient already holds still works — re-encrypt the vault (rotate) to truly cut off
// a leaked read key. Returns { revoked } and the updated roster.
async function revokeShare(vaultDir, { password, sid } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const cred = await unlockCredential(password, manifest);
	if (!cred) throw wrongPasswordError('The password is incorrect.');
	if (!cred.writeSeed) throw new Error('A read-only credential cannot revoke a share — unlock with a read-write password.');
	// Same serialized read-modify-write as recordShare, so a revoke is never lost to a concurrent mint/revoke/rotate.
	return withVaultLock(abs, async () => {
		const store = await readShares(abs);
		const share = store.shares.find(s => s.sid === sid);
		if (!share) throw new Error('That share was not found in this vault\'s list.');
		share.revoked = true;
		await writeSharesSigned(abs, store, cred.writeSeed, Integrity.vaultId(manifest));
		try { require('./Mobile').stopBySid(sid); } catch (_) {} // best-effort: also cut off a running mobile session for this share in this process
		return { revoked: true, sid };
	});
}
// Permanently drop the DEAD entries — revoked or expired — from the roster (needs the write password), re-signing
// what remains. Revoking a share only MARKS it; without this the access list would grow without bound. Active,
// still-usable shares are always kept, and removing a dead entry changes nothing about who can open the vault —
// it only tidies the list. Same serialized read-modify-write as recordShare/revokeShare.
async function pruneShares(vaultDir, { password } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const cred = await unlockCredential(password, manifest);
	if (!cred) throw wrongPasswordError('The password is incorrect.');
	if (!cred.writeSeed) throw new Error('A read-only credential cannot change the access list — unlock with a read-write password.');
	const now = Date.now();
	return withVaultLock(abs, async () => {
		const store = await readShares(abs);
		const before = store.shares.length;
		store.shares = store.shares.filter(s => !(s.revoked || (s.exp && now > Number(s.exp))));
		const removed = before - store.shares.length;
		if (removed > 0) await writeSharesSigned(abs, store, cred.writeSeed, Integrity.vaultId(manifest));
		return { removed, remaining: store.shares.length };
	});
}

// ---- Key rotation + full re-encryption (true, cryptographic revocation) ----
//
// The ONLY way to cut off a leaked read key on a single-key store is to change the key and re-encrypt
// every file. This rotates the vault's WRITE SEED (→ a new read key via HKDF, keeping the salt), rewrites
// the whole store under the new key, rotates the Ed25519 IDENTITY, and records a signed identity
// SUCCESSION (the old key vouches for the new; the new key co-signs) so the change is provably intentional
// and not an attack — modeled on TUF root rotation / DNSSEC double-signature.
//
// Data safety is the first priority: the OLD ciphertext is READ-ONLY the whole time. New ciphertext is
// staged in a sibling dir and VERIFIED byte-for-byte (decrypted, via `rclone check --download`) before
// anything live is touched; the new manifest — carrying the new keys — is staged too, so a crash mid-
// commit is completed deterministically on the next open WITHOUT needing to regenerate the random keys.
// An interruption at any point before the commit leaves the original vault fully intact.
//
// Honest consequences (surfaced to the user): every OTHER credential and read link is invalidated by the
// rotation and must be re-added; a mirror/backup/served copy still holds old-key ciphertext until it is
// re-encrypted or deleted; and plaintext a revoked party already downloaded can never be recalled.
const REKEY_JOURNAL = '.rekey-journal.json';
// The journal schema version. It anchors crash-recovery of the whole store, so — like the manifest, baseline,
// succession record, and shard header — it carries a version. A recovery pass refuses to act on a journal from a
// FUTURE build whose semantics it cannot know (it leaves it intact and warns) rather than misreading a phase and
// double-committing or rolling back a committed rotation. A journal with no version predates this field and is
// read as version 1.
const REKEY_JOURNAL_VERSION = 1;
const NEW_DATA_DIR = 'data.new.tmp';
const OLD_DATA_DIR = 'data.old.tmp';
const MANIFEST_NEW = MANIFEST + '.new';
const MANIFEST_BAK_NEW = MANIFEST_BAK + '.new';
const SUCCESSION_NAME = 'succession.json';
// A rotation refreshes its journal heartbeat every REKEY_HEARTBEAT_MS while the long copy/verify phases
// run. An unforced recovery sweep treats a journal whose heartbeat is fresher than REKEY_HEARTBEAT_STALE_MS
// as still actively progressing and leaves it alone — so a concurrent sweep (in another process) can never
// roll back a rotation that is merely slow rather than crashed.
const REKEY_HEARTBEAT_MS = 60 * 1000;
const REKEY_HEARTBEAT_STALE_MS = 3 * 60 * 1000;
// The staged sidecars a rotation writes beside the vault before committing. One list, so the three cleanup
// sites (pre-commit abort, leftover clean, catch rollback) can never drift apart.
const STAGED_REKEY_TEMPS = [MANIFEST_NEW, MANIFEST_BAK_NEW, SUCCESSION_NAME + '.new', SHARES_NAME + '.new'];
function rekeyJournalPath(abs) { return path.join(abs, REKEY_JOURNAL); }
async function writeRekeyJournal(abs, j) { await Common.writeJsonAtomic(rekeyJournalPath(abs), j, { fsync: true }); }
// Cap the read like every other sidecar: resumeRekey reads this automatically on mount and on the service-start
// orphan sweep of every known vault, so a crafted oversized journal on a removable or shared drive must not be
// slurped into memory. Over the cap it fails to parse and returns null, which resumeRekey treats as "no journal."
async function readRekeyJournal(abs) { return Common.readJsonCorruptAside(rekeyJournalPath(abs)).catch(() => null); } // null on missing/corrupt/error (its prior contract), via the shared capped reader
// True if a vault has an interrupted key rotation to finish — a rekey journal, or a staged manifest left behind
// by a crash mid-commit. The mount path and the startup sweep both gate resumeRekey on this one condition, and
// the boot watchdog surfaces one that still persists after the sweep tried to resolve it (a wedged rotation).
async function rekeyPending(abs) { return (await exists(rekeyJournalPath(abs))) || (await exists(path.join(abs, MANIFEST_NEW))); }

function successionPath(abs) { return path.join(abs, SUCCESSION_NAME); }
// The signed input binds the record's VERSION and SIGNATURE ALGORITHM as well as its keys and linkage, so that
// when a second signature scheme is ever introduced (e.g. a post-quantum one), the algorithm a record was signed
// under cannot be swapped to force a weaker verification — the `alg` field is authenticated, not just declared.
function successionInput(b) { return ['identity-succession-v1', String(b.v || 1), String(b.alg || 'ed25519'), b.prev || 'genesis', b.oldIdentity, b.oldPubkey, b.newIdentity, b.newPubkey, b.timestamp, b.reason || ''].join('\n'); }
const SUCCESSION_VERSION = 1; // the identity-succession format this build reads and writes
async function readSuccession(abs) { return readSidecarList(successionPath(abs), 'items', SUCCESSION_VERSION); }
// Verify the identity-succession chain: each record is signed by BOTH the old key (continuity) and the
// new key (possession), each pubkey hashes to its stated identity, and the chain links old→new without a
// gap. Returns { ok, chain: [{oldIdentity,newIdentity,at,reason,verified}], current }.
// IMPORTANT: `ok` means the chain is internally consistent, NOT that it is authentic. An attacker who controls both
// keys can forge a fully self-consistent chain, so a caller must ANCHOR the chain to a value it independently trusts —
// the rollback ledger's recorded identity, or the out-of-band fingerprint from the Recovery Kit (as the audit path
// does) — before treating `ok` as proof. Never trust `ok` alone from a new call site.
async function verifySuccession(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const store = await readSuccession(abs);
	let ok = true, prev = null, current = null;
	const chain = store.items.map((b) => {
		let verified = false;
		try {
			const input = successionInput(b);
			const sigOldOk = Integrity.verify(b.oldPubkey, input, b.sigOld);
			const sigNewOk = Integrity.verify(b.newPubkey, input, b.sigNew);
			const idsOk = Integrity.identity(b.oldPubkey) === b.oldIdentity && Integrity.identity(b.newPubkey) === b.newIdentity;
			const linkOk = (b.prev || null) === (prev || null);
			const algOk = (b.alg || 'ed25519') === 'ed25519'; // fail closed on a scheme this build cannot verify, rather than Ed25519-verifying it
			verified = sigOldOk && sigNewOk && idsOk && linkOk && algOk;
		} catch (_) { verified = false; }
		if (!verified) ok = false;
		prev = b.chain || null; current = b.newIdentity;
		return { oldIdentity: b.oldIdentity, newIdentity: b.newIdentity, at: b.timestamp, reason: b.reason || null, verified };
	});
	return { vault: abs, ok: chain.length ? ok : true, chain, current };
}

// The size of a directory tree, bounded so a pathological tree can't run away. Used only for the
// free-space precondition, so an estimate is fine.
async function dirSizeBounded(dir, budgetMs = 30000) {
	const start = Date.now(); let total = 0; const stack = [dir]; let truncated = false;
	while (stack.length) {
		if (Date.now() - start > budgetMs) { truncated = true; break; }
		const cur = stack.pop();
		let ents; try { ents = await fsp.readdir(cur, { withFileTypes: true }); } catch (_) { continue; }
		for (const e of ents) { const p = path.join(cur, e.name); if (e.isDirectory()) stack.push(p); else { try { total += (await fsp.stat(p)).size; } catch (_) {} } }
	}
	// Return both the total and whether the budget was hit before the walk finished, so a caller can tell a partial
	// result from a complete one. Returned on the result (not a shared function-static) so concurrent walks — e.g. a
	// vaultSize during a rotate free-space check — never clobber each other's truncated flag.
	return { bytes: total, truncated };
}

// How much data a vault holds, measured over its MOUNTED, decrypted contents — and only while it is mounted.
// Two reasons, both about deniability: sizing the mount (not the encrypted folder on disk) means a decoy unlock
// reports the DECOY's size, matching what is actually open; and never sizing an unmounted vault means the UI never
// broadcasts a folder's on-disk footprint, which could hint at a large real vault hidden behind a small decoy. The
// walk is the shared, spawn-free, bounded one above, so it stays cross-platform.
async function vaultSize(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs); // confirm this is a real vault (throws otherwise)
	// A LOCAL vault's ciphertext store is on THIS disk, so size it directly rather than walking the mounted drive.
	// This is the real disk space the vault uses, it needs no mount, and — crucially — its files stat reliably on
	// every platform: a WinFsp/FUSE mount can fail fs.stat, so a mount walk silently summed to 0 B on Windows. It is
	// the SAME source rotate's free-space check already uses (dirSizeBounded on cipherDirOf), so the two never
	// disagree. The store also holds the vault's tiny bookkeeping objects and the crypt overhead — a few KB — which
	// are genuinely part of its on-disk footprint, so they are counted, not subtracted.
	if (!isCloudVault(manifest)) {
		const { bytes, truncated } = await dirSizeBounded(cipherDirOf(abs), 60000);
		return { vault: abs, bytes, truncated };
	}
	// A CLOUD vault's ciphertext lives at the provider — there is nothing local to walk — so fall back to the
	// mounted drive, which requires a mount. (Subtract the in-store bookkeeping objects so the figure is your files.)
	const live = await liveMountFor(abs);
	const mp = live && live.mountpoint;
	if (!mp || !(await Rclone.isMounted(mp))) throw new Error('Mount the vault first to see how much space its contents use.');
	let { bytes, truncated } = await dirSizeBounded(mp, 60000);
	for (const name of INTERNAL_VAULT_OBJECTS) { try { const st = await fsp.stat(path.join(mp, name)); if (st.isFile()) bytes -= st.size; } catch (_) {} }
	if (bytes < 0) bytes = 0;
	return { vault: abs, bytes, truncated };
}

// Establish a signed baseline directly inside a store (a cipher dir), using the given keys, and return the
// snapshot SUMMARY to bake into the manifest — WITHOUT persisting the live manifest (the caller stages it).
// Reuses the same capture/root/hmac/sign pieces as writeSnapshot so the record format stays identical.
async function establishBaselineInStore(bin, cfg, newManifest, keys, { deep, sealed = false, prevRoot, timeoutMs } = {}) {
	const { files } = await captureFiles(bin, cfg, { deep, timeoutMs });
	const vid = Integrity.vaultId(newManifest); // new identity → its own ledger lineage
	const root = await Integrity.merkleRoot(files);
	const seen = await Integrity.lastSeen(vid);
	const seq = Math.max((seen && seen.seq) || 0, 0) + 1;
	const createdAt = new Date().toISOString();
	const fields = { scheme: Integrity.SCHEME, root, seq, prevRoot: prevRoot || null, count: files.length, createdAt, version: BASELINE_VERSION, sealed: !!sealed, deep: !!deep };
	const hmac = baselineHmac(keys.hmacKey, fields);
	const sig = Integrity.sign(keys.signPriv, Integrity.signingInput(fields));
	const record = { version: BASELINE_VERSION, tool: Brand.slug, scheme: Integrity.SCHEME, createdAt, deep: !!deep, auto: false, sealed: !!sealed, count: files.length, files, merkleRoot: root, prevRoot: prevRoot || null, seq, hmac, sig };
	await writeVaultObjectAtomic(bin, cfg, SNAPSHOT_NAME, JSON.stringify(record), { timeoutMs });
	// The rollback ledger is advanced only AFTER the rotation commits (see observeAfterRekey), never here: a
	// rotation can still be rolled back after this baseline is staged, and advancing the ledger pre-commit
	// would leave it ahead of the reverted vault and raise a false rollback alarm on the next audit.
	return snapshotFingerprint(fields, hmac, false); // self-verifying fingerprint (carries prevRoot + version)
}

// Advance the rollback ledger to a vault's now-live baseline, reading it from the committed manifest. Called
// after a rotation commits (from rotate's cleanup and from resumeRekey's completion), so the ledger only ever
// records a state that is actually live. Best-effort: a ledger hiccup must not fail a completed rotation.
async function observeAfterRekey(abs) {
	try {
		const m = await readManifest(abs);
		// identityAuthorized (final arg): a rotation's identity change is backed by the signed succession just
		// written, so this is the one path allowed to move the ledger's sticky known-good identity to the new one.
		if (m && m.snapshot && typeof m.snapshot.seq === 'number') await Integrity.observe(Integrity.vaultId(m), m.snapshot.seq, m.snapshot.root, null, Integrity.identity(Integrity.pubkeyOf(m)), true, !!m.snapshot.sealed);
	} catch (_) {}
}

// Complete the commit renames deterministically (idempotent — safe to re-run after a crash). Swaps the
// data dir to the new store and replaces the manifest and the roster/succession sidecars with their
// staged copies. Every step is a rename (no secret needed), so a resumed run finishes without the keys.
async function commitRekeyRenames(abs) {
	const cipherDir = cipherDirOf(abs), newDir = path.join(abs, NEW_DATA_DIR), oldDir = path.join(abs, OLD_DATA_DIR);
	// 1) Move the current (old) store aside, then the new store into place. Guarded so a re-run is a no-op.
	// The directory renames use a bounded retry so a transient lock on a file in the store (an antivirus or
	// search indexer holding a handle, common on Windows) cannot fail the commit mid-swap.
	if (await exists(path.join(abs, NEW_DATA_DIR))) {
		if (await exists(cipherDir) && !(await exists(oldDir))) await Common.renameWithRetry(cipherDir, oldDir); // data -> data.old.tmp
		if (!(await exists(cipherDir))) await Common.renameWithRetry(newDir, cipherDir);                              // data.new.tmp -> data
	}
	// 2) Replace the manifest and sidecars with their staged copies. Use the same bounded retry as the directory
	// swap above: vault.json is a prime target for an antivirus or search indexer's transient handle on Windows, and
	// a plain rename that hit that lock would throw out of a commit that has already begun (and could surface a
	// rotation that actually succeeded as a failure). The manifest replace is the most important one to protect.
	for (const [stg, live] of [[MANIFEST_NEW, MANIFEST], [MANIFEST_BAK_NEW, MANIFEST_BAK], [SUCCESSION_NAME + '.new', SUCCESSION_NAME], [SHARES_NAME + '.new', SHARES_NAME]]) {
		if (await exists(path.join(abs, stg))) await Common.renameWithRetry(path.join(abs, stg), path.join(abs, live));
	}
}

// After a rotation commits, the self-heal recovery data (if any) describes the OLD ciphertext — the rotation
// renamed and re-encrypted every block, so the recorded block names, sizes, and CRCs no longer match anything in
// the new store. Leaving it would make "Check & repair" report the whole vault as damaged, and — worse — let a
// scheduled auto-heal reconstruct old-key blocks over the new store, silently corrupting it. So remove it (the
// vault's own files are untouched; recovery data is redundancy, not the data): the user rebuilds it with
// "protect", and a normal mount/unmount would rebuild it anyway. Best-effort and idempotent, so it is equally safe
// on the crash-recovery path, which reaches the same commit.
// Off-site copies and version history describe the OLD keys after a rotation: every ciphertext name and byte
// changed, so a mirror or one-way backup will see "everything changed" and SAFELY refuse to update until it is
// re-established from this vault, and version snapshots taken under the old key cannot be opened with the new one.
// Say so plainly, so the refusal isn't mistaken for a drive fault and old snapshots aren't assumed restorable.
// The local vault is fully intact; this only warns about the OFF-SITE copies. Best-effort.
async function warnRotationOffsiteEffects(abs) {
	try {
		const s = await getSettings();
		const hasMirror = !!((s.syncDests || {})[abs]);
		const hasBackup = !!((s.backupDests || {})[abs] || (s.backupSchedules || {})[abs]);
		if (hasMirror || hasBackup) Common.warn('Rotation re-encrypted the whole vault, so its off-site ' + (hasMirror && hasBackup ? 'backup and mirror' : hasMirror ? 'mirror' : 'backup') + ' now describes the old keys and will refuse to update until you re-establish it from this vault. Version snapshots taken before the rotation cannot be opened with the new key.');
	} catch (_) {}
}
// After a rotation the two-way mirror's saved baseline describes the OLD ciphertext (every name changed), so a
// plain sync would see "everything changed" and fail with a misleading "check the destination" error. Clear the
// baseline: this marks the mirror UNPRIMED, so the background sync cleanly SKIPS it (it never auto-primes) and the
// next manual sync tells the user to re-prime — a deliberate, LOCAL-authoritative re-prime that rebuilds the
// destination from the new-key vault. It removes only sync STATE, never data, and never copies old ciphertext back
// to the local vault. Best-effort and idempotent, so it is safe on the crash-recovery commit path too.
async function clearStaleMirrorBaselineOnRekey(abs) {
	try { const dest = await mirrorDestFor(abs); if (dest) await Sync.clearState(Sync.workdirFor(abs, dest)); } catch (_) {}
}
// A rotation bumps a team vault's members epoch but commits by renaming the staged manifest in, NOT through
// persistManifest — so the members-epoch anchor recorded there would miss it. Anchor the committed epoch here so
// a later rollback to the pre-rotation manifest is still detected. Monotonic, best-effort, team vaults only.
async function anchorMembersEpochOnRekey(abs) {
	try { const m = await readManifest(abs); if (m && m.members && typeof m.members.epoch === 'number') await Integrity.noteMembersEpoch(Integrity.vaultId(m), m.members.epoch); } catch (_) {}
	// The committed manifest is renamed in (not persisted through persistManifest), so anchor the slot epoch here too.
	try { const m = await readManifest(abs); if (m && m.crypt && typeof m.crypt.slotEpoch === 'number') await Integrity.noteSlotEpoch(Integrity.vaultId(m), m.crypt.slotEpoch); } catch (_) {}
}
async function clearStaleRecoveryOnRekey(abs) {
	try {
		if (await Recovery.hasRecovery(abs)) {
			await Recovery.removeRecovery(abs);
			// Reset the rollback anchor to match: a re-protect after rotation restarts the recovery index at version 1,
			// and a stale high anchor would otherwise make heal (and scheduled auto-heal) falsely refuse the rebuilt
			// data as a downgrade. Safe — a rotation already proved write authority, which is outside the anchor's
			// (folder-level, credential-less) threat model; a later signed rebuild re-anchors from the new baseline.
			try { await Integrity.clearRecoverySigned(Integrity.vaultId(await readManifest(abs))); } catch (_) {}
			Common.warn('The rotation removed this vault\'s self-heal recovery data because it described the old keys. Run "' + Brand.cli + ' protect ' + displayName(abs) + '" to rebuild it.');
		}
	} catch (_) {}
}

// Recover an interrupted rotation on vault open. If the new manifest was staged (vault.json.new exists),
// the commit had begun — finish it deterministically. Otherwise the rotation aborted before touching
// anything live — discard the staged temp copy and leave the original vault exactly as it was.
async function resumeRekey(vaultDir, { force = false } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const journal = await readRekeyJournal(abs);
	const stagedManifest = await exists(path.join(abs, MANIFEST_NEW));
	const newDir = path.join(abs, NEW_DATA_DIR), oldDir = path.join(abs, OLD_DATA_DIR);
	if (!journal && !stagedManifest) return { resumed: false };
	// A journal written by a FUTURE build (a higher schema version) may use phases or semantics this build does
	// not understand. Never guess: leave it, the staged sidecars, and the store exactly as they are and warn, so
	// the build that wrote it — not this one — completes or rolls back the rotation. A missing version is legacy
	// (pre-versioning) and reads as version 1.
	if (journal && Number(journal.v || 1) > REKEY_JOURNAL_VERSION) {
		Common.warn('An interrupted key rotation for "' + displayName(abs) + '" was left untouched: its journal was written by a newer version of this program. Update to that version to finish it.');
		return { resumed: false, unknownVersion: true };
	}
	// Past the commit point — the manifest is staged, or the journal reached COMMIT/CLEANUP — the rotation is
	// beyond the point of no return: the new store is already (being) swapped in, so completing is idempotent
	// and ALWAYS safe, and a just-crashed commit MUST be finished, never skipped (finishing is what preserves
	// the data). So the completion path is NEVER gated by the heartbeat; it only defers to an active rotation
	// finishing it in THIS process (vaultBusy), which force bypasses.
	const committed = stagedManifest || (journal && (journal.phase === 'COMMIT' || journal.phase === 'CLEANUP'));
	if (committed) {
		if (!force && vaultBusy.has(abs)) return { resumed: false, busy: true };
		await commitRekeyRenames(abs);
		await observeAfterRekey(abs); // record the now-live new baseline in the rollback ledger
		await clearStaleRecoveryOnRekey(abs); // the recovery index described the old ciphertext — invalid now
		await clearStaleMirrorBaselineOnRekey(abs); // the mirror baseline described the old ciphertext — mark it unprimed so the next sync re-primes cleanly, not fails misleadingly
		await anchorMembersEpochOnRekey(abs); // record the rotated team-roster epoch so a later rollback to the pre-rotation manifest is detected
		await fsp.rm(oldDir, { recursive: true, force: true });
		await fsp.rm(rekeyJournalPath(abs), { force: true });
		Common.warn('A key rotation was completed after an interruption for "' + displayName(abs) + '".');
		return { resumed: true, completed: true };
	}
	// Pre-commit: the original vault (data/ + vault.json) is untouched, and discarding the staged copy is
	// DESTRUCTIVE to a rotation that is still actively writing it. So never roll back while the vault is busy in
	// this process, or while the journal heartbeat is still fresh (a rotation running in another process): the
	// owner will finish or roll back its own attempt. The rotation's own entry/catch and a mount pass force.
	if (!force) {
		const beat = journal && journal.heartbeatAt ? Date.parse(journal.heartbeatAt) : 0;
		const fresh = beat && (Date.now() - beat) < REKEY_HEARTBEAT_STALE_MS;
		if (vaultBusy.has(abs) || fresh) return { resumed: false, busy: true };
	}
	await fsp.rm(newDir, { recursive: true, force: true });
	for (const f of STAGED_REKEY_TEMPS) await fsp.rm(path.join(abs, f), { force: true });
	await fsp.rm(rekeyJournalPath(abs), { force: true });
	Common.warn('An interrupted key rotation for "' + displayName(abs) + '" was rolled back — the vault is unchanged.');
	return { resumed: true, completed: false };
}

// Rotate the vault's keys and re-encrypt the whole store. Requires a read-write password. Non-destructive
// and resumable (see the design note above). Reports coarse progress through onProgress.
async function rotate(vaultDir, { password, reason, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	if (isCloudVault(await readManifest(abs))) throw new Error('Key rotation is not yet supported for cloud vaults (it re-encrypts the whole store, which over cloud means re-uploading everything). Changing a password still works instantly.');
	// If this vault is mirrored and ANOTHER machine currently holds the write-lease (it has the vault mounted
	// there), refuse: a rotation renames every ciphertext byte, so committing here while the other side runs on the
	// old key would diverge the two copies and wedge the mirror. Best-effort — if the destination can't be reached
	// to check the lease, don't block a local rotation.
	try { const ls = await mirrorLeaseStatus(abs); if (ls.configured && ls.held && !ls.mine) throw Object.assign(new Error('This vault is mirrored and in use on "' + (ls.holder || 'another machine') + '" right now. Rotating here would diverge the two copies. Unmount it there first, then rotate.'), { code: 'MIRROR_IN_USE' }); }
	catch (e) { if (e && e.code === 'MIRROR_IN_USE') throw e; } // any other error (e.g. the destination is unreachable) must not block a local rotation
	// Finish or roll back any earlier interrupted rotation BEFORE claiming the vault — otherwise the PREP
	// cleanup below would delete the staged/old copies a prior crash left behind, which are the only surviving
	// data until that rotation is completed. A committed-but-interrupted rotation is completed here; a
	// pre-commit one that is still actively progressing (its heartbeat is fresh) returns busy — in that case we
	// must NOT fall through to the destructive prep, so refuse and let the caller retry once it settles.
	const priorResume = await resumeRekey(abs).catch(() => null);
	if (priorResume && priorResume.busy) throw new Error('This vault is recovering from an interrupted key rotation. Wait a few minutes and try again, or mount it once to finish the recovery.');
	// Hold the cross-process manifest lock for the WHOLE rotation, not just the in-process busy flag, so a key or
	// membership change made from another process (a CLI command while the service rotates, or the reverse) cannot
	// slip in and be overwritten when rotation commits its new manifest. The lock is never stolen from a live
	// holder on this machine however long the rotation runs; a concurrent change simply waits briefly, then is
	// told the vault is busy. removeMember/removeDevice release their own lock before calling rotate, so this is a
	// fresh, non-nested acquisition.
	return withVaultLock(abs, () => withVaultBusy(abs, 'This vault is busy with another operation — wait for it to finish, then rotate.', async () => {
		const manifest = await readManifest(abs);
		const hadRecovery = hasRecoveryCredential(manifest); // a rotation drops it; remember so we can nudge the owner to add a fresh one
		if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates key rotation. Create a new vault to use it.');
		await assertUnmounted(abs, 'before rotating its keys');
		const cred = await unlockCredential(password, manifest);
		if (!cred) throw wrongPasswordError('The password is incorrect.');
		if (!cred.writeSeed) throw new Error('A read-only credential cannot rotate the vault — unlock with a read-write password.');
		// A team vault's rotation re-seals the members and must re-sign the roster with the owner key, so it can only
		// be done by an OWNER. Without the owner seed the re-sealed member slots would be left with an invalid roster
		// signature (flagged as tampering), so refuse rather than produce that state.
		if (manifest.members && manifest.members.ownerPubKey && !cred.ownerSeed) throw new Error('Rotating a team vault re-encrypts and re-signs the membership roster, so it needs an OWNER credential — unlock with an owner password.');
		const bin = await ensureEngine();
		const cipherDir = cipherDirOf(abs), newDir = path.join(abs, NEW_DATA_DIR), oldDir = path.join(abs, OLD_DATA_DIR);
		const emit = (percent, label) => { try { if (onProgress) onProgress({ percent, label }); } catch (_) {} };

		// Free-space precondition (~2× the store during the copy).
		try { const used = (await dirSizeBounded(cipherDir)).bytes; const free = await Common.diskFree(abs); if (free != null && used > 0 && free.freeBytes < used * 1.1) throw new Error('Not enough free space to rotate safely — about ' + Math.ceil(used / 1e9 * 1.1) + ' GB free is needed (the store is temporarily written twice). Free some space and try again.'); } catch (e) {
		if (/Not enough free space/.test(e && e.message)) throw e; // the precondition fired -> surface it
		if (e instanceof TypeError || e instanceof ReferenceError || e instanceof RangeError) throw e; // a bug in the estimator must never hide silently behind this best-effort check
		// otherwise the free-space COULD NOT BE MEASURED (a transient I/O / statfs failure): skip this best-effort
		// precondition and let the real write surface any genuine out-of-space error, exactly as before.
	}

		// Old identity/keys and freshly generated new ones (new write seed → new read key via HKDF; keep salt).
		const oldPub = Integrity.pubkeyOf(manifest), oldIdentity = Integrity.identity(oldPub), oldSign = Integrity.signKeysFromSeed(cred.writeSeed);
		const salt = manifest.crypt.salt;
		const newWriteSeed = crypto.randomBytes(32).toString('base64');
		const newMaster = Integrity.readKeyFromSeed(newWriteSeed, salt), newSign = Integrity.signKeysFromSeed(newWriteSeed), newPub = newSign.pub, newIdentity = Integrity.identity(newPub);

		// Two crypt remotes in one config: OLD (read-only source) and NEW (the staged destination), for the
		// copy + verify. A second single-remote config names the NEW store "vault", so the baseline helpers
		// (which address "vault:") can write the fresh signed baseline into the new store.
		// Derive the crypt fields through the single shared extractor (cryptOptsOf), the same one mount/list/audit/
		// snapshot/versions/mirror use, so this re-encryption path can never drift from how the store is later read.
		const oldPwObsc = await Rclone.obscure(bin, cred.master), newPwObsc = await Rclone.obscure(bin, newMaster);
		const cfgText = Rclone.cryptRemoteSection('old', { cipherDir, ...cryptOptsOf(manifest, oldPwObsc) })
			+ Rclone.cryptRemoteSection('new', { cipherDir: newDir, ...cryptOptsOf(manifest, newPwObsc) });
		const cfg = await Rclone.writeEphemeralConfig(cfgText);
		const cfgNew = await Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: newDir, ...cryptOptsOf(manifest, newPwObsc) }));
		// The journal records the phase plus a heartbeat that a periodic timer refreshes during the long
		// copy/verify phases, so a concurrent recovery sweep can tell an actively-progressing rotation from a
		// crashed one. Each explicit phase write also refreshes the heartbeat.
		let journalState = { v: REKEY_JOURNAL_VERSION, phase: 'COPY', oldIdentity, newIdentity, reason: reason || 'rotation', at: new Date().toISOString() };
		const setPhase = async (phase) => { journalState = { ...journalState, phase, heartbeatAt: new Date().toISOString() }; await writeRekeyJournal(abs, journalState); };
		let beat = null, beatQueue = null, summary = null; // hoisted to the enclosing scope so the catch/finally can reference them (a catch is a separate lexical scope from its try)
		try {
			// Clean any leftovers from a previous aborted attempt (safe — pre-commit, nothing live yet).
			await fsp.rm(newDir, { recursive: true, force: true }); await fsp.rm(oldDir, { recursive: true, force: true });
			for (const f of STAGED_REKEY_TEMPS) await fsp.rm(path.join(abs, f), { force: true });
			await fsp.mkdir(newDir, { recursive: true });
			await setPhase('COPY');
			// Serialize the heartbeat writes so at most one is ever in flight, and so draining the queue before the
			// COMMIT write drains EVERY outstanding one — not just the latest. Otherwise, if a heartbeat's fsync ran
			// long (a wedged drive) two writes could overlap, and a stale one (carrying the COPY/VERIFY phase) could
			// land its atomic rename AFTER the COMMIT write, leaving the journal one phase behind — which a later
			// crash would misread as pre-commit and wrongly roll back a committed rotation.
			beatQueue = Common.serialQueue();
			beat = setInterval(() => { beatQueue(() => writeRekeyJournal(abs, { ...journalState, heartbeatAt: new Date().toISOString() })).catch(() => {}); }, REKEY_HEARTBEAT_MS);
			if (beat.unref) beat.unref();

			// COPY: decrypt from old, encrypt into new.
			emit(2, 'Re-encrypting every file under the new key…');
			const cp = await Rclone.run(bin, ['copy', 'old:', 'new:', '--transfers', '4', '--checkers', '8', '--retries', '3'], { configPath: cfg, timeoutMs: 24 * 60 * 60 * 1000 });
			if (cp.status !== 0) throw new Error('Re-encryption did not complete — the vault was NOT changed. ' + engineTail(cp));

			// VERIFY: decrypted content of both stores must be byte-for-byte identical.
			await setPhase('VERIFY');
			emit(80, 'Verifying the re-encrypted copy…');
			const chk = await Rclone.run(bin, ['check', 'old:', 'new:', '--download'], { configPath: cfg, timeoutMs: 24 * 60 * 60 * 1000 });
			if (chk.status !== 0) throw new Error('The re-encrypted copy did NOT verify identical to the original — nothing was changed. ' + engineTail(chk));

			// Establish a fresh baseline inside the NEW store, signed by the new key (content is unchanged, so the
			// Merkle root matches; only the signature/identity differ). Then build the staged new manifest.
			emit(92, 'Sealing the new baseline…');
			const newKeys = integrityKeys(newMaster, newWriteSeed, { crypt: { salt } });
			// The new primary slot carries the new write seed — and, for a TEAM vault, the owner seed too, so the
			// person rotating stays the owner. (The owner key itself is not rotated: it is independent of the
			// content key, so the roster's ownerPubKey and every member's identity are unchanged.)
			const isTeam = !!(manifest.members && manifest.members.ownerPubKey);
			const primaryBundle = isTeam && cred.ownerSeed ? { cap: 'rw', key: newWriteSeed, ownerSeed: cred.ownerSeed } : { cap: 'rw', key: newWriteSeed };
			const newSlot = await makeSlot(primaryBundle, password, 'password', 'Primary', vaultLevel(manifest));
			// Re-seal every REMAINING member to the NEW key under their (unchanged) public key, so a rotation done to
			// revoke a departed member keeps the rest of the team working without any re-invite. A read member gets
			// the new read key; a write member gets the new write seed. Their memberId/label/pub are preserved.
			const ownerSeedForReseal = isTeam ? cred.ownerSeed : null; // owner members are re-sealed with the (unchanged) owner seed
			const newMemberSlots = isTeam ? keySlotsOf(manifest.crypt).filter(s => s.kind === 'member').map(s =>
				memberCapSlot(memberBundle({ role: s.role, owner: s.owner }, { master: newMaster, writeSeed: newWriteSeed, ownerSeed: ownerSeedForReseal }),
					s.pub, { role: s.role, owner: s.owner, memberId: s.memberId, label: s.label })) : [];
			let newManifest = withKeySlots({ ...manifest }, [newSlot, ...newMemberSlots]);
			newManifest.integrity = { scheme: Integrity.SCHEME, pubkey: newPub };
			if (isTeam) newManifest.members = { ...manifest.members, epoch: (manifest.members.epoch || 0) + 1, keyGeneration: (manifest.members.keyGeneration || 0) + 1, pendingRotation: false };
			// Preserve a sealed vault's strict tamper tripwire across the rotation: re-establish the baseline as sealed
			// (re-signed under the new key) so a deliberate seal is never silently dropped by a key rotation. Also carry
			// the deep-scan setting forward. observeAfterRekey then advances the anchor with this same sealed state.
			summary = await establishBaselineInStore(bin, cfgNew, newManifest, newKeys, { deep: !!(manifest.snapshot && manifest.snapshot.deep), sealed: !!(manifest.snapshot && manifest.snapshot.sealed), prevRoot: (manifest.snapshot && manifest.snapshot.root) || null, timeoutMs: 60 * 60 * 1000 });
			newManifest.snapshot = summary;
			resealManifest(newManifest, newWriteSeed);
			if (isTeam) resealRoster(newManifest, cred.ownerSeed); // re-sign the roster with the (unchanged) owner key

			// Stage the succession record (old key vouches, new key co-signs), the cleared roster (all old read
			// links are dead under the new key), and the new manifest — all beside the vault, nothing live yet.
			const succ = await readSuccession(abs);
			succ.version = assertSidecarVersion(succ, SUCCESSION_VERSION, 'identity-succession record'); // never rewrite a newer-format succession chain under old rules
			const prev = succ.items.length ? succ.items[succ.items.length - 1].chain : null;
			const b = { type: 'identity-succession', v: 1, alg: 'ed25519', prev, oldIdentity, oldPubkey: oldPub, newIdentity, newPubkey: newPub, timestamp: new Date().toISOString(), reason: reason || 'rotation' };
			const input = successionInput(b);
			b.sigOld = Integrity.sign(oldSign.priv, input); b.sigNew = Integrity.sign(newSign.priv, input);
			b.chain = crypto.createHash('sha256').update(input + '\n' + b.sigOld).digest('hex');
			succ.items.push(b);
			await Common.writeJsonAtomic(path.join(abs, SUCCESSION_NAME + '.new'), succ, { fsync: true });
			// Give the cleared roster an epoch ABOVE the anchor this machine holds, so it is never mistaken for a
			// rolled-back copy after the rotation commits. The anchor itself is advanced by the next roster write,
			// not here — advancing it during staging would falsely flag the original roster if the rotation is
			// rolled back. Salt is preserved across rotation, so the vault id (and thus the anchor) is stable.
			let clearedEpoch = 1; try { clearedEpoch = (await Integrity.sharesEpochSeen(Integrity.vaultId(newManifest))) + 1; } catch (_) {}
			const clearedRoster = { version: 1, epoch: clearedEpoch, shares: [], sig: null };
			try { clearedRoster.sig = Integrity.sign(newSign.priv, sharesSigInput(clearedRoster)); } catch (_) {}
			await Common.writeJsonAtomic(path.join(abs, SHARES_NAME + '.new'), clearedRoster, { fsync: true });
			// Write the manifest BACKUP now — it is NOT the commit anchor. The staged MANIFEST itself is the anchor
			// (resumeRekey keys off it), so it is written LAST and, critically, only AFTER the lease fence below, so
			// its presence still implies every other staged file already exists.
			await Common.writeJsonAtomic(path.join(abs, MANIFEST_BAK_NEW), newManifest, { fsync: true });

			// COMMIT boundary approaches: from the anchor write on, a crash is COMPLETED (not rolled back) on next
			// open. The heartbeat stops now; the fast rename phases need no progress signal and must not race the
			// journal. Drain any in-flight heartbeat write first, so the COMMIT write is strictly last and wins.
			if (beat) { clearInterval(beat); beat = null; }
			await beatQueue(() => {}); // drain EVERY enqueued heartbeat write (an empty task runs after all prior ones), so the COMMIT write is strictly last and no stale heartbeat can land after it
			// FENCE before the point of no return — and BEFORE the commit anchor exists. If the lease was stolen during
			// the long re-encryption (a clock jump, or a stall past the lease TTL), another process may have changed the
			// live manifest; abort now, while no anchor is staged, so the interruption-recovery path ROLLS BACK and the
			// original is untouched. The fence MUST precede the MANIFEST_NEW write: once the anchor exists, recovery
			// treats the rotation as committed, so a fence placed AFTER it could not abort — it would instead complete
			// the rotation over the concurrent change (silently losing an added/removed key or member).
			await assertStillHoldLease(abs);
			await Common.writeJsonAtomic(path.join(abs, MANIFEST_NEW), newManifest, { fsync: true }); // commit anchor — written LAST, only after the fence passes
			await setPhase('COMMIT');
			emit(97, 'Switching over to the new keys…');
			await commitRekeyRenames(abs);

			// CLEANUP: delete the old ciphertext and the journal. Log the rotation in the tamper history.
			await setPhase('CLEANUP');
			await observeAfterRekey(abs); // record the now-live new baseline in the rollback ledger
			await clearStaleRecoveryOnRekey(abs); // the recovery index described the old ciphertext — invalid now, and an auto-heal over it would corrupt the new store
			await clearStaleMirrorBaselineOnRekey(abs); // the mirror baseline described the old ciphertext — mark it unprimed so the next sync re-primes cleanly, not fails misleadingly
			await anchorMembersEpochOnRekey(abs); // record the rotated team-roster epoch so a later rollback to the pre-rotation manifest is detected
			if (hadRecovery) { try { await Integrity.noteRecoveryDropped(Integrity.vaultId(manifest)); } catch (_) {} } // the rotation invalidated the recovery key/owner recovery — nudge to add one (best-effort; vault id is stable across rotation)
			await warnRotationOffsiteEffects(abs); // tell the user their off-site backup/mirror and old version snapshots describe the old keys
			try { await logTamper(await readManifest(abs), { kind: 'identity-rotated', notes: ['Vault keys rotated and re-encrypted; identity ' + oldIdentity + ' → ' + newIdentity + ' (' + (reason || 'rotation') + '). Other credentials and read links were invalidated.'] }); } catch (_) {}
			await fsp.rm(oldDir, { recursive: true, force: true });
			await fsp.rm(rekeyJournalPath(abs), { force: true });
			emit(100, 'Done.');
			return { vault: abs, oldIdentity, newIdentity, fingerprint: Integrity.fingerprint(summary.root), seq: summary.seq, recoveryDropped: hadRecovery };
		} catch (e) {
			// Stop the journal heartbeat BEFORE touching the journal, exactly as the success path does before COMMIT:
			// resumeRekey reads/rolls-back/removes the rekey journal below, and a queued heartbeat write must not
			// interleave with that. Drain the queue so no enqueued beat lands after resume has cleaned up.
			if (beat) { clearInterval(beat); beat = null; }
			if (beatQueue) await beatQueue(() => {}); // may be null if the failure happened before the queue was created
			// Resolve the interrupted rotation through the SAME recovery path the next open would use, so the two
			// can never disagree: resumeRekey completes a committed rotation (idempotent) or rolls back a
			// pre-commit one. A completed recovery means the rotation actually SUCCEEDED, so return success rather
			// than surfacing the interruption as a failure. If nothing was staged yet (the failure landed before
			// the journal was written), clean any partial leftovers by hand.
			const r = await resumeRekey(abs, { force: true }).catch(() => null);
			if (r && r.completed && summary) { emit(100, 'Done.'); return { vault: abs, oldIdentity, newIdentity, fingerprint: Integrity.fingerprint(summary.root), seq: summary.seq }; }
			// Clean up the staged state by hand ONLY when the interruption landed BEFORE the commit began and resume
			// confirmed there was nothing to finish. If resume threw (r is null — state unknown), or the commit had
			// begun (data.old.tmp present, or a new manifest is staged), or resume deferred (a newer-version journal,
			// or busy), leave the staged store and the journal in place: a later open re-runs resumeRekey to finish or
			// roll back the rotation. Deleting them here would strip the only copy of the new generation mid-commit
			// and brick the vault. resume's own pre-commit path already discards a cleanly-abortable rotation.
			const commitBegan = (await exists(oldDir)) || (await exists(path.join(abs, MANIFEST_NEW)));
			if (r && r.resumed === false && !r.unknownVersion && !r.busy && !commitBegan) {
				await fsp.rm(newDir, { recursive: true, force: true });
				for (const f of STAGED_REKEY_TEMPS) await fsp.rm(path.join(abs, f), { force: true });
				await fsp.rm(rekeyJournalPath(abs), { force: true });
			}
			throw e;
		} finally { if (beat) clearInterval(beat); await Rclone.removeConfig(cfg); await Rclone.removeConfig(cfgNew); }
	}));
}

// Build the ephemeral CONFIG TEXT for a vault from a passphrase entered now. This runs
// the (deliberately expensive) key-derivation stage, so callers that need several config
// files for one operation derive the text ONCE and write each file from it. Pass the
// manifest to avoid re-reading it. For a key-wrapping vault a wrong password fails here,
// when the master key won't unwrap.
// The crypt-remote options derived from a manifest — the ONE place that maps manifest.crypt to the engine's
// crypt fields, so every config-building site (mount, list, audit, snapshot, versions, mirror, rotate) stays
// consistent, including the immutable filename_encoding. Add a new crypt-config field here once, not at each site.
function cryptOptsOf(manifest, passwordObscured) {
	const c = (manifest && manifest.crypt) || {};
	return { passwordObscured, saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption, filenameEncoding: c.filename_encoding };
}
// Backends reached through a browser OAuth grant (they store a refresh token), so "Connect account" applies
// rather than an API key. The token write-back lifecycle only matters for those that ROTATE the refresh token.
const OAUTH_BACKENDS = new Set(['drive', 'onedrive', 'dropbox', 'box', 'pcloud', 'yandex', 'jottacloud', 'hidrive', 'sharefile', 'premiumizeme', 'gphotos', 'opendrive']);
const ROTATING_TOKEN_BACKENDS = new Set(['onedrive']); // Microsoft rotates the refresh token on every refresh; Drive/Dropbox do not
function isOAuthBackend(type) { return OAUTH_BACKENDS.has(String(type || '').toLowerCase()); }
// Backends that count filename length in UTF-16 code units, where crypt's default base32 name encoding blows
// past path limits — use the denser base32768 for those. Chosen once at creation and immutable per vault.
const UTF16_BACKENDS = new Set(['onedrive', 'dropbox', 'box', 'sharefile', 'pcloud']);
function cloudFilenameEncoding(type) { return UTF16_BACKENDS.has(String(type || '').toLowerCase()) ? 'base32768' : undefined; }
async function buildConfigText(bin, vaultDir, password, manifest, master) {
	manifest = manifest || await readManifest(vaultDir);
	// A caller that also needs the tamper-detection keys derives the master ONCE and passes it in,
	// so the deliberately expensive key derivation runs a single time per operation.
	const passwordObscured = await Rclone.obscure(bin, master || await enginePassword(password, manifest));
	const cryptOpts = cryptOptsOf(manifest, passwordObscured);
	// A CLOUD vault's store lives on a remote backend, so its config has TWO sections: the backend, and a
	// crypt layer wrapping "backend:<path>". A LOCAL vault wraps its own data/ directory. Everything downstream
	// (list, search, audit, snapshot, mount) reaches the store through this one function, so both work the same.
	const cloud = await cloudCryptTargetText(bin, manifest);
	if (cloud) return cloud.backendText + Rclone.cryptRemoteSection('vault', { cipherDir: cloud.remoteSpec, ...cryptOpts });
	return Rclone.buildConfig({ cipherDir: cipherDirOf(vaultDir), ...cryptOpts });
}

// Build an ephemeral config FILE for a vault from a passphrase entered now (or a pre-derived master).
async function configFor(bin, vaultDir, password, manifest, master) {
	return Rclone.writeEphemeralConfig(await buildConfigText(bin, vaultDir, password, manifest, master));
}

// Acquire an ephemeral engine config for a vault, run fn(cfg), and ALWAYS remove the config after —
// so the short-lived file holding the obscured secret can never leak on an error path. The
// per-caller password check and result shaping stay inside fn; this owns only acquire/release.
async function withVaultConfig(bin, vaultDir, password, manifest, master, fn) {
	const cfg = await configFor(bin, vaultDir, password, manifest, master);
	try { return await fn(cfg); } finally { await Rclone.removeConfig(cfg); }
}

// Verify a password by reading the canary token back through the encryption. Returns true
// only if it decrypts to the expected value. For a key-wrapping vault (format 3+) the
// password was ALREADY proven by unwrapping the master key when the config was built, so
// a missing or altered canary must not lock the user out — we treat it as verified and
// best-effort restore the canary. A genuine wrong password never reaches here: it fails
// earlier when the master key won't unwrap. For legacy vaults the canary IS the check.
async function verifyPassword(bin, cfg, manifest, { readOnly = false } = {}) {
	const r = await Rclone.run(bin, ['cat', 'vault:' + CANARY_NAME], { configPath: cfg, maxOutBytes: 65536 }); // the canary is a tiny fixed token; cap the read so a remote can't stream a huge object during unlock
	if (r.status === 0 && r.stdout === CANARY_TOKEN) return true;
	// The canary did not read back. Only a READ-WRITE unlock may establish or repair it — a read-only
	// credential (a read-only password or a read capability) must NEVER write into the store, and a
	// read capability that does not match this vault must fail CLOSED (return false) rather than mount
	// a garbage drive and plant a foreign canary blob that a later audit would flag as tampering.
	if (!readOnly && hasKeyWrapping(manifest.crypt)) {
		try { await Rclone.run(bin, ['rcat', 'vault:' + CANARY_NAME], { configPath: cfg, input: CANARY_TOKEN }); } catch (_) {}
		return true;
	}
	return false;
}

// Serialize the whole of mountImpl so choosing a mount point and recording it in state is
// atomic: two concurrent mount() calls can never pick the same path and untrack each other.
// This also serializes the pre-mount tamper scan (bounded by AUTO_SCAN_TIMEOUT_MS); mounts are
// infrequent and usually one at a time, so mounting several vaults at once runs them in sequence
// rather than in parallel — an accepted trade for the simpler, race-free establishment. The end
// state (several vaults mounted at once) is unaffected.
const withMountLock = Common.serialQueue(); // serialize mount establishment (shared serial-queue contract)

// RAM-cache directories being provisioned RIGHT NOW, before their mount reaches the state file.
// The orphan sweep excludes these so it can never eject a cache out from under an in-progress mount
// (mount is serialized, but sweep/repair are not).
const provisioningCacheDirs = new Set();
// pack/unpack/disperse/reconstruct temp paths (under the OS temp dir) in use by a live operation right now,
// so the stale-temp sweep never removes one out from under an in-progress import/pack/split.
const activeTemps = new Set();
// Vaults with an in-flight two-way mirror sync (keyed by resolved path). A sync rewrites the vault's cipher
// store in place, so mounting the SAME vault while it runs (or syncing while a mount is being established)
// could read or write half-synced ciphertext. BOTH operations claim this set SYNCHRONOUSLY at entry — no await
// between the check and the add — so the check-and-claim is atomic and there is NO time-of-check/time-of-use
// window in which a mount and a sync of the same vault could both slip through.
const vaultBusy = new Set();

// Run fn() while holding an EXCLUSIVE claim on a vault, so a mount / mirror / backup / pack / recovery-refresh of
// the same vault can never overlap and rewrite its cipher store concurrently. The invariant that makes the claim
// atomic lives here in ONE place: the has()-check and add() must run with NO await between them (a point-in-time
// assertUnmounted alone is not enough — another operation could slip in during a later await), and the claim is
// always released in finally. `busyMsg` names the operations that actually conflict, so the thrown error is
// specific to each caller. Non-reentrant by design: an accidental nested claim throws rather than deadlocking.
async function withVaultBusy(abs, busyMsg, fn) {
	if (vaultBusy.has(abs)) throw new Error(busyMsg);
	vaultBusy.add(abs); // synchronous with the check above — this is the atomic claim
	try { return await fn(); } finally { vaultBusy.delete(abs); }
}

// A CROSS-PROCESS advisory lock for manifest MUTATIONS (changing a password or key slot, or a team-membership
// change). `vaultBusy` above is in-memory and so only serializes operations inside ONE process; a CLI command
// and the background service are separate processes, and `persistManifest` rewrites the whole file, so without
// this lock a slot change made in one process could silently clobber a slot change made in the other (a revoked
// key resurrected, or an added key lost). The lock file lives under the app data dir keyed by the vault path,
// so it is per-machine (the realistic race) and never travels into a mirror or backup.
//
// It is crash-safe and can never wedge a vault. The lock is a small HEARTBEATED LEASE: while it is held its
// timestamp is refreshed periodically, so a lock whose timestamp has gone stale belongs to a crashed holder and
// is reclaimed. A live operation — however long it runs — keeps refreshing, so it is never stolen. On this
// machine a holder whose pid is gone is reclaimed at once (a fast path); a stale timestamp is the backstop that
// also covers a reused pid or another machine. Acquisition and reclaim are ATOMIC (O_EXCL create; a reclaim
// renames the stale file aside so only one racer wins and a fresh lock is never removed), and release removes
// only our OWN lock (identified by a random nonce). A caller that cannot get the lock within a short wait fails
// fast with a clear "busy" message rather than blocking. Not reentrant: no locked mutator calls another while
// holding it.
// The vault lock is the shared cross-process file lock (lib/FileLock.js) keyed by the vault's own lock file, PLUS an
// in-memory lease fence: while this process holds the lock it records the nonce, so a manifest write made under the
// lock can confirm it still owns the lease (assertStillHoldLease) and abort cleanly if the lock was stolen mid-op
// (a long event-loop stall past the TTL). The lock file name is derived from the vault path, so the CLI and the
// service serialize on the same file.
function vaultLockPath(abs) {
	const h = vaultDirTag(abs);
	return path.join(Common.dataDir(), 'locks', h + '.lock');
}
// The lease this process currently holds for each vault (resolved path -> nonce), used by the persist FENCE
// (assertStillHoldLease) so a manifest write under the lock aborts cleanly if the lease was lost mid-operation.
const heldLeases = new Map();
// The persist fence: throw if this process no longer owns the lease it took for `abs`. A no-op for writes not
// made under the lock (no heldLeases entry).
async function assertStillHoldLease(abs) {
	const want = heldLeases.get(resolveVaultDir(abs));
	if (!want) return;
	const cur = await FileLock.readHolder(vaultLockPath(abs));
	if (!cur || cur.nonce !== want) { const e = new Error('This vault was changed by another operation while your change was being prepared. Reload the vault and try again.'); e.code = 'LEASE_LOST'; throw e; }
}
async function withVaultLock(abs, fn) {
	abs = resolveVaultDir(abs);
	const { p, nonce } = await FileLock.acquire(vaultLockPath(abs));
	heldLeases.set(abs, nonce);
	// Refresh the lease while it is held, so a long operation (a whole rotation) is never judged stale and stolen.
	// Best-effort and unref'd so it never keeps the process alive; a fast mutator finishes before the first beat,
	// so it writes nothing extra. Even if a refresh is missed (a long event-loop stall) and the lease is stolen,
	// the persist fence turns the resulting double-mutation into a clean abort rather than a clobber.
	const beat = setInterval(() => { FileLock.refresh(p, nonce); }, FileLock.BEAT_MS);
	if (beat.unref) beat.unref();
	try { return await fn(); }
	finally {
		clearInterval(beat);
		heldLeases.delete(abs);
		await FileLock.release(p, nonce); // removes the lock file only if it is still ours (a reclaimed one has a new nonce)
	}
}

// Per-session tamper-detection signing material, held in memory ONLY while a vault is mounted
// (mountpoint -> { cfgText, key }). It lets a clean unmount refresh the vault's baseline to the
// settled post-session state without re-prompting for the password. Set at mount, deleted at
// unmount; never written to disk. A cross-process unmount simply finds no entry and skips the
// refresh — the baseline still updates on the next clean unmount done in-process.
const sessionKeys = new Map();

// The trust outcome of each vault's most recently ENDED session (resolved path -> { trusted, at }). A session
// is "trusted" only when the on-mount tamper check found the vault consistent with its baseline (a normal
// mount/edit/unmount) — the SAME signal that decides whether the tamper baseline may refresh. The recovery
// auto-refresh consults this so it NEVER rebuilds parity over a vault that changed AT REST (files moved out,
// truncated, corrupted) or a forced teardown, which would bake the loss/damage in and destroy recoverability.
const recentSessionTrust = new Map();
const RECENT_SESSION_MS = 15 * 60 * 1000;
// Whether each vault's most recent trusted session changed its REAL content (vs only OS metadata like
// .DS_Store / ._* churning). Derived from the tamper baseline's merkle root, which is computed over the
// junk-filtered file set — so this is the safe, content-based way to tell "the user actually edited something"
// from "macOS/Windows wrote a hidden file". The recovery auto-refresh skips a rebuild when nothing real changed.
const recentRealChange = new Map();
// Drop expired entries from both maps on the periodic sweep. A session-trust entry holds an Ed25519 signing key
// that takeRecentSigner nulls on first use, but nothing consumes it when a vault has no recovery configured — so
// without this the key bytes would linger in the long-running service, and either map would grow one entry per
// distinct vault path ever mounted. Deleting during a Map for-of is well-defined.
function pruneRecentMaps(now = Date.now()) {
	for (const [k, v] of recentSessionTrust) if (!v || (now - v.at) >= RECENT_SESSION_MS) { if (v) v.signPriv = null; recentSessionTrust.delete(k); }
	for (const [k, v] of recentRealChange) if (!v || (now - v.at) >= RECENT_SESSION_MS) recentRealChange.delete(k);
}

// Mount a vault as a real-time drive. Returns { mountpoint, pid, volname }.
function mount(vaultDir, opts = {}) { return withMountLock(() => mountImpl(vaultDir, opts)); }

// Claim the vault EXCLUSIVELY (against a concurrent mirror sync) before any mount work, holding it until the
// mount is committed to state and returns — so a mount and a sync of the same vault can never rewrite the store
// under each other.
async function mountImpl(vaultDir, opts = {}) {
	const abs = resolveVaultDir(vaultDir);
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount or a mirror sync). Wait for it to finish, then try again.', () => mountImplInner(vaultDir, opts));
}

async function mountImplInner(vaultDir, opts = {}) {
	const { password } = opts;
	if (!password && !opts.readCap && !opts.memberKey) throw new Error('A password (or a read capability, or a member key) is required to mount a vault.');
	const abs = resolveVaultDir(vaultDir);
	// For a decoy redirect, `abs` is the DECOY vault actually being opened, but the mount must PRESENT as the
	// real vault so nothing — the state file, `status`, the web poll, the return value — reveals the pairing.
	// So the externally visible identity is `presentVault` (the real vault when redirected, else the vault
	// itself), while everything that touches the cipher store, keys, and teardown uses the real backing `abs`.
	const presentVault = opts._presentAs ? resolveVaultDir(opts._presentAs) : abs;
	// Finish or roll back an interrupted key rotation before opening — but ONLY if one is actually staged. The
	// common mount (no rotation pending) skips the lock entirely, so it never queues behind another vault's
	// mutation and never pays the acquire cost. When staged state DOES exist, the forced resume bypasses the
	// rotation heartbeat, so it runs under the lock: if a rotation is actively running in another process, we wait
	// briefly and then refuse rather than deleting or double-committing its staged store.
	if (await rekeyPending(abs)) {
		try { await withVaultLock(abs, () => resumeRekey(abs, { force: true }).catch(() => {})); }
		catch (e) { if (e && e.code === 'VAULT_LOCKED') throw new Error('This vault is busy with a key change or rotation in another window. Wait for it to finish, then mount it.'); }
	}
	const manifest = await readManifest(abs); // throws clearly if there is no vault here

	const driver = await Driver.detect();
	if (!driver.ok) { const e = new Error('Mount driver missing: ' + driver.detail); e.install = driver.install; throw e; }

	await Rclone.sweepStaleConfigs();
	await pruneDeadMounts();

	// Single instance: if this vault is already mounted and live, return that mount
	// rather than starting a second one against the same backing folder (which would
	// race). pruneDeadMounts above has already cleared any stale record.
	const existing = await liveMountFor(abs);
	if (existing && (await Rclone.isMounted(existing.mountpoint))) {
		return { vault: abs, mountpoint: existing.mountpoint, pid: existing.pid, volname: existing.volname, already: true };
	}

	const bin = await ensureEngine();
	const name = displayName(abs);
	const preferred = opts.mountpoint ? normalizeMountpoint(opts.mountpoint) : path.join(defaultMountRoot(), name);
	const volname = opts.volname || name;
	// Resolve the cache mode. The DEFAULT is 'writes': files opened for writing are buffered so
	// in-place writes work — an app editing a file, and the small sidecar files an OS writes when
	// it opens media — while reads (including media playback) still stream and are never cached. A
	// 'working disk' ('full') also buffers reads, for heavy random read+write (databases, VM/disk
	// images). Both keep that buffer in a RAM-backed directory (provisioned below, once the password
	// is confirmed), so NOTHING decrypted ever reaches the persistent disk. 'streaming' ('off')
	// caches nothing at all — the lightest footprint, but it cannot do in-place writes. An explicit
	// --vfs-cache-mode or --cache-dir overrides. Per-MOUNT, so different vaults can run in different
	// modes at once.
	// Fall back to this vault's REMEMBERED mount preferences for any option the caller left unset — the
	// cache mode (working disk / streaming) and the FUSE-T backend — so a choice made once (e.g. "use
	// the SMB backend so large copies don't hit the driver's I/O error") sticks on every later mount
	// without re-choosing. An explicit flag or checkbox always wins (it is a real value, not undefined).
	try {
		const noCacheChoice = opts.vfsCacheMode == null && opts.workingDisk == null && opts.streaming == null;
		if (noCacheChoice || opts.fuseBackend == null) {
			const pref = ((await getSettings()).mountPrefs || {})[abs];
			if (pref) {
				if (noCacheChoice) { if (pref.workingDisk) opts = { ...opts, workingDisk: true }; else if (pref.streaming) opts = { ...opts, streaming: true }; }
				if (opts.fuseBackend == null && pref.fuseBackend) opts = { ...opts, fuseBackend: pref.fuseBackend };
			}
		}
	} catch (_) {}
	// An explicit cache mode must be one the engine accepts; reject anything else up front with a clear message
	// rather than forwarding it to --vfs-cache-mode and failing with an opaque engine error (same input-hardening
	// as the fuseBackend sanitize just below and the security-level/tier checks elsewhere).
	if (opts.vfsCacheMode != null && !['off', 'minimal', 'writes', 'full'].includes(opts.vfsCacheMode)) throw new Error('Unknown cache mode "' + opts.vfsCacheMode + '". Choose one of: off, minimal, writes, full.');
	let cacheMode = opts.vfsCacheMode || (opts.streaming ? 'off' : (opts.workingDisk ? 'full' : 'writes'));
	const fuseBackend = opts.fuseBackend === 'smb' ? 'smb' : null; // sanitize: only the SMB alternative is offered
	let cacheDir = opts.cacheDir ? path.resolve(opts.cacheDir) : null;
	let ramCache = null; // handle to a RAM disk we created for this mount's cache, released on unmount
	let ramDowngraded = false; // the user asked for a working disk but no RAM disk could be provisioned (fell back to streaming)

	// Derive the engine secret (the master key) ONCE: the config text is built from it AND the
	// tamper-detection signing key comes from the same secret, so the deliberately expensive
	// key-derivation runs a single time and each mount attempt writes a fresh short-lived config
	// from it. For a key-wrapping vault a wrong password fails right here, when the master won't unwrap.
	// Unlock either with a secret (a read-write or read-only password/keyfile) or with a shared read
	// capability token, which grants read-only access to a copy of the vault with no password.
	let cred = null, unlockErr = null;
	if (opts.readCap) cred = readCapCredential(opts.readCap, manifest);
	else if (opts.memberKey) {
		// A team member unlocks with their own private key, which opens their sealed member slot (read-only or
		// read-write per their role). No password and no decoy path — a member key either opens a member slot or
		// it does not.
		cred = await unlockByMemberKey(opts.memberKey, manifest);
		if (!cred) { throw wrongPasswordError('This member key does not open this vault.'); }
	}
	else if (opts._cred) {
		// Internal only: a decoy redirect (below) already derived and verified this credential against the decoy's
		// manifest during its openability probe. Reuse it so the expensive key derivation is not run a second time
		// on re-entry — which also narrows the timing gap between opening a decoy and opening a vault normally.
		cred = opts._cred;
	}
	else {
		try { cred = await unlockCredential(password, manifest); } catch (e) { unlockErr = e; }
		if (!cred) {
			// The password does not open THIS vault. If a decoy is paired with it and this password triggers the
			// pairing, transparently open the paired decoy vault instead — the honest per-vault duress path. This
			// is consulted ONLY on a failed unlock and ONLY when a decoy registry exists, so a vault with no decoy
			// pays nothing. The decoy is presented under this vault's name and mount point, so opening it looks
			// exactly like opening the real vault. `_decoyRedirected` stops any further redirect (no recursion).
			if (!opts._decoyRedirected && Decoy.hasRegistry()) {
				const decoyDir = await Decoy.resolveDecoy(abs, password).catch(() => null);
				// Redirect ONLY to a decoy that is actually present and opens with this password. A vault runs in
				// place and can be moved, so a decoy that was moved or removed since pairing would otherwise make the
				// mount throw a distinctive error — the one failure a duress path must avoid, since it reveals to a
				// compelled observer that a pairing existed. If the decoy is not openable, fall through silently to
				// the normal wrong-password path, so a stale pairing looks exactly like a mistyped password.
				if (decoyDir) {
					const decoyManifest = await readManifest(decoyDir).catch(() => null);
					// Probe that the decoy actually opens with this password BEFORE redirecting, so a moved/stale decoy
					// falls through silently to the wrong-password path (never a distinctive error that would reveal a
					// pairing existed). Carry the verified credential into the re-entry via _cred so the derivation is
					// not repeated there.
					const decoyCred = decoyManifest ? await unlockCredential(password, decoyManifest).catch(() => null) : null;
					if (decoyCred) {
						// Call mountImpl, NOT mount: we are already inside the mount serial queue (withMountLock), and
						// re-entering it would deadlock. mountImpl still takes the decoy vault's own busy claim.
						return mountImpl(decoyDir, { ...opts, _decoyRedirected: true, _cred: decoyCred, _presentAs: abs, mountpoint: preferred, volname });
					}
				}
			}
			throw unlockErr || wrongPasswordError();
		}
	}
	const master = cred.master;
	const cfgText = await buildConfigText(bin, abs, password, manifest, master);
	const keys = hasKeyWrapping(manifest.crypt) ? integrityKeys(master, cred.writeSeed, manifest) : null;
	// A read-only credential (no write seed) mounts READ-ONLY: it can never issue an authentic write, so
	// the drive is presented read-only and the baseline is only verified, never re-signed.
	const readOnlyCred = hasKeyWrapping(manifest.crypt) && !cred.writeSeed;
	if (readOnlyCred) opts = { ...opts, readOnly: true };

	// Wrong password is caught clearly BEFORE we launch the mount, by verifying the
	// canary token decrypts. This works even on an empty vault.
	const probeCfg = await Rclone.writeEphemeralConfig(cfgText);
	try {
		if (!(await verifyPassword(bin, probeCfg, manifest, { readOnly: readOnlyCred }))) throw opts.readCap ? new Error('This read capability does not match this vault.') : wrongPasswordError();
	} finally { await Rclone.removeConfig(probeCfg); }

	// If this vault is mirrored, claim the cross-machine write lease before mounting for writing, so
	// two machines don't edit it at once. Advisory and best-effort: a read-only or forced mount skips
	// it, and any trouble reaching the destination just proceeds — it can never block a mount except
	// by the deliberate "in use elsewhere" refusal, which force or a read-only mount overrides.
	await claimLeaseForMount(abs, opts);

	// Automatic tamper detection — best-effort, and NEVER able to block or fail a mount. On a
	// vault that has a baseline, compare the settled on-disk state to it and surface any change
	// while it was not in use; on a vault without one, establish a fast baseline so future
	// mounts can check. Bounded by a timeout so even a very large vault cannot delay the mount.
	let tamper = null;          // change summary to surface to the user (null = nothing to say)
	let baselineTrusted = false; // may the baseline be refreshed on unmount? only for a verified-clean session
	if (keys) {
		try {
			const res = await Common.withTimeout(autoTamperOnMount(bin, cfgText, abs, manifest, keys), 20000);
			tamper = res.warn; baselineTrusted = res.trusted;
		} catch (_) { tamper = null; baselineTrusted = false; } // could not verify -> do not bless the state on unmount
	}
	if (readOnlyCred) baselineTrusted = false; // a read-only mount never re-signs the baseline on unmount

	// Provision the write cache now that the password is confirmed (so a wrong password never
	// creates one). For any mode that caches, put the buffer in RAM so decrypted data never touches
	// the persistent disk. If the caller gave an explicit --cache-dir, honor it as-is (advanced). If
	// no RAM-backed store can be made (e.g. Windows without the RAM-disk driver), fall back to
	// streaming — which also writes nothing to disk, so the guarantee holds either way.
	if (cacheMode !== 'off') {
		// Guarded because this runs AFTER the write lease is claimed but BEFORE the mount-attempt try below that
		// releases it on failure. A throw here (a hardenDir/mkdir error, or after a RAM disk was provisioned) would
		// otherwise unwind with the lease still held — blocking another machine's write-mount for the full TTL —
		// and with the RAM disk (holding cleartext) leaked. So release both here on any failure, then rethrow,
		// exactly as the mount-attempt catch below does for a later failure.
		try {
			if (cacheDir) {
				await fsp.mkdir(cacheDir, { recursive: true, mode: 0o700 });
				await Common.hardenDir(cacheDir);
			} else {
				ramCache = await RamCache.provision(crypto.randomBytes(6).toString('hex'), { cacheSizeMB: opts.cacheSizeMB });
				if (ramCache) {
					cacheDir = ramCache.dir;
					provisioningCacheDirs.add(cacheDir); // shield it from the orphan sweep until it reaches the state file
					await Common.hardenDir(cacheDir);    // owner-only; the RAM buffer holds cleartext
				} else {
					// No RAM disk could be provisioned (e.g. Windows without ImDisk). Stay safe with streaming — nothing
					// is ever written decrypted to disk either way — but if the user actually ASKED for a working disk
					// (in-place editing / smooth media scrubbing), record that we could not honor it, so the mount
					// result can tell them plainly instead of silently degrading.
					cacheMode = 'off';
					if (opts.workingDisk) ramDowngraded = true;
				}
			}
		} catch (e) {
			if (ramCache) { provisioningCacheDirs.delete(ramCache.dir); try { await RamCache.release(ramCache); } catch (_) {} }
			try { await Common.withTimeout(releaseLease(abs), 20000); } catch (_) {}
			throw e;
		}
	}

	// A rotating-token cloud backend (OneDrive) issues a new refresh token mid-session, so on unmount we harvest
	// the engine's current in-memory token via config/get — a "sensitive" rc command that needs the rc server to
	// permit it. Flag the mount so its (owner-only) unix-socket control endpoint is started with --rc-no-auth;
	// the Windows loopback endpoint already carries auth. Computed once here (a settings read) and reused.
	const rotatesToken = await cloudVaultRotatesToken(manifest).catch(() => false);

	// The log file created by each attempt, so the transient ones can be removed once a
	// mount ultimately succeeds (only the live mount's log is kept, and it is removed on
	// unmount) — otherwise the run folder accumulates a log per attempt forever.
	const attemptLogs = [];

	// One mount attempt at a given mount point: launch the engine, wait for the
	// volume to go live, and always delete the ephemeral config afterwards. Returns
	// { pid, rcSocket, mountpoint, logFile } on success or { error } with the log tail.
	async function attemptMount(mp) {
		// Create the parent for a directory mount point. A drive-letter target (Windows)
		// has no creatable parent — path.dirname("X:\\") is "X:\\" itself — so skip it.
		if (!isDriveLetter(mp)) await boundedMountFs(fsp.mkdir(path.dirname(mp), { recursive: true }), mp);
		// The Windows driver creates the mount point itself and requires the leaf to
		// NOT already exist; the macOS/Linux drivers mount over an existing empty dir.
		if (process.platform !== 'win32') {
			await boundedMountFs(fsp.mkdir(mp, { recursive: true }), mp);
			// The FUSE driver refuses to mount over a non-empty folder, and macOS/Windows
			// routinely drop a .DS_Store / desktop.ini into an unmounted folder between
			// sessions. Remove only that OS junk so a real remount at the same path works.
			await cleanMountpointJunk(mp);
		}
		// A previous ungraceful exit on Windows can leave the empty mount directory behind,
		// which the driver then refuses to mount onto. Clear any OS junk first, then rmdir
		// (which removes only an empty dir, so it never touches real data).
		else if (!isDriveLetter(mp)) { await cleanMountpointJunk(mp); try { await fsp.rmdir(mp); } catch (_) {} }
		const cfg = await Rclone.writeEphemeralConfig(cfgText);
		try {
		const rcSocket = await Rclone.rcSocketPath(); // owner-only unix socket for this mount's control endpoint (null on Windows)
		// On Windows there is no unix socket, so use a loopback TCP control endpoint instead — but only for a
		// CACHING mount, which is the only one with a write-back queue to drain (streaming has none). This is what
		// lets a Windows unmount wait for the flush like macOS/Linux, closing the truncation gap.
		const rcTcp = (process.platform === 'win32' && cacheMode !== 'off') ? await Rclone.rcTcpEndpoint() : null;
		const { pid, logFile } = await Rclone.spawnMount(bin, {
			configPath: cfg, mountpoint: mp, volname, rcSocket, rcTcp,
			readOnly: !!opts.readOnly,
			rcNoAuth: rotatesToken, // permit the config/get token harvest on the owner-only unix socket (rotating cloud only)
			cloud: isCloudVault(manifest), // add cloud-reliability flags (retries/timeouts/chunking) for a remote store
			vfsCacheMode: cacheMode,
			cacheDir,
			vfsWriteBack: opts.vfsWriteBack, // let callers/tests tune write-back; spawnMount picks the default
			// On a RAM disk the cache is small, so evict aggressively: an already-flushed file left in
			// the cache is dead weight that can fill the disk during a burst of copies and make the
			// next write fail. A short max-age + frequent poll keep the cache to roughly what is
			// in-flight, so copying many large files in a row — or one large file — succeeds. (Only
			// clean, already-uploaded items are ever evicted, so this is safe.) On an explicit on-disk
			// cache there is no such pressure, so the engine's relaxed defaults are kept.
			vfsCacheMaxAge: opts.vfsCacheMaxAge || (ramCache ? '5s' : undefined),
			vfsCachePollInterval: opts.vfsCachePollInterval || (ramCache ? '2s' : undefined),
			// Also bound the cache to the RAM disk as a backstop so it can never physically fill.
			vfsCacheMaxSize: opts.vfsCacheMaxSize || (ramCache ? Math.max(64, Math.floor(ramCache.sizeMB * 0.9)) + 'M' : undefined),
			fusetLib: driver.fusetLib, // macOS: select FUSE-T for this engine process (macFUSE left intact)
			fuseBackend, // macOS/FUSE-T: optional 'smb' transport instead of the default NFS (large-write reliability)
			// Present every file as owned by the CURRENT USER by default, so a personal vault
			// is always fully yours to manage — otherwise items copied from a root-owned source
			// (an app in /Applications, a system folder) would appear owned by root and the
			// Finder would refuse to delete or move them ("No Access"). An explicit uid/gid
			// still overrides this.
			//
			// --metadata is OFF by default on every platform, and it is safe to leave off:
			// it does NOT change the encrypted on-disk format, and each file's CONTENTS, its
			// encrypted NAME, and its MODIFICATION TIME are preserved without it (mod-time is a
			// core attribute the engine always sets, not part of this flag). All it adds is
			// restoring each file's Unix MODE, owner, group, and access/creation times — values
			// that are not portable across machines or to Windows anyway, so dropping them keeps
			// a vault fully interchangeable between macOS, Linux and Windows. Turning it on also
			// forces an extra per-file metadata round-trip on every operation, which on macOS the
			// Finder and its preview generation drive so hard over the FUSE-T/NFS path that the
			// volume can stall for minutes. Leaving it off keeps the volume responsive at no cost
			// to portability. A caller that specifically wants mode/ownership preserved (e.g. to
			// keep executable bits on a Linux-only vault) can opt in with { metadata: true }.
			metadata: opts.metadata === true,
			defaultPermissions: opts.defaultPermissions !== false,
			allowOther: !!opts.allowOther,
			filePerms: opts.filePerms,
			dirPerms: opts.dirPerms,
			uid: opts.uid != null ? opts.uid : (process.platform !== 'win32' ? process.getuid() : undefined),
			gid: opts.gid != null ? opts.gid : (process.platform !== 'win32' ? process.getgid() : undefined)
		});
		attemptLogs.push(logFile);
		const outcome = await Rclone.waitForMountOrExit(mp, pid, opts.timeoutMs || 15000);
		if (outcome === 'mounted') {
			if (rcSocket) { try { await fsp.chmod(rcSocket, 0o700); } catch (_) {} } // make the control socket owner-only
			// Learn the port the engine actually bound its rc server to (it chose a free one), so the unmount drain
			// can reach it. If the line isn't found, rcTcp has no addr and the drain simply falls back to the settle.
			if (rcTcp) { const addr = await Rclone.parseRcPort(logFile); if (addr) rcTcp.addr = addr; }
			return { pid, rcSocket, rcTcp, mountpoint: mp, logFile };
		}
		await killPid(pid, 'SIGKILL'); // route through the platform-correct kill
		let tail = '';
		try { tail = (await fsp.readFile(logFile, 'utf8')).split(/\r?\n/).filter(Boolean).slice(-6).join('\n'); } catch (_) {}
		return { error: tail || 'unknown error', outcome };
		} finally { await Rclone.removeConfig(cfg); } // rclone has read it by now (or the spawn failed) — the secret must never linger on disk
	}

	// After a recent unmount the kernel driver can briefly report the previous mount
	// point or device as busy. Rather than fight that race, we retry the preferred
	// path a couple of times and then fall back to a fresh, uniquely named mount
	// point, which the driver accepts immediately — so a mount always succeeds
	// quickly. The actual mount point used is returned to the caller.
	let mp, res;
	try {
		// Pick a path not already claimed by another mount BEFORE attempting, so a second vault
		// never mounts over (and untracks) a different vault already at the default path. Inside the
		// try so a failure here (e.g. no free path) still releases the RAM disk we just provisioned.
		mp = await freeMountpoint(preferred);
		res = await attemptMount(mp);
		// A just-released FUSE device can briefly report "busy" (macFUSE error 16) while the
		// previous mount finishes tearing down — common in the seconds right after the app
		// restarts, when the prior session's engine is still exiting. Retry patiently with an
		// escalating wait, keeping the SAME path so it lands on the normal mount point once the
		// device frees. Only after a few tries fall back to a fresh, uniquely named path, for
		// the case where the path itself is genuinely occupied (a leftover/stale mount, a
		// non-empty leaf, or another vault of the same name).
		const BUSY = /busy|error 16|already exists|not empty|not connected|transport endpoint/i;
		for (let attempt = 1; res.error && attempt <= 6; attempt++) {
			await Common.sleep(Math.min(600 + attempt * 700, 3500));
			if (BUSY.test(res.error) && attempt >= 3 && !isDriveLetter(preferred)) mp = await freeMountpoint(preferred);
			res = await attemptMount(mp);
		}
		if (res.error) throw new Error('The volume did not mount. Run "' + Brand.cli + ' doctor" to check the engine and the mount driver, then try again.\n' + res.error);
	} catch (e) {
		if (ramCache) provisioningCacheDirs.delete(ramCache.dir);
		await RamCache.release(ramCache); // never leak a RAM disk when the mount fails
		// Release the cross-machine write lease we claimed above: the mount never entered state, so this machine
		// will not heartbeat it, and without this release another machine would see an active lease and be
		// refused a write-mount for the full TTL. Best-effort and bounded, exactly like the unmount release.
		try { await Common.withTimeout(releaseLease(abs), 20000); } catch (_) {}
		throw e;
	}

	// The mount succeeded: remove the logs from any transient failed attempts, keeping
	// only the live mount's log (which unmount removes) so the run folder stays tidy.
	for (const lf of attemptLogs) { if (lf !== res.logFile) { try { await fsp.unlink(lf); } catch (_) {} } }
	try {
		await State.add({ vault: presentVault, mountpoint: res.mountpoint, pid: res.pid, rcSocket: res.rcSocket, rcTcp: res.rcTcp, image: path.basename(bin), volname, cacheDir, ramCache, cacheMode, logFile: res.logFile, owner: opts.owner || 'cli', since: new Date().toISOString() });
	} catch (addErr) {
		// The mount is LIVE but could not be RECORDED (e.g. an unwritable state file). An untracked mount would
		// be a decrypted volume nothing owns — never unmounted on exit, its RAM disk leaked. Tear it down so the
		// failure leaves nothing exposed, then surface the error. Best-effort; each step is independently guarded.
		try { await Rclone.unmount(res.mountpoint, { force: true }); } catch (_) {}
		try { if (res.pid) await killPid(res.pid, 'SIGKILL'); } catch (_) {}
		if (ramCache) { provisioningCacheDirs.delete(ramCache.dir); try { await RamCache.release(ramCache); } catch (_) {} }
		// The mount was torn down and never recorded, so free the write lease too — otherwise it stays held with
		// no heartbeat and blocks another machine's write-mount for the full TTL.
		try { await Common.withTimeout(releaseLease(abs), 20000); } catch (_) {}
		throw addErr;
	}
	if (ramCache) provisioningCacheDirs.delete(ramCache.dir); // now tracked in state; the sweep can see it as in-use
	// Remember the signing key for the unmount refresh, but only mark the baseline refreshable
	// when this session was verified clean — a session that saw tampering must keep the old
	// baseline so a later audit can still show what changed.
	// Hold the real BACKING vault path in memory (never in the state file) so unmount finalizes the store that
	// was actually mounted — the decoy on a redirect — while the state file only ever shows the presented vault.
	if (keys) sessionKeys.set(res.mountpoint, { cfgText, keys, trusted: baselineTrusted, backing: abs });
	healMount(res.mountpoint); // best-effort, non-blocking: clear orphaned FUSE/NFS placeholders
	suppressSpotlight(res.mountpoint, opts.readOnly); // best-effort: keep the system index out of the vault
	refreshContentIndexIfPresent(res.mountpoint, presentVault, opts.readOnly); // best-effort, detached: keep the content-search index current for this session
	// Report the EFFECTIVE read-only state (a read-only password or read-cap forces it on here even when the
	// caller did not ask), so the server gates the cross-machine write-lease heartbeat on what actually
	// mounted — a reader must not publish a held write lease and block a writer on another machine.
	// `redirected` (server-side only; never persisted to state, never sent to the client) tells the caller a decoy
	// redirect happened, so it can suppress the write-lease heartbeat: the heartbeat keys on the PRESENTED vault, but
	// the mounted store is the decoy, so beating would publish a spurious active lease at the REAL vault's mirror
	// destination and could refuse another machine's legitimate write-mount of it. It never reveals the decoy path.
	return { vault: presentVault, mountpoint: res.mountpoint, pid: res.pid, volname, cacheMode, inRam: !!ramCache, ramDowngraded, fuseBackend: fuseBackend || 'nfs', readOnly: !!opts.readOnly, tamper, redirected: !!opts._presentAs };
}

// After a mount goes live, clear orphaned FUSE/NFS "silly-rename" placeholders at the vault
// root: a file deleted while still open is renamed to .fuse_hidden* / .nfs.* until its handle
// closes, and a crash or heavy delete can strand them (they clutter listings and can slow a
// file browser). Best-effort, bounded, and non-blocking so it never delays or fails a mount.
// A no-op on Windows, which has no such placeholders — the patterns simply match nothing.
async function healMount(mp) {
	try {
		const entries = await Common.withTimeout(fsp.readdir(mp), 4000);
		for (const name of entries) {
			if (/^\.fuse_hidden/i.test(name) || /^\.nfs\./i.test(name)) {
				try { await fsp.rm(path.join(mp, name), { force: true }); } catch (_) {}
			}
		}
	} catch (_) {}
}

// Keep macOS Spotlight from indexing a mounted vault. Without this, the system indexer
// can copy decrypted file names, metadata, and text snippets out of the open volume into
// the always-on system-wide index under ~/.Spotlight-V100, where they would persist after
// the vault is locked — defeating the encryption. A zero-byte .metadata_never_index marker
// at the volume root tells Spotlight to skip the whole volume. Written once and kept in the
// vault thereafter; best-effort, bounded, and only when the mount is writable. A no-op on
// other platforms, where the marker means nothing.
async function suppressSpotlight(mp, readOnly) {
	if (process.platform !== 'darwin' || readOnly) return;
	const marker = path.join(mp, '.metadata_never_index');
	try {
		const exists = await Common.withTimeout(fsp.access(marker).then(() => true, () => false), 4000);
		if (!exists) await Common.withTimeout(fsp.writeFile(marker, ''), 4000);
	} catch (_) {}
}

async function killPid(pid, signal = 'SIGTERM') {
	if (!pid) return;
	if (process.platform === 'win32') {
		// A windowless engine process does not act on a soft taskkill, so a graceful signal
		// would just stall for the whole timeout before the force-kill. Windows has no
		// control-socket drain, so unmount() settles briefly first (relying on
		// flush-on-close) and then terminates promptly here.
		try { await Rclone.exec('taskkill', ['/PID', String(pid), '/T', '/F'], { timeoutMs: 10000 }); } catch (_) {} // bound tightly: this runs on the unmount teardown path, which is otherwise 6s-bounded, so a hung taskkill must not stall it for the 60s default
	} else {
		try { process.kill(pid, signal); } catch (_) {}
	}
}

// Wait until a mount point is free (device id back to its parent). Used both during
// unmount teardown and before an immediate remount of the same path (which would
// otherwise hit a transient "device busy" error). Returns true if it was released.
function waitUnmounted(mp, timeoutMs, stepMs = 200) {
	return Common.pollUntil(async () => !(await Rclone.isMounted(mp)), { timeoutMs, stepMs });
}

// Wait until a process id is gone. The mount process holds the kernel device until
// it fully exits, so we must wait for the process — not just the mount table —
// before a remount of the same path can succeed. Returns true if it exited.
function waitPidGone(pid, timeoutMs) {
	if (!pid) return Promise.resolve(true);
	return Common.pollUntil(() => !Common.isProcessAlive(pid), { timeoutMs, stepMs: 100 });
}

// Unmount a vault by mount point or by vault path. Returns { ok, mountpoint }.
//
// GRACEFUL (default): signal the engine to shut down, which flushes its write-back cache to
// the encrypted store and unmounts itself, so no just-written data is lost; only if that does
// not take effect do we ask the OS to unmount, and force-kill as a last resort.
//
// FORCE (opts.force): the override for a stuck or wedged mount. On macOS the mount is a hard
// NFS mount whose server IS the engine process, so if the engine is killed FIRST the kernel is
// left pinned to a dead server and the mount can then only be cleared by a reboot. To make
// recovery always possible in place, a forced teardown force-RELEASES the mount point first —
// while the engine is still alive to answer the unmount — and only then reaps the engine.
// Every OS unmount attempt is strictly time-bounded (in Rclone.unmount), so a single call that
// blocks can never stall recovery. It skips the write-buffer flush, so it can discard writes
// not yet saved; it is only for when a normal unmount cannot complete.
// Mount points whose teardown is in progress. The periodic self-heal skips these so it can never
// race an unmount already running on the same mount (which would double up the force-release).
const unmounting = new Set();
function isUnmounting(mp) { return unmounting.has(path.resolve(mp)); }

async function unmount(target, opts = {}) {
	const entry = await State.find(target);
	const mountpoint = entry ? entry.mountpoint : path.resolve(target);
	unmounting.add(path.resolve(mountpoint));
	try { return await unmountImpl(opts, entry, mountpoint); }
	finally { unmounting.delete(path.resolve(mountpoint)); }
}

async function unmountImpl(opts, entry, mountpoint) {
	// Guarantee durability: drain the write buffer via the mount's control endpoint
	// BEFORE we tear anything down, because a plain unmount or SIGTERM is not
	// guaranteed to flush pending uploads. With writes flushed on close this is usually
	// instant, but the poll-until-empty is what makes it a guarantee. The endpoint is a unix
	// socket on macOS/Linux and a loopback TCP channel on Windows (a brief settle still runs
	// there first, as a fallback for the case the channel is unreachable). A forced unmount
	// skips this — the mount is stuck, so there is nothing to wait for.
	const bin = RcloneSetup.resolve(); // the engine binary — resolved once and reused by the drain and every teardown branch
	let drainedOk = true;
	let engineCrashedDuringDrain = false; // the engine exited on its own during the flush — preserve its on-disk cache (may hold replayable writes)
	// FLUSH before teardown. A caching mount buffers writes, and NO unmount primitive flushes them — an OS
	// unmount, a signal, and rc core/quit all cancel the write-back rather than push it. So we DRAIN the
	// write-back queue first (poll the mount's rc control endpoint — a unix socket on macOS/Linux, a loopback TCP
	// channel on Windows — until it is empty), and only then unmount. This is the durability guarantee: once
	// drained, the data is in the encrypted store, so the platform teardown below (external umount on macOS/Linux,
	// process termination on Windows) is safe. A streaming ('off') vault has no write-back queue, so it is skipped.
	if (!opts.force && entry && entry.cacheMode !== 'off') {
		// A caching mount MUST have a reachable drain channel, or we cannot prove its writes are flushed. If the rc
		// port was not captured at mount (Windows), recover it from the mount log before giving up.
		if (process.platform === 'win32' && entry.rcTcp && !entry.rcTcp.addr && entry.logFile) {
			const addr = await Rclone.parseRcPort(entry.logFile, 6); if (addr) entry.rcTcp.addr = addr;
		}
		const endpoint = entry.rcSocket || (entry.rcTcp && entry.rcTcp.addr ? entry.rcTcp : null);
		if (endpoint && bin) {
			let last = 0;
			const dr = await Rclone.drain(bin, endpoint, entry, 5 * 60 * 1000, () => {
				if (Date.now() - last > 4000) { last = Date.now(); Common.log('Finishing saving buffered changes before unmounting — keep ' + Brand.name + ' running…'); }
			});
			drainedOk = dr !== false;
			// The engine died on its own mid-drain: it did NOT flush cleanly, so preserve an on-disk cache that may
			// still hold replayable closed-but-unuploaded writes (mirrors the crashed-mount cache preservation in
			// pruneDeadMounts). Only matters on Windows, where a dead pid reads as "unmounted" and the wipe below runs.
			engineCrashedDuringDrain = dr === 'engine-gone';
		} else {
			// No reachable control channel for a caching mount: we cannot confirm the write-back is flushed, so we
			// must not tear it down (that could truncate an in-flight write). Treat it as an incomplete flush and
			// defer. In practice unreachable — macOS/Linux always have the unix socket, and the Windows port is
			// captured at mount and re-read from the log above; --force is the escape hatch if a mount is truly stuck.
			drainedOk = false;
		}
		// If it did not drain in time, buffered changes are not yet in the store. Do NOT tear down (that would
		// abandon them) — leave the mount up, reported as still flushing, so the caller retries; --force accepts the loss.
		if (!drainedOk) { Common.warn('Unmount deferred for ' + mountpoint + ': the vault is still saving buffered changes — left mounted so nothing is lost. Try again in a moment, or force-unmount if it is stuck.'); return { ok: false, busy: true, flushing: true, mountpoint, error: 'Still saving buffered changes — nothing is lost. Wait a moment, then unmount again.' }; }
		// The write-back is flushed and the engine is still alive — the one moment to capture a rotated cloud
		// sign-in token before teardown ends the process. Best-effort and fully guarded: a failure never affects
		// the unmount, and a stale token only means reconnecting that cloud account (the vault's keys are local),
		// never data loss. A no-op for a non-rotating backend (Dropbox/Drive) or a local vault.
		if (endpoint && bin && !engineCrashedDuringDrain) { try { await harvestRotatedCloudToken(bin, endpoint, entry, mountpoint); } catch (_) {} }
	}

	// Is the mount still live? On Windows the driver releases the mount as soon as the
	// owning process exits, but it can leave an empty reparse directory behind that a
	// path check would misread as "still mounted" — so key liveness off the process
	// there. Elsewhere the pure-Node mount check is authoritative.
	const live = async () => (process.platform === 'win32'
		? (entry && entry.pid ? Common.isProcessAlive(entry.pid) : await Rclone.isMounted(mountpoint))
		: await Rclone.isMounted(mountpoint));

	// Windows-only graceful stop. There is no OS unmount there, so the engine process ending IS the unmount; asking
	// it to quit over its control channel (core/quit) runs rclone's clean WinFsp teardown and releases the volume,
	// so the next mount does not land on a leftover "Vault (2)" drive that a hard TerminateProcess would leave. The
	// drain above already flushed every buffered write, so the kill fallback that follows is loss-free. No-op when
	// there is no control endpoint (a streaming mount, or a port that could not be recovered). Returns whether the
	// process is now gone. macOS/Linux never call this — core/quit's self-unmount cannot complete on a FUSE-T mount.
	const graceQuitWin = async () => {
		if (process.platform !== 'win32' || !entry || !entry.pid || !(entry.rcTcp && entry.rcTcp.addr)) return false;
		if (!(await live())) return true;
		await Rclone.rcQuit(bin, entry.rcTcp);
		return waitPidGone(entry.pid, 15000);
	};

	if (opts.force) {
		// Release the mount point FIRST, while the engine is still alive, so the kernel is never left pinned to a
		// dead server — the state that needs a reboot on macOS FUSE-T. On Linux the forced release LAZY-detaches
		// even a busy or dead-server mount; on macOS it works while the server still answers; on Windows it is a
		// no-op (the mount ends when the process exits).
		if (await live()) { await Rclone.unmount(mountpoint, { force: true }); await waitUnmounted(mountpoint, 4000, 250); }
		// Now reap the engine — but NEVER by killing a live engine while its FUSE mount is still up on macOS/Linux:
		// on FUSE-T that pins the kernel NFS client to a dead server, an unrecoverable-in-place wedge that forces a
		// reboot. So there we kill only once the mount is confirmed gone (a reap of a lingering process) AND only
		// when it is still OUR engine — engineAlive re-checks identity so a recorded pid the OS has since recycled
		// onto an unrelated process is never SIGKILLed. On Windows the kill IS the unmount (WinFsp drops the mount
		// on process exit), so there we reap while it is still live (or engineAlive). A macOS mount whose server is
		// unresponsive and did not release cannot be recovered in place; we leave it rather than wedge it, and the
		// unmount reports it still stuck.
		const killable = entry && entry.pid && Common.isProcessAlive(entry.pid);
		const okToKill = process.platform === 'win32' ? ((await Rclone.engineAlive(entry)) || (await live())) : ((await Rclone.engineAlive(entry)) && !(await live()));
		if (killable && okToKill) { await killPid(entry.pid, 'SIGKILL'); await waitPidGone(entry.pid, 5000); }
		// A mount can become releasable only once its server has exited — try the force release once more.
		if (await live()) { await Rclone.unmount(mountpoint, { force: true }); await waitUnmounted(mountpoint, 4000, 250); }
	} else if (opts.gentle && process.platform === 'win32') {
		// Windows has no OS-level unmount command, so the graceful-only OS unmount used below is a no-op
		// there — which would leave every "lock" reporting the vault as busy and never actually locking it.
		// The write buffer was already flushed by the settle-and-drain above (a caching mount waits on its
		// loopback control channel until the write-back queue is empty; if it could not, the unmount was
		// already deferred as "flushing" before reaching here), so releasing the mount now means ending the
		// engine process (WinFsp drops the mount on exit). This gentle path is only reached for an EXPLICIT
		// lock (auto-lock skips Windows,
		// because it cannot prove inactivity there), so terminating a vault with an open file is the
		// user's stated intent, not a surprise. Prefer a graceful core/quit (clean WinFsp release, no leftover
		// "Vault (2)" on remount); the drain above already flushed writes, so the SIGKILL fallback is loss-free.
		await graceQuitWin();
		if (entry && entry.pid && (await live()) && (await Rclone.engineAlive(entry))) { await killPid(entry.pid, 'SIGKILL'); await waitPidGone(entry.pid, 5000); }
		if (await live()) return { ok: false, busy: true, mountpoint };
	} else if (opts.gentle) {
		// Auto-lock / panic lock (macOS/Linux): the write buffer was already flushed by the drain
		// above; now ask the OS to unmount, but NEVER signal or force the engine. If the vault is busy
		// (a file is open), the unmount fails cleanly and we leave everything running to try again
		// later — so active use is never interrupted and nothing is lost. The engine exits on its own
		// once its mount is gone.
		if (await live()) { await Rclone.unmount(mountpoint, { gracefulOnly: true }); await waitUnmounted(mountpoint, 4000, 250); }
		if (await live()) return { ok: false, busy: true, mountpoint }; // still in use — leave it mounted, never force
		if (entry && entry.pid) await waitPidGone(entry.pid, 5000);
	} else {
		// Windows first: ask the engine to quit gracefully (clean WinFsp release, no leftover "Vault (2)");
		// a no-op elsewhere and when there is no control endpoint.
		if (await graceQuitWin()) await waitUnmounted(mountpoint, 4000, 250);
		// Only signal the recorded pid while the mount is actually live. If the mount is already
		// gone, there is nothing to tear down and the pid may since have been reused by an
		// unrelated process — so we must not send it a signal.
		if (entry && entry.pid && (await live()) && (await Rclone.engineAlive(entry))) {
			await killPid(entry.pid, 'SIGTERM');           // Unix: triggers rclone's self-unmount and clean exit (the drain above already flushed — the signal only tears down)
			await waitPidGone(entry.pid, 10000);
			await waitUnmounted(mountpoint, 2000, 250);
		}
		if (await live()) {
			await Rclone.unmount(mountpoint);              // ask the OS to unmount (Unix); no-op teardown on Windows
			await waitUnmounted(mountpoint, 6000, 300);
		}
		// Last resort. On WINDOWS terminating the engine IS the unmount (WinFsp drops the mount on exit), so a kill
		// releases a stuck mount there. On macOS/Linux we must NOT kill a live engine while its FUSE mount is still
		// up: on FUSE-T that pins the kernel NFS client to a dead server — a reboot-only wedge. A default unmount
		// that could not release gracefully is left for `--force` (which lazy-detaches on Linux) rather than wedged.
		if (process.platform === 'win32' && entry && entry.pid && (await live()) && (await Rclone.engineAlive(entry))) {
			await killPid(entry.pid, 'SIGKILL');
			await waitPidGone(entry.pid, 5000);
			await waitUnmounted(mountpoint, 3000, 300);
		}
	}

	const stillMounted = await live();
	// After a confirmed unmount, tidy the now-empty mount directory so leftovers don't
	// pile up and a later remount is never refused as "non-empty". Clear any OS junk
	// first; rmdir removes only an empty directory, so this can never delete real data.
	// Limited to our default mount root (plus the leftover reparse dir Windows leaves
	// after a force-kill) — a user-chosen custom mount point is left in place.
	if (!stillMounted) {
		try {
			await cleanMountpointJunk(mountpoint);
			const underDefault = Common.pathWithin(mountpoint, defaultMountRoot());
			if (underDefault || process.platform === 'win32') await fsp.rmdir(mountpoint);
		} catch (_) {}
	}
	// Keep the state entry (and the control socket) if it is somehow STILL mounted, so
	// it remains trackable and lockable; only clean up on a confirmed unmount.
	if (entry && !stillMounted) {
		await State.remove(mountpoint);
		if (entry.rcSocket) { try { await fsp.unlink(entry.rcSocket); } catch (_) {} }
		if (entry.logFile) { try { await fsp.unlink(entry.logFile); } catch (_) {} } // remove this mount's run log
		// Free the RAM disk that held the write cache. It is memory that cannot outlive the mount, so
		// this always runs; the graceful path already drained pending writes before reaching here (a
		// forced teardown deliberately skipped that, and its unflushed writes are lost by definition).
		if (entry.ramCache) await RamCache.release(entry.ramCache);
		// An explicit ON-DISK cache (advanced --cache-dir) is cleared on a normal unmount, but NEVER on a forced
		// one, nor when the engine crashed mid-flush: either way it can hold closed, durably-buffered files a
		// later remount would resume, so wiping it would destroy recoverable data.
		else if (opts.wipeCache && !opts.force && !engineCrashedDuringDrain && entry.cacheDir) { try { await fsp.rm(entry.cacheDir, { recursive: true, force: true }); } catch (_) {} }
	}

	// Wait for the driver to fully release the mount point (device id back to the
	// parent's), then a short settle, so an immediate remount of the same path does not
	// hit a transient "busy" error. On Windows the leftover dir is already gone above.
	if (!stillMounted && process.platform !== 'win32') { await waitUnmounted(mountpoint, 8000); await Common.sleep(400); }

	// Finalize the session on a clean (non-forced) unmount done in the same process that mounted it:
	// refresh the tamper baseline to the settled state (only if this session was trusted — a session
	// that saw tampering must keep the old baseline so a later audit can still show what changed) and
	// clear the session marker so this clean shutdown is not later mistaken for an interrupted one. A
	// forced teardown may leave unflushed writes, so its state is neither re-baselined nor un-marked —
	// which correctly lets the next mount treat it like a crash (an interrupted, acceptable session).
	const sk = sessionKeys.get(mountpoint);
	sessionKeys.delete(mountpoint);
	evictSearchIndexCache(mountpoint); // a locked vault must leave no loaded (plaintext-derived) search index in memory
	// Record this session's trust for the recovery auto-refresh: trusted ONLY on a clean (non-forced) unmount
	// of a session the on-mount tamper check blessed. A forced teardown or an untrusted session (vault changed
	// at rest) is recorded as untrusted so the post-unmount recovery refresh will DEFER instead of baking in.
	// Capture this read-write session's signing key (bounded to the recent window, cleared once used) so the
	// post-unmount recovery refresh can SIGN the rebuilt or current index — the only moment a write-authority key
	// is in hand for that keyless-by-design path. A read-only session carries no signing key, so none is stored.
	// Teardown targets the vault that was ACTUALLY mounted. For a decoy redirect that is the decoy (held in
	// memory as sk.backing, never in the state file); for every normal mount it is just the recorded vault.
	const backingVault = (sk && sk.backing) ? path.resolve(sk.backing) : (entry && entry.vault ? path.resolve(entry.vault) : null);
	if (backingVault) recentSessionTrust.set(backingVault, { trusted: !!(sk && sk.trusted) && !opts.force, at: Date.now(), signPriv: (sk && sk.keys && sk.keys.signPriv) || null });
	if (sk && !stillMounted && !opts.force && backingVault) {
		// Hold the vault while this post-unmount baseline refresh reads the store, so a re-mount racing the unmount
		// cannot smear the baseline. Best-effort and fail-fast (withVaultBusy throws at once if something already
		// claimed it, and it is time-bounded), so it can never delay or wedge the unmount — a busy vault just skips
		// the refresh, which the next clean unmount or mount redoes.
		try { await Common.withTimeout(withVaultBusy(backingVault, 'busy', () => finishSession(backingVault, sk)), 20000); } catch (_) {}
	}

	// Release our cross-machine write lease so another machine can take over (best-effort, bounded —
	// it must never delay or fail an unmount, and only clears a lease we still hold).
	if (!stillMounted && backingVault) { try { await Common.withTimeout(releaseLease(backingVault), 20000); } catch (_) {} }

	return { ok: !stillMounted, mountpoint, vault: entry && entry.vault ? path.resolve(entry.vault) : null, forced: !!opts.force };
}

// Crash recovery / self-heal: reconcile tracked mounts with reality. A mount whose engine
// process has died but that the OS STILL shows mounted is STALE — a dead FUSE mount hangs
// apps like Finder — so we force-release it here rather than leave it stranded (the failure
// the user hit: the engine died under load, the record was dropped, and a hung mount was
// left behind). Then the record, its cache, its log, and the empty mount folder are cleaned.
async function pruneDeadMounts() {
	const mounts = await State.readAll();
	let released = 0; // crashed (dead-engine) mounts reaped here — a signal the service did not shut down cleanly
	for (const m of mounts) {
		if (isUnmounting(m.mountpoint)) continue;    // an unmount is already tearing this one down
		if (await Rclone.engineAlive(m)) continue;   // OUR engine still running -> healthy, leave it
		// The engine is gone (pid dead, or the pid was recycled by an unrelated process — the
		// control-socket check tells the two apart, so a stale record is reaped either way).
		// The engine is dead. On non-Windows, if the OS still shows the mount, force-release
		// it before dropping the record (on Windows the driver releases on process exit).
		if (process.platform !== 'win32' && (await Rclone.isMounted(m.mountpoint))) {
			// The engine (the NFS server) is already gone, so a plain unmount would hang — go
			// straight to the force/lazy release so the kernel drops the dead mount cleanly.
			try { await Rclone.unmount(m.mountpoint, { force: true }); } catch (_) {}
			await waitUnmounted(m.mountpoint, 5000, 300);
		}
		await State.remove(m.mountpoint);
		released++;
		if (m.ramCache) await RamCache.release(m.ramCache);                                  // free the RAM disk of a crashed mount (memory; its contents cannot outlive the crash anyway)
		// Do NOT wipe an on-disk --cache-dir of a CRASHED mount: it can hold closed, durably-buffered files that
		// rclone resumes uploading on the next mount with the SAME --cache-dir. The engine is dead by definition
		// here (engineAlive was false above) and never got to drain, so preserve the cache for that replay
		// rather than destroying recoverable writes — exactly as a forced unmount preserves it.
		if (m.rcSocket) { try { await fsp.unlink(m.rcSocket); } catch (_) {} } // reap the crashed mount's control socket too, like a clean unmount does — nothing sweeps it otherwise
		if (m.logFile) { try { await fsp.unlink(m.logFile); } catch (_) {} }
		try {
			await cleanMountpointJunk(m.mountpoint);
			if (Common.pathWithin(m.mountpoint, defaultMountRoot())) await fsp.rmdir(m.mountpoint);
		} catch (_) {}
	}
	// Reaping a dead-engine mount means the service (or an engine) exited without a clean unmount — usually a crash.
	// The heal itself is silent, so record it (best-effort) for the stale_mount_healed self-check to surface for a
	// day, so a crash that happened while the user was away does not go completely unnoticed.
	if (released > 0) { try { await setSettings({ staleMountAt: new Date().toISOString(), staleMountCount: released }); } catch (_) {} }
}

// ── Import files into a mounted vault (streaming, no OS copy call) ─────────────────────────────
// Copy source files/folders INTO a mounted vault using Node read/write streams — plain read()/write()
// syscalls, never the operating system's copy-file call. This deliberately sidesteps macOS
// Finder/`copyfile`, which some FUSE-T driver versions mishandle for large files (surfacing as a
// "-36" I/O error), and it is the same steady streaming that copies reliably from the command line.
// Fully cross-platform: only Node `fs` streams and `path` joins — no shell, no platform-specific copy
// call, and native path separators throughout. Reports progress by bytes and, per the anti-clobber
// rule, never overwrites an existing file unless `force` is set.
function streamCopyFile(src, dst, { onChunk, flags = 'w' } = {}) {
	return new Promise((resolve, reject) => {
		const rs = fs.createReadStream(src);
		const ws = fs.createWriteStream(dst, { flags }); // 'w' overwrites, 'wx' fails if it already exists
		let settled = false, opened = false;
		ws.on('open', () => { opened = true; }); // whether we actually created/opened the destination
		const fail = (e) => { if (settled) return; settled = true; if (e) e.opened = opened; try { rs.destroy(); } catch (_) {} try { ws.destroy(); } catch (_) {} reject(e); };
		rs.on('error', fail); ws.on('error', fail);
		if (onChunk) rs.on('data', (c) => onChunk(c.length));
		ws.on('finish', () => { if (!settled) { settled = true; resolve(); } });
		rs.pipe(ws);
	});
}
// Walk a directory tree, collecting each FILE with a path relative to `base`. Skips dotfiles (OS junk)
// and does not follow directory symlinks out of the tree. Bounded to the tree; cross-platform.
async function collectImportFiles(dir, base, out) {
	let ents; try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { return; }
	for (const e of ents) {
		if (e.name.startsWith('.')) continue;
		const full = path.join(dir, e.name);
		if (e.isDirectory()) await collectImportFiles(full, base, out);
		else if (e.isFile()) { try { const st = await fsp.stat(full); out.push({ src: full, rel: path.relative(base, full), size: st.size }); } catch (_) {} }
	}
}
async function importFiles(vaultDir, sources, { onProgress, force = false } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const list = (Array.isArray(sources) ? sources : [sources]).map(s => String(s || '').trim()).filter(Boolean);
	if (!list.length) throw new Error('Choose at least one file or folder to add.');
	const root = await mountpointFor(abs, 'Mount the vault before adding files to it.');

	// Expand every source into concrete files, each with a path RELATIVE to the source's parent, so a
	// picked folder keeps its own name inside the vault and a picked file lands at the top level.
	const items = [];
	for (const s of list) {
		const srcAbs = path.resolve(s);
		let st; try { st = await fsp.stat(srcAbs); } catch (_) { throw new Error('Cannot read "' + s + '".'); }
		const base = path.dirname(srcAbs);
		if (st.isDirectory()) await collectImportFiles(srcAbs, base, items);
		else if (st.isFile()) items.push({ src: srcAbs, rel: path.relative(base, srcAbs), size: st.size });
		else throw new Error('"' + s + '" is not a file or folder.');
	}
	if (!items.length) throw new Error('Nothing to add — the selection has no files.');

	// Anti-clobber: never overwrite existing vault content unless the caller forces it.
	if (!force) {
		const clashes = [];
		for (const it of items) { if (await exists(path.join(root, it.rel))) clashes.push(it.rel); if (clashes.length >= 6) break; }
		if (clashes.length) { const e = new Error('Already in the vault: ' + clashes.slice(0, 5).join(', ') + (clashes.length > 5 ? ', …' : '') + '. Choose Replace to overwrite.'); e.clash = true; throw e; }
	}

	const total = items.reduce((n, it) => n + (it.size || 0), 0);
	let added = 0, copied = 0;
	for (const it of items) {
		const dst = path.join(root, it.rel);
		if (!Common.pathWithin(dst, root)) throw new Error('Refusing to write outside the vault.'); // defense-in-depth
		await fsp.mkdir(path.dirname(dst), { recursive: true });
		const onChunk = (n) => { copied += n; if (onProgress && total > 0) onProgress({ percent: Math.min(99, Math.floor(copied / total * 100)), label: 'Adding ' + path.basename(it.rel) }); };
		try {
			// Non-force writes use 'wx' so the never-overwrite rule holds ATOMICALLY — a file appearing
			// between the pre-scan above and this write can't be truncated (it fails with EEXIST instead).
			await streamCopyFile(it.src, dst, { onChunk, flags: force ? 'w' : 'wx' });
		} catch (e) {
			if (e && e.code === 'EEXIST') { const c = new Error('Already in the vault: ' + it.rel + '. Choose Replace to overwrite.'); c.clash = true; throw c; }
			// A real copy error (not a pre-existing file): remove the file we created so a failed import
			// never leaves a truncated file behind. Only unlink if we actually opened the destination.
			if (!e || e.opened) { try { await fsp.unlink(dst); } catch (_) {} }
			// An I/O error from the mounted drive itself: explain it in plain language instead of a bare
			// "EIO". On macOS this is usually the FUSE‑T driver failing a large write intermittently — not
			// a problem with the data — so the clearest advice is simply to try again.
			if (e && e.code === 'EIO') {
				const hint = process.platform === 'darwin' ? ' Some versions of the macOS mount driver (FUSE‑T) do this intermittently on large files.' : '';
				throw new Error('The mounted drive reported an I/O error while writing "' + path.basename(it.rel) + '", so it was not added (nothing was left behind).' + hint + ' Please try again.');
			}
			throw e;
		}
		added++;
	}
	if (onProgress) onProgress({ percent: 100, label: 'Added ' + added + (added === 1 ? ' file' : ' files') });
	return { added, bytes: copied, vault: abs };
}

// Periodic housekeeping for a long-running host: drop dead mount records (removing their
// caches and logs) and sweep any stale ephemeral configs and old logs left by a crash.
// Safe to call anytime; never throws.
// Remove orphaned pack/unpack/disperse/reconstruct temporaries left under the OS temp dir by a hard kill
// (each operation removes its own in a finally, so anything left is a crash leftover). These can be large —
// a dispersal/reconstruct archive is up to the pack ceiling — so reaping them keeps a long-running host from
// accumulating dead files. A temp a LIVE operation is using is protected two ways: it is in `activeTemps`,
// and a generous mtime grace covers a temp from another process too. Best-effort; never throws.
async function sweepStaleTemps(graceMs = 60 * 60 * 1000) {
	const now = Date.now();
	// Staging now lives under the app data directory (see makeStagingPath); an older build may have left temps
	// in os.tmpdir(), so sweep both locations for our own prefixes and leave everything else alone.
	for (const dir of [stagingRoot(), os.tmpdir()]) {
		try {
			for (const name of await fsp.readdir(dir).catch(() => [])) {
				if (!/^vdisk-(unpack|disperse|reconstruct)-/.test(name)) continue;
				const p = path.join(dir, name);
				if (activeTemps.has(p)) continue; // a live operation in THIS process is using it
				try { const st = await fsp.stat(p); if (now - st.mtimeMs > graceMs) await fsp.rm(p, { recursive: true, force: true }); } catch (_) {}
			}
		} catch (_) {}
	}
}

async function sweep() {
	try { await pruneDeadMounts(); } catch (_) {}
	try { await Rclone.sweepStaleConfigs(); } catch (_) {}
	try { await sweepStaleTemps(); } catch (_) {}
	try { pruneRecentMaps(); } catch (_) {} // drop expired session-trust (incl. any lingering signing key) and recent-change entries
	// Finish or roll back any key rotation interrupted by a crash, for every known vault — so recovery
	// happens at service start, not only on the next mount. Best-effort and cheap (a stat that usually
	// misses); a vault mid-rotation is left consistent either way.
	try { for (const dir of await listKnownVaults()) { try { const abs = path.resolve(dir); if (await Common.pathExistsBounded(abs) && await rekeyPending(abs)) await resumeRekey(dir); } catch (_) {} } } catch (_) {} // BOUNDED existence probe first, so a known vault on a disconnected/wedged drive can never hang this periodic sweep on an unbounded stat
	// Free any RAM disks left over from a crash — those still in use by a live mount, AND those a
	// mount is provisioning right now (not yet in the state file), are excluded so the sweep can
	// never pull a cache out from under an in-progress mount.
	try {
		// FAIL SAFE: only run the destructive RAM-disk sweep when the mount list is TRUSTWORTHY. If the state file
		// is unreadable/corrupt (readAllOrNull → null), a live mount would be absent from `active` and its
		// write-back cache could be force-detached, losing undrained writes. Skip instead — a genuinely leaked RAM
		// disk is harmless (reclaimed on a later sweep once state reads again, and never survives a reboot).
		const mounts = await State.readAllOrNull();
		if (mounts === null) {
			Common.warn('Skipped RAM-disk cleanup this cycle: the mount-state file is unreadable, so a live cache cannot be told apart from a leaked one.');
		} else {
			const active = mounts.map(m => m.ramCache && m.ramCache.dir).filter(Boolean).concat([...provisioningCacheDirs]);
			await RamCache.sweep(active);
		}
	} catch (_) {}
}

// Unmount (lock) recorded vaults. Used on shutdown of a long-running host, and by
// the guardian on a crash, so stopping the service never leaves a vault mounted and
// exposed. An `owner` filter limits it to vaults opened by exactly that host
// instance, leaving other instances' and independently-mounted vaults alone. Each
// unmount drains and flushes first, so no data is lost.
async function unmountAll(opts = {}) {
	const mounts = await State.readAll();
	const targets = opts.owner ? mounts.filter(m => (m.owner || 'cli') === opts.owner) : mounts;
	for (const m of targets) { try { await unmount(m.mountpoint, opts); } catch (_) {} }
	return { count: targets.length };
}

// --- Auto-lock and panic lock -------------------------------------------------------------
// Persistent settings (currently just the auto-lock timeout), a small JSON file under data/.
function settingsPath() { return path.join(Common.dataDir(), 'settings.json'); }

// A lenient read for read-only consumers: {} if the file is absent or unreadable. Callers that
// WRITE must go through mutateSettings so the read-modify-write is serialized and consistent.
//
// Memoized for a short window so the frequent read-only consumers do not re-read and re-parse the same file
// several times per operation — the UI state poll (every few seconds) reads it once directly and then again
// via the sftp/cloud/peer listers, and the health tick plus its schedule ticks each read it — so an uncached
// getSettings did ~4 reads per poll and per tick for the life of the server. The cache holds the raw TEXT (not
// the parsed object), and every call re-parses it, so each caller still gets its OWN object and can never
// corrupt a shared one. mutateSettings clears the cache the moment it writes, so a same-process change is seen
// at once; the small TTL bounds how long a cross-process CLI write (which also funnels through the settings
// lock) can go unseen. Semantics are otherwise identical to the previous direct read: absent or corrupt -> {},
// and a transient read error still propagates (never cached), so a caller can retry rather than see stale data.
let settingsMemo = { path: null, text: undefined, at: 0 }; // path-keyed single slot; text null = confirmed absent
const SETTINGS_MEMO_MS = 1000;
// In-flight de-dup of the raw settings read. The UI poll fires getSettings plus several settings-derived listers
// (SFTP/cloud/peers) in ONE tick, and it repeats every few seconds. With --data-dir on a network or removable mount
// that wedges, an un-deduped read would start a fresh hanging fsp.readFile per caller AND per poll, stacking until
// the libuv threadpool is exhausted — a process-wide freeze. Sharing one pending read per settings path pins at most
// ONE threadpool thread no matter how many callers or polls pile up, matching the mount-probe de-dup pattern.
let settingsReadInflight = null; // { path, promise } | null
function readSettingsTextDeduped(p) {
	if (settingsReadInflight && settingsReadInflight.path === p) return settingsReadInflight.promise;
	const promise = Common.readFileCapped(p, MAX_MANIFEST_BYTES, 'utf8'); // 16 MB cap: a pathologically large/corrupt file can't spike memory or block the loop on a giant parse
	settingsReadInflight = { path: p, promise };
	promise.then(() => {}, () => {}).finally(() => { if (settingsReadInflight && settingsReadInflight.promise === promise) settingsReadInflight = null; });
	return promise;
}
function invalidateSettingsMemo() { settingsMemo = { path: null, text: undefined, at: 0 }; }
async function getSettings() {
	const p = settingsPath();
	const now = Date.now();
	// Serve from the memo only when the data dir (hence the settings path) is the SAME — so a runtime setDataDir
	// change is always a cache miss, never a stale read from the previous directory.
	if (settingsMemo.path === p && settingsMemo.at && (now - settingsMemo.at) < SETTINGS_MEMO_MS) {
		if (settingsMemo.text === null) return {};
		try { return JSON.parse(settingsMemo.text) || {}; } catch (_) { return {}; }
	}
	let text;
	try { text = await readSettingsTextDeduped(p); } // each caller parses its own copy of the shared text — no shared mutable object
	catch (e) {
		if (e && e.code === 'ENOENT') { settingsMemo = { path: p, text: null, at: Date.now() }; return {}; } // absent is normal
		throw e; // a transient read error must NOT be cached and must surface, matching the prior read-only contract
	}
	settingsMemo = { path: p, text, at: Date.now() };
	try { return JSON.parse(text) || {}; } catch (_) { return {}; } // read-only: never move a corrupt file aside (that stays the mutateSettings write path's job, under its lock, with a settings-specific warning)
}

// Serialize every settings write so concurrent callers can never lose each other's updates. The in-process queue
// orders callers in THIS process; the cross-process vault lock (keyed to the settings file) orders the CLI, the
// background service, and a UI save across processes — without it, a schedule tick or an emergency check-in in one
// process could silently drop an off-site destination or a check-in written by another, and a lost check-in could
// let the dead-man switch fire early. The read→apply→write runs inside both.
const settingsQueue = Common.serialQueue();
async function mutateSettings(apply) {
	return settingsQueue(() => withVaultLock(settingsPath(), async () => {
		const p = settingsPath();
		let cur = {};
		try { cur = JSON.parse(await Common.readFileCapped(p, MAX_MANIFEST_BYTES, 'utf8')); } // same 16 MB cap as the read path, so a pathologically large file can't spike memory or block on a giant parse here either
		catch (e) {
			if (e && e.code === 'ENOENT') { /* no file yet — start fresh */ }
			else if (e instanceof SyntaxError) {
				// A present-but-unparseable file (a bad hand-edit or a truncated copy) is moved aside rather than
				// silently overwritten, so a reset never destroys recoverable settings.
				try { const saved = p + '.corrupt-' + Date.now(); await fsp.rename(p, saved); Common.warn('The settings file was unreadable and has been moved to "' + saved + '"; a fresh one was started, so saved off-site destinations, schedules, and the auto-lock timeout may need to be set again. The old file is preserved for recovery.'); } catch (_) {}
			} else {
				throw e; // a transient READ error (a permission or I/O hiccup, not corruption) must NOT reset settings — surface it so the caller retries rather than overwriting good settings with a fresh file
			}
		}
		const next = apply({ ...cur }) || cur;
		next.schemaVersion = Common.schemaVersionFor('settings', next); // stamp/preserve the schema version
		await Common.writeJsonAtomic(p, next, { mode: 0o600, chmod: true, fsync: true }); // owner-only (holds encrypted credentials) and durable, so a power loss can't lose the last change (e.g. an emergency check-in)
			invalidateSettingsMemo(); // this process's read-only cache must reflect the write immediately
		return next;
	}));
}
async function setSettings(patch) { return mutateSettings(cur => ({ ...cur, ...patch })); }
// Delete one entry from a keyed settings sub-store (peers, sftpDests, repairSchedules, …) under the settings lock.
function deleteSettingsKey(store, id) {
	return mutateSettings(cur => { const s = { ...(cur[store] || {}) }; delete s[id]; return { ...cur, [store]: s }; });
}
// Patch one entry in a keyed settings sub-store, no-op if the key is absent.
function patchStoreEntry(store, key, patch) {
	return mutateSettings(cur => { const s = cur[store] || {}; if (!s[key]) return cur; return { ...cur, [store]: { ...s, [key]: { ...s[key], ...patch } } }; });
}
// Set (replace) one entry in a keyed settings sub-store, under the settings lock. The sibling of patchStoreEntry
// (which merges) and deleteSettingsKey (which removes) — one place for the "write one entry outright" shape.
function setStoreEntry(store, key, value) {
	return mutateSettings(cur => ({ ...cur, [store]: { ...(cur[store] || {}), [key]: value } }));
}

// In-memory per-mount activity tracking for auto-lock (mountpoint -> { sig, since }).
const activityState = new Map();

// A cheap activity signature from the engine's cumulative transfer counters, plus any pending
// write-back. These only move on real I/O through the drive (reads that miss the cache, and
// writes) and are MONOTONIC, so — unlike the cache's own file counts — they do not churn as the
// cache evicts in the background, which would otherwise look like perpetual activity. Null when
// the stats are unavailable (treated as "no change").
async function vfsActivitySig(bin, rcSocket) {
	if (!bin || !rcSocket) return null;
	// The two stats reads are independent, so issue them together — halving the probe's worst-case wait, which
	// matters because autoLockTick evaluates every mount and must stay responsive even when the engine is briefly slow.
	const [core, vfs] = await Promise.all([
		Rclone.run(bin, ['rc', '--unix-socket', rcSocket, 'core/stats'], { timeoutMs: 2500 }),
		Rclone.run(bin, ['rc', '--unix-socket', rcSocket, 'vfs/stats'], { timeoutMs: 2500 }),
	]);
	if (core.status !== 0) return null;
	try {
		const c = JSON.parse(core.stdout);
		let up = 0;
		try { const d = JSON.parse(vfs.stdout).diskCache || {}; up = (d.uploadsInProgress || 0) + (d.uploadsQueued || 0); } catch (_) {}
		return [c.bytes || 0, c.transfers || 0, c.checks || 0, up].join(':');
	} catch (_) { return null; }
}

// One auto-lock pass over the given tracked mounts. A mount whose activity signature has been
// unchanged for idleMs is GENTLY unmounted (flushed, and skipped if a file is still open). Fully
// best-effort and safe: it never forces, so active use is never interrupted. Returns the
// mountpoints that were locked.
async function autoLockTick(mounts, idleMs) {
	if (!idleMs || idleMs <= 0) return { locked: [] };
	const bin = RcloneSetup.resolve();
	const now = Date.now();
	const list = mounts || [];
	const locked = [], vaults = [], present = new Set();
	for (const m of list) present.add(m.mountpoint);
	// Probe every mount's activity CONCURRENTLY (each vfsActivitySig is an independent, time-bounded rc call): a slow
	// or briefly-unreachable engine on one mount must not delay evaluating the rest. The probe can also reject under
	// fd pressure (EMFILE/EACCES), not just return null, so guard each one — a single bad mount must never abort the
	// pass. The decisions and any unmount stay STRICTLY SERIAL below, so at most one mount is torn down at a time.
	const probes = await Common.mapLimit(list, 8, async (m) => {
		if (isUnmounting(m.mountpoint)) return { m, skip: true };
		try { return { m, sig: await vfsActivitySig(bin, m.rcSocket) }; }
		catch (_) { return { m, skip: true }; } // a probe error on one mount: leave its state, evaluate the rest
	});
	for (const p of probes) {
		if (p.skip) continue;
		const m = p.m, sig = p.sig;
		// If activity can't be determined (no control socket — e.g. Windows — or the engine is
		// briefly unreachable), do NOT auto-lock: unmounting on wall-clock alone could disconnect
		// a vault that is actively being read. Auto-lock only acts when real inactivity is provable.
		if (sig === null) { activityState.delete(m.mountpoint); continue; }
		const prev = activityState.get(m.mountpoint);
		if (!prev || prev.sig !== sig) { activityState.set(m.mountpoint, { sig, since: now }); continue; } // activity -> reset
		if (now - prev.since < idleMs) continue; // idle, but not long enough yet
		try {
			const r = await unmount(m.mountpoint, { gentle: true });
			if (r && r.ok) { locked.push(m.mountpoint); if (r.vault) vaults.push(r.vault); activityState.delete(m.mountpoint); }
			else activityState.set(m.mountpoint, { sig, since: now }); // busy -> treat as active, retry later
		} catch (_) { /* an unmount error on one mount: leave its state, move on to the rest */ }
	}
	for (const k of [...activityState.keys()]) if (!present.has(k)) activityState.delete(k); // forget gone mounts
	return { locked, vaults };
}

// Panic lock: gently unmount every tracked mount right now (each is flushed first; any with a
// file still open is left mounted and reported, never force-killed). Returns how many locked
// and how many stayed because they were in use.
async function lockAll(opts = {}) {
	const mounts = await State.readAll();
	const targets = opts.owner ? mounts.filter(m => (m.owner || 'cli') === opts.owner) : mounts;
	let locked = 0, busy = 0;
	const vaults = []; // cleanly-unmounted vault paths, so the caller can refresh recovery/mirror in the background
	for (const m of targets) {
		try { const r = await unmount(m.mountpoint, { gentle: true }); if (r && r.ok) { locked++; if (r.vault) vaults.push(r.vault); } else busy++; }
		catch (_) { busy++; }
	}
	return { locked, busy, total: targets.length, vaults };
}

// Per-instance identity for a UI-opened mount: "ui:<pid>:<nonce>". The random nonce lets the boot-time orphan
// sweep tell OUR instance's leftover mounts from a DIFFERENT process that merely RECYCLED our pid after we
// died. A live instance refreshes a small heartbeat file keyed by its nonce every health tick; the sweep uses
// that only for a leftover mount from a PRIOR instance (never for the running instance's own live mounts, and
// never in the live crash-guardian's watch), so it can never prematurely unmount a healthy vault.
const OWNER_HEARTBEAT_STALE_MS = 90000; // ~7.5 health ticks — a running instance refreshes every tick, so it is never misjudged as stale
function ownerTag() { return 'ui:' + process.pid + ':' + crypto.randomBytes(6).toString('hex'); }
function ownerHeartbeatPath(owner) { const m = /^ui:\d+:([0-9a-f]+)$/.exec(owner || ''); return m ? path.join(Common.runDir(), 'uihb-' + m[1]) : null; }
async function touchOwnerAlive(owner) { const p = ownerHeartbeatPath(owner); if (!p) return; try { await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.writeFile(p, String(Date.now())); } catch (_) {} }
async function clearOwnerAlive(owner) { const p = ownerHeartbeatPath(owner); if (!p) return; try { await fsp.unlink(p); } catch (_) {} }

// Is the process instance that opened a mount still running? A UI-opened mount is tagged "ui:<pid>:<nonce>";
// independently-mounted vaults (tagged "cli") have no owning service and are never treated as orphans.
async function isOwnerAlive(owner) {
	const m = /^ui:(\d+)(?::([0-9a-f]+))?$/.exec(owner || '');
	if (!m) return true; // 'cli' or unknown -> not service-owned, leave alone
	if (!Common.isProcessAlive(parseInt(m[1], 10))) return false; // pid gone -> definitely an orphan
	if (!m[2]) return true; // legacy "ui:<pid>" with no nonce -> pid-alive is all we can check
	// The pid is alive, but it may have been RECYCLED after our instance died. Only our still-running instance
	// keeps this nonce's heartbeat fresh, so a stale or absent heartbeat means the original instance is gone and
	// the leftover mount is a true orphan.
	const p = ownerHeartbeatPath(owner);
	try { const st = await fsp.stat(p); return (Date.now() - st.mtimeMs) < OWNER_HEARTBEAT_STALE_MS; } catch (_) { return false; }
}

// Lock any vaults left mounted by a service instance that is no longer running
// (e.g. a hard-killed previous instance whose guardian could not run). Called on
// service startup as a backstop.
async function unmountOrphans(opts = {}) {
	const mounts = await State.readAll();
	let count = 0;
	for (const m of mounts) {
		if (!(await isOwnerAlive(m.owner))) { try { await unmount(m.mountpoint, opts); count++; } catch (_) {} }
	}
	return { count };
}

// List everything currently recorded as mounted, verifying liveness.
async function status() {
	await pruneDeadMounts();
	const mounts = await State.readAll();
	const out = [];
	for (const m of mounts) {
		const mounted = await Rclone.isMounted(m.mountpoint);
		out.push({ ...m, alive: Common.isProcessAlive(m.pid), mounted });
	}
	return out;
}

// The tracked mounts WITHOUT probing the filesystem — a plain read of the state file. Used on hot
// paths (the UI's frequent state poll, the health watch) that must never stat a mount point: a
// stat on a wedged hard-NFS mount blocks a worker thread until the mount is force-released, so
// repeatedly statting one could exhaust the pool and freeze the app. Responsiveness is reported
// separately by the Watchdog, which probes with a single, de-duplicated, bounded stat.
function listMounts() { return State.readAll(); }
function listMountsAndVaults() { return State.readMountsAndVaults(); } // both from one state read, for the UI poll

// List the decrypted file paths in a vault WITHOUT mounting (driver-free).
async function list(vaultDir, { password } = {}) {
	if (!password) throw new Error('A password is required to list a vault.');
	await Rclone.sweepStaleConfigs();
	const bin = RcloneSetup.resolve();
	if (!bin) throw new Error('The encryption engine is not available. Run "' + Brand.cli + ' setup" while online.');
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	return withVaultConfig(bin, abs, password, manifest, undefined, async (cfg) => {
		if (!(await verifyPassword(bin, cfg, manifest))) throw wrongPasswordError();
		const r = await Rclone.run(bin, ['lsf', '-R', 'vault:'], { configPath: cfg, maxOutBytes: MAX_LISTING_BYTES });
		if (r.status !== 0) throw new Error('Could not read the vault — it may be open in another program, on a disconnected drive, or its files may be damaged. Engine: ' + engineTail(r));
		return parseLsf(r.stdout); // hide the internal bookkeeping objects from user-facing listings
	});
}

// Bounded recursive walk of a mounted vault's DECRYPTED names, returned as vault-relative "/"-joined paths.
// Reads the mount point directly (plaintext names, no engine spawn, no password), capped so a pathological
// tree can't run away.
async function walkMountNames(root, { cap = 20000, budgetMs = 8000 } = {}) {
	const out = []; const start = Date.now(); const stack = [''];
	while (stack.length && out.length < cap && Date.now() - start < budgetMs) {
		const rel = stack.pop();
		let ents; try { ents = await fsp.readdir(path.join(root, rel), { withFileTypes: true }); } catch (_) { continue; }
		for (const e of ents) {
			const childRel = rel ? rel + '/' + e.name : e.name;
			if (e.isDirectory()) { out.push(childRel + '/'); stack.push(childRel); } else out.push(childRel);
			if (out.length >= cap) break;
		}
	}
	return out;
}

// Filename search: find files/folders in a vault whose path contains `query` (case-insensitive). When the
// vault is MOUNTED it reads the decrypted names straight from the mount point (no password, no engine spawn);
// otherwise it decrypts the names through a crypt config, reusing the same path as list() (password required).
// Names only — no content is read — so it is fast even on a large vault. Content search is a separate feature.
async function searchNames(vaultDir, { query, password } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Normalize to NFC on BOTH sides below: macOS returns file names decomposed (NFD) while a name typed into the
	// browser search box arrives composed (NFC), so the same accented or emoji name would otherwise never match.
	const q = String(query || '').normalize('NFC').trim().toLowerCase();
	if (!q) return { vault: abs, query: query || '', matches: [], mounted: false };
	// Needs the mountpoint itself (not just a boolean), so it keeps its own live lookup like mountpointFor does.
	const live = await liveMountFor(abs);
	const mounted = !!(live && live.mountpoint && (await Rclone.isMounted(live.mountpoint)));
	let names;
	if (mounted) names = await walkMountNames(live.mountpoint);
	else {
		if (!password) throw new Error('This vault is not mounted — enter its password to search it, or mount it first.');
		names = await list(abs, { password });
	}
	// Exclude the tool's own content-search directory from results: the walk recurses into it, but it is internal
	// metadata, not user content, and the content-index walk already skips it — so name search should not surface
	// ".vaultonaut-search" / its index file when a user searches for, say, "index".
	const inSearchDir = (p) => { const d = p.replace(/\/$/, ''); return d === SearchDefs.SEARCH_DIR || d.startsWith(SearchDefs.SEARCH_DIR + '/'); };
	const matches = names
		.filter(p => p !== CANARY_NAME && !isIgnoredVaultPath(p.replace(/\/$/, '')) && !inSearchDir(p) && p.normalize('NFC').toLowerCase().includes(q))
		.slice(0, 1000);
	return { vault: abs, query, matches, mounted };
}

// ---- Content search (search INSIDE files) ----
// A full-text index of the vault's text files, built and read only while the vault is MOUNTED: contents are
// read off the RAM-backed mount, and the serialized index is written back THROUGH the mount, so plaintext
// never reaches the physical disk. The index is one ordinary file inside the vault, so it is covered by the
// tamper baseline like everything else — which means re-indexing is a legitimate content change to re-snapshot.
async function mountpointFor(vaultDir, why) {
	const live = await liveMountFor(resolveVaultDir(vaultDir));
	if (!live || !live.mountpoint || !(await Rclone.isMounted(live.mountpoint))) throw new Error(why);
	return live.mountpoint;
}
// Build or refresh the index (incremental — only changed files are re-read). Heavy work runs in a worker.
// If a vault already has a content-search index, refresh it in the background right after it mounts — so a search
// this session reflects any changes made while it was last open, with no "update index" click. Detached and
// best-effort: it never delays or fails the mount, does nothing for a vault with no index, and skips a read-only
// mount (which could not write the updated index back). The reindex is incremental, so an unchanged vault moves
// nothing. Runs in the search worker thread, so it never blocks the event loop.
// One content reindex per vault at a time. The auto-refresh-on-mount and a user-clicked "Update index" both route
// through contentReindex, so this shared in-flight set stops the two from running two workers against the same vault
// (last-write-wins, where a slightly-older snapshot could overwrite the other's incremental delta). The webserver's
// oncePerVault guard covers rapid user clicks; this covers the auto-refresh-vs-user cross path the route cannot see.
const contentReindexing = new Set();
function refreshContentIndexIfPresent(mountpoint, vault, readOnly) {
	if (readOnly) return;
	if (contentReindexing.has(resolveVaultDir(vault))) return; // a reindex is already running for this vault — don't start a second
	// Bounded: this runs detached right after every mount, and the probe reaches INTO the mount. On a wedged mount
	// a plain access() never returns and permanently pins a libuv thread — so time-bound it, exactly as the sibling
	// in-mount probe (suppressSpotlight) does. A timeout simply skips the refresh rather than hanging.
	Common.withTimeout(fsp.access(searchIndexPathFor(mountpoint)), 4000)
		.then(() => contentReindex(vault).catch(() => {}), () => {}); // only when an index already exists
}
async function contentReindex(vaultDir, { onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	if (contentReindexing.has(abs)) return { vault: abs, skipped: 'a content reindex is already running for this vault' }; // never two workers on one vault
	contentReindexing.add(abs);
	try {
		const mountpoint = await mountpointFor(abs, 'Open (mount) this vault first — content search indexes the files inside it, so it must be unlocked.');
		// Cap the indexing worker's heap as a backstop: even with the extractor's own input/output bounds, a
		// pathological document should fail its own file, not consume unbounded RAM. 1 GB is far above any real
		// per-file need and keeps the worker from ever pressuring the host.
		return await WorkerRun.runWorker(path.join(__dirname, 'SearchWorker.js'), { op: 'index', args: { mountpoint } }, onProgress, { idleMs: 180000, idleMessage: 'Indexing the vault', resourceLimits: { maxOldGenerationSizeMb: 1024 } });
	} finally { contentReindexing.delete(abs); }
}
// A small cache of LOADED search indexes, so successive searches in one session (a user typing query after
// query) don't each re-read, inflate, and re-parse the whole index — the parse dominates and grows with the
// index, so without this every keystroke-search paid full deserialization. The cache is keyed by index path
// and validated by a cheap, bounded stat: an entry is reused only while the index file's mtime AND size are
// unchanged, and a reindex writes a brand-new file (atomic rename -> new mtime/size), so a rebuilt index is
// picked up on the next search. A MiniSearch instance is only ever READ by search(), so sharing one across
// concurrent searches is safe. The map is bounded (a handful of vaults' indexes at once) and, crucially, an
// index is EVICTED when its vault unmounts — a locked vault must leave no plaintext-derived index in memory,
// matching the always-encrypted model.
const searchIndexCache = new Map(); // indexPath -> { ms, mtimeMs, size }
const SEARCH_INDEX_CACHE_MAX = 8;
function searchIndexPathFor(mountpoint) { return path.join(mountpoint, SearchDefs.SEARCH_DIR, SearchDefs.INDEX_NAME); }
function evictSearchIndexCache(mountpoint) { try { searchIndexCache.delete(searchIndexPathFor(mountpoint)); } catch (_) {} }
function runIndexQuery(ms, q) {
	const hits = ms.search(q, { prefix: true, fuzzy: 0.2, boost: { name: 2 }, combineWith: 'AND' }).slice(0, 200);
	return hits.map(h => ({ path: h.path, name: h.name, score: Math.round(h.score * 100) / 100 }));
}
// Search the index. Returns [] with a flag when there is no index yet (suggest indexing) or it is incompatible.
async function contentSearch(vaultDir, { query } = {}) {
	// NFC-normalize the query to match the index's NFC-normalized `name` field, so an accented filename typed in the
	// browser (NFC) still matches even when the mount reported that name decomposed (NFD, e.g. on macOS).
	const q = String(query || '').normalize('NFC').trim();
	if (!q) return { query: '', results: [] };
	const mountpoint = await mountpointFor(vaultDir, 'Open (mount) this vault first — content search reads the encrypted index inside it, so it must be unlocked.');
	const indexPath = searchIndexPathFor(mountpoint);
	// Cheap, bounded validity check: the index lives inside the mount, which can wedge, so time-bound the stat and
	// simply skip the cache (fall through to the capped read) if it does not answer. A matching mtime+size means the
	// loaded index is still current — reuse it without touching disk again.
	let st = null; try { st = await Common.withTimeout(fsp.stat(indexPath), 4000); } catch (_) { st = null; }
	if (st) { const c = searchIndexCache.get(indexPath); if (c && c.mtimeMs === st.mtimeMs && c.size === st.size) return { query: q, results: runIndexQuery(c.ms, q) }; }
	// Cap the read: the index lives inside the vault store, so a shared/imported vault's index size is attacker-
	// chosen. Over the cap it reads as "no index" (rebuild), never an unbounded allocation.
	let buf; try { buf = await Common.readFileCapped(indexPath, SearchDefs.MAX_SEARCH_INDEX_BYTES); } catch (_) { searchIndexCache.delete(indexPath); return { query: q, results: [], noIndex: true }; }
	const env = await SearchDefs.unpackEnvelopeAsync(buf); // inflate off the event loop — the index can be large (attacker-chosen for a shared vault)
	if (!env) { searchIndexCache.delete(indexPath); return { query: q, results: [], stale: true }; }
	const ms = await MiniSearch.loadJSONAsync(env.indexJSON, SearchDefs.MS_OPTIONS);
	// Cache only when we have a stat to validate future reuse against; bound the map by dropping the oldest entry.
	if (st) { searchIndexCache.set(indexPath, { ms, mtimeMs: st.mtimeMs, size: st.size }); if (searchIndexCache.size > SEARCH_INDEX_CACHE_MAX) searchIndexCache.delete(searchIndexCache.keys().next().value); }
	return { query: q, results: runIndexQuery(ms, q) };
}
// Whether an index exists for a (mounted) vault, and how many files it covers — for the UI to offer indexing.
async function contentIndexStatus(vaultDir) {
	let mountpoint; try { mountpoint = await mountpointFor(vaultDir, 'not mounted'); } catch (_) { return { mounted: false, hasIndex: false, indexed: 0 }; }
	try { const env = await SearchDefs.unpackEnvelopeAsync(await Common.readFileCapped(searchIndexPathFor(mountpoint), SearchDefs.MAX_SEARCH_INDEX_BYTES)); return { mounted: true, hasIndex: !!env, indexed: env ? env.fileCount : 0 }; } // fileCount comes from the small meta — no need to parse the whole change manifest just to count files
	catch (_) { return { mounted: true, hasIndex: false, indexed: 0 }; }
}

// Recognizable cloud-sync artifacts left in the encrypted store by Dropbox / iCloud / OneDrive /
// Drive and similar tools. Because the vault often lives in a synced folder, a sync tool that hits a
// conflict or an interrupted upload creates one of these ALONGSIDE the real encrypted file — which
// the tamper check would otherwise report only as a mysterious "added" or undecryptable file. The
// names below are high-precision (they rarely occur by chance), so matching one is a strong signal.
const SYNC_PATTERNS = [
	// The two-way mirror's OWN conflict copies (it keeps both sides rather than overwriting one). This must be
	// classified BEFORE the generic external-sync-tool pattern below, and with honest remediation: the extra
	// copy is a raw encrypted-store file whose name carries the suffix, so it will NOT appear through the
	// mounted drive by its real name. The fix is in this product, not an external app.
	{ kind: 'mirror-conflict', re: /sync-conflict/i, why: 'the two-way mirror found this file changed on both sides and kept BOTH versions instead of overwriting one. The extra copy is a raw encrypted-store file, so it will not show through the mounted drive under its real name. Decide which version to keep and remove the "sync-conflict" part from the store file name to restore it (or open the destination copy), then run this check again.' },
	{ kind: 'conflict', re: /conflicted copy|\(case conflict\)|-conflict|\.conflict\b/i, why: 'a sync tool made a conflicting copy of an encrypted file. Resolve the conflict in your sync app (keep the newest), then run this check again.' },
	{ kind: 'partial', re: /\.(part|partial|crdownload|filepart|!sync|!ut)$|\.dropbox\.cache|\.sb-[a-z0-9]+-[a-z0-9]+$/i, why: 'a sync or download did not finish. Let your sync app catch up, then run this check again.' },
	{ kind: 'temp', re: /^~\$|\.tmp$|\.temp$/i, why: 'a temporary file was left behind. It is usually safe to remove once your sync app is idle.' }
];
function classifySyncName(name) { for (const p of SYNC_PATTERNS) if (p.re.test(name)) return p; return null; }

// Walk the encrypted store and report any sync artifacts found (best-effort; never throws). Returns
// [{ file, kind, why }]. The store holds only obfuscated names, so a match is the sync tool's own
// suffix on top of one, never a hint about the vault's real contents.
async function scanSyncArtifacts(abs) {
	const found = [];
	const root = cipherDirOf(abs);
	async function walk(dir, rel) {
		let entries = [];
		// Time-bound the read: the store can live on an external or network drive that wedges, and this walk runs
		// during verify and on mount. A bounded read fails the one directory fast instead of pinning a thread, like
		// the backup/mirror-dest and mobile store walks do.
		try { entries = await Common.withTimeout(fsp.readdir(dir, { withFileTypes: true }), 8000); } catch (_) { return; }
		for (const e of entries) {
			const relPath = rel ? rel + '/' + e.name : e.name;
			const hit = classifySyncName(e.name);
			if (hit) found.push({ file: relPath, kind: hit.kind, why: hit.why });
			if (e.isDirectory() && found.length < 200) await walk(path.join(dir, e.name), relPath);
		}
	}
	await walk(root, '');
	return found;
}

// ── Self-healing: optional per-vault corruption recovery (parity over the ciphertext) ──────────
// None of these need a password — the parity is over the encrypted bytes — but protect/verify/heal
// touch the raw store, so the vault must be unmounted to be in a settled state (and, for heal, so a
// live mount is never written under). A quick "is it protected" status reads only the index.

// The tool's own metadata blobs to keep OUT of the recovery parity (computed on mount and cached in a per-machine
// sidecar under the app data dir; empty until the vault has been mounted at least once). If a tamper baseline already exists but the
// exclude set is still empty, REFUSE rather than build parity that would cover those metadata blobs — a
// later heal would then revert them and break the baseline. That state is transient (the exclude is
// recomputed on the next mount), so callers treat err.code === 'EXCLUDE_NOT_READY' as "retry after a mount".
async function recoveryExcludeFor(abs) {
	let manifest; try { manifest = await readManifest(abs); } catch (_) { return []; }
	const exclude = (await readRecoveryExcludeCache(abs, manifest)) || [];
	if (manifest.snapshot && exclude.length === 0) {
		const e = new Error('This vault has a tamper baseline but its protected-metadata list is not ready yet. Mount the vault once (that computes it), then add or refresh self-healing recovery data.');
		e.code = 'EXCLUDE_NOT_READY';
		throw e;
	}
	return exclude;
}
// Read and CONSUME the write-authority signer captured from a recent trusted read-write session. Single-use:
// the reference is dropped from the map right here, so it never outlives this call on ANY path — success, an
// early return, or a later throw — and it is honored only within the recent-session window.
function takeRecentSigner(abs) {
	const trust = recentSessionTrust.get(abs);
	const signPriv = trust && trust.signPriv && (Date.now() - trust.at) < RECENT_SESSION_MS ? trust.signPriv : null;
	if (trust) trust.signPriv = null;
	return signPriv;
}
// Record that the recovery index was signed at this version, so a later signed->unsigned downgrade is caught.
// Best-effort: a failure here must never break the rebuild that produced it.
async function noteRecoverySignedResult(r, vaultId) {
	if (r && r.signed && r.signedVersion && vaultId != null) { try { await Integrity.noteRecoverySigned(vaultId, r.signedVersion); } catch (_) {} }
}

async function protectWork(abs, { tier, thorough, onProgress } = {}) {
	const manifest = await readManifest(abs); // ensure it is a valid vault
	if (isCloudVault(manifest)) throw new Error('Self-heal recovery data is not used for cloud vaults — the cloud provider handles durability, and the engine authenticates every chunk on read. Use a backup for a second copy.');
	await assertUnmounted(abs, 'before protecting it');
	// Sign the rebuilt index if a write-authority key from a recent read-write session is still in hand, so the
	// common "unmount, then update self-healing" flow yields a verifiable, signed index. A cold protect (no recent
	// session) stays unsigned until the next trusted unmount signs it — surfaced honestly, never blocking.
	const signPriv = takeRecentSigner(abs);
	const vaultId = signPriv ? Integrity.vaultId(manifest) : null;
	const r = await Recovery.protect(abs, { tier, thorough, cipherDir: cipherDirOf(abs), exclude: await recoveryExcludeFor(abs), signPriv, vaultId, onProgress });
	await noteRecoverySignedResult(r, vaultId);
	return r;
}
// Take the same per-vault BUSY claim as heal/verify and the mount path, so a manual "update protection" can never
// run concurrently with a mount, backup, mirror, or repair of the same vault — which could otherwise read the
// cipher store mid-write and build parity over an inconsistent snapshot. assertUnmounted inside is a further
// point-in-time guard; the busy claim is what actually serializes the whole operation against the others.
async function protect(vaultDir, opts = {}) { const abs = resolveVaultDir(vaultDir); return withVaultBusy(abs, RECOVERY_BUSY, () => protectWork(abs, opts)); }

// Rebuild a vault's recovery data if — and only if — its contents changed since the data was last
// built. Best-effort and self-contained: callers (e.g. just after an unmount) invoke it so recovery
// data stays current automatically, and it does nothing when the vault is unprotected or unchanged.
async function refreshRecoveryIfStale(vaultDir, { onProgress, deep = false } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Don't read the cipher store while a mount / backup / mirror / pack could be touching it: a concurrent
	// remount would otherwise make this compute parity over a half-written store. Skip if the vault is already
	// busy (something reclaimed it), and hold the claim for the whole read+rebuild so none can interleave. This
	// only ever writes .recovery/ (never the store), so the worst it prevented was briefly-stale parity — but a
	// point-in-time assertUnmounted alone did not close the window, so take the same exclusive claim as backup/pack.
	if (vaultBusy.has(abs)) return { refreshed: false, reason: 'busy' };
	vaultBusy.add(abs);
	try {
		const cipherDir = cipherDirOf(abs);
		let idx = null;
		// Read only the index METADATA (tier/thorough), not the whole index. readIndexMeta is stat-keyed, so on the
		// common tick where the index has not changed it returns cached metadata WITHOUT re-parsing and re-hashing a
		// possibly-huge index on the event loop. The real index is re-read inside the worker by Recovery.protect
		// below, so these fields are only hints. A newer-format or tampered index still throws here (→ 'unreadable').
		try { idx = await Recovery.readIndexMeta(abs); } catch (_) { return { refreshed: false, reason: 'unreadable' }; }
		if (!idx || !idx.protected) return { refreshed: false, reason: 'not-protected' };
		// A thorough vault re-checks block contents (in the worker, so it never blocks) to catch a same-size
		// in-place edit; a normal vault uses the cheap set+size check. Either way, a needless rebuild is skipped.
		// A write-authority signer captured (and consumed) from the last read-write session, used to sign the
		// recovery index. Read the vault id once for the signed payload. takeRecentSigner drops the key reference
		// immediately, so it never lingers regardless of which branch below runs.
		const signPriv = takeRecentSigner(abs);
		let vaultId = null;
		if (signPriv) { try { vaultId = Integrity.vaultId(await readManifest(abs)); } catch (_) {} }
		// `deep` forces the content-level staleness check even on a non-thorough vault. The unattended auto-heal path
		// passes it so a same-byte-length in-place edit made in a recent TRUSTED session is detected here and its parity
		// rebuilt (preserving the edit), instead of the cheap set+size check missing it and the subsequent heal
		// reverting it from stale parity. The deep read runs in the worker (staleCheck), so it never blocks the loop.
		const useDeep = idx.thorough || deep;
		const stale = useDeep ? await Recovery.staleCheck(abs, { cipherDir }) : await Recovery.isStale(abs, { cipherDir });
		if (!stale) {
			// Nothing to rebuild — but if a signer is in hand and the current index is not yet signed (e.g. a manual
			// password-less protect, or an older unsigned build), sign it in place so it becomes verifiable.
			if (signPriv && vaultId != null) {
				try { const s = await Recovery.signIndex(abs, { signPriv, vaultId }); if (s && s.signed) await Integrity.noteRecoverySigned(vaultId, s.signedVersion); } catch (_) {}
			}
			return { refreshed: false, reason: 'up-to-date' };
		}
		// If we WOULD rebuild but have NO write-authority signer in hand, and this vault's recovery is currently
		// SIGNED, a rebuild now would produce an UNSIGNED index and clear the signature — which heal then refuses as
		// a downgrade until the next read-write session re-signs it. Rather than transiently make a healthy vault
		// un-repairable after a routine background refresh, DEFER: leave the existing signed index in place. The
		// added files are protected on the next trusted unmount, which carries a signer and signs the rebuild.
		if (!signPriv) {
			let vid = null; try { vid = Integrity.vaultId(await readManifest(abs)); } catch (_) {}
			if (vid != null) { let signedVer = 0; try { signedVer = await Integrity.recoverySignedVersion(vid); } catch (_) {} if (signedVer > 0) return { refreshed: false, reason: 'deferred-unsigned-no-signer' }; }
		}
		// If the most recent trusted session changed ONLY OS metadata (the tamper baseline's real-content root did
		// not move — .DS_Store / ._* and the like churned, but nothing the user actually edited), there is nothing
		// new to protect: skip the rebuild. This is content-based (via the tamper root, which filters OS junk by
		// the same list the tamper check uses), so it never mistakes a real file for junk or vice-versa.
		const rc = recentRealChange.get(abs);
		if (rc && (Date.now() - rc.at) < RECENT_SESSION_MS && rc.changed === false) return { refreshed: false, reason: 'metadata-only' };
		// DATA SAFETY (critical): the auto-refresh must NEVER rebuild parity over a LOSS or over damaged-at-rest
		// content — that bakes the damage into the new parity and destroys "Check & repair"'s ability to restore it
		// (and makes a later verify falsely report the vault clean). Rebuild ONLY when the change is provably safe:
		//   • the session was TRUSTED — a normal mount/edit/unmount, so the changes are the user's own legit edits
		//     (the same signal the tamper baseline uses to decide it may refresh); OR
		//   • the vault still VERIFIES CLEAN against the existing parity — the staleness is purely ADDED files,
		//     nothing protected was lost, truncated, corrupted, or grown.
		// Otherwise DEFER and leave the vault repairable; accepting a reduction/change is then an explicit
		// "Update protection". This covers deletion, truncation, oversize, and (on thorough vaults) same-size
		// bit-rot alike, without ever reverting a legitimate edit.
		const trust = recentSessionTrust.get(abs);
		const trustedRecent = !!(trust && (Date.now() - trust.at) < RECENT_SESSION_MS && trust.trusted);
		if (!trustedRecent) {
			// FAIL SAFE: if the loss check cannot complete (the index is unreadable), do NOT rebuild — that would
			// bake an undetected loss into the new parity. Leave the vault as-is and repairable.
			let missing;
			try { missing = await Recovery.missingProtectedCount(abs, { cipherDir }); }
			catch (e) { Common.warn('Recovery auto-refresh skipped for ' + abs + ': the loss check could not complete (' + (e && e.message || e) + ') — left as-is rather than risk rebuilding over a loss.'); return { refreshed: false, reason: 'loss-check-failed' }; }
			if (missing > 0) { Common.warn('Recovery auto-refresh skipped for ' + abs + ': ' + missing + ' protected file(s) are missing — left repairable via "Check & repair" rather than baking the loss into the recovery data.'); return { refreshed: false, reason: 'files-missing', missing }; }
			let clean = true; try { const v = await Recovery.verify(abs, { cipherDir }); clean = !(v && v.protected && v.clean === false); } catch (_) { clean = false; }
			if (!clean) { Common.warn('Recovery auto-refresh skipped for ' + abs + ': the vault has damage against its recovery data and the last session was not trusted — left repairable via "Check & repair" rather than rebuilding over it.'); return { refreshed: false, reason: 'damage-detected' }; }
		}
		await assertUnmounted(abs, 'before refreshing its recovery data');
		// Best-effort background refresh: if the metadata-exclude isn't ready yet (a baseline exists but the
		// one-time name lookup hasn't succeeded), defer rather than build parity that would break the baseline.
		let exclude;
		try { exclude = await recoveryExcludeFor(abs); }
		catch (e) { if (e.code === 'EXCLUDE_NOT_READY') return { refreshed: false, reason: 'exclude-not-ready' }; throw e; }
		const r = await Recovery.protect(abs, { tier: idx.tier, thorough: idx.thorough, cipherDir, exclude, signPriv, vaultId, onProgress });
		await noteRecoverySignedResult(r, vaultId);
		return { refreshed: true, tier: r.tier, dataBlocks: r.dataBlocks, parityBlocks: r.parityBlocks, signed: !!r.signed };
	} finally { vaultBusy.delete(abs); }
}

async function recoveryStatus(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	// A read-only status probe: never let a too-new (or otherwise unreadable) recovery format abort the
	// caller — report it as present-but-unreadable so an overall `verify` still completes. Uses the cached,
	// stat-keyed status reader so the frequent UI poll never re-parses a large index.
	try { return await Recovery.readIndexMeta(abs); }
	catch (e) { return { protected: true, unreadable: true, message: e.message }; }
}

// The published verify key + vault id used to check the recovery index's authenticity signature, read from the
// manifest once. Best-effort: an unreadable manifest yields nulls, so the check degrades to "unsigned/unverified"
// rather than throwing.
async function recoveryAuthContext(abs) {
	try { const m = await readManifest(abs); return { pubkey: Integrity.pubkeyOf(m), vaultId: Integrity.vaultId(m) }; }
	catch (_) { return { pubkey: null, vaultId: null }; }
}
// One place that turns a recovery-authenticity result into a stable state key, so the CLI and the web UI share
// the SAME precedence (tampered > downgrade > verified > unsigned) and can differ only in wording, never in
// judgement. Adding a new state here updates every surface at once.
function authenticityState(a) {
	if (!a) return 'unsigned';
	if (a.tampered) return 'tampered';
	if (a.downgrade) return 'downgrade';
	if (a.signed && a.verified) return 'verified';
	return 'unsigned';
}
// Flag a DOWNGRADE: the recovery index is not signed-and-valid at (at least) the highest version this app has
// seen signed for the vault — the trace an attacker leaves when they strip the signature to force the weaker
// "unsigned" path. A vault that was never signed stays soft (no flag). Surfaced to the user, never blocking.
async function annotateRecoveryDowngrade(res, vaultId) {
	if (!res || !res.protected) return res;
	const a = res.authenticity || (res.authenticity = { signed: false });
	if (vaultId != null) {
		const expected = await Integrity.recoverySignedVersion(vaultId);
		if (expected && !(a.signed && a.verified && (a.version || 0) >= expected)) { a.downgrade = true; a.expectedVersion = expected; }
	}
	a.state = authenticityState(a); // stamp the shared state last, after downgrade is decided
	return res;
}

// The claim shared by the recovery check and repair. heal REWRITES ciphertext blocks in place, so it must hold
// the vault exclusively — otherwise a mount, a backup, or a mirror on the same vault could run concurrently and
// copy or serve a half-repaired store. verify is read-only but takes the same claim for a consistent read.
const RECOVERY_BUSY = 'This vault is busy with another operation (a mount, backup, mirror, or repair). Wait for it to finish, then try again.';
// The un-claimed inner work, so the scheduled scrub can hold ONE claim across a verify+heal (see runScrub) rather
// than claiming twice with a gap another operation could slip into.
async function verifyRecoveryWork(abs, { onProgress } = {}) {
	await assertUnmounted(abs, 'before checking its recovery data');
	const ctx = await recoveryAuthContext(abs);
	const res = await Recovery.verify(abs, { cipherDir: cipherDirOf(abs), pubkey: ctx.pubkey, vaultId: ctx.vaultId, onProgress });
	return annotateRecoveryDowngrade(res, ctx.vaultId);
}
async function healWork(abs, { allowUnverified, force, onProgress } = {}) {
	await assertUnmounted(abs, 'before healing it');
	const ctx = await recoveryAuthContext(abs);
	const res = await Recovery.heal(abs, { cipherDir: cipherDirOf(abs), pubkey: ctx.pubkey, vaultId: ctx.vaultId, allowUnverified, force, onProgress });
	return annotateRecoveryDowngrade(res, ctx.vaultId);
}
async function verifyRecovery(vaultDir, opts = {}) { const abs = resolveVaultDir(vaultDir); return withVaultBusy(abs, RECOVERY_BUSY, () => verifyRecoveryWork(abs, opts)); }
// allowUnverified is the user's explicit "repair anyway" choice — it lets a repair proceed even when the
// recovery index's signature does not verify, so a rare multi-fault can never leave a vault unrepairable.
async function heal(vaultDir, opts = {}) { const abs = resolveVaultDir(vaultDir); return withVaultBusy(abs, RECOVERY_BUSY, () => healWork(abs, opts)); }

async function unprotect(vaultDir, { password } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Removing recovery data destroys the vault's ability to repair future corruption, so require the same read-write
	// proof as a permanent delete — a visible vault path is no authorization on its own.
	const manifest = await readManifest(abs);
	await assertWriteCredential(manifest, password);
	await Recovery.removeRecovery(abs);
	// Reset the rollback anchor: a later re-protect restarts the index at version 1, and a stale high anchor would
	// otherwise make heal (and scheduled auto-heal) falsely refuse the fresh recovery data as a downgrade. Safe
	// because this path already proved write authority. Best-effort — the ledger is local and never on the data path.
	try { await Integrity.clearRecoverySigned(Integrity.vaultId(manifest)); } catch (_) {}
	return { ok: true, vault: abs };
}

// Environment check for `doctor`.
// Environment readiness (mount driver + engine). This is polled by the web UI every few seconds, so it must
// never re-run the (process-spawning) driver/engine probes on every call: memoize the result with a short TTL
// and serve it stale-while-revalidating. A stale value is returned instantly while a single background refresh
// runs; concurrent callers coalesce onto that one refresh. Combined with Driver.detect being async and the
// engine probe being timeout-bounded, a hung helper binary can neither block the poll nor be hammered by it.
let _doctor = null, _doctorAt = 0, _doctorInflight = null;
const DOCTOR_TTL_MS = 20000;
// Install the engine in the BACKGROUND for a fresh first run. Driven ONLY by the long-running service (see the web
// server's boot and health tick) — never by doctor() or a short-lived CLI command, so a `doctor` invocation can
// never hang on, or orphan, a tens-of-MB download. At most one install runs at a time, with a short retry backoff
// so an offline first run retries later without hammering the network. A real operation (mount/create) still calls
// ensureEngine() directly and waits, exactly as before.
let _engineSetupInflight = null, _engineSetupNextAt = 0, _engineInstalled = false;
function startEngineSetup() {
	if (_engineInstalled) return null;                 // already installed this process — nothing to do (cheap for the health tick to call every time)
	if (_engineSetupInflight) return _engineSetupInflight;
	if (Date.now() < _engineSetupNextAt) return null;  // backing off after a recent failure
	_engineSetupInflight = RcloneSetup.ensure()
		.then((r) => { if (r && r.ok) { _engineInstalled = true; _doctor = null; _doctorAt = 0; } else { _engineSetupNextAt = Date.now() + 30000; } return r; }) // on success: stop retrying and drop the cached status once, so the next poll re-probes and clears the "Setting up…" banner
		.catch(() => { _engineSetupNextAt = Date.now() + 30000; return null; }) // e.g. offline — retry after a short pause, never throw out of this background task
		.finally(() => { _engineSetupInflight = null; });
	return _engineSetupInflight;
}
function engineSetupInProgress() { return !!_engineSetupInflight; }
function refreshDoctor() {
	if (_doctorInflight) return _doctorInflight;
	_doctorInflight = (async () => {
		let driver; try { driver = await Driver.detect(); } catch (_) { driver = { ok: false, name: null, detail: 'Driver detection failed.', install: null }; } // guard: this runs as a discarded background promise in the stale branch, so an unexpected rejection must never become an unhandledRejection
		// PASSIVE probe only — never block the status poll on a first-run download. If the engine is not installed/
		// verified yet, report whether a background install is currently running so the UI can show a "Setting up…"
		// state instead of a frozen screen or a hard error; the service is what actually triggers that install.
		let engine;
		try { engine = await RcloneSetup.probe(); } catch (_) { engine = { ok: false, rclone: null }; }
		if (!engine.ok) engine = { ...engine, downloading: engineSetupInProgress() };
		_doctor = { engine, driver, platform: process.platform, arch: process.arch };
		_doctorAt = Date.now();
		return _doctor;
	})().finally(() => { _doctorInflight = null; });
	return _doctorInflight;
}
async function doctor() {
	if (_doctor && (Date.now() - _doctorAt) < DOCTOR_TTL_MS) return _doctor; // fresh
	if (_doctor) { refreshDoctor().catch(() => {}); return _doctor; }         // stale — refresh in background (errors swallowed), serve stale now
	return refreshDoctor();                                                  // first call — must wait
}

// The OS file-manager command (and its argv) for a platform, given the target path. Pure — no spawn — so the
// per-platform choice is unit-testable from any single host. The path is one argv entry, so a space needs no
// quoting, and an unrecognized platform falls back to the freedesktop opener that virtually every Unix desktop has.
function fileManagerCommand(platform, mp) {
	if (platform === 'darwin') return ['open', [mp]];
	if (platform === 'win32') return ['explorer', [mp]];
	return ['xdg-open', [mp]];
}

// Open a path in the platform's file manager (best-effort; used by the UI's "Reveal" button). Launched DETACHED,
// the same way the browser opener is: a file manager is fire-and-forget, so piping its stdio, waiting on it, and
// (on Windows) hiding its window — all of which the engine spawn wrapper does — is exactly what stopped the folder
// from ever appearing. Never throws into the caller.
async function reveal(target) {
	// On Windows a bare drive-letter mountpoint ("X:") is drive-RELATIVE, so normalize it to the drive root ("X:\")
	// first; a no-op for ordinary paths and on other platforms, and the SAME normalizer the mount path uses.
	const mp = normalizeMountpoint(String(target || ''));
	const { spawn } = require('child_process');
	const [cmd, args] = fileManagerCommand(process.platform, mp);
	return await new Promise((resolve) => {
		let settled = false;
		const done = (v) => { if (!settled) { settled = true; resolve(v); } };
		try {
			// Detached with stdio ignored and unref'd so it outlives this request. NOT windowsHide: explorer is a
			// GUI launcher, and hiding its window suppresses the folder we are opening. explorer also exits non-zero
			// even on success, so an exit status is never treated as failure.
			const child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
			// A missing opener (e.g. xdg-open absent on a minimal Linux box) emits 'error' within a tick; report it
			// so the UI can show the path instead of silently doing nothing.
			child.on('error', () => done({ ok: false, error: 'No file manager is available to open ' + mp }));
			child.unref();
			setTimeout(() => done({ ok: true }), 300);
		} catch (_) { done({ ok: false, error: 'No file manager is available to open ' + mp }); }
	});
}

// Known-vault registry passthroughs for the UI. addKnownVault validates that the
// path really is a vault before remembering it.
async function addKnownVault(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	await readManifest(abs); // throws if not a valid vault
	await State.addVault(abs);
	return { ok: true };
}
// Overwrite a file's bytes with random data, flush, then delete it. Best-effort: the overwrite is a gesture
// (an SSD's wear-leveling can keep a remnant physically), but the unlink removes the file from the live
// filesystem, which is what matters for destroying a small key file.
async function overwriteThenUnlink(file) {
	// Shred the bytes IN PLACE first, so the key material is physically gone even if a lock later stops us from
	// deleting the file, then delete the file. Report BOTH outcomes: `overwritten` (the random-fill landed, or the
	// file was already absent) tells the caller the ORIGINAL key bytes are gone; `gone` tells it the file itself is
	// no longer on disk. The caller needs the two apart — "shredded but a locked husk lingers" is a success with a
	// leftover, while "neither could run" is a real failure where the original wrapped key may still be readable.
	let overwritten = false;
	try {
		const st = await fsp.stat(file);
		const fh = await fsp.open(file, 'r+');
		try { let left = st.size, off = 0; while (left > 0) { const n = Math.min(left, 1 << 20); await fh.write(crypto.randomBytes(n), 0, n, off); off += n; left -= n; } await fh.sync(); overwritten = true; }
		finally { await fh.close(); }
	} catch (e) {
		// A file that is already absent has no key bytes to destroy, so count that as overwritten; any other error
		// (a lock that blocked the open-for-write) leaves the original bytes possibly intact — keep it false.
		if (e && e.code === 'ENOENT') overwritten = true;
	}
	// Retry the unlink on a transient lock — on Windows an antivirus scanner or the search indexer can hold a
	// handle (EPERM/EBUSY/EACCES) so a single rm silently fails and the key file survives — then confirm it is
	// actually gone.
	let gone = false;
	for (let i = 0; i < 8; i++) {
		try { await fsp.rm(file, { force: true }); } catch (_) {}
		if (!(await exists(file))) { gone = true; break; }
		await Common.sleep(100 * (i + 1));
	}
	if (!gone) gone = !(await exists(file));
	return { overwritten, gone };
}

// CRYPTO-ERASE: permanently destroy a vault's key material so THIS copy can never be opened again. The manifest
// (and its backup) hold every wrapped copy of the master key; overwrite-then-delete them and the ciphertext
// becomes undecryptable noise. This is the fast, effective way to make a copy unrecoverable — you cannot reliably
// shred every ciphertext byte on modern flash storage, but destroying the key makes those bytes meaningless. It
// does NOT touch backups, mirrors, or another machine's copy — each keeps its own keys. For a LOCAL vault the
// whole folder (the ciphertext blobs included) is then removed; for a CLOUD vault only the local key folder is
// removed and the remote store is left, now permanently undecryptable (its keys only ever existed here). An
// optional `keepPath` packs a portable, still-encrypted copy FIRST as a safety net (local vaults only). This is
// deliberately irreversible: the caller is responsible for confirming intent before calling it.
async function secureRemove(vaultDir, { password, keepPath, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs); // must be a real vault — throws otherwise, so we never erase a non-vault folder
	// Proof of ownership before anything is touched, so nobody who cannot open a vault can erase it and a stray or
	// replayed request can never destroy one. The vault name is visible in the list and so is no secret.
	await assertWriteCredential(manifest, password);
	const cloud = isCloudVault(manifest);
	let kept = null;
	if (keepPath) {
		if (cloud) throw new Error('A cloud vault keeps its data in the cloud, so it cannot be packed into a local file here. Make sure you have another way in first (your password and a copy of this vault folder), then erase with --no-keep, or use --panic.');
		// The safety copy must land OUTSIDE the vault — otherwise the erase below deletes the whole folder including
		// the copy we just wrote, and secureRemove would report a saved copy that no longer exists (and packing an
		// output file into the tree being packed can corrupt it). Refuse an in-vault --keep path up front. Check
		// containment TWO ways and refuse if EITHER says "inside", so the guard errs toward safety: a purely lexical
		// compare (catches a plain "..") AND a symlink-resolved compare of BOTH sides (catches a --keep path that
		// resolves through a symlink back into the vault). Both sides must be resolved the same way — resolving only
		// the keep path while comparing against a lexical vault path is an asymmetry that misses an in-vault keep
		// whenever the vault itself sits under a symlinked path (on macOS /tmp and /var are symlinks, for example).
		const keepReal = (await Common.resolveThroughSymlinks(keepPath)) || path.resolve(keepPath);
		const vaultReal = (await Common.resolveThroughSymlinks(abs)) || abs;
		if (Common.pathWithin(path.resolve(keepPath), abs) || Common.pathWithin(keepReal, vaultReal)) throw new Error('Choose a --keep location OUTSIDE the vault folder — a copy saved inside it would be erased along with the vault.');
		await pack(abs, keepPath, { onProgress }); // a portable, still-encrypted copy, openable with the password
		// Confirm the safety copy actually landed and is non-empty BEFORE destroying the keys — otherwise a failed or
		// truncated pack would leave the caller believing a copy exists while the erase makes the loss permanent. The
		// pack itself is fsync'd on write, so a present, non-empty file here is durable.
		const keepStat = await fsp.stat(keepPath).catch(() => null);
		if (!keepStat || !keepStat.isFile() || keepStat.size === 0) throw new Error('The safety copy could not be written to ' + keepPath + ', so nothing was erased. Check the destination has space and is writable, then try again.');
		kept = path.resolve(keepPath);
	}
	// Take the per-vault BUSY claim for the DESTRUCTIVE steps, so a concurrent scheduled backup, mirror, or scrub
	// that already holds it is not deleted out from under (secureRemove then refuses cleanly instead of racing the
	// read). The optional safety-copy pack above took and released the same claim itself, so this never self-conflicts.
	return withVaultBusy(abs, 'This vault is busy with another operation (a backup, mirror, or scrub). Wait for it to finish, then erase it.', async () => {
		try { await unmount(abs, { force: true }); } catch (_) {} // no live decrypted data (also wipes the RAM cache)
		// Destroy the key material. Per file, distinguish a TRUE failure — the original wrapped-key bytes may still be
		// readable because neither the overwrite nor the delete could run (a lock held the file the whole time) — from a
		// harmless leftover, where the bytes were shredded in place but a lock kept us from deleting the now-meaningless
		// husk. The first means nothing is safely destroyed and the user must retry; the second is a success.
		let keysMayBeIntact = false;
		// Shred EVERY manifest-family file, not just the canonical pair: an interrupted or pending rotation leaves
		// staged copies (vault.json.new, .vault.bak.new) that each hold a fresh-key-wrapped master, and an atomic
		// write can leave a vault.json.<pid>.<hex>.tmp. On media where an unlinked file is forensically recoverable —
		// the exact threat this feature targets — those must be overwritten in place too, not merely deleted. Match by
		// the manifest name prefixes so any current or future manifest residue is covered; fall back to the canonical
		// pair if the folder cannot be listed.
		let keyFiles;
		try { keyFiles = (await fsp.readdir(abs)).filter(n => n === MANIFEST || n === MANIFEST_BAK || n.startsWith(MANIFEST + '.') || n.startsWith(MANIFEST_BAK + '.')); }
		catch (_) { keyFiles = KEY_MATERIAL_FILES.slice(); }
		if (!keyFiles.length) keyFiles = KEY_MATERIAL_FILES.slice();
		for (const name of keyFiles) {
			const r = await overwriteThenUnlink(path.join(abs, name));
			if (!r.overwritten && !r.gone) keysMayBeIntact = true;
		}
		try { await fsp.rm(abs, { recursive: true, force: true }); } catch (_) {} // remove the rest of the local folder
		// A manifest is the ONLY copy of the salt and the wrapped master key. If one still exists on disk AND its
		// original bytes might be intact (a lock blocked BOTH shredding and deleting it), the vault is still openable —
		// fail loudly and tell the user to retry. If instead the bytes were already overwritten, the surviving file is
		// meaningless noise: the keys ARE destroyed, so we report success and note the leftover rather than lying about it.
		let leftKeyFile = null;
		for (const name of KEY_MATERIAL_FILES) { if (await exists(path.join(abs, name))) { leftKeyFile = name; break; } }
		if (leftKeyFile && keysMayBeIntact) throw new Error('Secure-remove could not overwrite or delete the vault\'s key file (' + path.join(abs, leftKeyFile) + '); another program is holding it open (often an antivirus scanner or file indexer on Windows). Close anything using the vault and run it again — the keys have NOT been destroyed yet.' + (kept ? ' Your safety copy at ' + kept + ' is intact.' : ''));
		try { await removeKnownVault(abs); } catch (_) {} // drop the list entry + its per-path settings
		// Emergency access is armed under a key derived from the vault's identity (its pubkey), not its path, so it is
		// NOT among the path-keyed settings removeKnownVault scrubs. Drop any arming for THIS vault here — otherwise the
		// dead-man switch could later hand a trusted contact a sealed grant for a vault that no longer exists, and the
		// arming holds a standalone copy of read-capability key material that would outlive the crypto-erase. Match on the
		// stored resolved path (the map key is the pubkey). Best-effort — a settings hiccup must never fail the erase.
		try {
			await mutateSettings(cur => {
				const em = cur.emergency;
				if (!em || !em.armed) return cur;
				let changed = false; const armed = {};
				for (const [id, rec] of Object.entries(em.armed)) { if (rec && rec.path === abs) { changed = true; continue; } armed[id] = rec; }
				return changed ? { ...cur, emergency: { ...em, armed } } : cur;
			});
		} catch (_) {}
		// The keys are provably destroyed. `leftover` is true when a lock kept a now-meaningless (already-shredded) file
		// on disk, so the caller can mention it — the data is unrecoverable either way.
		return { vault: abs, kept, cloud, leftover: !!leftKeyFile };
	});
}

async function removeKnownVault(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	pollManifestCache.delete(abs); // drop the poll's stat-keyed manifest entry so a removed vault leaves nothing behind
	await State.removeVault(vaultDir);
	// Also drop this vault's per-path settings so they don't accumulate forever, and so a NEW vault
	// later created at the same path can't silently inherit an old backup destination or schedule.
	try {
		await mutateSettings(cur => {
			const next = { ...cur };
			for (const store of VAULT_PATH_KEYED) {
				if (next[store] && next[store][abs] !== undefined) { next[store] = { ...next[store] }; delete next[store][abs]; }
			}
			return next;
		});
	} catch (_) {}
	return { ok: true, path: abs }; // resolved path so a caller can evict any per-path cache keyed on it (e.g. the UI's vault-state cache)
}
async function listKnownVaults() { return State.listVaults(); }

// ---- Travel mode ----
// Hide every known vault from this app and lock everything, stashing the vault list and all path-keyed settings
// (backup destinations, schedules, favorites, serve credentials, …) encrypted under a TRAVEL PASSWORD so the
// app's own plaintext state names none of them. The vault folders on disk are untouched — their tamper
// baselines and self-heal data live inside them and are unaffected — so nothing is ever lost; even without the
// travel password a vault is still on disk and can be re-added by its folder. See lib/Travel.js for the honest
// limits this carries (it hides the pointer in THIS app, not the data on your disk).
async function travelEnable({ travelPassword, owner } = {}) {
	if (!travelPassword) throw new Error('A travel password is required.');
	if (Travel.hasHidden()) throw new Error('Travel mode is already on — restore your vaults first.');
	const vaults = await State.listVaults();
	const settings = await getSettings();
	const maps = {};
	for (const k of VAULT_PATH_KEYED) if (settings[k] && Object.keys(settings[k]).length) maps[k] = settings[k];
	// The emergency (dead-man) config is a single object, not a path-keyed map, but its `armed` entries hold each
	// vault's absolute PATH and display NAME in plaintext — so it must be hidden too, or travel's "the app's own
	// plaintext state names none of them" guarantee breaks. Stashing it also stops a release from firing (and
	// naming a vault in the release folder) while the vaults are meant to be hidden. It is restored on exit.
	const emergency = settings.emergency || null;
	// Stash first (durably) so a later interruption can never lose what we are about to remove from live state.
	await Travel.enable(travelPassword, { vaults, maps, emergency });
	try { await lockAll({ owner }); } catch (_) {} // unmount + lock everything before it disappears from the list
	for (const v of vaults) { try { await State.removeVault(v); } catch (_) {} }
	await mutateSettings(cur => { const next = { ...cur }; for (const k of VAULT_PATH_KEYED) if (next[k]) next[k] = {}; delete next.emergency; return next; });
	return { hidden: vaults.length };
}
// Restore what travel mode hid, with the travel password. Re-applies the stashed state, THEN clears the travel
// registry — so an interruption mid-restore leaves the stash intact to try again.
async function travelRestore({ travelPassword } = {}) {
	const blob = await Travel.restore(travelPassword);
	if (blob === null) throw new Error('The travel password is incorrect, or travel mode is not on.');
	for (const v of (blob.vaults || [])) { try { await State.addVault(v); } catch (_) {} }
	const maps = blob.maps || {};
	if (Object.keys(maps).length) await mutateSettings(cur => { const next = { ...cur }; for (const k of Object.keys(maps)) next[k] = { ...(next[k] || {}), ...maps[k] }; return next; });
	// Restore the emergency config, but treat the restore as a check-in: refresh lastCheckIn to now and clear any
	// releasedAt, so the timer does not fire immediately just because the inactivity window elapsed while travel
	// was on (the person is clearly present — they just entered the travel password to restore).
	if (blob.emergency) await mutateSettings(cur => ({ ...cur, emergency: { ...blob.emergency, lastCheckIn: new Date().toISOString(), releasedAt: null } }));
	await Travel.clear();
	return { restored: (blob.vaults || []).length };
}
function travelStatus() { return { active: Travel.hasHidden() }; }

// ---- Emergency / inheritance access (a dead-man's switch) ----
// Seal a vault's READ capability to a trusted contact's public key now; if the owner stops checking in for the
// inactivity window plus a grace period, the sealed blob is released so the contact can open it with their own
// private key. Read-only by construction (a read capability can never rotate, delete, or evict). The vault data
// is never touched — this is an additive read path guarded by a timer, so a failed switch just means the contact
// gets nothing (fail-closed), never data loss. Honest limits (surfaced to the user): the timer here lives on
// THIS machine, so it cannot fire if this machine is gone; the contact's device security becomes part of the
// threat model; and true revocation is rotating the vault's keys, not just disarming (a released or copied blob
// stays openable). A relay-hosted timer that survives this machine, and a no-custodian time-lock, are future work.
const EMERGENCY_RELEASE_DIR = 'emergency-release';
// Serialize the state-changing emergency operations — check-in (the user's veto), the release tick, and disarm —
// so none can interleave with another. Without this, a release tick that read settings a moment before a check-in
// could still write the sealed grants and stamp "released" AFTER the check-in tried to veto it, defeating the
// veto and exposing read access against the user's will. The queue also stops a slow release from re-entering on
// the next tick. It is per-process, which matches the single-service deployment; the settings write itself is
// additionally cross-process locked.
const emergencyQueue = Common.serialQueue();
// The last check-in as a finite epoch, or null when it is missing or unparseable. Read through this everywhere so
// a corrupt or partially written config can never be mistaken for a real timestamp.
function emergencyCheckInAt(cfg) {
	const t = cfg && cfg.lastCheckIn ? new Date(cfg.lastCheckIn).getTime() : NaN;
	return Number.isFinite(t) ? t : null;
}
function emergencyPhase(cfg, now) {
	if (!cfg || !cfg.contactPubKey) return 'off';
	if (cfg.releasedAt) return 'released';
	// FAIL-SAFE: a missing/unparseable check-in time, or a non-finite inactivity/grace window (a corrupt or
	// partially written config), must NEVER be read as "the owner has been silent forever" and fire the switch.
	// Treat any of those as freshly armed — the dead-man switch only ever releases on a real, positive elapsed time.
	const t = emergencyCheckInAt(cfg);
	if (t === null || !Number.isFinite(cfg.inactivityMs) || !Number.isFinite(cfg.graceMs)) return 'armed';
	const elapsed = emergencyElapsed(cfg, now, t);
	if (elapsed > cfg.inactivityMs + cfg.graceMs) return 'due';   // release now
	if (elapsed > cfg.inactivityMs) return 'grace';               // past inactivity, still inside the veto window
	return 'armed';
}
// Elapsed since the last check-in, MINUS any detected forward clock jump ("drift credit"). A wall-clock jump
// forward (an NTP correction of a badly-wrong clock, a manual change, a VM resumed with an adjusted clock) would
// otherwise inflate the elapsed time and fire the switch early. The service's health tick tells a real jump apart
// from ordinary sleep with the monotonic clock and records the spurious amount here (emergencyNoteClockDrift), so
// only FAKE time is discounted — genuine time away, whether the machine was on or off, still counts. Never negative.
function emergencyElapsed(cfg, now, t) {
	const credit = Number(cfg && cfg.driftCreditMs) || 0;
	return Math.max(0, (now - t) - (credit > 0 ? credit : 0));
}
// A trusted contact runs this on THEIR device and gives the owner only the public key; the private key stays
// with them. Exposed so the CLI/UI can generate one.
function emergencyKeypair() { return Emergency.generateContactKeypair(); }
async function emergencyEnroll({ contactPubKey, contactLabel, inactivityDays, graceDays } = {}) {
	if (!contactPubKey) throw new Error('The contact\'s public key is required — they generate it once and share only the public half.');
	try { Emergency.seal(contactPubKey, 'validate'); } catch (_) { throw new Error('That does not look like a valid contact public key.'); }
	const inactivityMs = Math.max(1, Number(inactivityDays) || 30) * 86400000;
	// Guard against a non-numeric graceDays: Math.max(0, NaN) is NaN, which would persist a NaN graceMs and corrupt
	// the dead-man-switch timing. A non-finite or negative value falls back to the 14-day default.
	const g = Number(graceDays);
	const graceMs = (Number.isFinite(g) && g >= 0 ? g : 14) * 86400000;
	// If the enrolled contact's KEY changes, every already-armed vault was sealed to the OLD key: the old contact
	// could still open a released blob (a confidentiality leak) and the NEW contact could not open it at all. We
	// cannot re-seal without the old contact's private key, so the fail-safe is to DROP the stale armed grants and
	// have the user re-arm for the new contact. A label-only change (same key) keeps the grants. Computed inside the
	// single locked read-modify-write so it reflects the exact prior state.
	let rearmNeeded = 0;
	await mutateSettings(cur => {
		const prev = cur.emergency || {};
		const contactChanged = !!(prev.contactPubKey && prev.contactPubKey !== contactPubKey);
		rearmNeeded = contactChanged ? Object.keys(prev.armed || {}).length : 0;
		return { ...cur, emergency: { ...prev, contactPubKey, contactLabel: contactLabel || 'Trusted contact', inactivityMs, graceMs, lastCheckIn: new Date().toISOString(), driftCreditMs: 0, armed: contactChanged ? {} : (prev.armed || {}), releasedAt: null } };
	});
	return { enrolled: true, rearmNeeded };
}
async function emergencyArm(vaultDir, { password } = {}) {
	const cfg = (await getSettings()).emergency;
	if (!cfg || !cfg.contactPubKey) throw new Error('Set up a trusted contact first (emergency enroll).');
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (isCloudVault(manifest)) throw new Error('Emergency access is not yet supported for cloud vaults.');
	const cap = await makeReadCap(abs, { password, label: 'Emergency access — ' + cfg.contactLabel });
	const sealed = Emergency.seal(cfg.contactPubKey, cap.token);
	const vaultId = (manifest.integrity || {}).pubkey || abs;
	const rec = { path: abs, name: displayName(abs), sealed, at: new Date().toISOString() };
	await mutateSettings(cur => ({ ...cur, emergency: { ...cur.emergency, armed: { ...(cur.emergency.armed || {}), [vaultId]: rec } } }));
	return { armed: true, vault: abs };
}
async function emergencyCheckIn() {
	return emergencyQueue(async () => {
		const cfg = (await getSettings()).emergency;
		if (!cfg || !cfg.contactPubKey) throw new Error('No emergency access is set up.');
		// A check-in re-baselines the timer AND clears any accumulated clock-drift credit: the owner is present, the
		// clock is trusted as of now, so past jumps no longer matter.
		await mutateSettings(cur => ({ ...cur, emergency: { ...cur.emergency, lastCheckIn: new Date().toISOString(), driftCreditMs: 0, releasedAt: null } }));
		try { await fsp.rm(path.join(Common.dataDir(), EMERGENCY_RELEASE_DIR), { recursive: true, force: true }); } catch (_) {} // a check-in vetoes a release
		return { checkedIn: true };
	});
}
// Record a detected forward clock jump so the dead-man timer discounts it (see emergencyElapsed). Called by the
// service's health tick, which distinguishes a real jump from sleep with the monotonic clock. Serialized with the
// other emergency mutations and a no-op unless enrolled; best-effort — it must never disturb the health tick.
async function emergencyNoteClockDrift(jumpMs) {
	const ms = Number(jumpMs);
	if (!(ms > 0)) return { noted: false };
	return emergencyQueue(async () => {
		const cfg = (await getSettings()).emergency;
		if (!cfg || !cfg.contactPubKey || cfg.releasedAt) return { noted: false };
		// Cap the accumulated credit at one full inactivity+grace window. The credit only needs to offset up to a
		// window of spurious time; letting it grow without bound would let a flapping clock (or a local attacker
		// repeatedly jumping the clock forward) hold effective elapsed near zero forever and suppress a LEGITIMATE
		// release indefinitely. With the cap, a genuinely inactive owner's switch is delayed by at most one window,
		// while any realistic single jump (hours to days) stays far under the window and never fires it early.
		const cap = (Number(cfg.inactivityMs) || 0) + (Number(cfg.graceMs) || 0);
		await mutateSettings(cur => ({ ...cur, emergency: { ...cur.emergency, driftCreditMs: Math.min(cap, (Number(cur.emergency && cur.emergency.driftCreditMs) || 0) + ms) } }));
		return { noted: true };
	});
}
async function emergencyStatus() {
	const cfg = (await getSettings()).emergency;
	if (!cfg || !cfg.contactPubKey) return { enrolled: false };
	const now = Date.now();
	const t = emergencyCheckInAt(cfg);
	// daysUntilRelease is only meaningful with a real check-in time and finite windows; otherwise report null rather
	// than a NaN or a misleading 0 (mirrors the fail-safe in emergencyPhase, which treats such a config as armed).
	const known = t !== null && Number.isFinite(cfg.inactivityMs) && Number.isFinite(cfg.graceMs);
	const daysUntilRelease = known ? Math.max(0, Math.ceil((cfg.inactivityMs + cfg.graceMs - emergencyElapsed(cfg, now, t)) / 86400000)) : null;
	return { enrolled: true, contactLabel: cfg.contactLabel, inactivityDays: Math.round((cfg.inactivityMs || 0) / 86400000), graceDays: Math.round((cfg.graceMs || 0) / 86400000), lastCheckIn: cfg.lastCheckIn, phase: emergencyPhase(cfg, now), releasedAt: cfg.releasedAt || null, daysUntilRelease, armed: Object.values(cfg.armed || {}).map(a => ({ name: a.name, at: a.at })) };
}
// Best-effort periodic check (wired into the service's schedule tick). Releases when overdue, else no-op.
async function emergencyTick(now = Date.now()) {
	// Read the config and decide to release INSIDE the queue, so a check-in cannot land between the decision and
	// the release. A check-in already waiting on the queue runs first and moves lastCheckIn out of "due", so the
	// release is correctly skipped; one that arrives after runs next and withdraws the just-made release cleanly.
	return emergencyQueue(async () => {
		// Read settings FRESH, past the short read memo: a check-in committed by ANOTHER process (a CLI
		// `emergency-checkin`) in the last second would otherwise be invisible to this service's memoized copy, so
		// the tick could release access a valid check-in just vetoed. The tick is infrequent, so the memo saves
		// nothing here; dropping it closes the cross-process veto window.
		invalidateSettingsMemo();
		let cfg; try { cfg = (await getSettings()).emergency; } catch (_) { return { phase: 'off' }; }
		const phase = emergencyPhase(cfg, now);
		if (phase !== 'due') return { phase };
		return await emergencyRelease(cfg, now);
	});
}
async function emergencyRelease(cfg, now) {
	const dir = path.join(Common.dataDir(), EMERGENCY_RELEASE_DIR);
	// Guard the filesystem writes: a failure here (disk full, a read-only data dir) must NOT reject out of the
	// health tick's emergencyTick. releasedAt is stamped only AFTER the writes succeed, so a failed release leaves
	// the phase 'due' and the next tick retries — the release is idempotent.
	try {
		await fsp.mkdir(dir, { recursive: true });
		for (const [vaultId, a] of Object.entries(cfg.armed || {})) {
			// Name the file after the vault for the contact's benefit, but disambiguate with a short hash of the
			// unique vault id: two vaults whose display names sanitize to the same string (e.g. "My Vault" and
			// "My/Vault") would otherwise write to the same ".sealed" file and one contact grant would be lost.
			const base = String(a.name || vaultId).replace(/[^\p{L}\p{N}.-]/gu, '_') || 'vault'; // keep accented/CJK letters in the filename hint (ASCII \w would strip them); the sha256 tag below still guarantees uniqueness
			const idTag = Common.sha256Hex(String(vaultId)).slice(0, 10);
			await fsp.writeFile(path.join(dir, base + '-' + idTag + '.sealed'), a.sealed, 'utf8');
		}
		await fsp.writeFile(path.join(dir, 'HOW-TO-OPEN.txt'), emergencyReadme(cfg));
	} catch (e) {
		try { Common.warn('Emergency access is due but the release files could not be written (' + (e && e.message || e) + '); will retry on the next check.'); } catch (_) {}
		return { released: false, error: e && e.message };
	}
	await mutateSettings(cur => ({ ...cur, emergency: { ...cur.emergency, releasedAt: new Date(now).toISOString() } }));
	try { Common.warn('Emergency access RELEASED: no check-in within the inactivity + grace window. The sealed read access for ' + cfg.contactLabel + ' is now in ' + dir + '. If this is a mistake, check in and it will be withdrawn.'); } catch (_) {}
	return { released: true, dir, count: Object.keys(cfg.armed || {}).length };
}
function emergencyReadme(cfg) {
	return ['How to open this emergency access', '', 'These ".sealed" files each contain read-only access to a vault, sealed to your',
		'public key. Only your private key can open them. On a computer with ' + Brand.name + ':', '',
		'  ' + Brand.cli + ' emergency-open <file>.sealed --key <your-private-key>', '',
		'That prints a read link. Mount a copy of the vault with it:', '',
		'  ' + Brand.cli + ' mount <vault-folder> --read-cap <the-read-link>', '',
		'You can read the files. You cannot change the vault, its keys, or its owner.'].join('\n') + '\n';
}
// The contact side: open a sealed blob with their private key, recovering the read link.
function emergencyOpen(privateKey, sealed) { return Emergency.open(privateKey, String(sealed).trim()); }
async function emergencyDisarm() {
	return emergencyQueue(async () => {
		await mutateSettings(cur => { const n = { ...cur }; delete n.emergency; return n; });
		try { await fsp.rm(path.join(Common.dataDir(), EMERGENCY_RELEASE_DIR), { recursive: true, force: true }); } catch (_) {} // serialized with the release tick, so a disarm can't be overwritten by a release that read settings just before it
		return { disarmed: true };
	});
}

// ---- Per-vault decoy (duress) protection ----
//
// Pair a real vault with a separate DECOY vault; opening the real vault with the decoy vault's password
// transparently opens the decoy instead. The pairing lives in a uniform encrypted registry (never in the
// vault's manifest), so WHICH vault a decoy protects, and HOW MANY decoys exist, are invisible in the file.
// The registry file's presence does reveal that the decoy feature is in use (an honest, disclosed limit; the
// alternative — a permanently-present registry — cannot tell a wrong manager password from first-time setup
// without risking orphaned or clobbered pairings). The mount path consults it ONLY when a normal unlock fails,
// so a vault with no decoy pays nothing. See lib/Decoy.js.
function decoyProtected() { return Decoy.hasRegistry(); }
// Public fingerprints of a paired vault, taken from its manifest alone (NO password): the stable identity — to
// tell if a DIFFERENT vault later sits at the same path — and a hash of the passphrase-family key-slot wrapped
// keys, which changes when the vault's password changes (the change rewrites the opened slot). Used only by the
// manager-authenticated decoy list, so a pairing that has silently gone stale can be surfaced there.
function decoyVaultFp(manifest) {
	const slots = keySlotsOf((manifest && manifest.crypt) || {}).filter(s => s.kind !== 'member').map(s => String(s.wrappedKey || '')).sort();
	return { id: Integrity.vaultId(manifest), keyFp: Common.sha256Hex(slots.join('\n')) };
}
// Judge whether a stored pairing still holds, from the vaults' current PUBLIC manifests (read raw — no self-heal,
// no password). A real vault that moved breaks the path match the redirect needs; a decoy that moved cannot open;
// a vault replaced by a different one, or a decoy whose keys changed (a password change), means the recorded decoy
// password may no longer trigger the redirect. Returns { status, warning } for the manager view; 'ok' or, for a
// pairing made before this check existed, 'unverified' (only a missing vault is still detectable there).
async function decoyMappingStatus(mp) {
	const fp = mp.fingerprints || null;
	const real = await readManifestRaw(mp.realVault).catch(() => null);
	if (!real) return { status: 'real-missing', warning: 'The protected vault is no longer at its recorded location, so the duress redirect will not trigger. Re-pair after moving it.' };
	if (fp && fp.real && fp.real.id && Integrity.vaultId(real) !== fp.real.id) return { status: 'real-replaced', warning: 'A different vault now sits at the protected vault\'s location. Re-pair to restore duress protection.' };
	const decoy = await readManifestRaw(mp.decoyVault).catch(() => null);
	if (!decoy) return { status: 'decoy-missing', warning: 'The decoy vault is missing or has moved, so the decoy cannot open. Re-pair after moving it.' };
	if (fp && fp.decoy && fp.decoy.id && Integrity.vaultId(decoy) !== fp.decoy.id) return { status: 'decoy-replaced', warning: 'A different vault now sits at the decoy vault\'s location. Re-pair to restore duress protection.' };
	if (fp && fp.decoy && fp.decoy.keyFp && decoyVaultFp(decoy).keyFp !== fp.decoy.keyFp) return { status: 'decoy-keys-changed', warning: 'The decoy vault\'s keys have changed since pairing (a password change, for example), so its password may no longer trigger the duress redirect. Re-pair to be sure.' };
	if (!fp) return { status: 'unverified', warning: 'This pairing predates the staleness check. Re-pair it to confirm the decoy still triggers and to enable ongoing checks.' };
	return { status: 'ok', warning: null };
}
async function decoySet({ realVault, decoyVault, decoyPassword, managerPassword } = {}) {
	const realAbs = resolveVaultDir(realVault), decoyAbs = resolveVaultDir(decoyVault);
	const realManifest = await readManifest(realAbs);   // both must be real vaults
	const decoyManifest = await readManifest(decoyAbs);
	if (!hasKeyWrapping(realManifest.crypt) || !hasKeyWrapping(decoyManifest.crypt)) throw new Error('Both vaults must support key wrapping (format 3 or newer).');
	// The decoy password must actually open the decoy vault (the mount uses it to unlock the decoy), so verify
	// it now rather than letting a mistyped pairing fail only under duress.
	if (!(await unlockCredential(decoyPassword, decoyManifest).catch(() => null))) throw new Error('That password does not open the decoy vault. Use the decoy vault\'s own password.');
	// The decoy password must NOT also open the REAL vault: the mount only redirects to the decoy AFTER the real
	// vault fails to unlock, so a password that opens the real vault would reveal the real vault under duress and
	// never trigger the decoy. Reject it at pairing time rather than let the protection silently do nothing.
	if (await unlockCredential(decoyPassword, realManifest).catch(() => null)) throw new Error('That password also opens the real vault, so unlocking with it would reveal the real vault instead of the decoy. Pick a decoy whose password differs from every password of the real vault.');
	// Record public fingerprints of both vaults so the manager view can later detect a pairing gone stale. The real
	// vault only needs its identity (a moved real vault is caught by the missing-path check; its password is
	// irrelevant to the trigger); the decoy needs identity + key fingerprint (a decoy password change is the main
	// silent-breakage case). Computed from the manifests already read above — no extra password handling.
	const fingerprints = { real: { id: Integrity.vaultId(realManifest) }, decoy: decoyVaultFp(decoyManifest) };
	return Decoy.setDecoy({ realVault: realAbs, decoyVault: decoyAbs, decoyPassword, managerPassword, fingerprints });
}
async function decoyRemove({ realVault, managerPassword } = {}) {
	return Decoy.removeDecoy({ realVault: resolveVaultDir(realVault), managerPassword });
}
async function decoyList(managerPassword) {
	const mappings = await Decoy.listMappings(managerPassword);
	if (mappings == null) return null; // wrong manager password (or no registry) — indistinguishable, as before
	// Annotate each pairing with a staleness status. This runs ONLY after the manager password verified, so it adds
	// no observable to the decoy-password mount path and leaks nothing to a decoy-password-only adversary.
	return Promise.all(mappings.map(async (mp) => ({ realVault: mp.realVault, decoyVault: mp.decoyVault, ...(await decoyMappingStatus(mp)) })));
}

// macOS only: set the Finder "bundle" bit so a .vault folder is presented as a
// single package item the user cannot casually open and delete a file from. This is
// the closest thing to "one file" without giving up cross-platform portability.
// Best-effort — never fatal, and a no-op on other platforms.
async function markAsPackage(dir) {
	if (process.platform !== 'darwin') return;
	try {
		// 32-byte FinderInfo with the folder's Finder flags (bytes 8–9) set to the
		// kHasBundle bit (0x2000).
		const finderInfo = '0000000000000000200000000000000000000000000000000000000000000000';
		await Rclone.exec('xattr', ['-wx', 'com.apple.FinderInfo', finderInfo, dir]);
	} catch (_) {}
}

// Check a vault's health. Always verifies the manifest (and repairs the redundant
// copy). With a password it also confirms the password and, when deep, reads every
// file through the encryption so any corrupted or tampered chunk is detected. Never
// mounts. Returns a structured report.
async function verify(vaultDir, { password, deep = true } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const report = { vault: abs, manifest: 'unreadable', password: null, integrity: null, files: 0, syncIssues: [], errors: [], ok: false };
	report.syncIssues = await scanSyncArtifacts(abs); // sync-tool leftovers in the store (best-effort)

	let manifest;
	try { manifest = await readManifest(abs); } // resilient read repairs/ensures the backup copy
	catch (e) {
		// A valid but too-new vault is not "unreadable" — say what it actually is.
		report.manifest = e.newerFormat ? 'newer format — update the tool to open it' : 'unreadable';
		report.errors.push('manifest: ' + e.message); return report;
	}
	const hasPrimary = await exists(path.join(abs, MANIFEST));
	const hasBackup = await exists(path.join(abs, MANIFEST_BAK));
	report.manifest = hasPrimary && hasBackup ? 'ok (with backup)' : 'ok';

	if (!password) { report.ok = true; return report; }

	const bin = RcloneSetup.resolve();
	if (!bin) throw new Error('The encryption engine is not available. Run "' + Brand.cli + ' setup" while online.');
	await withVaultConfig(bin, abs, password, manifest, undefined, async (cfg) => {
		report.password = (await verifyPassword(bin, cfg, manifest)) ? 'ok' : 'wrong';
		if (report.password !== 'ok') { report.errors.push('wrong password'); return; }

		const listed = await Rclone.run(bin, ['lsf', '-R', '--files-only', 'vault:'], { configPath: cfg, maxOutBytes: MAX_LISTING_BYTES });
		if (listed.status !== 0) { report.errors.push('could not list the vault: ' + (listed.stderr || listed.status).toString().trim()); return; }
		report.files = parseLsf(listed.stdout).length;

		if (deep) {
			// Read every file through the encryption; a bad chunk fails authentication.
			// Stdout is discarded so this is memory-safe on large vaults.
			const scan = await Rclone.run(bin, ['cat', 'vault:'], { configPath: cfg, discardStdout: true, timeoutMs: 60 * 60 * 1000 });
			if (scan.status === -1) { report.integrity = 'inconclusive'; report.errors.push('integrity scan did not finish in time'); }
			else if (scan.status !== 0 || hasIntegrityFailure(scan.stderr)) {
				report.integrity = 'corrupt';
				report.errors.push(...integrityFailureLines(scan.stderr).slice(-5));
			} else report.integrity = 'ok';
		}
	});

	report.ok = report.password === 'ok' && report.integrity !== 'corrupt';
	return report;
}

// ---------------------------------------------------------------------------
// Tamper detection: snapshot + audit
// ---------------------------------------------------------------------------

// OS-generated junk that is not user data — the system creates, moves, and deletes these on
// its own (Finder metadata and AppleDouble sidecars, Spotlight/Trash caches, FUSE/NFS
// "silly-rename" placeholders). Excluded from the tamper file set, together with the vault's
// own control files, so the OS's own churn between sessions never reads as tampering.
// Operating-system and tool-generated control files that appear and disappear on their own; they
// are not user content, so they must never register as a tamper. `.metadata_never_index` is written
// by this tool itself (through the mount, to keep the system indexer out of the vault), so it must
// be ignored too — otherwise it shows as an "added" file on the next mount and, on a sealed vault
// that is never auto-refreshed, would raise a false tamper alarm on every mount thereafter.
// Built from the shared OS-junk core (regex-escaped) PLUS the extra macOS/FUSE/NFS metadata and wildcards the
// integrity scan must also exclude — so the common names can't drift from the mount-empty list. The commonhelpers
// test pins the exact matched set against a golden list, so a build-logic slip here is caught.
const IGNORED_BASENAME = new RegExp('^(' + [
	...OS_JUNK_COMMON.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
	'\\._.*', '\\.metadata_never_index', '\\.TemporaryItems', '\\.DocumentRevisions-V100', '\\.apDisk', '\\.fuse_hidden.*', '\\.nfs.*'
].join('|') + ')$');
function isIgnoredVaultPath(p) {
	const base = p.slice(p.lastIndexOf('/') + 1);
	// EXACTLY the tool's own metadata blobs: the baseline snapshot and the session marker, plus each one's
	// ".new" write-temp (both are written temp-then-renamed). Matched exactly, NOT by prefix — a prefix
	// match would let a holder of the read key plant a tamper-invisible file (e.g. ".vaultsnapshot-x"),
	// defeating the point of the tamper check. Everything else here is transient OS/tool control-file noise.
	return INTERNAL_VAULT_OBJECTS.has(base) || IGNORED_BASENAME.test(base); // the tool's own blobs (single-sourced set) + transient OS/tool noise
}

// The tamper scan runs inside the mount's timeout budget, so its engine calls are bounded well
// under it — a wedged backing store frees the mount (and cleans the ephemeral config) promptly
// instead of leaving a listing running for many minutes.
const AUTO_SCAN_TIMEOUT_MS = 18000;

// Capture the vault's file set as [{ path, size, hash? }]. Two depths:
//   fast (deep=false): paths + sizes from a directory listing — NO decryption, so it is
//     quick even on a large vault. This is what the on-mount check and the auto baseline use.
//   deep (deep=true):  also a content hash of every file, which requires reading and
//     decrypting each file (so it also proves the content is intact). Used by the manual
//     snapshot/audit for a thorough, rollback-proof check.
// The canary and the snapshot file itself are always excluded so they never show as changes.
// Extract the names of any files/dirs the engine could not decrypt from a listing's stderr. rclone crypt
// SKIPS every entry in the store whose encrypted name it cannot decode, logging one
// "NOTICE: <name>: Skipping undecryptable file name: <reason>" (or "dir name") per entry — and those are
// exactly the entries a decrypted-view listing can never show. In a healthy vault nothing triggers this:
// every file the vault writes has a valid encrypted name. A hit therefore means a foreign file was dropped
// straight into the encrypted store by someone WITHOUT the key (it cannot decrypt, so it never surfaces as
// a real file when mounted), or a stored name was corrupted. rclone's own cryptcheck does not report these,
// so we parse the notice ourselves — the one reliable way to see files that live outside the crypt view.
function foreignCipherNames(stderr) {
	const names = [];
	for (const line of String(stderr || '').split(/\r?\n/)) {
		const idx = line.indexOf(': Skipping undecryptable ');
		if (idx < 0) continue;
		// Drop the log prefix (timestamp + level) but keep the name verbatim, so a foreign name that itself
		// contains spaces is preserved. Key on the stable level keyword rather than a fixed column layout.
		const name = line.slice(0, idx).replace(/^.*?(?:NOTICE|ERROR|WARNING|INFO):\s*/, '').trim();
		names.push(name || '(unnamed)');
	}
	return names;
}

// A self-explanatory finding for foreign/undecryptable files in the encrypted store: what it means and
// what to do, naming a few offenders (capped so a flood of them never floods the message).
function foreignNote(names) {
	const n = names.length;
	const shown = names.slice(0, 5).join(', ');
	const more = n > 5 ? ', and ' + (n - 5) + ' more' : '';
	return n + ' file' + (n === 1 ? '' : 's') + ' in the encrypted store could not be decrypted (' + shown + more + ') — '
		+ 'added or changed outside the vault by someone without the password, or corrupted. Remove them from the '
		+ "vault's data folder after checking they are not yours, then re-audit.";
}

// Iterate the lines of a (possibly very large) engine listing WITHOUT freezing the event loop. A single
// str.split(/\r?\n/) over a listing near MAX_LISTING_BYTES allocates one giant array and the loop over it runs as
// one uninterruptible burst, stalling every request and the health watch — the same reason merkleRoot and
// compareFileSets yield. This scans line-by-line with indexOf (no whole-file array) and yields every
// LINE_YIELD_EVERY lines. A normal (small) listing never reaches a yield, so it pays nothing.
const LINE_YIELD_EVERY = 8192;
async function forEachLine(str, fn) {
	let start = 0, count = 0;
	while (start <= str.length) {
		let nl = str.indexOf('\n', start);
		if (nl === -1) nl = str.length;
		let end = nl;
		if (end > start && str.charCodeAt(end - 1) === 13) end--; // trim a trailing \r (CRLF)
		if (end > start) fn(str.slice(start, end));
		if (nl === str.length) break;
		start = nl + 1;
		if (++count % LINE_YIELD_EVERY === 0) await Common.yieldToLoop();
	}
}
async function captureFiles(bin, cfg, { deep, timeoutMs }) {
	// Sizes (and the authoritative path list) come from lsf. "sp" => "<size>;<path>"; the path
	// is everything after the first ';', so a ';' inside a name is preserved.
	const l = await Rclone.run(bin, ['lsf', '-R', '--files-only', '--format', 'sp', 'vault:'], { configPath: cfg, timeoutMs: timeoutMs || 15 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES });
	if (l.status === -1) throw new Error('Listing the vault did not finish in time.');
	if (l.status !== 0) throw new Error('Could not list the vault: ' + engineTail(l));
	// Foreign/undecryptable entries the crypt view skips — surfaced so the tamper check can flag them.
	// A cloud-sync tool's conflicted-copy of an encrypted blob is ALSO undecryptable-by-name, but it is a
	// benign leftover, not tampering — scanSyncArtifacts reports those as sync issues to resolve. Split them
	// out of `foreign` (so a synced-folder vault is not falsely flagged as tampered) into `syncForeign`, so
	// callers can still surface them — a file dropped in and NAMED like a sync conflict is never fully silent.
	const undecryptable = foreignCipherNames(l.stderr);
	const foreign = undecryptable.filter(n => !classifySyncName(n));
	const syncForeign = undecryptable.filter(n => classifySyncName(n));
	const sizes = new Map();
	await forEachLine(l.stdout, (line) => {
		const i = line.indexOf(';');
		if (i < 0) return;
		const p = line.slice(i + 1);
		if (isIgnoredVaultPath(p)) return;
		const n = parseInt(line.slice(0, i), 10);
		sizes.set(p, Number.isFinite(n) ? n : null);
	});
	if (!deep) return { files: await filesFromSizes(sizes, null), foreign, syncForeign };

	// --download makes the engine read and decrypt each file to hash its PLAINTEXT content;
	// without it the encrypted store reports "hash unsupported" (it stores no plaintext hash).
	// Cap the retained output like the listing above: without a ceiling the hashsum text for a vault with millions
	// of files could grow to gigabytes in memory over the up-to-one-hour window.
	const h = await Rclone.run(bin, ['hashsum', SNAPSHOT_HASH, 'vault:', '--download'], { configPath: cfg, timeoutMs: 60 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES });
	if (h.status === -1) throw new Error('The integrity scan did not finish in time.');
	if (h.status !== 0 || hasIntegrityFailure(h.stderr)) {
		throw new Error('Could not scan the vault: ' + engineTail(h));
	}
	const hashes = new Map();
	await forEachLine(h.stdout, (line) => {
		// The engine emits "<hex-hash><two spaces><path>". Split on that fixed two-space separator
		// and keep the rest verbatim, so a filename that itself begins with a space is preserved
		// exactly (a greedy whitespace match would eat it, dropping that file to a size-only check).
		const m = line.match(/^([0-9a-fA-F]+) {2}(.*)$/);
		if (!m) return;
		if (isIgnoredVaultPath(m[2])) return;
		hashes.set(m[2], m[1].toLowerCase());
	});
	return { files: await filesFromSizes(sizes, hashes), foreign, syncForeign };
}
// Materialize the file-set array from the sizes map (plus optional per-path hashes) WITHOUT one long synchronous
// burst: on a vault with millions of entries, `[...map].map(...)` builds every object in a single uninterruptible
// pass — the same stall class forEachLine was added to avoid, just moved to materialization. This yields to the loop
// periodically. A normal vault is far below the yield step and pays nothing.
async function filesFromSizes(sizes, hashes) {
	const files = new Array(sizes.size);
	let i = 0;
	for (const [p, size] of sizes) { files[i] = hashes ? { path: p, size, hash: hashes.get(p) || null } : { path: p, size }; if (++i % LINE_YIELD_EVERY === 0) await Common.yieldToLoop(); }
	return files;
}

// The snapshot-signing key is derived from the vault's MASTER secret (the same secret the
// engine is given), not from the password directly. This keeps it stable across a password
// change (which only re-wraps the master, never changing it) and lets an unmount refresh the
// baseline from the secret held for the live session without re-prompting. An offline
// attacker never has the master, so they still cannot forge a snapshot.
// The baseline's symmetric HMAC key, derived from the vault MASTER secret (stable across a
// password change). Paired with an Ed25519 keypair (also master-derived) so every baseline
// carries both a symmetric tag (the owner's forgery-resistance) and a signature the PUBLIC key
// can verify without the password. Bundled together and derived once from a single master.
// The integrity keys for a snapshot: an HMAC key (a secondary integrity check, keyed to the read key
// and the stable engine salt) and the Ed25519 signing key pair. The signing PRIVATE key comes only
// from the WRITE SEED, so a read-only credential (writeSeed = null) gets no private key — it can still
// verify against the published public key, but it cannot sign. This is what makes a write authentic
// and unforgeable by a read holder.
function integrityKeys(master, writeSeed, manifest) {
	const salt = Buffer.from(String(manifest.crypt.salt), 'utf8');
	const hmacKey = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(master, 'base64'), salt, Buffer.from('vdisk-snapshot-hmac-v1'), 32));
	if (writeSeed) { const sk = Integrity.signKeysFromSeed(writeSeed); return { hmacKey, signPriv: sk.priv, signPub: sk.pub }; }
	return { hmacKey, signPriv: null, signPub: Integrity.pubkeyOf(manifest) };
}

// The signing input both tags cover, plus the HMAC over it. The Merkle root commits to every
// file, so this binds the whole vault state (root), its monotonic version (seq), its lineage
// (prevRoot), and the timestamp.
function baselineHmac(hmacKey, fields) {
	return crypto.createHmac('sha256', hmacKey).update(Integrity.signingInput(fields)).digest('hex');
}

// The manifest's snapshot fingerprint — a password-less CACHE of the signed baseline's identity, kept in the
// (unencrypted) manifest so `fingerprint` can report the vault's version and content fingerprint without a
// password. It carries EVERY field the baseline's HMAC binds (prevRoot and version included), so the
// fingerprint is SELF-VERIFYING: a reader can recompute its HMAC from its own fields and confirm the vault's
// own key produced it — independent of whether it names the exact same baseline as the in-vault record. That
// is what lets a FORGED fingerprint be caught while a benign LAG (an authentic fingerprint of a slightly
// older or newer baseline, left behind when a snapshot write was interrupted) is not mistaken for tampering.
// `fields` is the same object passed to baselineHmac; `auto` is informational (not part of the signed input).
function snapshotFingerprint(fields, hmac, auto) {
	return { at: fields.createdAt, seq: fields.seq, root: fields.root, prevRoot: fields.prevRoot || null, hmac, count: fields.count, version: fields.version, deep: !!fields.deep, auto: !!auto, sealed: !!fields.sealed };
}

// True when a manifest fingerprint's HMAC recomputes from its own fields (an authentic fingerprint this vault's
// key produced), false when it does not (its fields or HMAC were altered — tampering), or null when it cannot be
// decided because the fingerprint predates the self-verifying shape (no prevRoot/version). A pre-existing
// fingerprint is therefore treated as unverifiable rather than forged, so an upgraded vault never false-alarms
// before its next snapshot rewrites the fingerprint in the richer shape.
function fingerprintAuthentic(fp, hmacKey) {
	if (!fp || fp.prevRoot === undefined || fp.version == null) return null; // not independently checkable (legacy shape)
	const fields = { scheme: Integrity.SCHEME, root: fp.root, seq: fp.seq, prevRoot: fp.prevRoot, count: fp.count, createdAt: fp.at, version: fp.version, sealed: !!fp.sealed, deep: !!fp.deep };
	return Integrity.equalHex(baselineHmac(hmacKey, fields), fp.hmac);
}

// Is this vault KNOWN to be sealed (the strict, never-auto-refreshed tripwire)? Used on the no-record paths — where
// the in-vault baseline reads as absent — to refuse silently replacing a missing seal with a fresh unsealed baseline.
// The local ledger's sealed anchor is the authoritative, attacker-inaccessible source; the manifest's snapshot.sealed
// is a fallback for a vault this device has not recorded, and it is trusted ONLY when the fingerprint self-verifies
// (so an attacker who edits snapshot.sealed to false cannot fake "not sealed" — the edit breaks the fingerprint, and
// a genuinely-sealed vault this device has ever mounted has the ledger anchor regardless). Shared by audit and the
// on-mount check so the seal-authority decision lives in exactly one place.
async function knownSealed(manifest, hmacKey) {
	const ledger = await Integrity.lastSeen(Integrity.vaultId(manifest));
	if (ledger && ledger.sealed) return true;
	const fp = manifest && manifest.snapshot;
	return !!(fp && fp.sealed && fingerprintAuthentic(fp, hmacKey) === true);
}

// The exact bytes the MANIFEST SEAL (a write-key signature stored in the manifest) covers: the vault's
// stable security fields — its salt, its set of key slots (each as id + a hash of the wrapped key + its
// KDF level), and the published verification key. It excludes the snapshot summary (already signed by the
// baseline) and the seal itself. A robust, order-independent form so a JSON round-trip can never change
// it. This seals the manifest against tampering with its key slots or settings, and gives a third party a
// value to confirm the manifest is authentic — defense in depth: a changed salt or KDF already breaks
// unlock, and a swapped published key is caught by the identity check, but the seal covers the whole set.
function manifestSealInput(manifest) {
	const c = (manifest && manifest.crypt) || {};
	// The write-seed seal covers the passphrase-family slots (salt, published verify key, each slot's wrapped-key
	// hash + KDF level). MEMBER slots are deliberately excluded here — they are covered instead by the OWNER-key
	// roster signature (see rosterSealInput), so a write member can re-seal their own password slot without holding
	// the owner key, and membership can only be changed by an owner.
	// v2 folds each slot's FULL KDF (Kdf.sealTag: cost params + salt + hashLen + algo/version), closing the gap where
	// levelOf alone left salt/hashLen unsealed. The signature binds to this exact string, so a vault sealed at v2 is
	// fully covered; a legacy v1 seal is still accepted by manifestSealVerifies until the vault is next re-sealed.
	const slots = keySlotsOf(c).filter(s => s.kind !== 'member').map(s => s.id + ':' + crypto.createHash('sha256').update(String(s.wrappedKey || '')).digest('hex') + ':' + Kdf.sealTag(s.kdf)).sort();
	return ['vault-manifest-seal-v2', Integrity.SCHEME, String(c.salt || ''), (manifest.integrity && manifest.integrity.pubkey) || '', slots.join(',')].join('\n');
}
// The legacy v1 seal input (each slot folded to Kdf.levelOf — cost parameters only). Kept ONLY so manifests sealed
// by an earlier build still verify; new seals are always written at v2 by manifestSealInput above.
function manifestSealInputLegacy(manifest) {
	const c = (manifest && manifest.crypt) || {};
	const slots = keySlotsOf(c).filter(s => s.kind !== 'member').map(s => s.id + ':' + crypto.createHash('sha256').update(String(s.wrappedKey || '')).digest('hex') + ':' + Kdf.levelOf(s.kdf)).sort();
	return ['vault-manifest-seal-v1', Integrity.SCHEME, String(c.salt || ''), (manifest.integrity && manifest.integrity.pubkey) || '', slots.join(',')].join('\n');
}
// Verify a manifest's write-seed seal, accepting the current v2 input OR a legacy v1 seal. The signature binds to
// the exact input version it was made over, so accepting v1 only helps genuine v1 seals — a v2-sealed vault whose
// KDF salt/hashLen was mutated fails BOTH (the v2 input changed, and the stored sig was never over the v1 string).
function manifestSealVerifies(manifest, pub, sig) {
	try { if (Integrity.verify(pub, manifestSealInput(manifest), sig)) return true; } catch (_) {}
	try { if (Integrity.verify(pub, manifestSealInputLegacy(manifest), sig)) return true; } catch (_) {}
	return false;
}
// Verify a manifest's OWN security seal — the write-key signature over its salt, key slots, and published verify
// key. Password-free (a public verification). Returns { sealed, ok }: sealed=false when there is no seal to check
// (an un-snapshotted or legacy vault), otherwise ok is whether the seal verifies. Single-sourced so the mount
// check, the audit report, and the boot self-check all judge a manifest the same way — and so an altered or
// half-written manifest (its key slots or settings no longer matching the seal) is caught consistently.
function checkManifestSeal(manifest) {
	if (!(manifest && manifest.integrity && manifest.integrity.manifestSig && manifest.integrity.pubkey)) return { sealed: false, ok: true };
	return { sealed: true, ok: manifestSealVerifies(manifest, manifest.integrity.pubkey, manifest.integrity.manifestSig) };
}
// The OWNER-key seal over the membership roster: the members meta (epoch, key generation, owner public key) plus
// every member slot (id, role, public-key fingerprint, and a hash of its sealed capability). Signed by the owner
// key so a party who can write to the shared remote — even a write member — cannot forge a membership change.
function rosterSealInput(manifest) {
	const m = (manifest && manifest.members) || {};
	const memberSlots = keySlotsOf((manifest && manifest.crypt) || {}).filter(s => s.kind === 'member')
		.map(s => s.id + ':' + (s.role || 'read') + ':' + (s.owner ? 'owner' : '-') + ':' + (s.pubFp || '') + ':' + crypto.createHash('sha256').update(String(s.sealed || '')).digest('hex')).sort();
	const rec = m.recovery ? (m.recovery.k + '/' + m.recovery.n + ':' + (m.recovery.trustees || []).map(t => t.fp + ':' + crypto.createHash('sha256').update(String(t.sealed || '')).digest('hex')).sort().join(',')) : '';
	return ['vault-roster-seal-v1', Integrity.SCHEME, String(m.epoch || 0), String(m.keyGeneration || 0), String(m.ownerPubKey || ''), memberSlots.join(','), rec].join('\n');
}
// Re-sign the roster after a legitimate membership change. Requires the owner seed (only an owner can). Stored in
// members.sig. Best-effort like resealManifest — a vault with no members section is left untouched.
function resealRoster(manifest, ownerSeed) {
	try {
		if (ownerSeed && manifest.members && manifest.members.ownerPubKey) {
			manifest.members.sig = Integrity.sign(Integrity.signKeysFromSeed(ownerSeed).priv, rosterSealInput(manifest));
		}
	} catch (_) {}
	return manifest;
}
// Verify the roster signature against the pinned owner public key. Returns true only if a members section exists,
// carries an owner key and signature, and the signature verifies over the current roster. Fail-closed.
function verifyRoster(manifest) {
	const m = manifest && manifest.members;
	if (!m || !m.ownerPubKey || !m.sig) return false;
	try { return Integrity.verify(m.ownerPubKey, rosterSealInput(manifest), m.sig); } catch (_) { return false; }
}
// A short, human-comparable fingerprint of a member public key (for TOFU verification and display).
function memberFingerprint(pubB64) { return Integrity.identity(crypto.createHash('sha256').update(String(pubB64)).digest('hex')); }

// Membership writes use the same whole-manifest compare-and-swap as key-slot writes (assertManifestEpochs, above):
// it re-reads before persisting and refuses if EITHER the roster epoch OR the slot epoch moved since the change was
// loaded, so a concurrent owner edit — or a concurrent key-slot change carried forward in the same manifest — is
// caught rather than silently clobbered. Roster ROLLBACK (replaying an older, still-signed roster) is not a
// practical escalation because a hard remove ROTATES the key — a replayed roster restores a dead slot, not access.
// Refresh the manifest seal after a legitimate key-slot change (add / remove / change-password), so the
// seal keeps pace and an audit never mistakes an owner's key change for tampering. Only possible once a
// verification key has been published (the first snapshot) and only by a write holder (every key op here
// requires the write seed). Returns the manifest for chaining into persistManifest.
function resealManifest(manifest, writeSeed) {
	try {
		if (writeSeed && manifest.integrity && manifest.integrity.pubkey) {
			manifest.integrity.manifestSig = Integrity.sign(Integrity.signKeysFromSeed(writeSeed).priv, manifestSealInput(manifest));
		}
	} catch (_) {}
	return manifest;
}

// Compare a snapshot's file set to the current one. Uses content hashes when BOTH sides have
// them (a deep audit against a deep snapshot); otherwise falls back to size, which still
// catches every add, remove, rename, and size-changing edit. Returns sorted change lists.
//
// Cooperative for the same reason as merkleRoot: on a vault with a very large file count the map
// builds and the diff loop are O(N) work on the mount/audit paths, so they yield to the loop every
// COMPARE_YIELD_EVERY entries rather than run as one burst. The final sorts act only on the (normally
// tiny) changed lists, so they stay inline. A normal vault never reaches a yield.
const COMPARE_YIELD_EVERY = 8192;
async function compareFileSets(snapFiles, curFiles) {
	const snap = new Map(), cur = new Map();
	let n = 0;
	for (const f of (snapFiles || [])) { snap.set(f.path, f); if (++n % COMPARE_YIELD_EVERY === 0) await Common.yieldToLoop(); }
	for (const f of (curFiles || [])) { cur.set(f.path, f); if (++n % COMPARE_YIELD_EVERY === 0) await Common.yieldToLoop(); }
	const added = [], removed = [], modified = [];
	for (const [p, s] of snap) {
		const c = cur.get(p);
		if (!c) { removed.push(p); continue; }
		const changed = (s.hash && c.hash) ? (s.hash !== c.hash) : (s.size !== c.size);
		if (changed) modified.push(p);
		if (++n % COMPARE_YIELD_EVERY === 0) await Common.yieldToLoop();
	}
	for (const p of cur.keys()) { if (!snap.has(p)) added.push(p); if (++n % COMPARE_YIELD_EVERY === 0) await Common.yieldToLoop(); }
	added.sort(); removed.sort(); modified.sort();
	return { added, removed, modified };
}

// Write `input` to a vault object ATOMICALLY: rcat to a "<name>.new" temp, then moveto over the real
// name, so a concurrent reader (e.g. another process opening the same vault) never sees a half-written
// record — it sees the old one or the new one, never a torn one (the rename is atomic on the local
// backing store). Throws with err.stage 'write' | 'finalize' and err.detail (engine stderr or status)
// so a caller can phrase a stage-specific message; the temp is removed on a finalize failure. Shared
// by the baseline and the session marker — the one place the temp-then-rename invariant lives.
async function writeVaultObjectAtomic(bin, cfg, name, input, { timeoutMs } = {}) {
	const tmp = name + '.new';
	const w = await Rclone.run(bin, ['rcat', 'vault:' + tmp], { configPath: cfg, input, timeoutMs });
	if (w.status !== 0) { const e = new Error('rcat failed'); e.stage = 'write'; e.detail = (w.stderr || w.status); throw e; }
	const mv = await Rclone.run(bin, ['moveto', 'vault:' + tmp, 'vault:' + name], { configPath: cfg, timeoutMs });
	if (mv.status !== 0) { try { await Rclone.run(bin, ['deletefile', 'vault:' + tmp], { configPath: cfg }); } catch (_) {} const e = new Error('moveto failed'); e.stage = 'finalize'; e.detail = (mv.stderr || mv.status); throw e; }
}

// Write a signed baseline record for the vault's current file set. Stored as an encrypted file
// inside the vault; a compact fingerprint (root + counter + tag + depth) is also recorded in
// the outer manifest and its backup, so removing the in-vault record is itself detectable.
// Carries a Merkle root over the file set, a monotonic version counter, the previous root (a
// hash chain), an HMAC, and an Ed25519 signature. Shared by the manual command and the
// automatic (mount/unmount) baseline.
async function writeSnapshot(bin, cfg, abs, manifest, keys, { deep, auto, sealed, timeoutMs }) {
	// Writing a baseline requires the WRITE key. A read-only credential (no signing key) can never
	// produce an authentic baseline, so it is refused here — the single choke point every write passes.
	if (!keys || !keys.signPriv) { const e = new Error('A read-only credential cannot sign a baseline.'); e.readOnly = true; throw e; }
	const { files, foreign } = await captureFiles(bin, cfg, { deep, timeoutMs });
	const vid = Integrity.vaultId(manifest); // one deterministic hash, reused for the ledger, checkpoint, and observe below
	const root = await Integrity.merkleRoot(files);
	const prevRoot = (manifest.snapshot && manifest.snapshot.root) || null;
	// The counter never moves backward: it steps past both the vault's own last value and the
	// highest this app has ever seen, so accepting a rolled-back vault (by taking a fresh
	// snapshot) lifts it clear of the rollback alarm instead of staying stuck below it.
	const seen = await Integrity.lastSeen(vid);
	const seq = Math.max((manifest.snapshot && manifest.snapshot.seq) || 0, (seen && seen.seq) || 0) + 1;
	const createdAt = new Date().toISOString();
	// version 4 binds the seal state and deep flag into the signed input (see Integrity.signingInput), so a
	// read-key holder cannot strip a seal or downgrade a deep baseline undetectably.
	const fields = { scheme: Integrity.SCHEME, root, seq, prevRoot, count: files.length, createdAt, version: BASELINE_VERSION, sealed: !!sealed, deep: !!deep };
	const hmac = baselineHmac(keys.hmacKey, fields);
	const sig = Integrity.sign(keys.signPriv, Integrity.signingInput(fields));
	const record = { version: BASELINE_VERSION, tool: Brand.slug, scheme: Integrity.SCHEME, createdAt, deep: !!deep, auto: !!auto, sealed: !!sealed, count: files.length, files, merkleRoot: root, prevRoot, seq, hmac, sig };
	// Written atomically (temp-then-rename) so a concurrent reader never sees a torn record.
	try { await writeVaultObjectAtomic(bin, cfg, SNAPSHOT_NAME, JSON.stringify(record), { timeoutMs }); }
	catch (e) { throw new Error('Could not ' + (e.stage === 'finalize' ? 'finalize' : 'write') + ' the snapshot: ' + e.detail); }
	const snap = snapshotFingerprint(fields, hmac, auto); // self-verifying fingerprint (carries prevRoot + version)
	manifest.snapshot = snap; // reflect the new baseline on the caller's in-memory manifest
	// Persist the snapshot summary + integrity fields through the shared partial-update helper, which re-reads a
	// fresh manifest under the vault lock. captureFiles above can take up to the auto-scan budget (~20s), so writing
	// back the copy we read before it would clobber a key or membership change another process committed under the
	// same lock during the scan (resurrecting a removed key or dropping a just-added one). Only snapshot + integrity
	// are updated; key slots and members come from the fresh manifest. Runs automatically on unmount and mount.
	const fresh = await updateManifestFields(abs, (m) => {
		m.snapshot = snap;
		// Publish the verification public key once (safe to expose; it cannot forge or decrypt).
		if (!m.integrity) m.integrity = { scheme: Integrity.SCHEME, pubkey: keys.signPub };
		// Seal the manifest's security fields (salt, key slots, published key) with the write key, so tampering with
		// them is detectable at audit time. The seal excludes itself and the snapshot summary, so it stays stable
		// across snapshots. Best-effort so it never disturbs a snapshot.
		try { m.integrity.manifestSig = Integrity.sign(keys.signPriv, manifestSealInput(m)); } catch (_) {}
	});
	manifest.integrity = fresh.integrity; // keep the caller's in-memory manifest consistent with what was persisted,
	manifest.crypt = fresh.crypt;         // key slots included, so its seal never seals a stale-crypt object
	await Integrity.observe(vid, seq, root, undefined, Integrity.identity(Integrity.pubkeyOf(manifest)), false, !!sealed); // advance the local ledger, recording the committed identity and seal state
	// Opportunistically co-sign the tamper-log head with the write key (a signed checkpoint), so the
	// unforgeable checkpoint keeps pace with the detection history through read-only/password-less appends.
	// Best-effort: a hiccup here must never disturb a snapshot (the money path of tamper detection).
	try { await Integrity.signTamperHead(vid, keys.signPriv); } catch (_) {}
	// `changed` = did the REAL (OS-junk-excluded) file set change vs the previous baseline? The recovery
	// auto-refresh uses this to skip rebuilding when a session only churned .DS_Store / ._* metadata.
	return { vault: abs, createdAt, count: files.length, deep: !!deep, sealed: !!sealed, seq, root, changed: !prevRoot || !Integrity.equalHex(prevRoot, root), fingerprint: Integrity.fingerprint(root), foreign: foreign || [] };
}

// Read and verify the stored baseline (given a config + keys). Returns { record } on success,
// { tamper } describing why it could not be trusted, { none } when no baseline exists yet, or
// { unknown } for a baseline written by a newer scheme/version (left untouched, never clobbered).
// Re-sign an ALREADY-VERIFIED baseline record at the current BASELINE_VERSION without changing any of its
// content (file set, root, seq, prevRoot, count, createdAt) or its seal/deep state — only the version, HMAC,
// and signature are recomputed, which binds the seal state under the current signing input. Used to upgrade a
// legacy sub-v4 record in place so a read-key holder can no longer strip its seal undetectably. Needs the
// write key (a read-only session cannot and does not call this).
// Map a STORED baseline record to the exact field set its signature/HMAC covers. The record's field names differ
// from the signed names (root ← merkleRoot), so this one place owns that mapping — a mistyped remapping in a
// second copy would make sign and verify silently disagree. `version` is the one field that varies by caller (the
// verify path binds the record's OWN version; the v4 re-sign upgrades it to BASELINE_VERSION), so it is a param.
function recordSigningFields(record, version) {
	return { scheme: record.scheme, root: record.merkleRoot, seq: record.seq, prevRoot: record.prevRoot, count: record.count, createdAt: record.createdAt, version, sealed: !!record.sealed, deep: !!record.deep };
}
async function resignBaselineV4(bin, cfg, abs, manifest, keys, record, { timeoutMs } = {}) {
	if (!keys || !keys.signPriv || !(record.version < BASELINE_VERSION)) return;
	const fields = recordSigningFields(record, BASELINE_VERSION); // re-sign UPGRADES the record to the current version
	const hmac = baselineHmac(keys.hmacKey, fields);
	const sig = Integrity.sign(keys.signPriv, Integrity.signingInput(fields));
	const upgraded = { ...record, version: BASELINE_VERSION, hmac, sig };
	await writeVaultObjectAtomic(bin, cfg, SNAPSHOT_NAME, JSON.stringify(upgraded), { timeoutMs });
	// Keep the manifest fingerprint in step with the upgraded record: refresh the WHOLE self-verifying fingerprint
	// (version, prevRoot, and HMAC), not just the HMAC — leaving version behind would make the fingerprint fail its
	// own self-check and read as forged. Go through the shared partial-update helper, which re-reads a fresh manifest
	// under the lock — the manifest here was read at mount time, before this function's slow rclone calls, so writing
	// the whole stale copy back would clobber a key or membership change another process committed under the same lock
	// in between. Only the snapshot fingerprint is updated; key slots and members come from the fresh manifest.
	if (manifest.snapshot) {
		const snap = snapshotFingerprint(fields, hmac, manifest.snapshot.auto); // preserve the informational auto flag
		await updateManifestFields(abs, (m) => { if (m.snapshot) m.snapshot = snap; });
		manifest.snapshot = snap; // reflect on the caller's in-memory manifest too
	}
}

async function readSnapshot(bin, cfg, manifest, keys, { timeoutMs } = {}) {
	const fp = manifest.snapshot; // fingerprint recorded at write time (may be absent)
	const r = await Rclone.run(bin, ['cat', 'vault:' + SNAPSHOT_NAME], { configPath: cfg, timeoutMs, maxOutBytes: MAX_REMOTE_SNAPSHOT_BYTES });
	const have = r.status === 0 && r.stdout;
	// Distinguish an over-cap read (the engine child was killed after the body reached MAX_REMOTE_SNAPSHOT_BYTES,
	// so stdout is truncated AT the cap) from a genuinely absent record (a "cat" of a missing file exits non-zero
	// with EMPTY stdout). A snapshot merely too large to read back is NOT tampering — reporting it as "removed"
	// would be a false alarm — so surface it as unreadable and leave the record untouched.
	const overCap = !have && r.stdout && r.stdout.length >= MAX_REMOTE_SNAPSHOT_BYTES;
	if (!fp && !have) return overCap ? { unreadable: true, reason: 'the snapshot is too large to read back for verification' } : { none: true };
	if (fp && !have) {
		if (overCap) return { unreadable: true, at: fp.at, reason: 'the snapshot is too large to read back for verification' };
		return { tamper: 'The snapshot record has been removed from the vault.', at: fp.at };
	}
	let record;
	try { record = JSON.parse(r.stdout); } catch (_) { return { tamper: 'The snapshot record is unreadable or corrupt.' }; }
	// Forward/backward-safe. A pre‑release record is treated as "no baseline" and re‑established.
	// A record this build cannot interpret is left UNTOUCHED and reported — never clobbered — and
	// we say which kind it is: a newer record structure, or an integrity scheme we don't recognize
	// (which a future build will verify with the matching algorithm rather than rewrite).
	if (!(record.version >= 3)) return { none: true };
	if (record.version > BASELINE_VERSION) return { unknown: true, at: record.createdAt, reason: 'written by a newer version of the tool' };
	if (record.scheme !== Integrity.SCHEME) return { unknown: true, at: record.createdAt, reason: 'written with an integrity scheme this version does not recognize' };
	// Everything else is verified. Any exception during recompute/verify (e.g. a crafted record
	// whose fields are the wrong type) is treated as tampering — fail closed, never throw.
	try {
		// First, the record's OWN authenticity, independent of the manifest fingerprint: its file list matches its
		// recorded root, its HMAC and Ed25519 signature verify over the same signed fields, and the published
		// verification key matches the one derived from the master. A failure here is a genuine alteration of the
		// baseline record (or a key mismatch) — fail closed.
		const root = await Integrity.merkleRoot(record.files || []);
		// Reconstruct the signed input EXACTLY as written: for v4+ that includes the record's own version, seal
		// state, and deep flag, so flipping any of them (or downgrading the version to dodge the binding) makes
		// the signature fail to verify below.
		const fields = recordSigningFields(record, record.version); // verify binds the record's OWN version (a downgrade fails below)
		const rootOk = Integrity.equalHex(root, record.merkleRoot);
		const hmacOk = Integrity.equalHex(baselineHmac(keys.hmacKey, fields), record.hmac);
		const pubOk = !(manifest.integrity && manifest.integrity.pubkey) || manifest.integrity.pubkey === keys.signPub;
		const sigOk = Integrity.verify(keys.signPub, Integrity.signingInput(fields), record.sig);
		// "Altered" means the record itself is inauthentic: its file list no longer hashes to its recorded root, or its
		// HMAC/signature/published key do not verify. The manifest's snapshot fingerprint is only a convenience CACHE of
		// this record's identity, updated right after the record is written — a desync between the two (from a snapshot
		// write interrupted by, say, a killed service) is NOT tampering, so it is deliberately not checked here. Whether
		// the vault was genuinely rolled back is judged by CONTENT against the local ledger (see rollbackWarning), not by
		// these two bookkeeping records being in step.
		if (!rootOk || !hmacOk || !pubOk || !sigOk) return { tamper: 'The snapshot signature does not match — the snapshot has been altered.', at: record.createdAt };
		// The manifest's snapshot fingerprint is a password-less cache. It does NOT have to name the same baseline as
		// the in-vault record (a snapshot write interrupted by a killed service can leave one lagging the other — benign
		// bookkeeping, handled by the content anchor), so it is NOT compared field-by-field against the record. But it IS
		// self-verifying: if it is present in the current shape, its own HMAC must recompute from its own fields. A
		// fingerprint whose fields or HMAC were altered (someone editing the manifest to fake the vault's version or
		// content fingerprint) fails that and is reported — fail closed. A legacy fingerprint that predates the
		// self-verifying shape returns null here and is left unchecked (no false alarm) until the next snapshot rewrites it.
		const fpAuth = fingerprintAuthentic(fp, keys.hmacKey);
		if (fpAuth === false) return { tamper: 'The snapshot fingerprint recorded in the vault settings was altered — it does not match this vault.', at: record.createdAt };
		if (fpAuth === true) {
			// The fingerprint is authentic (this vault's own key produced it). A snapshot always writes the in-vault
			// record BEFORE the manifest fingerprint, so a benign interrupted write can only leave the record AT or
			// AHEAD of the fingerprint (record.seq >= fp.seq). Therefore an authentic fingerprint whose seq is AHEAD of
			// the record means the record was rolled back below a state this vault itself attested — tamper. And at the
			// SAME seq the two are written together, so a seal-state mismatch there is a stripped or added seal — tamper.
			// Neither can fire for a legitimate interrupted write (which leaves the record newer, so fp.seq < record.seq).
			if (fp.seq > record.seq) return { tamper: 'The vault was rolled back to an earlier snapshot than its own settings record — the snapshot in the vault is older than the vault attested.', at: record.createdAt };
			if (fp.seq === record.seq && (!!fp.sealed !== !!record.sealed)) return { tamper: 'The vault\'s seal state does not match its settings record — a seal was added or removed.', at: record.createdAt };
		}
		return { record };
	} catch (_) { return { tamper: 'The snapshot record is unreadable or corrupt.', at: record.createdAt }; }
}

// ── Session marker (crash-vs-tamper) ──────────────────────────────────────────────────────────
// The marker records that a read-write keyholder had a LIVE mount that started from a particular
// baseline. It is signed with the write key (so only a keyholder can create one) and bound to the
// baseline seq plus a random nonce (so a stale marker from an earlier baseline never matches). If it
// survives to the next mount, the previous session ended abnormally — a crash, a hard kill, or power
// loss — so the file changes since the baseline are that interrupted session's own writes, NOT an
// offline change by someone without the key, and can be accepted rather than reported as tampering.
function sessionSigningInput(f) { return ['vdsession', f.vaultId, f.seq, f.nonce, f.startedAt].join('\n'); }

async function writeSessionMarker(bin, cfg, manifest, keys, seq, { timeoutMs } = {}) {
	if (!keys || !keys.signPriv || seq == null) return; // only a read-write session marks a session
	try {
		const fields = { vaultId: Integrity.vaultId(manifest), seq, nonce: crypto.randomBytes(16).toString('hex'), startedAt: new Date().toISOString() };
		const sig = Integrity.sign(keys.signPriv, sessionSigningInput(fields));
		const record = { version: 1, ...fields, sig };
		// Best-effort: the marker is an optimization, never a gate on the mount — any failure is swallowed.
		await writeVaultObjectAtomic(bin, cfg, SESSION_NAME, JSON.stringify(record), { timeoutMs });
	} catch (_) {}
}

// Return the marker ONLY when it is present, its signature verifies against the vault's key, and it is
// bound to the CURRENT baseline seq — i.e. it genuinely marks an interrupted session for the state we
// are about to check. Anything else (absent, unreadable, wrong signature, stale seq, wrong vault)
// returns null, so a missing or forged marker can never soften a real tamper finding.
async function readSessionMarker(bin, cfg, manifest, keys, seq, { timeoutMs } = {}) {
	try {
		const r = await Rclone.run(bin, ['cat', 'vault:' + SESSION_NAME], { configPath: cfg, timeoutMs, maxOutBytes: MAX_MANIFEST_BYTES });
		if (r.status !== 0 || !r.stdout) return null;
		const rec = JSON.parse(r.stdout);
		if (!rec || rec.version !== 1 || rec.seq !== seq || rec.vaultId !== Integrity.vaultId(manifest)) return null;
		const pub = (keys && keys.signPub) || Integrity.pubkeyOf(manifest);
		if (!pub) return null;
		const fields = { vaultId: rec.vaultId, seq: rec.seq, nonce: rec.nonce, startedAt: rec.startedAt };
		if (!Integrity.verify(pub, sessionSigningInput(fields), rec.sig)) return null;
		return rec;
	} catch (_) { return null; }
}

async function removeSessionMarker(bin, cfg, { timeoutMs } = {}) {
	try { await Rclone.run(bin, ['deletefile', 'vault:' + SESSION_NAME], { configPath: cfg, timeoutMs }); } catch (_) {}
}

// Classify a vault's version counter against the highest this app has seen (rollback ledger),
// returning a warning string or null. Shared by the on-mount check and the manual audit.
async function rollbackWarning(manifest, record) {
	const roll = await Integrity.observe(Integrity.vaultId(manifest), record.seq, record.merkleRoot, record.prevRoot, Integrity.identity(Integrity.pubkeyOf(manifest)), false, !!record.sealed);
	// All three of these also fire for a COMMON, HARMLESS reason: the app tracks the highest version it has seen for a
	// vault's identity across every copy of it, and a copy IS the same vault (a byte-for-byte copy shares the identity).
	// So if you have used a separate copy or backup of this vault on its own — say on another drive — that copy advances
	// further, and later opening the original (which stayed behind) looks like a rollback. The same fix clears the benign
	// case: a fresh snapshot lifts this copy's version past the highest the app has seen and re-signs the baseline.
	const acceptHint = ' If you have used a separate copy or backup of this vault on its own (for example on another drive), this is expected — take a fresh snapshot to accept this copy as current, and the warning clears. If that does not explain it, treat it as tampering and do not trust this copy.';
	if (roll.status === 'rollback') return 'This vault is an older version than this app last saw (version ' + record.seq + ', after version ' + roll.seen.seq + ') — a possible rollback.' + acceptHint;
	if (roll.status === 'fork') return 'This vault has the same version number as before but different contents — its history was altered.' + acceptHint;
	if (roll.status === 'chain-break') return 'This vault\'s history does not connect to the version this app last saw (version ' + record.seq + ' does not follow on from version ' + roll.seen.seq + ') — a baseline in between was hidden or the history was rewritten.' + acceptHint;
	return null;
}

// True when the vault's CURRENT contents hash to the last baseline this device recorded in its monotonic ledger — i.e.
// the vault is genuinely unchanged from the last trusted state. In that case any staleness or desync in the in-vault
// snapshot record is bookkeeping (e.g. a snapshot write interrupted by a killed service), NOT tampering; it self-heals
// on the next mount. This is the anti-rollback best practice — judge by content against the monotonic counter, not by
// two bookkeeping records being in step — and it can never hide a real change, since altered or rolled-back content
// hashes to a different root than the ledger's. `capturedFiles` is reused when taken at the baseline's depth; otherwise
// the files are re-captured at that depth (rare — only when a discrepancy is already suspected). Best-effort/bounded.
async function contentAtTrustedBaseline(bin, cfg, manifest, capturedFiles, capturedDeep, timeoutMs) {
	const ledger = await Integrity.lastSeen(Integrity.vaultId(manifest));
	if (!ledger || !ledger.root) return false; // no anchor recorded yet → let the record-based checks decide
	// Compare against the trusted root at the depth we already captured. The Merkle root is depth-specific (a
	// content-hash root differs from a size-only root over the same files), so a match proves the current content
	// is exactly the last trusted state — it can never match a changed vault.
	if (Integrity.equalHex(await Integrity.merkleRoot(capturedFiles), ledger.root)) return true;
	// The ledger root could have been written at the OTHER depth than we happened to capture (the last baseline's
	// depth and the manifest's cached depth can diverge if a snapshot write was interrupted between the two). Try
	// the opposite depth before giving up, so a genuinely-unchanged vault is recognized regardless of that skew.
	// This second capture is only reached when a discrepancy is already suspected (a rollback or a diff), so it is
	// rare; it is bounded by timeoutMs like every other engine call.
	try { const c = await captureFiles(bin, cfg, { deep: !capturedDeep, timeoutMs }); return Integrity.equalHex(await Integrity.merkleRoot(c.files), ledger.root); }
	catch (_) { return false; } // could not confirm within budget → fall back to the record-based checks (never a false clear)
}

// The single, shared place that decides whether a verified baseline record plus a fresh capture is TAMPERING or a
// benign bookkeeping desync. Both the manual audit and the on-mount check call this, so the security-sensitive
// "clear the alarm" logic lives in exactly one place and cannot drift between the two. It computes the file diff
// and the rollback warning, then applies the content anchor — clearing both when the vault's current contents still
// hash to the last trusted ledger root — with ONE hard exception: a SEAL DOWNGRADE is never cleared. If the last
// state this device trusted (the ledger anchor) was sealed and the current record is not, clearing would silently
// erase a strict tripwire, so it is always reported. Returns { roll, added, removed, modified, staleBaseline,
// sealDowngrade }; `capDeep` says at which depth `capFiles` was captured.
async function classifyAgainstBaseline(bin, cfg, manifest, record, capFiles, capDeep, timeoutMs) {
	const diff = await compareFileSets(record.files, capFiles);
	let roll = await rollbackWarning(manifest, record); // also advances the ledger on a legitimate forward step
	let { added, removed, modified } = diff;
	let staleBaseline = false;
	const ledger = await Integrity.lastSeen(Integrity.vaultId(manifest));
	const sealDowngrade = !!(ledger && ledger.sealed && !record.sealed); // clearing this would strip a seal — never benign
	// Note: a record rolled back to an OLDER but still-sealed baseline, with the encrypted content left at the trusted
	// ledger root, is NOT a seal downgrade (both ledger and record are sealed) and IS cleared by the content anchor —
	// intentional, per "judge by content, not bookkeeping": nothing changed, the seal is intact, and the next write
	// re-advances the seq. This relies on the local ledger (assumed attacker-inaccessible) for the trusted root.
	if ((roll || added.length || removed.length || modified.length) && !sealDowngrade) {
		if (await contentAtTrustedBaseline(bin, cfg, manifest, capFiles, capDeep, timeoutMs)) {
			added = []; removed = []; modified = []; roll = null; staleBaseline = true;
		}
	}
	return { roll, added, removed, modified, staleBaseline, sealDowngrade };
}
const sealDowngradeNote = 'This vault was sealed, but the snapshot now in it is not sealed — the strict tamper seal appears to have been removed.';

// Detect an identity substitution and return a tamper note (or null). A holder of the READ key can rewrite the
// manifest's published verify key, re-sign the baseline, and re-seal the manifest with their OWN write key — leaving
// a manifest that verifies against itself, so the seal and baseline checks pass and only the vault's cryptographic
// identity string changes. The local rollback ledger records the last known-good identity, so if the current identity
// differs, a VALID, signed succession must connect the two (forging it needs the real old write key). This is shared
// by the manual audit and the on-mount check so a read-only-password mounter — who has no independent key anchor and
// might never run an audit — is protected on the mount path too, not only in the audit.
async function identitySubstitutionNote(abs, manifest) {
	const identity = Integrity.identity(Integrity.pubkeyOf(manifest));
	const prior = await Integrity.lastSeen(Integrity.vaultId(manifest)); // identity is sticky in the ledger, so reading it here is stable
	if (!identity || !prior || !prior.identity || prior.identity === identity) return null;
	const succ = await verifySuccession(abs).catch(() => null);
	// Require a connected chain of VERIFIED succession links from the last known-good identity to the current one.
	if (succ && Array.isArray(succ.chain)) {
		let cursor = prior.identity;
		for (const link of succ.chain) {
			if (link.verified && link.oldIdentity === cursor) { cursor = link.newIdentity; if (cursor === identity) return null; }
		}
	}
	return 'The vault\'s cryptographic identity changed without a valid, signed succession — its published verification key was replaced. This is treated as tampering.';
}

// Record a signed snapshot of the vault's current file set. `deep` (the default for the
// manual command) also fingerprints each file's content; a fast snapshot records paths and
// sizes only. `auto` marks a baseline written automatically on mount/unmount.
// Write a baseline for a vault (the shared path for snapshot, seal, and unseal). Requires the
// vault unmounted so the on-disk store is settled, and the correct password.
async function writeBaseline(vaultDir, password, opts) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates tamper baselines (format 3 or newer is required).');
	if (!password) throw new Error('A password is required.');
	// Hold the vault exclusively across the WHOLE capture, exactly as backup, pack, and mirror do — a point-in-time
	// assertUnmounted alone lets a mount start mid-capture (from another tab or the CLI) and smear the signed tamper
	// baseline over a half-written store, so it would later either raise false alarms or mask a real change. The
	// mount path's own auto-baseline is already inside its withVaultBusy claim; this is the manual snapshot/seal path.
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount, backup, or mirror). Wait for it to finish, then try again.', async () => {
		await assertUnmounted(abs, 'first');
		const bin = await ensureEngine();
		const cred = await unlockCredential(password, manifest); // one key derivation, shared by config + integrity keys
		if (!cred.writeSeed) throw new Error('This is a read-only credential — it cannot change the vault. Unlock with a read-write password.');
		return withVaultConfig(bin, abs, password, manifest, cred.master, async (cfg) => {
			if (!(await verifyPassword(bin, cfg, manifest))) throw wrongPasswordError();
			return await writeSnapshot(bin, cfg, abs, manifest, integrityKeys(cred.master, cred.writeSeed, manifest), opts);
		});
	});
}

// A manual (deep) snapshot — the point-in-time content baseline for the optional deep audit. Taking
// a snapshot writes an UNSEALED baseline, so if the vault was sealed this removes the tripwire; that
// is a deliberate, logged action (the callers warn the user first), never a silent loss of the seal.
async function snapshot(vaultDir, { password, deep = true, auto = false, force = false } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const before = await readManifest(abs);
	const wasSealed = !auto && before.snapshot && before.snapshot.sealed;
	// Removing a seal is a deliberate act; the gate lives HERE so it holds for every caller (the CLI,
	// the web API, an embedder), not only the ones that remember to ask. `force` is the explicit
	// acknowledgment the callers pass once the user has confirmed.
	if (wasSealed && !force) { const e = new Error('This vault is sealed. Taking a snapshot would remove the seal — pass force to proceed, or use unseal / re-seal instead.'); e.sealed = true; throw e; }
	const rep = await writeBaseline(vaultDir, password, { deep, auto, sealed: false });
	if (wasSealed) await logTamper(await readManifest(abs), { kind: 'unsealed', notes: ['Seal removed by taking a new snapshot.'] });
	if (!auto) maybeAutoAttest(abs); // opt-in, fire-and-forget: timestamp each deliberate new baseline
	return rep;
}

// Opt-in, best-effort auto-attestation. When the user has enabled it, every DELIBERATE new baseline
// (a snapshot or a seal) is timestamped so the vault's attested history keeps pace with its real state —
// which is what lets a rollback be detected later against the recorded chain head. Fire-and-forget and
// fully guarded: it never blocks the operation, never throws into it, and simply does nothing when the
// setting is off or the network/TSA is unreachable (attestation is always optional and offline-tolerant).
function maybeAutoAttest(abs) {
	(async () => {
		try { if (!(await getSettings()).autoAttest) return; } catch (_) { return; }
		try { await attest(abs, { timeoutMs: 20000 }); } catch (_) {} // offline / TSA down / no baseline — leave it for next time
	})();
}

// Seal a vault: a strict, signed baseline (deep content hashes) that is NEVER auto-refreshed.
// Once sealed, the fast on-mount check reports any file added, removed, or resized against it on every mount,
// and the deep `audit` additionally reports a SAME-SIZE content edit of an existing file — together the tamper
// tripwire that stands until you seal again. (A full content hash cannot fit the mount's time budget on a large
// vault, so same-size edits are an audit-level check; a naive byte flip also fails closed on read.) Re-seal to
// accept the current state as trusted.
// `accept`, when supplied by a caller that has just shown the user the outstanding changes, is the
// set being acknowledged; it is recorded in the tamper history so the acceptance is itself audited.
async function seal(vaultDir, { password, accept } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const before = await readManifest(abs);
	const rep = await writeBaseline(vaultDir, password, { deep: true, auto: false, sealed: true });
	const after = await readManifest(abs);
	const changes = accept && (((accept.added || []).length) || ((accept.removed || []).length) || ((accept.modified || []).length));
	const note = (before.snapshot && before.snapshot.sealed)
		? (changes ? 'Accepted outstanding changes and re-sealed at version ' + rep.seq + '.' : 'Re-sealed at version ' + rep.seq + '.')
		: 'Vault sealed at version ' + rep.seq + '.';
	await logTamper(after, changes
		? { kind: 'accepted', added: accept.added, removed: accept.removed, modified: accept.modified, notes: [note] }
		: { kind: 'sealed', notes: [note] });
	maybeAutoAttest(abs); // opt-in, fire-and-forget: timestamp the sealed baseline
	return rep;
}

// Unseal: drop the strict baseline and return to automatic (self-updating) tracking.
async function unseal(vaultDir, { password } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const rep = await writeBaseline(vaultDir, password, { deep: false, auto: true, sealed: false });
	await logTamper(await readManifest(abs), { kind: 'unsealed', notes: ['Seal removed — back to automatic tracking.'] });
	return rep;
}

// Append a detected-tamper event to the persistent local log (best-effort; never throws).
// Classify a tamper event so the history can be read at a glance. Content loss (a removed or
// modified file) or a forged/removed baseline is the most serious; new files are a step below; a
// seal, re-seal, or unseal the user performed is an informational audit-trail entry.
function severityOf(event) {
	if (event.severity) return event.severity;
	if (event.kind === 'baseline-altered') return 'critical';
	if (event.kind === 'sealed' || event.kind === 'accepted' || event.kind === 'unsealed') return 'info';
	if ((event.removed && event.removed.length) || (event.modified && event.modified.length) || (event.foreign && event.foreign.length)) return 'high';
	if (event.added && event.added.length) return 'medium';
	// A rollback or rewritten-history finding is detected by the version counter, not the file diff,
	// so its file arrays are empty but it carries an explanatory note — it is serious, not routine.
	if (event.notes && event.notes.length) return 'high';
	return 'info';
}

async function logTamper(manifest, event) {
	try {
		const cap = a => Array.isArray(a) ? a.slice(0, 100) : a;
		const e = { kind: event.kind, severity: severityOf(event), added: cap(event.added), removed: cap(event.removed), modified: cap(event.modified), foreign: cap(event.foreign), notes: event.notes };
		if (manifest.snapshot && manifest.snapshot.root) { e.fingerprint = Integrity.fingerprint(manifest.snapshot.root); e.seq = manifest.snapshot.seq; }
		await Integrity.logTamper(Integrity.vaultId(manifest), e);
	} catch (_) {}
}

// The vault's recorded tamper-event history (newest first). Needs no password.
async function tamperLog(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const vid = Integrity.vaultId(manifest);
	const pub = Integrity.pubkeyOf(manifest);
	// Alongside the events, verify the history itself is intact (hash chain + head/eviction anchors + any
	// signed checkpoint), so the UI can tell the user whether the record can be trusted or was tampered with.
	return { vault: abs, events: await Integrity.tamperLog(vid), history: await Integrity.verifyTamperLog(vid, pub) };
}

// The vault's current fingerprint and version, read from the manifest — no password needed,
// since the root and counter are not secret. Record the fingerprint somewhere safe to detect,
// across machines, that a vault has been rolled back to an earlier state.
async function fingerprint(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	// The stable IDENTITY (of the write-authority public key) tells you this is the genuine vault — a hacker's
	// recreation has a different one they can't reproduce. The content fingerprint tells you it is the exact
	// same state. Both are non-secret and need no password.
	const identity = Integrity.identity(Integrity.pubkeyOf(manifest));
	const s = manifest.snapshot;
	if (!s || !s.root) return { vault: abs, identity, fingerprint: null, seq: null, at: null };
	return { vault: abs, identity, fingerprint: Integrity.fingerprint(s.root), seq: s.seq, at: s.at };
}

// Build a printable one-page Recovery Kit for a vault: its stable identity, its current content
// fingerprint, plain restore steps, and — unless the caller opts out — a freshly generated recovery
// key so a lost password becomes a recovery rather than a catastrophe. Returns the kit HTML plus the
// recovery key (shown ONCE; the kit is its only copy). Adding a recovery key mutates the vault (a new
// key slot) and so needs the current password; an identity-only kit (addKey:false) changes nothing and
// needs no password. All wording lives in the template data file — this just gathers the values.
async function recoveryKit(vaultDir, { password, addKey = true } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const fp = await fingerprint(abs); // identity + content fingerprint; no password required
	let recoveryKey = null;
	if (addKey) {
		if (!password) throw new Error('The current password is required to add a recovery key to the kit. Choose the identity-only option to make a kit without adding a key.');
		recoveryKey = (await addRecoveryKey(abs, { password, label: 'Recovery key (kit)' })).recoveryKey;
	}
	const html = RecoveryKit.render({
		appName: Brand.name, cli: Brand.cli,
		vaultName: displayName(abs), vaultPath: abs,
		identity: fp.identity, fingerprint: fp.fingerprint, seq: fp.seq,
		recoveryKey, generatedAt: new Date().toLocaleString(),
	});
	return { vault: abs, identity: fp.identity, fingerprint: fp.fingerprint, seq: fp.seq, recoveryKey, html };
}

// ---- Provable, timestamped attestation (RFC 3161) ----
//
// Proof that a vault existed in an EXACT state at an EXACT time, verifiable by anyone — "court-grade
// evidence." We hash a value that binds the vault's stable identity, its content Merkle root, and its
// version counter, then have a trusted Time-Stamping Authority sign that hash together with the current
// time. Only the hash leaves the machine — never the vault, its names, or its contents. The proofs are
// kept in a plain sidecar file that travels with the vault (through backup, mirror, and pack), and each
// token is independently verifiable, so tampering can only remove a proof, never forge one. Attestation
// is entirely optional and never gates opening a vault; it needs no password (nothing here is secret).
const ATTEST_NAME = 'attestations.json';
function attestPath(vaultDir) { return path.join(path.resolve(vaultDir), ATTEST_NAME); }

// The digest a token certifies: a domain-separated hash over the vault identity + content root +
// version, so a token can never be lifted onto a different vault or a different state.
function attestDigest(identity, root, seq) {
	return crypto.createHash('sha256').update('vault-attest-v1\n').update(String(identity) + '\n' + String(root) + '\n' + String(seq)).digest();
}
// The attestations form a hash CHAIN so the sidecar is tamper-evident as a whole: each proof commits to
// the one before it, binding the immutable token bytes and the state digest. Reordering, inserting, or
// removing a proof from the middle breaks the chain. (Trimming the newest proofs leaves a shorter valid
// chain — that is why the chain's HEAD is meant to be recorded out of band; a vault presenting an older
// head than the one recorded has been rolled back.) The genesis link is bound to the vault identity so a
// whole foreign chain cannot be substituted.
function attestGenesis(identity) { return crypto.createHash('sha256').update('vault-attest-genesis-v1\n').update(String(identity)).digest('hex'); }
function attestChainHash(prev, digestHex, tokenHashHex) {
	return crypto.createHash('sha256').update('vault-attest-chain-v1\n').update(String(prev) + '\n' + String(digestHex) + '\n' + String(tokenHashHex)).digest('hex');
}
function tokenHashOf(tokenBytes) { return crypto.createHash('sha256').update(tokenBytes).digest('hex'); }
const ATTEST_VERSION = 1; // the attestation-record format this build reads and writes
async function readAttestations(abs) { return readSidecarList(attestPath(abs), 'items', ATTEST_VERSION); }

// Create a fresh attestation for the vault's current signed state. Requires that a baseline (snapshot)
// exists — that is what fixes the exact state being proven. Contacts the TSA (bounded), verifies the
// returned token really certifies our digest, then appends it to the sidecar. No password needed.
async function attest(vaultDir, { tsaUrl, timeoutMs } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const identity = Integrity.identity(Integrity.pubkeyOf(manifest));
	const root = manifest.snapshot && manifest.snapshot.root;
	const seq = manifest.snapshot && manifest.snapshot.seq;
	if (!root) throw new Error('Take a snapshot first — an attestation certifies a recorded state, and this vault has no baseline yet.');
	const digest = attestDigest(identity, root, seq);
	const r = await Attest.timestamp(digest, { tsaUrl, timeoutMs });
	// Fully verify the token now, while online (signature + timestamping-EKU + ESSCertID + chain to a
	// trusted root), and record the verdict. The token embeds its own certificate chain, so it stays
	// verifiable offline later. genTime is read out of the (verified) token, never trusted from elsewhere.
	const verified = Attest.verifyToken(r.token, { digest });
	const genTime = verified.genTime || r.genTime;
	// The TSA call above is done; now serialize only the read-append-write so two concurrent attestations (a manual
	// one racing the fire-and-forget auto-attest, or a double-submit) can't both link off the same previous entry
	// and have the later write drop the earlier proof. The token is independent of chain position, so computing it
	// outside the lock is correct — the chain link is computed inside, against the current last entry.
	return withVaultLock(abs, async () => {
		const store = await readAttestations(abs);
		// Link this proof onto the tamper-evident chain: prev = the last proof's link (or the identity-bound
		// genesis for the first), chain = a hash committing prev + the state digest + the exact token bytes.
		const prev = store.items.length ? (store.items[store.items.length - 1].chain || attestGenesis(identity)) : attestGenesis(identity);
		const chain = attestChainHash(prev, digest.toString('hex'), tokenHashOf(r.token));
		const item = {
			at: new Date().toISOString(),
			identity, root, seq,
			digest: digest.toString('hex'),
			tsaUrl: r.tsaUrl,
			genTime: genTime ? genTime.toISOString() : null,
			serialHex: verified.serialHex || r.serialHex || null,
			tsaSubject: verified.tsaSubject || null,
			verified: verified.ok,
			verifyReason: verified.reason || null,
			prev, chain,
			token: Buffer.from(r.token).toString('base64'),
		};
		store.version = assertSidecarVersion(store, ATTEST_VERSION, 'attestation record'); // never rewrite a newer-format attestation log under old rules
		store.items.push(item);
		await Common.writeJsonAtomic(attestPath(abs), store, { fsync: true }); // durable like the other signed sidecars, so a power loss can't lose a just-recorded proof
		return { vault: abs, identity, root, seq, genTime: item.genTime, tsaUrl: item.tsaUrl, serialHex: item.serialHex, verified: verified.ok, verifyReason: verified.reason || null, chain, count: store.items.length };
	});
}

// List and verify a vault's attestations. Each token is re-checked against the state IT recorded (its
// own stored digest), and we read the certified time back OUT of the signed token rather than trusting
// the sidecar. We also flag which proofs match the vault's CURRENT state. No password needed.
async function attestations(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const curIdentity = Integrity.identity(Integrity.pubkeyOf(manifest));
	const curRoot = manifest.snapshot && manifest.snapshot.root;
	const curSeq = manifest.snapshot && manifest.snapshot.seq;
	const store = await readAttestations(abs);
	let chainOk = true, maxAttestedSeq = -1;
	// Walk the hash chain in order, recomputing each link from the prior one. A break (reorder / insert /
	// middle-removal / altered token) is surfaced as chainOk=false.
	let prevExpected = store.items.length ? attestGenesis(store.items[0].identity) : null;
	const items = store.items.map((it) => {
		let verifiedOk = false, genTime = null, reason = null, chained = false;
		try {
			const token = Buffer.from(it.token, 'base64');
			const want = attestDigest(it.identity, it.root, it.seq);
			// The stored digest must match what identity+root+seq hash to (no rewritten metadata), AND the
			// token must FULLY verify for that digest — signature, timestamping-EKU, ESSCertID, and a chain to
			// a trusted root — both, or it is not a trustworthy proof. The time is read from the signed token.
			if (Buffer.from(it.digest, 'hex').equals(want)) {
				const v = Attest.verifyToken(token, { digest: want });
				verifiedOk = v.ok; genTime = v.genTime ? v.genTime.toISOString() : null; reason = v.ok ? null : v.reason;
			} else { reason = 'digest-mismatch'; }
			// Chain link: recompute from the expected previous link and the immutable token bytes.
			if (it.chain != null && prevExpected != null) {
				const expect = attestChainHash(prevExpected, it.digest, tokenHashOf(token));
				chained = (it.chain === expect) && (it.prev == null || it.prev === prevExpected);
			}
		} catch (_) { reason = reason || 'unreadable'; }
		if (!chained) chainOk = false;
		prevExpected = (it.chain != null) ? it.chain : prevExpected; // advance on the stored link so one break doesn't cascade
		if (verifiedOk && typeof it.seq === 'number' && it.seq > maxAttestedSeq) maxAttestedSeq = it.seq;
		const matchesCurrent = !!(curRoot && it.identity === curIdentity && it.root === curRoot && it.seq === curSeq);
		return { at: it.at, seq: it.seq, root: it.root, identity: it.identity, tsaUrl: it.tsaUrl, tsaSubject: it.tsaSubject || null, serialHex: it.serialHex, genTime, verified: verifiedOk, reason, matchesCurrent, chained };
	});
	// The chain HEAD: record it out of band. A vault later presenting an OLDER head (or a lower attested
	// version than you recorded) has been rolled back. We also flag the local signal where the sidecar
	// still holds a proof for a NEWER version than the vault currently presents (an incomplete rollback).
	const last = store.items.length ? store.items[store.items.length - 1] : null;
	const head = last ? { identity: last.identity, seq: last.seq, root: last.root, genTime: last.genTime || null, serialHex: last.serialHex || null, chain: last.chain || null, count: store.items.length } : null;
	const rolledBack = !!(curSeq != null && maxAttestedSeq >= 0 && maxAttestedSeq > curSeq);
	return { vault: abs, identity: curIdentity, currentRoot: curRoot || null, currentSeq: (curSeq == null ? null : curSeq), items, chainOk, head, maxAttestedSeq: maxAttestedSeq < 0 ? null : maxAttestedSeq, rolledBack };
}

// ---- Portable, third-party-verifiable proof (make-bundle / verify-bundle) ----
//
// A "proof bundle" is a small, HASH-ONLY package that anyone can verify OFFLINE, without the vault, without a
// password, and without trusting us: the manifest (identity + published verify key + sealed security fields),
// the signed baseline (the file set reduced to a Merkle root, signed by the write key), the identity-
// succession chain, the RFC 3161 timestamped attestation chain, and a genesis anchor (the vault's ORIGINAL
// identity, so a fully-forged succession can't validate). No file contents, names, or sizes-with-content leave
// the machine beyond the paths+sizes+hashes the owner chooses to include. verifyBundle re-runs every check and
// returns GENUINE / TAMPERED / ROLLED-BACK, naming the exact failing check when it does not pass.

// The genesis (original) identity for a vault: the oldest succession link's oldIdentity if it was ever
// rotated, else the current identity. Anchors the succession walk so an attacker's fully self-signed chain,
// which cannot start from the real original identity, is rejected.
function genesisAnchor(manifest, succession) {
	// Versioned like every other bundle file, so a future field (e.g. a post-quantum anchor key) is recognizable
	// and an offline verifier can reject an anchor written by a newer format it does not understand.
	const items = (succession && succession.items) || [];
	if (items.length) return { v: 1, identity: items[0].oldIdentity, pubkey: items[0].oldPubkey, createdAt: manifest.createdAt || null };
	const pub = Integrity.pubkeyOf(manifest);
	return { v: 1, identity: Integrity.identity(pub), pubkey: pub, createdAt: manifest.createdAt || null };
}

// Build a proof bundle for a vault into outDir. Requires the password (to read the signed baseline out of the
// encrypted store); everything written is non-secret.
async function makeBundle(vaultDir, { password, outDir } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates signed baselines (format 3 or newer is required).');
	if (!password) throw new Error('A password is required to build a proof bundle.');
	const bin = await ensureEngine();
	const cred = await unlockCredential(password, manifest);
	const record = await withVaultConfig(bin, abs, password, manifest, cred.master, async (cfg) => {
		if (!(await verifyPassword(bin, cfg, manifest))) throw wrongPasswordError();
		const r = await Rclone.run(bin, ['cat', 'vault:' + SNAPSHOT_NAME], { configPath: cfg, timeoutMs: 60 * 60 * 1000, maxOutBytes: MAX_REMOTE_SNAPSHOT_BYTES });
		if (r.stdout && r.stdout.length >= MAX_REMOTE_SNAPSHOT_BYTES) throw new Error('This vault\'s snapshot is too large to read back for a proof bundle.'); // over-cap read: don't misreport it as "no snapshot"
		if (r.status !== 0 || !r.stdout) throw new Error('This vault has no snapshot yet — run a snapshot first, then build the bundle.');
		try { return JSON.parse(r.stdout); } catch (_) { throw new Error('This vault\'s snapshot could not be read (it is unreadable or corrupt) — take a fresh snapshot, then build the bundle.'); } // a clear message instead of a raw SyntaxError, matching the other snapshot readers
	});
	const succession = await readSuccession(abs);
	const attestations = await readAttestations(abs);
	const genesis = genesisAnchor(manifest, succession);
	const dir = outDir ? path.resolve(outDir) : abs + '.proof';
	await fsp.mkdir(dir, { recursive: true });
	const write = (name, obj) => Common.writeJsonAtomic(path.join(dir, name), obj);
	await write('manifest.json', manifest);
	await write('baseline.json', record);
	await write('succession.json', succession);
	await write('attestations.json', attestations);
	await write('genesis.json', genesis);
	// Copy the self-contained verifier INTO the bundle, so the recipient can check it with nothing but a
	// stock Node.js — no install of this tool required. Best-effort: the bundle still verifies with the tool.
	try { await fsp.copyFile(path.join(__dirname, 'verify-bundle.js'), path.join(dir, 'verify.js')); } catch (_) {}
	await fsp.writeFile(path.join(dir, 'verify.README.txt'),
		'This is a ' + Brand.name + ' proof bundle. It proves the exact state of a vault at a point in time,\n' +
		'and can be checked by anyone, offline, without the vault and without any password.\n\n' +
		'Verify it with either:\n' +
		'  node verify.js .            (needs only a stock Node.js — no install)\n' +
		'  ' + Brand.cli + ' verify-bundle "' + dir + '"   (the full tool; also checks the RFC 3161 timestamps)\n\n' +
		'The check reports GENUINE, TAMPERED, or ROLLED-BACK. GENUINE means the file set, the signed\n' +
		'baseline, the key settings, the identity succession, and the trusted timestamps all agree and\n' +
		'have not been altered. Nothing here contains your file contents.\n\n' +
		'This vault\'s ORIGINAL identity is:\n' +
		'  ' + genesis.identity + '\n' +
		'Two things the math inside this bundle CANNOT prove on its own, so confirm them yourself:\n' +
		'  1. That this origin identity is really the owner\'s. Compare it to a value the owner gave you\n' +
		'     separately (their Recovery Kit, website, or told you). Then verify with that value:\n' +
		'       node verify.js . ' + genesis.identity + '\n' +
		'       ' + Brand.cli + ' verify-bundle "' + dir + '" --expect ' + genesis.identity + '\n' +
		'  2. That this is the LATEST version, if the bundle has no trusted-timestamp proof — GENUINE then\n' +
		'     means authentic and untampered, not necessarily current.\n');
	return { bundle: dir, identity: genesis.identity, originIdentity: genesis.identity, fingerprint: Integrity.fingerprint(record.merkleRoot), seq: record.seq };
}

// Verify a proof bundle offline. Returns { verdict, checks[], identity, fingerprint, asOf, timestamped }.
// verdict: 'GENUINE' | 'TAMPERED' | 'ROLLED-BACK' | 'UNVERIFIED'. Never throws on a bad bundle — a missing or
// malformed file becomes a failed check, fail-closed.
async function verifyBundle(bundleDir, { expectIdentity } = {}) {
	const dir = path.resolve(bundleDir);
	const checks = [];
	const add = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail: detail || '' }); return ok; };
	// A proof bundle is a shared, externally-supplied artifact, so cap each file read — a malicious bundle must not
	// be able to exhaust memory before the fail-closed checks run. Over the cap reads as a missing file (a failed
	// check), never an unbounded allocation. The cap is generous vs a real baseline's file list.
	const load = async (f) => { try { return JSON.parse(await Common.readFileCapped(path.join(dir, f), MAX_REMOTE_SNAPSHOT_BYTES, 'utf8')); } catch (_) { return null; } };
	const manifest = await load('manifest.json'), baseline = await load('baseline.json');
	const succession = await load('succession.json') || { items: [] }, attest = await load('attestations.json') || { items: [] };
	const genesis = await load('genesis.json');
	if (!manifest || !baseline) { add('bundle-complete', false, 'The bundle is missing its manifest or baseline.'); return { verdict: 'UNVERIFIED', checks, identity: null }; }

	const pub = Integrity.pubkeyOf(manifest);
	const identity = pub ? Integrity.identity(pub) : null;
	add('identity-present', !!identity, identity ? '' : 'No published verification key.');

	// Manifest seal (present-but-invalid = the security fields were altered).
	let sealOk = true;
	if (manifest.integrity && manifest.integrity.manifestSig) { sealOk = manifestSealVerifies(manifest, pub, manifest.integrity.manifestSig); }
	add('manifest-seal', sealOk, sealOk ? '' : 'The manifest security fields were altered since they were sealed.');

	// Baseline signature over the exact (root, seq, prevRoot, …).
	let sigOk = false;
	try { sigOk = Integrity.verify(pub, Integrity.signingInput({ scheme: baseline.scheme, root: baseline.merkleRoot, seq: baseline.seq, prevRoot: baseline.prevRoot, count: baseline.count, createdAt: baseline.createdAt, version: baseline.version, sealed: baseline.sealed, deep: baseline.deep }), baseline.sig); } catch (_) { sigOk = false; }
	add('baseline-signature', sigOk, sigOk ? '' : 'The baseline signature does not verify.');

	// The Merkle root reproduces from the recorded file set.
	let rootOk = false;
	try { rootOk = (await Integrity.merkleRoot(baseline.files || [])) === baseline.merkleRoot; } catch (_) { rootOk = false; }
	add('content-root', rootOk, rootOk ? '' : 'The file set does not reproduce the signed root.');

	// Succession anchored from the genesis identity to the current identity. Collect the verified LINEAGE (every
	// identity this vault has provably had) so the caller can confirm a recorded anchor is somewhere in it.
	let successionOk = true;
	const lineage = new Set();
	if (genesis && genesis.identity) lineage.add(genesis.identity);
	if (identity) lineage.add(identity);
	if (genesis && identity && genesis.identity !== identity) {
		let cursor = genesis.identity, reached = false, prevChain = null;
		for (const b of (succession.items || [])) {
			let vfd = false;
			// Same rule as the audit path: each hop is doubly signed, each key hashes to its stated identity, AND
			// the record links to the previous one (its `prev` equals the previous record's `chain`), so a reordered
			// or spliced chain is rejected here too, not only in the full tool.
			try { const input = successionInput(b); vfd = (b.alg || 'ed25519') === 'ed25519' && Integrity.verify(b.oldPubkey, input, b.sigOld) && Integrity.verify(b.newPubkey, input, b.sigNew) && Integrity.identity(b.oldPubkey) === b.oldIdentity && Integrity.identity(b.newPubkey) === b.newIdentity && (b.prev || null) === (prevChain || null); } catch (_) { vfd = false; }
			if (vfd && b.oldIdentity === cursor) { cursor = b.newIdentity; lineage.add(cursor); prevChain = b.chain || null; if (cursor === identity) { reached = true; break; } }
		}
		successionOk = reached;
	}
	add('identity-succession', successionOk, successionOk ? '' : 'The identity does not descend from the original by a valid signed succession.');

	// Origin anchor (closes the fake-lineage gap that no in-bundle crypto can close on its own): the internal
	// checks only prove the chain is self-consistent, NOT that its genesis is the RIGHT one. When the caller passes
	// the origin identity they recorded out of band, confirm it appears in the verified lineage; a mismatch means
	// this bundle is a DIFFERENT vault, or a fabricated lineage rooted at an attacker's own genesis.
	let originOk = true;
	if (expectIdentity) {
		originOk = lineage.has(String(expectIdentity).trim());
		add('origin-identity', originOk, originOk ? 'Matches the recorded origin identity.' : 'This bundle\'s identity lineage does not include the origin identity you recorded — it is a different vault, or a fabricated lineage.');
	}

	// Attestation chain to a trusted timestamp, and the newest attested version.
	let chainOk = true, timestamped = false, asOf = null, maxAttested = -1;
	// Anchor the chain to the identity the FIRST attestation was made under — that is what the writer stored as
	// its `prev` (attestGenesis(item0.identity)), and each item's identity is itself committed inside the
	// TSA-signed digest. Anchoring to the vault's original genesis identity instead would wrongly read a vault
	// first attested AFTER a key rotation as TAMPERED. Succession/origin are proven separately below.
	let prevExpected = attest.items && attest.items.length ? attestGenesis(attest.items[0].identity) : null;
	for (const it of (attest.items || [])) {
		let vok = false, chained = false;
		try {
			const token = Buffer.from(it.token, 'base64');
			const want = attestDigest(it.identity, it.root, it.seq);
			if (Buffer.from(it.digest, 'hex').equals(want)) { const v = Attest.verifyToken(token, { digest: want }); vok = v.ok; if (v.ok && v.genTime) asOf = v.genTime.toISOString(); }
			const expect = attestChainHash(prevExpected, it.digest, tokenHashOf(token));
			chained = (it.chain === expect) && (it.prev == null || it.prev === prevExpected);
		} catch (_) {}
		if (!chained) chainOk = false;
		prevExpected = (it.chain != null) ? it.chain : prevExpected;
		if (vok) { timestamped = true; if (typeof it.seq === 'number' && it.seq > maxAttested) maxAttested = it.seq; }
	}
	if (attest.items && attest.items.length) add('attestation-chain', chainOk, chainOk ? '' : 'The timestamp proof chain is broken (reordered, inserted, or altered).');

	// Rollback: an attested proof exists for a NEWER version than this bundle presents.
	const rolledBack = maxAttested >= 0 && typeof baseline.seq === 'number' && maxAttested > baseline.seq;
	add('not-rolled-back', !rolledBack, rolledBack ? 'A trusted proof exists for a newer version (' + maxAttested + ') than this bundle (' + baseline.seq + ').' : '');

	const structureOk = identity && sealOk && sigOk && rootOk && successionOk && chainOk && originOk;
	let verdict;
	if (!structureOk) verdict = 'TAMPERED';
	else if (rolledBack) verdict = 'ROLLED-BACK';
	else verdict = 'GENUINE';
	return { verdict, checks, identity, fingerprint: baseline.merkleRoot ? Integrity.fingerprint(baseline.merkleRoot) : null, seq: baseline.seq, asOf, timestamped, originIdentity: genesis ? genesis.identity : null };
}

// ---- Secure notes (encrypted, stored as ordinary files inside a mounted vault) ----
//
// A lightweight place to keep secrets, logins, and short notes — not a full password manager. Each note
// is a small JSON file inside the OPEN vault, so the engine encrypts it exactly like any other file: the
// plaintext exists only in the mounted view (kept in RAM), never written decrypted to persistent disk.
// The vault must be unlocked to read or write notes. Notes live in a dedicated hidden folder so they do
// not clutter the vault's normal file view; because they are real vault files, a tamper check accounts
// for them like any other content.
const NOTES_DIR = '.' + Brand.slug + '-notes';
function newNoteId() { return crypto.randomBytes(12).toString('hex'); }
function isNoteId(id) { return /^[a-f0-9]{8,64}$/.test(String(id || '')); } // hex only — never a path or traversal
async function noteMountpoint(vaultDir) {
	return mountpointFor(vaultDir, 'Open (mount) this vault first — secure notes live inside the vault, so it must be unlocked to read or write them.');
}
function notesDirFor(mountpoint) { return path.join(mountpoint, NOTES_DIR); }
async function notesList(vaultDir) {
	const dir = notesDirFor(await noteMountpoint(vaultDir));
	let entries = [];
	try { entries = await fsp.readdir(dir); } catch (_) { return { notes: [] }; } // no folder yet = no notes
	const notes = [];
	for (const f of entries) {
		if (!f.endsWith('.json')) continue;
		const j = await Common.readJsonCorruptAside(path.join(dir, f)).catch(() => null); // skip an unreadable/corrupt note file, like before
		if (j && isNoteId(j.id)) notes.push({ id: j.id, title: j.title || '(untitled)', updatedAt: j.updatedAt || null });
	}
	notes.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
	return { notes };
}
async function noteGet(vaultDir, id) {
	if (!isNoteId(id)) throw new Error('Unknown note.');
	const dir = notesDirFor(await noteMountpoint(vaultDir));
	const j = JSON.parse(await Common.readFileCapped(path.join(dir, id + '.json'), MAX_MANIFEST_BYTES, 'utf8'));
	return { id: j.id, title: j.title || '', body: j.body || '', updatedAt: j.updatedAt || null };
}
const NOTE_VERSION = 1; // the note-record format this build reads and writes
async function noteSave(vaultDir, { id, title, body } = {}) {
	const dir = notesDirFor(await noteMountpoint(vaultDir));
	await fsp.mkdir(dir, { recursive: true });
	let theId = id;
	if (!theId) theId = newNoteId();
	else if (!isNoteId(theId)) throw new Error('Unknown note.');
	// Read any existing record first and PRESERVE its fields, so editing a note never drops a field a newer build
	// added to it (a note lives inside the vault and travels between machines and builds). Refuse to rewrite a
	// newer-format record under this build's older rules, mirroring the sidecar readers.
	let existing = {};
	try { existing = JSON.parse(await Common.readFileCapped(path.join(dir, theId + '.json'), MAX_MANIFEST_BYTES, 'utf8')) || {}; } catch (_) {}
	if (Number(existing.v) > NOTE_VERSION) throw new Error('This note was written by a newer version of the tool, so it is not edited here to avoid dropping what that version added. Update to edit it.');
	const rec = { ...existing, v: NOTE_VERSION, id: theId, title: [...String(title || '')].slice(0, 400).join(''), body: String(body == null ? '' : body), updatedAt: new Date().toISOString() };
	// Atomic write through the mount so a reader never sees a half-written note.
	await Common.writeJsonAtomic(path.join(dir, theId + '.json'), rec);
	return { id: theId, updatedAt: rec.updatedAt };
}
async function noteDelete(vaultDir, id) {
	if (!isNoteId(id)) throw new Error('Unknown note.');
	const dir = notesDirFor(await noteMountpoint(vaultDir));
	await fsp.rm(path.join(dir, id + '.json'), { force: true });
	return { deleted: true };
}

// Compare the vault against its last snapshot and report what changed. Detects added,
// removed, and modified files, plus tampering with the snapshot itself (removed or altered).
// `deep` (the default) compares content hashes when the snapshot has them; a fast audit
// compares sizes only. `clean` is true only when nothing changed and the signature is intact.
async function audit(vaultDir, { password, deep = true } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	// `clean` (not `ok`) is the "nothing changed" flag: the web layer reserves `ok` for
	// "the request succeeded", so a found-changes report must not report ok:false there.
	const report = { vault: abs, hasSnapshot: false, noSnapshot: false, snapshotAt: null, verified: false, deep: false, sealed: false, seq: null, identity: Integrity.identity(Integrity.pubkeyOf(manifest)), fingerprint: null, tamper: [], added: [], removed: [], modified: [], foreign: [], syncIssues: [], errors: [], clean: false };
	report.syncIssues = await scanSyncArtifacts(abs); // explain sync-tool leftovers rather than leaving them as mystery changes
	// Verify the manifest seal (a write-key signature over the salt, key slots, and published key). A
	// present-but-invalid seal means the manifest's security fields were altered since it was last sealed —
	// reported as tampering. Absent seal (a legacy vault, or one not snapshotted since this feature landed)
	// is not a finding; it is added on the next snapshot. Verified against the published key — no password.
	{ const seal = checkManifestSeal(manifest); if (seal.sealed && !seal.ok) report.tamper.push('The vault manifest (its key slots or security settings) has been altered since it was last sealed.'); }
	// Team vault: the membership roster must verify against the pinned owner key. A failure means the member list
	// (who has access, and at what role) was changed without the owner key — treated as tampering.
	if (manifest.members && manifest.members.ownerPubKey && !verifyRoster(manifest)) {
		report.tamper.push('The team membership roster has been altered since it was last signed by the vault owner (a member added, removed, or a role changed without the owner key).');
	}
	if (!password) throw new Error('A password is required to audit a vault.');
	if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault predates snapshot support (format 3 or newer is required).');
	// A mounted vault may hold unflushed writes in its cache, so the encrypted store on disk
	// can lag the live view — auditing it would report phantom changes. Compare it unmounted.
	await assertUnmounted(abs, 'before auditing it');

	const bin = await ensureEngine();
	const cred = await unlockCredential(password, manifest); // one key derivation, shared by config + integrity keys
	return withVaultConfig(bin, abs, password, manifest, cred.master, async (cfg) => {
		if (!(await verifyPassword(bin, cfg, manifest))) { report.errors.push('wrong password'); return report; }
		// Auditing only READS and verifies the signed baseline, so a read-only credential can audit too.
		const auditKeys = integrityKeys(cred.master, cred.writeSeed, manifest);
		const s = await readSnapshot(bin, cfg, manifest, auditKeys);
		if (s.none) {
			// A vault KNOWN to be sealed whose record now reads as absent is a stripped seal, not an un-snapshotted
			// vault — same authenticated-anchor judgment the on-mount check uses, so the two paths agree.
			if (await knownSealed(manifest, auditKeys.hmacKey)) {
				report.hasSnapshot = true; report.sealed = true; report.snapshotAt = (manifest.snapshot && manifest.snapshot.at) || null;
				report.tamper.push('The sealed baseline record is missing from the vault.');
				return report;
			}
			report.noSnapshot = true; report.errors.push('No snapshot has been taken for this vault yet — run "' + Brand.cli + ' snapshot" to create one.');
			// Foreign-file detection needs no baseline, and a user who suspects tampering may audit before
			// ever snapshotting — so still scan for undecryptable files dropped into the store.
			try { const cap = await captureFiles(bin, cfg, { deep: false }); report.foreign = cap.foreign || []; } catch (_) {}
			if (report.foreign.length) report.tamper.push(foreignNote(report.foreign));
			return report;
		}
		if (s.unknown) { report.hasSnapshot = true; report.snapshotAt = s.at || null; report.sealed = !!(manifest.snapshot && manifest.snapshot.sealed); report.errors.push('This vault\'s baseline was ' + s.reason + ', so this version cannot verify it — update the tool to check this vault' + (report.sealed ? ' (it is sealed, so verify before trusting it)' : '') + '.'); return report; }
		if (s.unreadable) { report.hasSnapshot = true; report.snapshotAt = s.at || null; report.sealed = !!(manifest.snapshot && manifest.snapshot.sealed); report.errors.push('This vault\'s baseline could not be verified because ' + s.reason + '. The snapshot record is present and has not been removed; this is a size limit, not tampering.'); return report; }
		report.hasSnapshot = true;
		// The baseline record itself is missing or forged. Report it as tampering, and carry the
		// sealed state from the manifest (which still stands) so the surface can present it as a
		// serious finding rather than "0 changes since <null>".
		if (s.tamper) { report.snapshotAt = s.at || (manifest.snapshot && manifest.snapshot.at) || null; report.sealed = !!(manifest.snapshot && manifest.snapshot.sealed); report.tamper.push(s.tamper); return report; }
		report.snapshotAt = s.record.createdAt;
		report.verified = true;
		report.sealed = !!s.record.sealed;
		report.seq = s.record.seq;
		report.fingerprint = Integrity.fingerprint(s.record.merkleRoot);

		// Identity-substitution check (a swapped published verify key with no signed succession). Shared with the
		// on-mount check. Evaluated before the diff below, whose rollbackWarning advances the ledger.
		const idNote = await identitySubstitutionNote(abs, manifest);
		if (idNote) report.tamper.push(idNote);

		// Only hash the current files when a deep compare is possible and requested. The shared classifier computes the
		// diff and rollback warning, applies the content anchor (clearing benign bookkeeping desync), and never clears a
		// seal downgrade — one copy of that logic for both audit and the on-mount check.
		report.deep = !!(deep && s.record.deep);
		const cur = await captureFiles(bin, cfg, { deep: report.deep });
		const cls = await classifyAgainstBaseline(bin, cfg, manifest, s.record, cur.files, report.deep);
		report.staleBaseline = cls.staleBaseline; // the vault is current; only its in-vault baseline record was out of date (re-established on the next mount)
		if (cls.sealDowngrade) report.tamper.push(sealDowngradeNote);
		if (cls.roll) report.tamper.push(cls.roll);
		report.added = cls.added; report.removed = cls.removed; report.modified = cls.modified;
		// Foreign files sitting in the encrypted store that the crypt view can't decrypt — added or altered
		// outside the vault by someone without the key, or name-corrupted. Invisible to the file-by-file
		// compare above (which only sees decryptable files), so surface them explicitly as tampering.
		report.foreign = cur.foreign || [];
		if (report.foreign.length) report.tamper.push(foreignNote(report.foreign));
		report.clean = !report.added.length && !report.removed.length && !report.modified.length && !report.tamper.length;
		if (!report.clean) await logTamper(manifest, { kind: report.sealed ? 'sealed-mismatch' : 'audit-change', added: report.added, removed: report.removed, modified: report.modified, foreign: report.foreign, notes: report.tamper });
		return report;
	});
}

// The automatic on-mount check. Returns { trusted, warn }:
//   trusted — whether the vault matched its baseline (or a fresh baseline was just
//     established). Only a trusted session may refresh the baseline on unmount; a session
//     that found changes must NOT, or unmounting would silently bless the tampered state and
//     erase the evidence before the user can audit it.
//   warn — null when there is nothing to tell the user, else { tamper, added, removed,
//     modified } to surface.
// Uses only a fast (paths + sizes) scan so it never decrypts content or delays the mount
// noticeably. Wrapped by the caller in a timeout and try/catch; any failure is silent, the
// mount proceeds, and the session is treated as NOT trusted (so it will not re-baseline).
// The tool's own metadata files that CHANGE on their own schedule — the signed tamper snapshot (rewritten
// on every baseline refresh) and the session marker (written at mount, removed at unmount). Their
// encrypted blobs must be LEFT OUT of the self-healing recovery parity: otherwise a heal, finding them
// different from the parity built earlier, reverts them to a stale version and breaks the tamper
// baseline. The canary is excluded for the same reason: rclone crypt gives every write a fresh random
// nonce, so if the canary is ever legitimately rewritten (verifyPassword restores it when it fails to read
// back), its ciphertext changes at the SAME size — which the size-based staleness check misses, leaving
// verify to report the canary block as damaged forever and heal to keep reverting it. A corrupted canary
// does not need parity anyway: verifyPassword re-establishes it on the next unlock of a key-wrapping vault.
// The encrypted on-disk names are deterministic, so compute them once (when a mount gives us the crypt
// config) and cache them in the manifest for the passwordless recovery code to read. Best-effort.
// Fixed-name OS metadata files that the system creates and churns on ordinary use (browsing folders in
// Finder writes a .DS_Store per folder; navigating/playing media touches more), which would otherwise make
// the recovery data look "stale" and rebuild on every unmount even for a read-only session. They are excluded
// from recovery by BASENAME — rclone crypt encrypts each filename segment deterministically, so a fixed name
// has ONE encrypted basename in every folder. Only FIXED names can be excluded this way; variable-named junk
// (._<file> AppleDouble sidecars, .fuse_hidden<hex>, .nfs<hex>) is not covered here. This set BUILDS ON the shared
// OS_JUNK_COMMON core (so a fixed name added there flows through automatically) and adds MORE OS-metadata names —
// recovery deliberately excludes a broader set than the mount/tamper IGNORED_BASENAME list, because it only needs to
// match fixed encrypted basenames; the core's junk-DIRECTORY names are harmless here (they never match a file).
// The CANONICAL, cross-platform set of FIXED-name OS metadata files, matching the widely-used GitHub
// "Global" gitignore templates (macOS/Windows/Linux). These are OS-reserved names that the system creates
// and regenerates on its own; users do not store real data under them. Only FIXED names are here — VARIABLE
// junk (AppleDouble ._<file>, .fuse_hidden<hex>, .nfs<hex>, and the contents of junk DIRECTORIES like
// .Spotlight-V100 / .fseventsd) cannot be matched by a fixed encrypted basename and is instead handled by the
// content-based refresh gate (which never rebuilds recovery when only OS metadata churned). IMPORTANT: being
// on this list only means a file is not covered by SELF-HEAL/tamper — it is still fully stored and encrypted
// in the vault; nothing here is ever deleted or hidden from you.
const OS_JUNK_NAMES = [...new Set([
	...OS_JUNK_COMMON, // the shared fixed-name core (.DS_Store, Thumbs.db, desktop.ini, and the junk-dir names — the latter harmless as file-basename excludes)
	// recovery-only additions — a broader set of fixed OS-metadata names:
	'.localized', '.VolumeIcon.icns', '.com.apple.timemachine.donotpresent', '.apdisk', '.LSOverride', '.metadata_never_index', // macOS
	'ehthumbs.db', 'ehthumbs_vista.db', 'Desktop.ini', // Windows
	'.directory' // Linux (KDE)
])];
const RECOVERY_EXCLUDE_NAMES = [SNAPSHOT_NAME, SNAPSHOT_NAME + '.new', SESSION_NAME, SESSION_NAME + '.new', CANARY_NAME, ...OS_JUNK_NAMES];
const RECOVERY_EXCLUDE_V = 4; // bump when RECOVERY_EXCLUDE_NAMES changes, so an existing vault recomputes its cached list
// The encrypted metadata/junk names that recovery must skip are a DETERMINISTIC, recomputable cache — not part
// of the signed manifest. They live in a per-machine sidecar under the app data dir (keyed by the vault path),
// NOT in vault.json, so a mount never rewrites the sealed manifest. That is what stops a mount from clobbering a
// key/member change another process made at the same time. If the vault moves to another machine, the first
// mount there simply recomputes the sidecar. A legacy value left in the manifest is still read as a fallback.
function recoveryExcludeCachePath(abs) {
	const h = vaultDirTag(abs);
	return path.join(Common.dataDir(), 'recovery-exclude', h + '.json');
}
async function readRecoveryExcludeCache(abs, manifest) {
	try { const j = JSON.parse(await fsp.readFile(recoveryExcludeCachePath(abs), 'utf8')); if (j && j.v === RECOVERY_EXCLUDE_V && Array.isArray(j.names) && j.names.length) return j.names; } catch (_) {}
	if (manifest && Array.isArray(manifest.recoveryExclude) && manifest.recoveryExclude.length && manifest.recoveryExcludeV === RECOVERY_EXCLUDE_V) return manifest.recoveryExclude; // legacy: cached in the manifest by an older build
	return null;
}
async function ensureRecoveryExclude(bin, cfg, abs, manifest) {
	const cached = await readRecoveryExcludeCache(abs, manifest);
	if (cached) return cached;
	try {
		const enc = await Rclone.cryptEncodeNames(bin, cfg, RECOVERY_EXCLUDE_NAMES);
		if (enc.length) {
			const p = recoveryExcludeCachePath(abs);
			// Best-effort cache; never fail the mount. But WARN on a write failure: if the app data dir is not
			// writable the cache never persists, and self-heal setup would otherwise keep reporting the misleading
			// "mount the vault once first" (EXCLUDE_NOT_READY) with no hint of the real cause.
			try { await fsp.mkdir(path.dirname(p), { recursive: true }); await Common.writeJsonAtomic(p, { v: RECOVERY_EXCLUDE_V, names: enc }); }
			catch (e) { Common.warn('Could not save the recovery-metadata cache to the app data folder (' + (e && e.message ? e.message : e) + '); self-healing setup may report the vault as not ready until this folder is writable.'); }
			return enc;
		}
	} catch (_) {}
	return (manifest && manifest.recoveryExclude) || [];
}

async function autoTamperOnMount(bin, cfgText, abs, manifest, keys) {
	const cfg = await Rclone.writeEphemeralConfig(cfgText);
	const t = AUTO_SCAN_TIMEOUT_MS; // bound every engine call so a wedged store frees the mount fast
	await ensureRecoveryExclude(bin, cfg, abs, manifest); // cache the metadata blob names so recovery skips them
	try {
		const s = await readSnapshot(bin, cfg, manifest, keys, { timeoutMs: t });
		if (s.none) {
			// This device recorded this vault as SEALED (in the local, attacker-inaccessible rollback ledger), yet the
			// in-vault record now reads as absent or downgraded. That is exactly what stripping a seal looks like:
			// removing the strict record and editing the manifest's (unauthenticated) sealed flag to false. Judge the
			// seal from the ledger anchor, not from the editable manifest field, so the downgrade cannot be laundered by
			// rewriting the manifest. Never silently replace a seal with a fresh unsealed baseline: report tampering and
			// leave the seal in force. (A brand-new vault has no ledger entry, so the first-baseline path below still runs.)
			if (await knownSealed(manifest, keys && keys.hmacKey)) {
				const note = 'The sealed baseline record is missing from the vault.';
				await logTamper(manifest, { kind: 'baseline-altered', notes: [note] });
				return { trusted: false, warn: { kind: 'tamper', tamper: [note], added: [], removed: [], modified: [], sealed: true } };
			}
			// No baseline yet — establish a fast one so future mounts can check, and mark the session.
			// Only report the session as trusted if a baseline was actually written (a read-only
			// credential, or an engine hiccup, leaves seq null and nothing to trust).
			let seq = null, firstForeign = [];
			try { const w = await writeSnapshot(bin, cfg, abs, manifest, keys, { deep: false, auto: true, timeoutMs: t }); seq = w.seq; firstForeign = w.foreign || []; } catch (_) {}
			await writeSessionMarker(bin, cfg, manifest, keys, seq, { timeoutMs: t });
			// Foreign files already sitting in the store when the very first baseline is taken must still be
			// reported and must not leave the session trusted — otherwise a clean unmount would bless them.
			if (firstForeign.length) {
				await logTamper(manifest, { kind: 'changed-while-unmounted', foreign: firstForeign, notes: [foreignNote(firstForeign)] });
				return { trusted: false, warn: { kind: 'tamper', tamper: [foreignNote(firstForeign)], added: [], removed: [], modified: [], foreign: firstForeign, sealed: false } };
			}
			return { trusted: seq != null, warn: null };
		}
		if (s.unreadable) {
			// The baseline is present but too large to read back for verification (a size limit, not tampering). Do
			// NOT raise a tamper alarm — that would be a false alarm — but do NOT auto-trust either: leave the
			// session untrusted so the baseline is preserved and never auto-refreshed. The vault still mounts; the
			// explicit audit/verify path reports the size limit in words. This is unreachable for any realistic vault.
			return { trusted: false, warn: null };
		}
		if (s.unknown) {
			// A baseline record this build cannot interpret (a newer version, or an integrity scheme this build
			// does not know). We must NOT clobber it — a genuinely newer tool may have written it — but we must NOT
			// silently trust it either: an attacker who can write a store object could otherwise bump the record's
			// version to make this check return "all clear" and even void a seal. Fail CLOSED — surface it and
			// leave the session untrusted, so the user learns their baseline cannot be verified by this build (and
			// updates the tool) rather than getting a silent pass. If the vault is sealed, the seal state is carried
			// through so it is never quietly downgraded.
			const note = 'This vault\'s baseline was ' + (s.reason || 'written by a newer version of the tool') + ', so this version of ' + Brand.name + ' cannot verify it — update ' + Brand.name + ' to check this vault.';
			await logTamper(manifest, { kind: 'baseline-altered', notes: [note] });
			return { trusted: false, warn: { kind: 'tamper', tamper: [note], added: [], removed: [], modified: [], sealed: !!(manifest.snapshot && manifest.snapshot.sealed) } };
		}
		if (s.tamper) { await logTamper(manifest, { kind: 'baseline-altered', notes: [s.tamper] }); return { trusted: false, warn: { kind: 'tamper', tamper: [s.tamper], added: [], removed: [], modified: [], sealed: !!(s.record && s.record.sealed) } }; }
		// A baseline written before the seal state was bound into the signature (version < 4) could have its
		// seal bit stripped by a read-key holder without breaking the signature. The record has just VERIFIED,
		// so a write-key session re-signs it at the current version in place — identical file set, seq, and seal
		// state — making the seal (and deep flag) signature-bound. Sealed baselines never auto-refresh, so this
		// is the only path that upgrades them; it changes nothing the user sees. Best-effort, never blocks mount.
		if (s.record.version < BASELINE_VERSION && keys && keys.signPriv) {
			try { await resignBaselineV4(bin, cfg, abs, manifest, keys, s.record, { timeoutMs: t }); } catch (_) {}
		}
		const sealed = !!s.record.sealed;
		const tamper = [];
		// Identity substitution (a swapped published verify key with no signed succession) — checked on the mount path
		// too, not only in audit, so a read-only-password mounter who never runs an audit is protected. Evaluated
		// before the classifier below, whose rollbackWarning advances the ledger.
		const idNote = await identitySubstitutionNote(abs, manifest);
		if (idNote) tamper.push(idNote);
		// The on-mount check is a FAST STRUCTURAL check (paths + sizes), even for a sealed vault: a full content
		// hash of every file cannot reliably fit the mount's time budget on a large vault, and overrunning it would
		// abort the check silently. So the mount catches anything added, removed, or resized; a SAME-SIZE content
		// edit of an existing file is caught by the deep `audit` (and a naive byte flip fails closed on read, since
		// the encryption is authenticated). This is why a sealed vault should be audited periodically for the
		// strictest content assurance — see the tamper-detection docs.
		const cap = await captureFiles(bin, cfg, { deep: false, timeoutMs: t });
		// The shared classifier computes the diff + rollback warning and applies the content anchor (clearing a benign
		// bookkeeping desync), never clearing a seal downgrade — the exact logic the manual audit uses.
		const cls = await classifyAgainstBaseline(bin, cfg, manifest, s.record, cap.files, false, t);
		if (cls.sealDowngrade) tamper.push(sealDowngradeNote);
		if (cls.roll) tamper.push(cls.roll); // whole-vault rollback / rewritten history (null when the content anchor cleared it)
		const diff = { added: cls.added, removed: cls.removed, modified: cls.modified };
		// Foreign/undecryptable files in the store are a HARD finding: they can't be the owner's own
		// interrupted writes (those always carry a valid encrypted name), so they are added to `tamper`
		// — which both forces a report and blocks the interrupted-session path from ever blessing them.
		const foreign = cap.foreign || [];
		if (foreign.length) tamper.push(foreignNote(foreign));
		const changed = diff.added.length || diff.removed.length || diff.modified.length;

		// Self-heal. When the classifier cleared everything via the content anchor (the vault's contents still hash to
		// the last trusted ledger root) and there is no hard finding, the vault is genuinely unchanged — the in-vault
		// record merely fell behind (for example a snapshot write cut short when the service was killed). Re-establish
		// the baseline in place (a write-key, unsealed session) so it stops re-alarming, and treat the session as
		// clean. A sealed vault is never auto-refreshed, so its record is left untouched — the false alarm is simply
		// suppressed. A seal downgrade never reaches here: the classifier refuses to clear it, so `tamper` is non-empty.
		if (cls.staleBaseline && !tamper.length) {
			if (!sealed && keys && keys.signPriv) {
				let seq = null;
				try { const w = await writeSnapshot(bin, cfg, abs, manifest, keys, { deep: !!s.record.deep, auto: true, timeoutMs: t }); seq = w.seq; } catch (_) {}
				await writeSessionMarker(bin, cfg, manifest, keys, seq, { timeoutMs: t });
			}
			return { trusted: !sealed, warn: null };
		}

		// Clean and matches the baseline. Mark the live session (an unsealed baseline only re-signs on a
		// clean unmount, so the marker is what tells the NEXT mount whether this one ended cleanly).
		if (!tamper.length && !changed) {
			await writeSessionMarker(bin, cfg, manifest, keys, s.record.seq, { timeoutMs: t });
			// Undecryptable files whose name matches a sync-conflict pattern are benign leftovers (they never
			// block trust), but surface them on mount too — not only in an audit — so one that was dropped in
			// and named like a conflict to dodge the foreign-file finding is never completely silent.
			const syncForeign = cap.syncForeign || [];
			if (syncForeign.length) {
				const note = syncForeign.length + ' cloud-sync leftover' + (syncForeign.length === 1 ? '' : 's') + ' in the store (such as a "conflicted copy"). Resolve them in your sync app, or remove any you did not expect — a tamper check lists them.';
				return { trusted: !sealed, warn: { kind: 'changed', tamper: [note], added: [], removed: [], modified: [], sealed } };
			}
			return { trusted: !sealed, warn: null };
		}

		// Content changed and/or the version counter moved. A HARD finding (rollback / rewritten
		// history) is always reported and never softened. For content-only changes on an UNSEALED
		// vault, a valid, current session marker means the previous session was interrupted before a
		// clean unmount could record its writes — so accept them into the baseline and say so gently,
		// instead of raising a tamper alarm for the owner's own files. Requires the write key.
		if (!tamper.length && !sealed && keys && keys.signPriv) {
			const marker = await readSessionMarker(bin, cfg, manifest, keys, s.record.seq, { timeoutMs: t });
			if (marker) {
				await logTamper(manifest, { kind: 'interrupted-session', added: diff.added, removed: diff.removed, modified: diff.modified,
					notes: ['The vault was not closed cleanly; these changes are from the interrupted session and have been accepted into the baseline.'] });
				let seq = null;
				// Preserve the baseline's DEPTH: if it carried per-file content hashes, re-capture deep so those
				// hashes stay current instead of being erased down to size-only (which would leave a same-size
				// substitution undetectable even by a later deep audit). A timeout leaves the prior baseline intact.
				try { const w = await writeSnapshot(bin, cfg, abs, manifest, keys, { deep: !!s.record.deep, auto: true, timeoutMs: t }); seq = w.seq; } catch (_) {}
				await writeSessionMarker(bin, cfg, manifest, keys, seq, { timeoutMs: t });
				return { trusted: true, warn: { kind: 'interrupted', tamper: [], ...diff, sealed: false } };
			}
		}

		// No interruption evidence (or a sealed vault, or a hard finding): report it. A sealed vault is
		// authoritative and is NEVER auto-refreshed, so any change keeps being reported until re-sealed.
		await logTamper(manifest, { kind: sealed ? 'sealed-mismatch' : 'changed-while-unmounted', added: diff.added, removed: diff.removed, modified: diff.modified, foreign, notes: tamper });
		return { trusted: false, warn: { kind: tamper.length ? 'tamper' : 'changed', tamper, ...diff, foreign, sealed } };
	} finally { await Rclone.removeConfig(cfg); }
}

// Run the on-mount integrity check against a vault's CURRENT settled state WITHOUT mounting it, and
// return { trusted, warn } exactly as a mount would — the same crash-vs-tamper decision (establishing
// or refreshing the baseline and the session marker included), on its own for diagnostics and tests.
// Requires the vault unmounted so the store is settled; a read-only credential yields warn only.
async function checkOnMount(vaultDir, password) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) return { trusted: false, warn: null };
	await assertUnmounted(abs, 'before checking it');
	const bin = await ensureEngine();
	const cred = await unlockCredential(password, manifest);
	const cfgText = await buildConfigText(bin, abs, password, manifest, cred.master);
	const keys = integrityKeys(cred.master, cred.writeSeed, manifest);
	return autoTamperOnMount(bin, cfgText, abs, manifest, keys);
}

// Finalize a session on a CLEAN unmount: refresh the automatic baseline to the vault's settled state
// (only when this session was trusted and the vault is unsealed), and ALWAYS clear the session marker
// so a clean shutdown is never later read as an interrupted one. Best-effort and bounded by the
// caller; the manifest is re-read so a concurrent change is never clobbered. A read-only session
// (no signing key) never wrote a baseline or a marker, so both steps are harmless no-ops for it.
async function finishSession(abs, { cfgText, keys, trusted }) {
	const bin = RcloneSetup.resolve();
	if (!bin) return;
	const manifest = await readManifest(abs);
	if (!hasKeyWrapping(manifest.crypt)) return;
	const sealed = !!(manifest.snapshot && manifest.snapshot.sealed); // a sealed baseline is the tripwire — never auto-refreshed
	const cfg = await Rclone.writeEphemeralConfig(cfgText);
	try {
		// Only a read-WRITE session writes a baseline or a marker, so only it finalizes them. A read-only
		// session leaves both untouched — in particular it must not clear a crash marker left by a
		// read-write session, which would make the next read-write mount miss the interrupted-session case.
		if (keys && keys.signPriv) {
			if (trusted && !sealed) {
				// Preserve the baseline's DEPTH on the clean-unmount refresh: a vault the user protected with a
				// deep (content-hash) baseline keeps accurate per-file hashes instead of being silently downgraded
				// to size-only, which would erase the only evidence that catches a same-size content substitution.
				// Re-hashing a large deep vault can be slow; if it exceeds the budget it simply throws and the prior
				// baseline (and its evidence) is retained — an unmount must never be disrupted by the refresh.
				const prevDeep = !!(manifest.snapshot && manifest.snapshot.deep);
				try { const w = await writeSnapshot(bin, cfg, abs, manifest, keys, { deep: prevDeep, auto: true, timeoutMs: AUTO_SCAN_TIMEOUT_MS }); recentRealChange.set(abs, { changed: !!w.changed, at: Date.now() }); } // record whether REAL content changed, so the post-unmount recovery refresh can skip a metadata-only session
				catch (_) {} // a slow/failed refresh leaves the previous baseline intact — evidence preserved, unmount undisturbed
			}
			await removeSessionMarker(bin, cfg, { timeoutMs: AUTO_SCAN_TIMEOUT_MS });
		}
	} finally { await Rclone.removeConfig(cfg); }
}

// Pack a vault into a single, portable .vdisk file (a container of the already-
// encrypted vault folder) — convenient for backup or transport, and impossible to
// accidentally remove one file from. The contents are already encrypted, so packing
// adds no security but also leaks nothing. Packing streams the tree entry-by-entry, so a
// vault of any size packs in constant memory — there is no in-memory size ceiling.

// A private staging root for the large intermediate archives that unpack/disperse/reconstruct build. Deliberately
// under the app data directory rather than os.tmpdir(): on many Linux systems /tmp is a RAM-backed tmpfs sized at
// a fraction of memory, so staging a multi-GB ciphertext archive there fails with ENOSPC (or thrashes swap) even
// when the real disk has ample room — the same reason the RAM cache refuses an os.tmpdir() fallback. The data
// directory lives on real disk on every platform. Callers pair this with a free-space precondition.
function stagingRoot() { return path.join(Common.dataDir(), 'staging'); }
async function makeStagingPath(tag, ext = '') {
	const root = stagingRoot();
	await fsp.mkdir(root, { recursive: true });
	return path.join(root, 'vdisk-' + tag + '-' + crypto.randomBytes(6).toString('hex') + ext);
}
// Fail fast, with a clear message, when the staging disk lacks room for an archive of about `bytes` — turning a
// confusing mid-operation ENOSPC into an upfront, recoverable error. Best-effort: an unreadable free figure never
// blocks the operation, since the write itself still surfaces a real out-of-space error if it comes to that.
async function assertStagingSpace(bytes, action) {
	try {
		await fsp.mkdir(stagingRoot(), { recursive: true });
		const free = await Common.diskFree(stagingRoot());
		if (free != null && bytes > 0 && free.freeBytes < bytes * 1.1) {
			throw new Error('Not enough free space to ' + action + ' — about ' + Math.ceil(bytes / 1e9 * 1.1) + ' GB free is needed on the app data disk. Free some space and try again.');
		}
	} catch (e) {
		if (/Not enough free space/.test(e && e.message)) throw e; // the precondition fired -> surface it
		if (e instanceof TypeError || e instanceof ReferenceError || e instanceof RangeError) throw e; // a bug in the estimator must never hide silently behind this best-effort check
		// otherwise the free-space COULD NOT BE MEASURED (a transient I/O / statfs failure): skip this best-effort
		// precondition and let the real write surface any genuine out-of-space error, exactly as before.
	}
}

async function pack(vaultDir, outFile, opts = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Claim the vault EXCLUSIVELY vs a concurrent mount/mirror BEFORE any I/O, and synchronously so the claim
	// is atomic with the mount-side check. assertUnmounted below is only a point-in-time check; without this
	// claim a mount could begin partway through the long tree read and the archive would capture a torn cipher
	// store (it corrupts only the shareable copy, never the source, but breaks pack's own guarantee). Held for
	// the whole operation. This also serializes two concurrent packs of the same vault.
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount, mirror, or pack). Wait for it to finish, then try again.', async () => {
		const manifest = await readManifest(abs); // ensure it is a valid vault (and read its key slots)
		// A cloud vault keeps only its manifest here — the encrypted files are at the provider — so a pack would
		// produce an archive with the keys but no data, which is not the portable copy the user expects. Refuse it.
		if (isCloudVault(manifest)) throw new Error('This vault\'s data lives in your cloud provider, so it cannot be packed into a portable file here (the archive would hold only its keys, not the data). Export a Recovery Kit for the keys: ' + Brand.cli + ' recovery-kit ' + displayName(abs) + '.');
		// Refuse a mounted vault: the working cache may hold unflushed data and files can
		// be mid-write, so a pack could capture a torn, undecryptable state.
		await assertUnmounted(abs, 'before packing it');
		// No in-memory size ceiling: packing streams the tree entry-by-entry (constant memory, one open file at a
		// time), so a vault of any size can be packed. A destination that runs out of space fails cleanly — the
		// half-written temp is removed and the original is untouched.
		// outFile wins; otherwise place the default-named container in opts.destFolder (used by the Share UI's
		// folder picker) or, failing that, the current directory. The name derivation stays single-sourced here.
		const out = outFile ? path.resolve(outFile) : path.join(opts.destFolder ? path.resolve(opts.destFolder) : process.cwd(), displayName(abs) + Brand.packExt);
		if (!opts.overwrite && (await exists(out))) throw new Error('A file already exists at ' + out + ' (use --force to overwrite).');
		// Optional: share the vault with only SELECTED keys. Substitute a manifest that keeps just the chosen
		// key slots, so a password (e.g. the owner's) whose slot is left out cannot open the shared copy. Only
		// the slot list is filtered — every other manifest field is preserved untouched, so this stays correct
		// as the format grows. The rest of the vault (the encrypted store, the signed baseline, recovery data)
		// is byte-identical; the master key is unchanged, access is governed purely by which slots are present.
		let override;
		if (Array.isArray(opts.keepSlots) && opts.keepSlots.length) {
			if (!hasKeyWrapping(manifest.crypt)) throw new Error('This vault has no key slots to choose from.');
			const keep = new Set(opts.keepSlots.map(String));
			const filtered = keySlotsOf(manifest.crypt).filter(s => keep.has(String(s.id)));
			if (!filtered.length) throw new Error('Sharing with selected keys needs at least one of the vault\'s keys, but none of the chosen ones were found.');
			// A device (biometric) slot is bound to the machine it was enrolled on and cannot open a copy
			// elsewhere, so a copy carrying ONLY device slots could be opened by no one. Require at least one
			// portable key (password / read-only / recovery / keyfile) so the shared copy is actually openable.
			if (!filtered.some(s => (s.kind || 'password') !== 'device')) throw new Error('The chosen keys are all device (Touch ID / Windows Hello) keys, which only work on the machine they were set up on. Include a password, read-only, recovery, or keyfile key so the shared copy can be opened.');
			const shared = Buffer.from(JSON.stringify(withKeySlots(manifest, filtered), null, 2));
			override = { [MANIFEST]: shared, [MANIFEST_BAK]: shared }; // both manifest copies carry the filtered slots
		}
		// Build the container in a worker: packing streams the tree entry-by-entry (constant memory), and running it
		// off the main thread keeps the long-running service's event loop clear during the CPU-bound compression. The
		// idle watchdog (fed by per-entry and byte-level heartbeats) also bounds a pack wedged on unresponsive storage.
		await WorkerRun.runWorker(path.join(__dirname, 'PackWorker.js'), { op: 'pack', args: { vaultDir: abs, out, override } }, opts.onProgress, { idleMs: 120000, idleMessage: 'Packing the vault' });
		return { file: out };
	});
}

// Unpack a .vdisk file back into a usable vault folder and remember it. The archive
// is extracted into a private staging area and validated (exactly one .vault folder,
// no stray top-level files that could overwrite things in the destination) BEFORE
// anything is placed in the destination.
async function unpack(file, destDir, opts = {}) {
	const src = path.resolve(file);
	const dest = destDir ? path.resolve(destDir) : process.cwd();
	// The archive extracts into staging before anything lands in the destination, so the staging disk needs
	// room for roughly the archive's own size. Check it up front (the archive is ciphertext, so its unpacked
	// size is close to the file's size) rather than failing partway through the extraction.
	let srcSize = 0; try { srcSize = (await fsp.stat(src)).size; } catch (_) {} // best-effort: an unreadable size just skips the check
	await assertStagingSpace(srcSize, 'unpack the archive'); // already swallows all but the space error, so no wrapper is needed
	const staging = await makeStagingPath('unpack');
	activeTemps.add(staging); // shield it from the stale-temp sweep for the duration
	await fsp.mkdir(staging, { recursive: true });
	try {
		const tops = await Net.unzip(src, staging, { onProgress: opts.onProgress });
		const vaultTops = tops.filter(t => /\.vault$/i.test(t));
		const strays = tops.filter(t => !/\.vault$/i.test(t) && t !== Net.CONTAINER_MARKER);
		if (vaultTops.length !== 1 || strays.length) throw new Error('This is not a valid vault archive.');
		const stagedVault = path.join(staging, vaultTops[0]);
		await readManifest(stagedVault); // validate the payload
		const target = path.join(dest, vaultTops[0]);
		if (await exists(target)) throw new Error('A vault already exists at ' + target + '.');
		await fsp.mkdir(dest, { recursive: true });
		try { await Common.renameWithRetry(stagedVault, target); } // retry a transient Windows lock; falls through to the copy path only for a real cross-device move
		catch (e) {
			if (e.code !== 'EXDEV') throw e;
			// Cross-device: copy instead of rename. If the copy fails partway (e.g. disk full), remove the
			// half-written target so it can never later look like a real (but corrupt) vault.
			try { await fsp.cp(stagedVault, target, { recursive: true }); }
			catch (ce) { try { await fsp.rm(target, { recursive: true, force: true }); } catch (_) {} throw ce; }
		}
		await markAsPackage(target);
		await State.addVault(target);
		return { vault: target };
	} finally { try { await fsp.rm(staging, { recursive: true, force: true }); } catch (_) {} activeTemps.delete(staging); }
}

// --- Tier 3: disperse a vault across nodes (durability), and threshold-split its key (custody) -----
// Dispersal is for DURABILITY, not a live mount: a vault is packed into one archive, the archive is
// split into n shards (any k rebuild it), and one shard goes to each node/folder. Each node holds only
// an incomplete slice of the already-encrypted vault (ciphertext), so no single shard reveals its
// contents. To USE a dispersed vault you gather any k shards, reconstruct the archive, and unpack it
// back to a normal vault — rehydrate-then-use. Everything here is off any hot mount and best-effort,
// and never overwrites an existing shard or vault without being asked.
//
// The Reed–Solomon encode/decode and the whole (bounded) archive are held in the WORKER thread (see
// DisperseWorker.js), never on the calling thread — so even a large vault dispersed from the long-running
// web server can never block the event loop or a mounted drive's health checks.

// Recommended durability guidance for an (n, k) choice: the storage expansion is n/k, and the vault
// survives losing up to n-k nodes. Exposed so the CLI/UI can guide the user instead of forcing a default.
function dispersalGuidance(n, k) {
	const expansion = k > 0 ? n / k : 0;
	return { n, k, m: n - k, tolerate: n - k, expansionFactor: Math.round(expansion * 100) / 100 };
}

// Disperse a vault into n shards written to n destination folders (local drives, external disks, or
// network/served-peer mounts). Any k of them reconstruct it. The vault must be unmounted.
async function disperse(vaultDir, { n, k, dests, force, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// A cloud vault's data is at the provider, not on this machine, so dispersing it would produce shards holding
	// only the keys and no data — no real durability. Refuse it (pack, which disperse uses, refuses too).
	if (isCloudVault(await readManifest(abs))) throw new Error('This vault\'s data lives in your cloud provider, so it cannot be dispersed into shards here (they would hold only its keys, not the data). Export a Recovery Kit for the keys: ' + Brand.cli + ' recovery-kit ' + displayName(abs) + '.');
	await assertUnmounted(abs, 'before dispersing it');
	if (!Number.isInteger(n) || !Number.isInteger(k) || k < 1 || n < k || n > 255) throw new Error('Choose 1 ≤ k ≤ n ≤ 255 (k shards rebuild the vault; n shards are made).');
	if (!Array.isArray(dests) || dests.length !== n) throw new Error('Provide exactly ' + n + ' destination folder(s), one per shard.');
	const name = displayName(abs);
	// Resolve and pre-check every destination BEFORE writing anything, so a clash on the last one does
	// not leave a half-dispersed set. The shard's index is in the filename too (not only inside the
	// file), so a shard that is deleted entirely can still be re-created into the right slot on repair.
	const files = dests.map((d, i) => path.join(path.resolve(d), name + '.' + i + 'of' + n + '.vdshard'));
	if (!force) for (const f of files) if (await exists(f)) throw new Error('A shard already exists at ' + f + '. Move it aside, choose another folder, or force.');
	// The whole vault FOLDER is packed into one staged archive before it is split (manifest, signed baseline, any
	// in-vault recovery parity and snapshots — not just the cipher store), so size the staging pre-check from the same
	// whole-tree measure the pack itself uses. Estimating from the cipher store alone could pass here yet hit ENOSPC
	// mid-pack on a protected vault with substantial parity. A clear upfront error beats a failure halfway through.
	await assertStagingSpace(await Net.treeSize(abs), 'disperse this vault');
	const tmp = await makeStagingPath('disperse', Brand.packExt);
	activeTemps.add(tmp); // shield it from the stale-temp sweep for the duration
	// Packing has no measurable percentage (the engine reads the tree and streams one archive), so report
	// it as indeterminate — the UI animates rather than sitting at a fixed number. It can dominate for a
	// large vault, so a "working" signal matters here.
	if (onProgress) onProgress({ indeterminate: true, label: 'Packing the vault' });
	try {
		await pack(abs, tmp, { overwrite: true }); // inside the try so a pack failure still hits the finally that clears activeTemps and removes the temp
		// The Reed–Solomon split and the shard writes run in the worker (holding the whole archive off the
		// main thread), so a large vault can never block the event loop or a mounted drive.
		await dispersalInWorker('encode', { archivePath: tmp, files, n, k }, onProgress);
		if (onProgress) onProgress({ percent: 100, label: 'Done' });
		return { vault: abs, ...dispersalGuidance(n, k), shards: files };
	} catch (e) {
		// A failed OR watchdog-terminated encode (the worker's own rollback only covers thrown JS errors, not a
		// terminate/crash) can leave a PARTIAL shard set. On a fresh disperse we pre-verified every target was
		// empty, so every shard now at a target path was written by THIS run — remove them so a half-written set
		// can never masquerade as complete. With --force over pre-existing shards we can't tell ours from the
		// prior set, so those are left as-is (reconstruction already rebuilds from the largest consistent group).
		if (!force) for (const f of files) { try { await fsp.rm(f, { force: true }); } catch (_) {} }
		// Sweep any leftover atomic-write temps from a terminated/crashed encode (the worker's own cleanup runs
		// only for a thrown JS error, not a hard terminate). Each temp is "<shard>.tmp-…" beside its target, so it
		// is always THIS run's — remove it on any failure, force or not. Bounded so a removable dest can't stall.
		for (const f of files) { try { const dir = path.dirname(f), pre = path.basename(f) + '.tmp-'; for (const nm of await Common.withTimeout(fsp.readdir(dir), 4000)) if (nm.startsWith(pre)) { try { await fsp.rm(path.join(dir, nm), { force: true }); } catch (_) {} } } catch (_) {} }
		throw e;
	} finally { try { await fsp.rm(tmp, { force: true }); } catch (_) {} activeTemps.delete(tmp); }
}

// Dispatch a Reed–Solomon dispersal job to the worker thread (see DisperseWorker.js) via the shared runner.
// Under the idle watchdog (like recovery), so a shard read that wedges on a yanked/unreachable drive fails
// fast instead of hanging the reconstruct/repair forever and stranding its in-flight guard; the worker
// streams per-shard progress so the watchdog never trips a slow-but-working read of a large shard.
function dispersalInWorker(op, args, onProgress) {
	return WorkerRun.runWorker(path.join(__dirname, 'DisperseWorker.js'), { op, args }, onProgress, { idleMs: 120000, idleMessage: 'A dispersal operation' });
}

// Inspect a set of shard files: how many are present and readable, and whether k of them survive. The read +
// full-payload SHA of each shard runs in the dispersal WORKER (shards can be ~2 GiB each), so this never
// stalls the event loop — important because the scheduled repair tick calls it in the background.
async function inspectShards(shardPaths, { onProgress } = {}) {
	return dispersalInWorker('inspect', { shardPaths: (shardPaths || []).map(String) }, onProgress);
}

// Reconstruct a vault from k or more shard files: rebuild the archive, then unpack it to destDir.
async function reconstructFromShards(shardPaths, destDir, { onProgress } = {}) {
	if (!Array.isArray(shardPaths) || !shardPaths.length) throw new Error('Provide the shard files to rebuild from.');
	const resolved = shardPaths.map(p => path.resolve(p));
	// The rebuilt archive is staged before it is unpacked, and it is no larger than the shards it comes from, so
	// the combined shard size is a safe upper bound for the staging free-space check.
	let shardBytes = 0; for (const p of resolved) { try { shardBytes += (await fsp.stat(p)).size; } catch (_) {} }
	await assertStagingSpace(shardBytes, 'rebuild this vault');
	const tmp = await makeStagingPath('reconstruct', Brand.packExt);
	activeTemps.add(tmp); // shield it from the stale-temp sweep for the duration
	try {
		// Reading the shards and the Reed–Solomon decode run in the worker (the rebuilt archive is written
		// to a temp file there, never posted back across the thread), so nothing heavy hits the event loop.
		await dispersalInWorker('decode', { shardPaths: resolved, archivePath: tmp }, onProgress);
		if (onProgress) onProgress({ indeterminate: true, label: 'Unpacking the vault' });
		const r = await unpack(tmp, destDir);
		if (onProgress) onProgress({ percent: 100, label: 'Done' });
		return r;
	} finally { try { await fsp.rm(tmp, { force: true }); } catch (_) {} activeTemps.delete(tmp); }
}

// Re-create any missing or corrupted shards from the surviving ones, restoring the full set of n. Reads
// k good shards, rebuilds the archive, re-shards it, and writes back only the shards that are absent or
// failed their integrity check — so a churned-out node can be replaced without re-dispersing by hand.
async function repairDispersal(shardPaths, { onProgress } = {}) {
	const status = await inspectShards(shardPaths);
	if (!status.recoverable) throw new Error('Cannot repair: only ' + status.good + ' good shard(s), need ' + (status.k || '?') + '.');
	// Which shards to re-create: the bad/missing ones that have a usable slot index. The main thread
	// decides (a light header read); the worker does the decode + re-encode + writes.
	const targets = status.shards
		.filter(s => !s.ok && s.idx != null && s.idx < status.n)
		.map(s => ({ path: path.resolve(s.path), idx: s.idx }));
	const resolved = shardPaths.map(p => path.resolve(p));
	const r = await dispersalInWorker('repair', { shardPaths: resolved, targets, n: status.n, k: status.k }, onProgress);
	if (onProgress) onProgress({ percent: 100, label: 'Done' });
	return { repaired: r.repaired, total: status.total, n: status.n, k: status.k };
}

// --- Threshold key (Shamir): split a vault's unlock key across n holders, any k restore access -----
// Independent of data dispersal (data-k and key-k are separate knobs). It adds a random keyfile slot to
// the vault and splits that keyfile's bytes into n shares. The reconstructed secret never touches disk:
// mounting takes the unlock secret directly (a keyfile slot is unlocked by base64(sha256(bytes))).
function thresholdUnlockSecret(secretBytes) { return slotSecretFromBytes(secretBytes); }

// Add a threshold (Shamir) key: split a fresh secret into n shares, any k of which reconstruct it and unlock
// the vault. `readOnly` makes the reconstructed key a READ-ONLY credential — the safe default for emergency /
// inheritance access, where the people who hold shares should be able to read the vault but never rotate you
// out or change its contents. Leave it off for a self-recovery threshold where you want full access back.
async function addThresholdKey(vaultDir, { password, n, k, readOnly } = {}) {
	const abs = resolveVaultDir(vaultDir);
	if (!password) throw new Error('The current password is required to add a threshold key.');
	if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > 255) throw new Error('Choose 2 ≤ k ≤ n ≤ 255 for a threshold key (any k shares unlock the vault).');
	const secret = crypto.randomBytes(32); // the keyfile's bytes; only its base64(sha256) is stored in the slot
	const label = (readOnly ? 'emergency access' : 'threshold key') + ' (' + k + '-of-' + n + (readOnly ? ', read-only' : '') + ')';
	await addKeyfile(abs, { password, keyfileDigest: thresholdUnlockSecret(secret), keyfileName: label, readOnly: !!readOnly });
	return { n, k, readOnly: !!readOnly, shares: Shamir.split(secret, n, k) };
}

// Reconstruct the unlock secret from k or more key shares. Returns the value to pass as `password` to
// mount/unlock — no key material is written to disk. Throws if fewer than k shares are given.
function unlockSecretFromShares(keyShares) { return thresholdUnlockSecret(Shamir.combine(keyShares)); }

// --- Off-site backup and restore ----------------------------------------------------------
// A vault is already encrypted at rest, so backing it up is just mirroring its folder to
// another location — an external drive, a network share, or a synced folder. The destination
// never sees anything but ciphertext. The engine's mirror is incremental (only changed files
// move) and removes files the vault no longer has, so a repeat backup stays a faithful copy.
function engineTail(r) { return (r.stderr || r.status).toString().split(/\r?\n/).filter(Boolean).slice(-3).join('; '); }

// Copy a vault, still encrypted, into destRoot/<name>.vault. Must be unmounted so the on-disk
// store is settled. Remembers the destination for a one-click repeat.
// Before a one-way backup (rclone sync, which DELETES at the destination whatever is absent from the source),
// refuse to propagate a LOSS. If the source vault is protected and some protected files have gone missing (a
// deletion / at-rest damage), a scheduled sync would mirror-DELETE the good copies at the backup — often the
// only surviving copy. Aborting here forces the user to repair or explicitly accept the change first.
async function assertBackupSourceIntact(abs) {
	let missing = 0;
	// FAIL SAFE: a one-way backup mirror-DELETES at the destination, so if the loss check cannot even complete
	// (the recovery index is unreadable, or the cipher store can't be scanned) we must NOT proceed — an
	// undetected loss would be propagated to the only surviving copy. Refuse until the vault reads cleanly. An
	// UNPROTECTED vault returns 0 without throwing, so this never blocks a plain (non-protected) vault's backup.
	try { missing = await Recovery.missingProtectedCount(abs, { cipherDir: cipherDirOf(abs) }); }
	catch (e) { const err = new Error('Backup skipped: could not verify this vault is intact (' + (e && e.message || 'the recovery index was unreadable') + '). A one-way backup mirror-deletes at the destination, so it will not run until the vault reads cleanly — run "Check & repair" first.'); err.sourceDamaged = true; throw err; }
	if (missing > 0) { const e = new Error('Backup skipped: ' + missing + ' protected file(s) are missing from this vault — it looks damaged. Run "Check & repair" first (or "Update protection" to accept the change), then back up. Refusing to mirror the loss to the backup.'); e.sourceDamaged = true; throw e; }
}

// A one-way `rclone sync` mirror-DELETES anything at the destination that is not in the source, so if the
// source vault has silently emptied or lost most of its files (an external-drive fault, an errant delete, a
// half-finished external sync), a scheduled backup would wipe the destination — often the only surviving copy.
// assertBackupSourceIntact covers PROTECTED vaults; this covers ALL of them (it needs no recovery data) and is
// all-or-nothing: it refuses before the real sync runs if the sync would delete more than half of what is
// already backed up. A plain `--max-delete` cap can't stand in for this — rclone deletes up to the cap and only
// THEN aborts, a partial wipe.
//
// The count is DETERMINISTIC: list both sides (rclone lsf, one path per line) and take the set difference — the
// files present at the destination but absent from the source are exactly what the sync would delete. This does
// not depend on the engine's log format or verbosity (the previous version scraped a "Deleted: N" line from
// stderr, which could silently under-count if that line was absent at the active log level). Fail-open: if
// either listing cannot be obtained, it declines to second-guess and lets the real sync proceed under its own
// checks. The two backup callers sync the whole vault folder with no filters, so the difference is exact; a
// future filtered caller could only ever OVER-count (refuse more) here, never under-count, which is the safe side.
async function assertBackupDeletionsSafe(bin, source, dest, { configPath, caPath } = {}) {
	async function listing(target) {
		// Cap the listing size so an enormous vault can't grow this in memory unbounded — an over-cap listing is
		// killed and returns non-zero, which becomes a null here (fail-open), same as any other listing failure.
		// EXCLUDE the version-history store: it lives only at the destination (the source never has it), so counting
		// it would make accumulated history look like a huge deletion and falsely refuse a legitimate backup.
		try { const r = await Rclone.run(bin, ['lsf', '-R', '--files-only', target, '--filter', '- /' + VERSIONS_DIR + '/**', ...caArgs(caPath)], { configPath, timeoutMs: 6 * 60 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES }); if (r && r.status === 0) return new Set(String(r.stdout || '').split(/\r?\n/).filter(Boolean)); } catch (_) {}
		return null;
	}
	const dst = await listing(dest);
	if (!dst) return; // destination unreachable/unreadable — let the real sync surface any error
	const destCount = dst.size;
	if (destCount === 0) return; // nothing at the destination yet — a first backup deletes nothing
	const src = await listing(source);
	if (!src) return;
	let would = 0;
	for (const f of dst) if (!src.has(f)) would++; // files at the destination the source no longer has = deletions
	// Refuse a suspicious MASS deletion — the source was emptied or has become unreadable (a drive fault, an errant
	// delete, a half-finished sync) — while never second-guessing an ordinary edit of a few files. The threshold
	// tightens as the backup shrinks, so a small vault is still protected against losing (almost) everything without
	// tripping on routine changes: a TOTAL wipe at ANY count; 90%+ once there are at least ten files; more than half
	// once there are at least twenty. (The previous rule skipped the check entirely below twenty files, so a small
	// vault could be mirror-emptied silently.)
	const wipeAll = would === destCount;
	if (Common.suspiciousMassDeletion(destCount, would)) {
		const e = new Error('Backup skipped: it would delete ' + would + ' of ' + destCount + ' backed-up file(s)' + (wipeAll ? ' — every backed-up file' : '') + '. That usually means the source was emptied or damaged (a drive fault, an errant delete, or a half-finished sync), so the backup is refused to avoid mirroring the loss. If the change is intentional, remove the old backup and back up fresh.');
		e.sourceDamaged = true; throw e;
	}
}

// ---- File version history (prior versions kept at the backup destination) ----
//
// Versions are captured at BACKUP time: rclone's --backup-dir moves each about-to-be-overwritten or deleted
// file into a timestamped snapshot folder under <dest>/.versions/ (a subfolder, not a name suffix, so the
// moved files' encrypted names stay valid and can be decrypted with the vault's key to browse and restore).
// They live WITH the backup, so the vault itself and its tamper baseline are untouched. Confirmed by an
// empirical spike that a crypt remote over a snapshot folder decrypts the original names and old contents.
const VERSIONS_DIR = Sync.VERSIONS_DIR; // single-sourced in Sync.js — the one-way backup and the two-way mirror share it
// How many local pre-deletion mirror snapshots to keep when the user has version history turned OFF. These
// snapshots protect the PRIMARY local copy from a destination loss that a two-way sync would otherwise propagate
// back; they are almost always empty (only populated when a sync actually deletes or overwrites local files), so
// keeping a small window costs next to nothing while still giving a recovery point across several syncs.
const MIRROR_LOCAL_SAFETY_KEEP = 5;
function versionStamp() { return new Date().toISOString().replace(/[:.]/g, '-'); } // 2026-09-01T14-22-05-123Z — fs-safe, sortable
function isVersionStamp(s) { return /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/.test(String(s || '')); }
function parseVersionStamp(name) {
	const m = /^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/.exec(String(name));
	if (!m) return null;
	const d = new Date(m[1] + 'T' + m[2] + ':' + m[3] + ':' + m[4] + '.' + m[5] + 'Z');
	return isNaN(d.getTime()) ? null : d.toISOString();
}
// Versioning policy from settings: on unless versionsKeep === 0; keep the newest N snapshots (default 10).
// Two optional caps tighten this further: versionsMaxAgeDays drops snapshots older than that many days, and
// versionsMaxSizeMB drops the oldest snapshots until the folder fits the budget. Both default off (0).
function nonNegNum(v) { return (typeof v === 'number' && v > 0) ? v : 0; }
function versionsPolicy(settings) {
	const k = settings && settings.versionsKeep;
	return {
		on: k !== 0,
		keep: (typeof k === 'number' && k > 0) ? k : 10,
		maxAgeDays: nonNegNum(settings && settings.versionsMaxAgeDays),
		maxSizeMB: nonNegNum(settings && settings.versionsMaxSizeMB),
	};
}
// Decide which snapshot folders to prune, by count, then age, then total size. The newest snapshot is ALWAYS
// kept, so a recovery point never disappears entirely while any exist. Backend-agnostic: it works purely on the
// folder NAMES (timestamps) and asks the caller for a size only when the size cap is active, via `sizeOf` — so
// the same decision logic serves a local folder and a remote store without a second implementation. Returns the
// set of names to delete.
async function versionsToPrune(names, policy, sizeOf) {
	const p = (typeof policy === 'number') ? { keep: policy } : (policy || {});
	const keep = (typeof p.keep === 'number' && p.keep > 0) ? p.keep : 10;
	const maxAgeDays = nonNegNum(p.maxAgeDays);
	const maxSizeMB = nonNegNum(p.maxSizeMB);
	names = names.filter(isVersionStamp).sort(); // timestamp names sort chronologically (oldest first)
	if (!names.length) return new Set();
	const newest = names[names.length - 1]; // the one recovery point we never prune
	const doomed = new Set();
	for (const n of names.slice(0, Math.max(0, names.length - keep))) doomed.add(n); // count cap
	if (maxAgeDays > 0) { // age cap
		const cutoff = Date.now() - maxAgeDays * 86400000;
		for (const n of names) { const at = Date.parse(parseVersionStamp(n) || ''); if (!isNaN(at) && at < cutoff) doomed.add(n); }
	}
	doomed.delete(newest);
	if (maxSizeMB > 0) { // size cap: walk survivors newest-first; once over budget, doom the rest
		const budget = maxSizeMB * 1024 * 1024;
		let total = 0;
		for (const n of names.filter(x => !doomed.has(x)).reverse()) {
			total += await sizeOf(n).catch(() => 0);
			if (total > budget && n !== newest) doomed.add(n);
		}
	}
	return doomed;
}
// Prune a LOCAL `.versions` folder in place. `versionsDir` is the folder itself (…/.versions).
async function pruneVersionsAt(versionsDir, policy) {
	let names = [];
	try { names = (await fsp.readdir(versionsDir, { withFileTypes: true })).filter(e => e.isDirectory() && isVersionStamp(e.name)).map(e => e.name); } catch (_) { return; }
	const doomed = await versionsToPrune(names, policy, async (n) => (await dirSizeBounded(path.join(versionsDir, n), 10000)).bytes);
	for (const n of doomed) { try { await fsp.rm(path.join(versionsDir, n), { recursive: true, force: true }); } catch (_) {} }
}
// Prune a REMOTE `.versions` store (SFTP / WebDAV peer) through the engine. `remoteVersions` is an rclone path
// like "remote:vault/.versions"; `configPath` is the ephemeral config for that remote. Best-effort and bounded.
async function pruneVersionsRemote(bin, configPath, remoteVersions, policy, caPath) {
	const ca = caArgs(caPath);
	let names = [];
	try { const r = await Rclone.run(bin, ['lsf', '--dirs-only', remoteVersions + '/', ...ca], { configPath, timeoutMs: 5 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES }); if (r.status === 0) names = r.stdout.split(/\r?\n/).map(s => s.replace(/\/+$/, '')).filter(Boolean); } catch (_) { return; }
	const sizeOf = async (n) => { try { const r = await Rclone.run(bin, ['size', '--json', remoteVersions + '/' + n, ...ca], { configPath, timeoutMs: 5 * 60 * 1000 }); if (r.status === 0) return (JSON.parse(r.stdout).bytes) || 0; } catch (_) {} return 0; };
	const doomed = await versionsToPrune(names, policy, sizeOf);
	for (const n of doomed) { try { await Rclone.run(bin, ['purge', remoteVersions + '/' + n, ...ca], { configPath, timeoutMs: 30 * 60 * 1000 }); } catch (_) {} }
}
// Backwards-compatible shim used by the one-way backup: prune <dest>/.versions locally.
function pruneVersions(dest, policy) { return pruneVersionsAt(path.join(dest, VERSIONS_DIR), policy); }

// A destination key that names an OFF-SITE remote (reached through the engine) rather than a local OS folder.
// One definition so every local-vs-remote branch stays in step when a new transport is added.
function isRemoteDest(key) { return typeof key === 'string' && (key.startsWith('sftp:') || key.startsWith('webdav:')); }
// Join a sub-path onto an rclone remote path (always forward-slash), stripping any trailing slash first. Kept
// identical everywhere a remote `.versions` path is built so capture, browse, and prune all address one place.
function remoteJoin(remote, sub) { return String(remote).replace(/\/+$/, '') + '/' + sub; }

// Where a two-way mirror keeps PATH1 (the live vault) version snapshots: OUTSIDE the vault, under the app data
// dir, so the live vault folder is never touched — the mount, tamper check, recovery, pack, and the one-way
// backup all stay oblivious to it. Keyed by the vault path so it is stable across re-primes and independent of
// which destination the vault mirrors to. (Path2's snapshots, by contrast, live in the destination's own
// `.versions/`, traveling with that copy — exactly like the one-way backup.)
function localMirrorVersionsDir(abs) {
	const h = vaultDirTag(abs);
	return path.join(Common.dataDir(), 'mirror-versions', h);
}
// List a vault's version snapshots (newest first). Without a password, only the snapshot times are returned;
// with the password, each snapshot also lists the logical files it holds (decrypted through the vault key).
// The places a vault's version snapshots can live, in one list so browse and restore treat them uniformly:
//   • backup       — the one-way backup destination's `.versions/` (local).
//   • mirror-local  — the two-way mirror's PATH1 store, kept outside the vault under the app data dir (local).
//   • mirror-dest   — the two-way mirror destination's `.versions/` (local folder, or an SFTP/WebDAV remote).
// A remote source carries the engine config it is reached through; the caller MUST call each source's cleanup()
// when done. Every entry is best-effort — a missing or unreachable store simply contributes no snapshots.
async function versionSources(bin, abs) {
	const out = [];
	const name = path.basename(abs);
	const backupRoot = await backupDestFor(abs).catch(() => null);
	if (backupRoot) {
		if (isRemoteDest(backupRoot)) {
			// An off-site backup keeps its versions in the remote's own `.versions/`, reached through the same
			// engine config the backup uses. Resolve it the same way the mirror does so browse/restore work.
			try { const { path2, configPath, cleanup, caPath } = await resolveMirrorTarget(bin, backupRoot, name); out.push({ origin: 'backup', label: 'Backup', base: remoteJoin(path2, VERSIONS_DIR), remote: true, configPath, cleanup, caPath }); } catch (_) {}
		} else {
			const base = path.join(path.resolve(backupRoot), name, VERSIONS_DIR);
			if (await Common.pathExistsBounded(base)) out.push({ origin: 'backup', label: 'Backup', base, remote: false, configPath: null, cleanup: null }); // a backup dest can be a removable/network drive — bound the probe
		}
	}
	const local1 = localMirrorVersionsDir(abs);
	if (await exists(local1)) out.push({ origin: 'mirror-local', label: 'This computer (mirror)', base: local1, remote: false, configPath: null, cleanup: null });
	const destKey = await mirrorDestFor(abs).catch(() => null);
	if (destKey) {
		if (isRemoteDest(destKey)) {
			try { const { path2, configPath, cleanup, caPath } = await resolveMirrorTarget(bin, destKey, name); out.push({ origin: 'mirror-dest', label: 'Mirror', base: remoteJoin(path2, VERSIONS_DIR), remote: true, configPath, cleanup, caPath }); } catch (_) {}
		} else {
			const base = path.join(path.resolve(destKey), name, VERSIONS_DIR);
			if (await Common.pathExistsBounded(base)) out.push({ origin: 'mirror-dest', label: 'Mirror', base, remote: false, configPath: null, cleanup: null }); // a mirror dest can be a removable/network drive — bound the probe
		}
	}
	return out;
}
async function cleanupSources(sources) { for (const s of sources) if (s.cleanup) { try { await s.cleanup(); } catch (_) {} } }
// List the snapshot timestamps in one source, newest first (local via fs, remote via the engine).
async function versionStamps(bin, src) {
	if (src.remote) { try { const r = await Rclone.run(bin, ['lsf', '--dirs-only', src.base + '/', ...caArgs(src.caPath)], { configPath: src.configPath, timeoutMs: 5 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES }); if (r.status === 0) return r.stdout.split(/\r?\n/).map(s => s.replace(/\/+$/, '')).filter(isVersionStamp).sort().reverse(); } catch (_) {} return []; }
	try { return (await Common.withTimeout(fsp.readdir(src.base, { withFileTypes: true }), 8000)).filter(e => e.isDirectory() && isVersionStamp(e.name)).map(e => e.name).sort().reverse(); } catch (_) { return []; } // a local backup/mirror dest may be on a disconnected drive — bound the listing
}
function verCipherDir(src, stamp, storeName) { return src.remote ? (src.base + '/' + stamp + '/' + storeName) : path.join(src.base, stamp, storeName); }
// Build an engine config that exposes a snapshot's crypt store as `ver:` (and, when restoring, the live vault as
// `vault:`). For a remote source the underlying remote's own config is prepended, so the crypt layer can reach it.
async function verConfig(src, cryptSections) {
	let text = ''; if (src.remote) { try { text = await fsp.readFile(src.configPath, 'utf8') + '\n'; } catch (_) {} }
	return Rclone.writeEphemeralConfig(text + cryptSections);
}
async function versionFiles(bin, src, stamp, storeName, manifest, pwObsc) {
	const cfg = await verConfig(src, Rclone.cryptRemoteSection('ver', { cipherDir: verCipherDir(src, stamp, storeName), ...cryptOptsOf(manifest, pwObsc) }));
	try { const r = await Rclone.run(bin, ['lsf', '-R', '--files-only', 'ver:', ...caArgs(src.caPath)], { configPath: cfg, timeoutMs: 5 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES }); if (r.status === 0) return parseLsf(r.stdout); } catch (_) {} finally { await Rclone.removeConfig(cfg); }
	return [];
}
// Browse a vault's version snapshots across ALL its stores (backup + both mirror sides), newest first. Without a
// password only the times are returned; with it, each snapshot also lists the files it holds. Each snapshot is
// tagged with its `origin` (and a human `originLabel`) so restore knows exactly which store to read from.
async function listVersions(vaultDir, { password } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	const bin = await ensureEngine();
	const storeName = path.basename(cipherDirOf(abs));
	const sources = await versionSources(bin, abs);
	try {
		if (!sources.length) return { vault: abs, hasStore: false, snapshots: [] };
		let pwObsc = null;
		if (password) { const cred = await unlockCredential(password, manifest); if (!cred) throw wrongPasswordError('The password is incorrect.'); pwObsc = await Rclone.obscure(bin, cred.master); }
		const snapshots = [];
		for (const src of sources) {
			for (const n of await versionStamps(bin, src)) {
				let files = null;
				if (pwObsc) files = await versionFiles(bin, src, n, storeName, manifest, pwObsc);
				snapshots.push({ origin: src.origin, originLabel: src.label, timestamp: n, at: parseVersionStamp(n), files });
			}
		}
		snapshots.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)) || a.origin.localeCompare(b.origin));
		return { vault: abs, hasStore: true, snapshots };
	} finally { await cleanupSources(sources); }
}
// Restore one file from a version snapshot back INTO the vault under a non-clobbering "(restored ...)" name, so
// the current file is never touched. The vault must be unmounted (the restore writes through its crypt remote).
// `origin` picks which store to read from; when omitted, the first store that actually holds the snapshot is used.
async function restoreVersion(vaultDir, { password, origin, timestamp, file } = {}) {
	const abs = resolveVaultDir(vaultDir);
	if (!isVersionStamp(timestamp)) throw new Error('Unknown version.');
	const rel = String(file || '').replace(/^\/+/, '');
	if (!rel || rel.split('/').some(seg => seg === '..' || seg === '')) throw new Error('Unknown file in that version.');
	// Claim the vault BUSY for the restore — exactly like backup, pack, mirror, and secure-remove — so this
	// cipher-store write cannot interleave with a concurrent recovery rebuild, mirror sync, or version prune on the
	// same store, which could otherwise mis-scan the just-restored file as damage or delete the snapshot mid-copy.
	return withVaultBusy(abs, 'This vault is busy with another operation (a backup, mirror, or scrub). Wait for it to finish, then restore.', () => restoreVersionWork(abs, { password, origin, timestamp, rel }));
}
async function restoreVersionWork(abs, { password, origin, timestamp, rel }) {
	const manifest = await readManifest(abs);
	await assertUnmounted(abs, 'before restoring a version');
	const cred = await unlockCredential(password, manifest);
	if (!cred) throw wrongPasswordError('The password is incorrect.');
	const bin = await ensureEngine();
	const storeName = path.basename(cipherDirOf(abs)), pwObsc = await Rclone.obscure(bin, cred.master);
	const sources = await versionSources(bin, abs);
	try {
		if (!sources.length) throw new Error('This vault has no version history yet.');
		// Choose the store: the named origin, else the first store that actually contains this snapshot.
		let src = origin ? sources.find(s => s.origin === origin) : null;
		if (!src) { for (const s of sources) { if ((await versionStamps(bin, s)).includes(timestamp)) { src = s; break; } } }
		if (!src) throw new Error('That version was not found in any of this vault\'s history stores.');
		const cfg = await verConfig(src,
			Rclone.cryptRemoteSection('ver', { cipherDir: verCipherDir(src, timestamp, storeName), ...cryptOptsOf(manifest, pwObsc) })
			+ Rclone.cryptRemoteSection('vault', { cipherDir: cipherDirOf(abs), ...cryptOptsOf(manifest, pwObsc) }));
		try {
			// Tag the restored copy with the snapshot's DATE AND TIME (to the second), so restoring two different
			// snapshots of the same file — even on the same day — never overwrites the earlier restored copy.
			const ext = path.extname(rel), stampTag = String(timestamp).slice(0, 19).replace('T', ' ');
			const restoredName = rel.slice(0, rel.length - ext.length) + ' (restored ' + stampTag + ')' + ext;
			const r = await Rclone.run(bin, ['copyto', 'ver:' + rel, 'vault:' + restoredName, ...caArgs(src.caPath)], { configPath: cfg, timeoutMs: 6 * 60 * 60 * 1000 });
			if (r.status !== 0) {
				// A snapshot taken BEFORE a key rotation is encrypted under the OLD key, which the rotation replaced
				// and did not keep — so it can't be opened with the current key. That is expected, not a missing file,
				// so if the vault has a later identity-succession entry than this snapshot, say so clearly (and how to
				// recover it) instead of the generic "may not exist".
				let predatesRotation = false;
				try {
					const succ = await readSuccession(abs);
					const iso = parseVersionStamp(timestamp);
					const t = iso ? Date.parse(iso) : NaN;
					predatesRotation = !isNaN(t) && (succ.items || []).some(it => it && it.timestamp && Date.parse(it.timestamp) > t);
				} catch (_) {}
				if (predatesRotation) throw new Error('That version predates this vault\'s key rotation, so it is encrypted with the old key — which the rotation replaced and did not keep — and cannot be opened here. To recover it, use a copy of the vault from before the rotation, which still has the old key.');
				throw new Error('Could not restore that version — it may not exist in that snapshot. ' + engineTail(r));
			}
			return { vault: abs, restoredAs: restoredName, origin: src.origin };
		} finally { await Rclone.removeConfig(cfg); }
	} finally { await cleanupSources(sources); }
}

async function backup(vaultDir, destRoot, opts = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs); // ensure it is a valid vault (and get its identity)
	// A cloud vault keeps only its manifest on this machine — the encrypted files live at the provider. A local
	// (or off-site) backup would therefore copy only the keys, not the data, while looking like a full backup.
	// Refuse it and point at the right tool: the provider already keeps the data redundant, and a Recovery Kit
	// protects the KEYS that open it. (Checked before the sftp branch so that path is covered too.)
	if (isCloudVault(manifest)) throw new Error('This vault\'s data lives in your cloud provider, so a backup here would copy only its keys, not the encrypted files — the data is already kept by the provider. To protect the keys that open it, export a Recovery Kit: ' + Brand.cli + ' recovery-kit ' + displayName(abs) + '.');
	// A destination is either a local folder path or an off-site "sftp:<id>" target.
	if (typeof destRoot === 'string' && destRoot.startsWith('sftp:')) return backupToSftp(vaultDir, destRoot.slice(5));
	if (!destRoot) throw new Error('A backup destination folder is required.');
	// Claim the vault vs a concurrent mount / mirror / pack / backup IN THIS PROCESS for the whole read. The backup runs
	// `rclone sync` over the cipher store for minutes; assertUnmounted below is only a point-in-time check, so
	// without this claim a mount could begin partway through and the backup would capture a torn cipher store
	// (the destination is mirror-deleted to match, so a torn capture replaces the previously-good backup). pack
	// and syncMirror take the same claim. Scope note: withVaultBusy is per-PROCESS; it does not serialize a backup
		// run by a separate process (for example a CLI backup racing the service's scheduled backup to the same
		// destination). It is deliberately NOT wrapped in the cross-process vault lease, which refuses after a short
		// deadline meant for quick key/membership changes and would turn a multi-minute backup into a spurious failure.
		// The residual cross-process case is bounded and never risks the SOURCE (a backup only reads it): a live mount
		// is still excluded cross-process by assertUnmounted reading the shared state file, a two-way mirror is
		// serialized by the engine's own bisync lock, and version history retains any destination file a torn
		// same-destination run would otherwise overwrite.
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount, backup, or mirror). Wait for it to finish, then try again.', async () => {
		await assertUnmounted(abs, 'before backing it up');
		const name = path.basename(abs);
		const dest = path.join(path.resolve(destRoot), name);
		// The backup mirrors (it deletes files at the destination that are not in the source), so make
		// sure it can never clobber unrelated data or a different vault.
		await assertVaultDestSafe(dest, name, manifest);
		await assertBackupSourceIntact(abs); // never mirror-delete the backup when the source silently lost protected files
		await fsp.mkdir(dest, { recursive: true });
		const bin = await ensureEngine();
		const syncArgs = ['sync', abs, dest, '--transfers', '8', '--checkers', '8'];
		// Version history: keep prior versions of changed/deleted files. --backup-dir MOVES the destination's
		// about-to-be-overwritten/deleted files into a timestamped subfolder (rather than losing them) BEFORE
		// the new ones are written, so the current backup is never torn. A timestamped SUBFOLDER (not a name
		// suffix) keeps the moved files' encrypted names valid, so a version can be browsed and restored later
		// through the vault's own key. The folder is excluded from the sync so it never mirror-deletes itself.
		const vs = versionsPolicy(await getSettings());
		if (vs.on) syncArgs.push('--backup-dir', path.join(dest, VERSIONS_DIR, versionStamp()), '--filter', '- /' + VERSIONS_DIR + '/**');
		await assertBackupDeletionsSafe(bin, abs, dest); // all-or-nothing backstop, covers unprotected vaults too
		const r = await Rclone.run(bin, syncArgs, { timeoutMs: 12 * 60 * 60 * 1000 });
		if (r.status !== 0) throw new Error('Backup failed — check the destination folder is reachable and has free space. ' + engineTail(r));
		if (!(await exists(path.join(dest, MANIFEST)))) throw new Error('The backup did not complete (the settings file is missing at the destination).');
		if (vs.on) await pruneVersions(dest, vs).catch(() => {}); // keep the newest N snapshots (plus optional age/size caps); never touch the live backup
		await recordBackup(abs, path.resolve(destRoot));
		return { vault: abs, dest };
	});
}

// Record that a vault was just backed up (local or off-site): remember the destination for a
// one-click repeat, and count it as this period's scheduled run so a manual backup does not
// trigger another and a good run clears any prior error. Shared by every backup path.
async function recordBackup(abs, destKey) {
	try {
		await mutateSettings(cur => {
			const next = { ...cur, backupDests: { ...(cur.backupDests || {}), [abs]: destKey } };
			if ((cur.backupSchedules || {})[abs]) {
				next.backupSchedules = { ...cur.backupSchedules, [abs]: { ...cur.backupSchedules[abs], lastRunAt: new Date().toISOString(), lastResult: 'ok', lastErrorAt: null } };
			}
			return next;
		});
	} catch (e) {
		// The backup itself ran, but persisting its bookkeeping failed. Leaving lastRunAt untouched would make the
		// next tick see the schedule still "due" and re-run the whole backup, with no error recorded to engage the
		// back-off. Best-effort: stamp lastErrorAt (which the tick's back-off keys on) and warn, so a persistent
		// settings-write failure surfaces and the schedule waits instead of spinning.
		try { await mutateSettings(cur => (cur.backupSchedules || {})[abs] ? { ...cur, backupSchedules: { ...cur.backupSchedules, [abs]: { ...cur.backupSchedules[abs], lastErrorAt: new Date().toISOString() } } } : cur); } catch (_) {}
		Common.warn('A backup finished but its schedule bookkeeping could not be saved (' + (e && e.message ? e.message : e) + '); it will retry after a short delay rather than repeat immediately.');
	}
}

// Guard a folder before we mirror this vault onto it: never overwrite unrelated files, and never
// overwrite a DIFFERENT vault that merely shares this folder name — only this same vault's own copy.
// Shared by the one-way backup and the two-way mirror's priming pass (both can delete at the dest).
async function assertVaultDestSafe(dest, name, manifest) {
	if (!(await exists(dest))) return;
	const looksVault = await looksLikeVault(dest);
	const entries = await dirRealEntries(dest);
	if (Array.isArray(entries) && entries.length && !looksVault) {
		throw new Error('The destination already contains other files at ' + dest + '. Choose an empty folder or a previous copy of this vault.');
	}
	if (looksVault && !(await sameVaultIdentity(dest, manifest))) {
		throw new Error('The destination already holds a DIFFERENT vault named "' + name + '" at ' + dest + '. Choose an empty folder, or this vault\'s own copy, so an unrelated vault is never overwritten.');
	}
}

// ── Tier 1 "Mirror": two-way, zero-knowledge sync of a vault's encrypted folder ─────────────────
// A mirror destination is remembered per vault exactly like a backup destination: a local folder
// path, or an off-site "sftp:<id>" target. Only ciphertext is ever sent; the destination never sees
// the key or plaintext. The mechanics (running the bidirectional sync, its state) live in Sync.js.

const mirrorDestFor = async (vaultDir) => { try { return ((await getSettings()).syncDests || {})[resolveVaultDir(vaultDir)] || null; } catch (_) { return null; } };

// The mirror status for display: whether one is set up, its destination, whether it has been primed,
// and the last sync time / whether that run left conflicts to resolve.
async function mirrorStatus(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const s = await getSettings();
	const dest = (s.syncDests || {})[abs] || null;
	if (!dest) return { configured: false };
	const last = (s.syncLast || {})[abs] || null;
	const primed = await Sync.hasBaseline(Sync.workdirFor(abs, dest));
	return { configured: true, dest, primed, lastSyncAt: last && last.at ? last.at : null, lastConflicts: !!(last && last.conflicts) };
}

// Remember (or change) a vault's mirror destination. Changing it clears the old pair's sync state so
// the new destination gets a fresh baseline on the next prime.
async function setMirrorDest(vaultDir, destKey) {
	const abs = resolveVaultDir(vaultDir);
	if (!destKey || typeof destKey !== 'string') throw new Error('A mirror destination is required.');
	// A cloud vault keeps only its manifest on this machine, so a two-way mirror would sync just the keys (and
	// could even propagate a manifest deletion) — not the data, which is at the provider. Refuse it.
	if (isCloudVault(await readManifest(abs))) throw new Error('This vault\'s data lives in your cloud provider, so a mirror here would sync only its keys, not the data. The provider already keeps the data; export a Recovery Kit for the keys: ' + Brand.cli + ' recovery-kit ' + displayName(abs) + '.');
	const prev = await mirrorDestFor(abs);
	if (prev && prev !== destKey) {
		try { await releaseLease(abs); } catch (_) {} // release any write-lease we hold at the OLD destination before repointing, so it isn't stranded there
		await Sync.clearState(Sync.workdirFor(abs, prev));
	}
	await setStoreEntry('syncDests', abs, destKey);
	return { ok: true, dest: destKey };
}

// Stop mirroring: forget the destination and discard the local sync state (the copy at the
// destination is left untouched — removing a mirror never deletes data).
async function removeMirror(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const destKey = await mirrorDestFor(abs);
	try { await releaseLease(abs); } catch (_) {} // release any write-lease we hold at the destination before forgetting it, so it isn't stranded there
	await mutateSettings(cur => {
		const syncDests = { ...(cur.syncDests || {}) }; delete syncDests[abs];
		const syncLast = { ...(cur.syncLast || {}) }; delete syncLast[abs];
		return { ...cur, syncDests, syncLast };
	});
	if (destKey) await Sync.clearState(Sync.workdirFor(abs, destKey));
	return { ok: true };
}

async function recordMirror(abs, destKey, conflicts) {
	let stillConflicted = !!conflicts;
	// A clean run must NOT clear the conflict flag while unresolved conflict copies still sit in the vault —
	// the user hasn't dealt with them yet. Scan once here (this runs per-sync, not per-poll) so the mirror
	// badge stays accurate: it lights up when conflicts appear and clears only once the copies are gone.
	if (!stillConflicted) { try { stillConflicted = (await scanSyncArtifacts(abs)).some(a => a.kind === 'mirror-conflict' || a.kind === 'conflict'); } catch (_) {} }
	try { await setStoreEntry('syncLast', abs, { at: new Date().toISOString(), conflicts: stillConflicted }); } catch (_) {}
}

// Resolve a destination key to the endpoint the engine syncs against (a local folder path, or an
// SFTP remote + its ephemeral config), plus a cleanup to run afterwards.
async function resolveMirrorTarget(bin, destKey, name) {
	if (destKey.startsWith('sftp:')) {
		const d = ((await getSettings()).sftpDests || {})[destKey.slice(5)];
		if (!d) throw new Error('That mirror destination no longer exists.');
		const { cfg, remote, cleanup } = await buildSftpConfig(bin, d);
		return { path2: remote + name, configPath: cfg, cleanup, localDir: null };
	}
	if (destKey.startsWith('webdav:')) {
		// A peer node (Tier 2). The served endpoint IS the remote vault's folder, so the client mirrors
		// against the peer's root — no per-name subfolder.
		const d = ((await getSettings()).peers || {})[destKey.slice(7)];
		if (!d) throw new Error('That peer no longer exists.');
		const { cfg, remote, cleanup, caPath } = await buildWebdavConfig(bin, d);
		return { path2: remote, configPath: cfg, cleanup, localDir: null, caPath };
	}
	const dest = path.join(path.resolve(destKey), name);
	return { path2: dest, configPath: undefined, cleanup: async () => {}, localDir: dest };
}

// Run a two-way mirror. The first run (or one asked to `prime`) establishes the baseline, making the
// destination match this vault — guarded so it can never clobber unrelated data. Every run after is
// a true two-way merge; conflicts keep both versions and are surfaced via the sync-artifact check.
// Must be unmounted (a settled vault), and is best-effort/off the hot mount by construction.
// The mirror's source-loss guard keeps a tiny record — the local vault's file count at the last successful sync —
// in the pair's workdir (never in the vault, never synced). It is the two-way analogue of the one-way backup's
// assertBackupDeletionsSafe: bisync reads a shrunken local side as deletions and propagates them to the
// destination, and with version history OFF (no destination-side capture) both copies then lose those files
// unrecoverably. Guarding the LOCAL side is sufficient because the destination→local direction is always caught by
// backupDir1 (the local safety snapshots are kept even when history is off). A remote listing is never needed.
const MIRROR_INVENTORY = 'inventory.json';
// Count the files in the LOCAL vault folder, recursively, natively (no engine spawn) and bounded by the tree
// itself. Symlinks are neither counted nor descended, so it cannot loop. Returns the count, or null only when the
// vault folder itself cannot be read at all (fail-open at the call site).
async function countLocalVaultFiles(abs) {
	let n = 0, readTop = false; const stack = [abs];
	while (stack.length) {
		const dir = stack.pop();
		let ents; try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
		if (dir === abs) readTop = true;
		for (const e of ents) { if (e.isDirectory()) stack.push(path.join(dir, e.name)); else if (e.isFile()) n++; }
	}
	return readTop ? n : null;
}
// Refuse a steady mirror sync when the LOCAL vault has lost a suspicious fraction of its files since the last
// successful sync — the source-was-damaged case that a plain deletion cap catches only partially (it deletes up to
// the cap and only THEN aborts). All-or-nothing: it throws BEFORE bisync runs, so nothing is deleted at the
// destination and the destination's still-good copy remains a recovery point. Fail-open: with no recorded baseline
// (a mirror primed by an older version, or the first sync), or if the count cannot be taken, it declines to
// second-guess and lets bisync proceed under its own --check-access and --max-delete backstops. The thresholds
// match the one-way backup guard exactly, so the mirror is neither more nor less trusting than the backup.
async function assertMirrorSourceIntactByCount(workdir, abs) {
	let inv = null; try { inv = JSON.parse(await fsp.readFile(path.join(workdir, MIRROR_INVENTORY), 'utf8')); } catch (_) {}
	if (!inv || !Number.isFinite(inv.p1) || inv.p1 <= 0) return; // no trustworthy baseline yet
	const prev = inv.p1;
	const cur = await countLocalVaultFiles(abs);
	if (cur === null) return; // vault folder unreadable — let bisync surface the real error
	const lost = prev - cur;
	if (lost <= 0) return; // unchanged or grew
	const wipeAll = cur === 0;
	if (Common.suspiciousMassDeletion(prev, lost)) {
		const e = new Error('Mirror skipped: this computer\'s copy of the vault now holds ' + cur + ' file(s), down from ' + prev + ' at the last successful sync' + (wipeAll ? ' — every file is gone' : '') + '. That usually means the local copy lost data (a drive fault, an errant delete, or a half-finished sync), so the mirror was refused rather than delete those files at the destination too — the destination still has them. If the change is intentional, re-prime the mirror.');
		e.sourceDamaged = true; throw e;
	}
}
// Record the local vault's current file count as the new baseline. Best-effort — a failure here must never fail the
// sync that just succeeded; the guard simply falls open next time until a count is recorded.
async function recordMirrorSourceCount(workdir, abs) {
	try { const p1 = await countLocalVaultFiles(abs); if (p1 !== null) { await fsp.mkdir(workdir, { recursive: true }); await Common.writeJsonAtomic(path.join(workdir, MIRROR_INVENTORY), { v: 1, p1, at: new Date().toISOString() }); } } catch (_) {}
}
async function syncMirror(vaultDir, { onProgress, prime } = {}) {
	const abs = resolveVaultDir(vaultDir);
	// Claim the vault EXCLUSIVELY vs a concurrent mount BEFORE any I/O — the resolve/ensureEngine awaits below
	// take real time — and synchronously, so the claim is atomic with the mount-side check. Held until the end.
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount or a mirror sync). Wait for it to finish, then try again.', async () => {
		const manifest = await readManifest(abs);
		const destKey = await mirrorDestFor(abs);
		if (!destKey) throw new Error('This vault has no mirror set up yet.');
		await assertUnmounted(abs, 'before mirroring it');
		const bin = await ensureEngine();
		const name = path.basename(abs);
		const { path2, configPath, cleanup, localDir, caPath } = await resolveMirrorTarget(bin, destKey, name);
		const workdir = Sync.workdirFor(abs, destKey);
		// Version capture: keep prior copies of files this sync overwrites/deletes, on BOTH sides, unless the user
		// has turned version history off. Path1's snapshots go OUTSIDE the vault (app data dir); path2's go in the
		// destination's own `.versions/`. Both are passed to bisync as --backup-dir1/2; the runBisync filter keeps
		// a `.versions/` inside a path from being re-synced. A remote destination (SFTP/WebDAV) uses forward-slash
		// rclone paths; a local one uses OS paths.
		const vs = versionsPolicy(await getSettings());
		const remoteDest = isRemoteDest(destKey);
		// The LOCAL vault is the primary, most-precious copy, so ALWAYS snapshot the files a sync is about to delete
		// or overwrite on the local side (backupDir1) — even when the user turned version history off. Without it, a
		// destination that silently lost ciphertext could two-way-propagate those deletions back into the local
		// vault (its recovery data included) with no way back. These snapshots live OUTSIDE the vault (the app data
		// dir) and, when history is off, are pruned to a small safety window (MIRROR_LOCAL_SAFETY_KEEP) rather than
		// kept indefinitely. The DESTINATION-side history (backupDir2, the user-facing "prior versions") stays
		// governed by the version-history setting.
		const localVs = vs.on ? vs : { keep: MIRROR_LOCAL_SAFETY_KEEP };
		let backupDir1 = null, backupDir2 = null;
		{
			const stamp = versionStamp();
			backupDir1 = path.join(localMirrorVersionsDir(abs), stamp);
			if (vs.on) backupDir2 = remoteDest ? (remoteJoin(path2, VERSIONS_DIR) + '/' + stamp) : path.join(path2, VERSIONS_DIR, stamp);
		}
		try {
			// A prime makes the destination match THIS (authoritative) source, so it is only ever done on purpose:
			// mirror setup passes prime explicitly (CLI `mirror`, the web "Set up"/"Re-prime" button). A plain sync
			// must NEVER silently re-prime just because the baseline is missing — if the sync workdir was cleared
			// (a cache wipe, a migration) while the destination holds newer edits, an implicit resync would make the
			// local copy authoritative and overwrite those edits (a resync overwrites, so the deletion cap does not
			// catch it, and the destination-side version history is kept only when it is enabled). Refuse instead and
			// ask the user to re-prime deliberately, mirroring what the background sync already does (it skips an
			// unprimed vault). The local copy is never at risk either way (backupDir1 is always kept).
			if (!prime && !(await Sync.hasBaseline(workdir))) {
				throw new Error('This mirror has lost its baseline and must be primed again before it can sync. Use "Re-prime" in the web interface, or run the mirror setup again on the command line. Priming makes the destination match this computer, so first make sure this computer holds the version you want to keep.');
			}
			const needsPrime = !!prime;
			// A prime makes the destination match this (authoritative) source. If the source silently lost
			// protected files, that would mirror-delete the destination's still-good copies — and the mirror is
			// often the only second copy. Guard the source's integrity before priming, exactly as the one-way
			// backup does; the deletion cap in runBisync is the second backstop for unprotected vaults.
			if (needsPrime) await assertBackupSourceIntact(abs);
			if (needsPrime && localDir) { await assertVaultDestSafe(localDir, name, manifest); await fsp.mkdir(localDir, { recursive: true }); }
			// For a REMOTE destination there is no local folder to inspect, so make the same foreign-vault check the
			// off-site backup makes: refuse to prime over a DIFFERENT vault (or unrelated data) already at path2.
			// Fail-open (a fresh or unreadable destination proceeds); the deletion cap in runBisync is the backstop.
			if (needsPrime && !localDir && !(await remoteVaultSafeToOverwrite(bin, configPath, path2, manifest, caPath))) {
				throw new Error('The mirror destination already holds a different vault under this name, so priming was refused rather than overwrite it. Choose an empty destination folder, or remove the other vault there first.');
			}
			// All-or-nothing source-loss guard for a STEADY sync (a prime is authoritative and deliberate, and its
			// source is already guarded by assertBackupSourceIntact above). Refuses BEFORE bisync if the local copy
			// shrank suspiciously since the last sync, so a local drive fault is never mirror-deleted at the destination.
			if (!needsPrime) await assertMirrorSourceIntactByCount(workdir, abs);
			const r = await Sync.runBisync(bin, { path1: abs, path2, configPath, workdir, resync: needsPrime, onProgress, caPath, backupDir1, backupDir2, bwlimit: remoteDest ? bwlimitOf(await getSettings()) : '' });
			if (!r.ok) {
				if (r.needsResync) throw new Error('The mirror lost its baseline and needs to be primed again (use "Re-prime"). ' + r.tail);
				throw new Error('Mirror failed — check the destination is reachable and has free space. ' + r.tail);
			}
			await recordMirror(abs, destKey, r.conflicts);
			await recordMirrorSourceCount(workdir, abs); // refresh the source-loss baseline after a clean sync (best-effort)
			// Prune both version stores to the retention policy. BEST-EFFORT and awaited only so the remote prune
			// runs while the destination config is still live: it can never fail or wedge the mirror (bounded and
			// fully swallowed), so a slow or unreachable store just leaves history untrimmed until next time.
			// Always prune the LOCAL safety snapshots (to the full policy when history is on, else the small safety
			// window). The DESTINATION-side history is pruned only when history is on, since it isn't written otherwise.
			try { await pruneVersionsAt(localMirrorVersionsDir(abs), localVs); } catch (_) {}
			if (vs.on) {
				try {
					if (remoteDest) await pruneVersionsRemote(bin, configPath, remoteJoin(path2, VERSIONS_DIR), vs, caPath);
					else await pruneVersionsAt(path.join(path2, VERSIONS_DIR), vs);
				} catch (_) {}
			}
			return { vault: abs, dest: destKey, primed: needsPrime, conflicts: r.conflicts };
		} finally { await cleanup(); }
	});
}

// Background trigger (after a clean unmount): sync a configured, already-primed mirror. It never
// auto-primes — priming is a deliberate, potentially destructive first step that the user confirms.
async function syncMirrorIfConfigured(vaultDir, { onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const destKey = await mirrorDestFor(abs);
	if (!destKey) return { synced: false, reason: 'not-configured' };
	if (!(await Sync.hasBaseline(Sync.workdirFor(abs, destKey)))) return { synced: false, reason: 'not-primed' };
	const r = await syncMirror(abs, { onProgress });
	return { synced: true, conflicts: r.conflicts };
}

// ── Cross-machine write lease (Tier 1/2) ────────────────────────────────────────────────────────
// An ADVISORY lease that stops two machines from mounting the SAME mirrored vault for writing at
// once — which is the one situation that produces conflict copies. It is deliberately best-effort:
// it is a small file on the shared destination (never synced), claimed at mount and released at
// unmount, and it can NEVER break the mount path — any failure to reach the destination just proceeds
// without coordination. It is not a hard lock (there is no central authority and a mounted vault
// cannot be synced), and it does not need to be: the real data-safety net is the per-file
// authentication plus conflict-preservation. The lease only spares the user the annoyance.
//
// A lease older than LEASE_STALE_MS is treated as abandoned (a crashed holder), so it never wedges a
// vault permanently; and a caller can always override with force, or mount read-only (which cannot
// conflict). Because a mount here is a detached process with no long-running heartbeat, the window is
// generous rather than a few seconds.
const LEASE_STALE_MS = 12 * 60 * 60 * 1000;  // default TTL for a mount with no heartbeat (e.g. the CLI, which exits)
const LEASE_TTL_HEARTBEAT = 10 * 60 * 1000;  // TTL for a mount owned by the long-running server, which heartbeats it
const LEASE_HEARTBEAT_MS = 3 * 60 * 1000;    // how often that owner refreshes the lease (well under the heartbeat TTL)

// A stable, non-secret machine id derived from this install's credential key (so it needs no new
// file), plus a friendly name for messages. Cached after the first read.
let cachedMachineIdentity = null;
async function machineIdentity() {
	if (cachedMachineIdentity) return cachedMachineIdentity;
	let id;
	try { id = Common.sha256Hex(await machineCredKey()).slice(0, 16); }
	catch (_) { id = 'unknown'; }
	cachedMachineIdentity = { id, name: os.hostname() || 'a machine' };
	return cachedMachineIdentity;
}

function leasePathFor(path2) { return (path2.endsWith(':') || path2.endsWith('/')) ? path2 + Sync.LEASE_FILE : path2 + '/' + Sync.LEASE_FILE; }
// A lease is active until its own TTL elapses (each record carries the TTL it was written with, so a
// heartbeated server mount expires fast while a CLI mount lingers). Falls back to the long default.
function leaseActive(lease) {
	if (!lease || !lease.holder || !lease.since) return false;
	// The ttl comes from a peer-controllable lease file, so CLAMP it: a hostile peer must not be able to set a
	// gigantic ttl that makes its lease look "active" forever and blocks this machine from ever taking over.
	const ttl = Math.min(Math.max(0, Number(lease.ttlMs) || LEASE_STALE_MS), LEASE_STALE_MS);
	return (Date.now() - Date.parse(lease.since)) < ttl;
}
// One place that builds the lease record (held or released), stamped with a format version so a
// future field can be added without breaking older readers (which only ever look at holder/since).
function makeLease(me, released, ttlMs) {
	const rec = { v: 1, holder: released ? null : me.id, name: me.name, since: new Date().toISOString(), ttlMs: ttlMs || LEASE_STALE_MS };
	if (released) rec.released = true;
	return rec;
}

// The lease file's path on a destination — a native local path (so separators are correct on every
// OS) for a folder mirror, or an engine "remote:path" (forward slashes) for a peer/SFTP dest.
function leaseObjectPath(path2, localDir) { return localDir ? path.join(localDir, Sync.LEASE_FILE) : leasePathFor(path2); }
// Short, fixed engine-call bounds so a lease check never adds more than a few seconds to a mount even
// when the destination is unreachable (it then simply proceeds uncoordinated).
const LEASE_ARGS = ['--low-level-retries', '1', '--contimeout', '4s', '--timeout', '5s'];

// Read the lease from the mirror destination (best-effort; returns null if unset or unreachable).
async function readLease(bin, destKey, name) {
	const { path2, configPath, cleanup, localDir, caPath } = await resolveMirrorTarget(bin, destKey, name);
	try {
		const r = await Rclone.run(bin, ['cat', leaseObjectPath(path2, localDir), ...LEASE_ARGS, ...caArgs(caPath)], { configPath, timeoutMs: 8000, maxOutBytes: 65536 }); // a lease is tiny JSON; cap the read so a hostile peer can't stream a huge file into memory (an oversize/truncated read fails to parse -> treated as no lease)
		if (r.status !== 0 || !r.stdout) return null;
		// The lease comes from a mirror destination that may be hostile, and its free-text `name` is shown in
		// user-facing "in use on X" messages. Sanitize it once, at the source: strip control characters and clamp
		// the length, so a crafted name can't garble a message or a log line downstream (the strict CSP already
		// blocks any script, so this is defense-in-depth, not the only guard).
		try { const j = JSON.parse(r.stdout); if (j && j.name != null) j.name = String(j.name).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 100); return j; } catch (_) { return null; }
	} catch (_) { return null; } finally { await cleanup(); }
}

// Write (or clear) the lease at the mirror destination (best-effort; never throws).
async function writeLease(bin, destKey, name, leaseObj) {
	const { path2, configPath, cleanup, localDir, caPath } = await resolveMirrorTarget(bin, destKey, name);
	try { await Rclone.run(bin, ['rcat', leaseObjectPath(path2, localDir), ...LEASE_ARGS, ...caArgs(caPath)], { configPath, input: JSON.stringify(leaseObj), timeoutMs: 8000 }); }
	catch (_) {} finally { await cleanup(); }
}

// Before mounting a mirrored vault for writing, claim the lease. Throws a clear, force-overridable
// error (e.locked) if another machine is actively holding it. Read-only mounts skip this entirely —
// they cannot cause a conflict. Fully best-effort otherwise: any failure reaching the destination
// proceeds without coordination so a mount is never blocked by a network hiccup.
async function claimLeaseForMount(abs, opts) {
	if (opts.readOnly) return; // a read-only mount can't conflict — it needs no lease at all
	const destKey = await mirrorDestFor(abs);
	if (!destKey) return; // no mirror -> nothing to coordinate
	let bin; try { bin = await ensureEngine(); } catch (_) { return; }
	const name = path.basename(abs);
	const me = await machineIdentity();
	if (!opts.force) { // force skips the refusal but still takes the lease over, so our unmount frees it
		let lease = null;
		try { lease = await readLease(bin, destKey, name); } catch (_) { return; } // can't reach -> proceed uncoordinated
		if (leaseActive(lease) && lease.holder !== me.id) {
			const mins = Math.round((Date.now() - Date.parse(lease.since)) / 60000);
			const e = new Error('This vault is in use on "' + (lease.name || 'another machine') + '" (opened ' + (mins < 60 ? mins + ' min' : Math.round(mins / 60) + ' h') + ' ago). Unmount it there first, mount it here read-only, or force the mount (which may create sync-conflict copies).');
			e.locked = true; e.holder = lease.name || null; e.since = lease.since;
			throw e;
		}
	}
	await writeLease(bin, destKey, name, makeLease(me, false));
}

// Read the current write-lease for a mirrored vault, for display: who holds it, since when, whether
// it is still active, and whether it is us. Returns { configured:false } when there is no mirror.
async function mirrorLeaseStatus(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	const destKey = await mirrorDestFor(abs);
	if (!destKey) return { configured: false };
	let bin; try { bin = await ensureEngine(); } catch (_) { return { configured: true, reachable: false }; }
	const me = await machineIdentity();
	const lease = await readLease(bin, destKey, path.basename(abs));
	if (!lease || !lease.holder) return { configured: true, reachable: true, held: false };
	return { configured: true, reachable: true, held: leaseActive(lease), stale: !leaseActive(lease), holder: lease.name || null, since: lease.since || null, mine: lease.holder === me.id };
}

// Release our lease after a clean unmount (best-effort). Marks the vault free for another machine.
async function releaseLease(abs) {
	try {
		const destKey = await mirrorDestFor(abs);
		if (!destKey) return;
		const bin = await ensureEngine();
		const me = await machineIdentity();
		// Clear it only if WE still hold it — so we never stomp a lease another machine has since claimed,
		// and we skip the write entirely (no wasted spawn) when there is nothing of ours to release or the
		// destination is unreachable.
		const cur = await readLease(bin, destKey, path.basename(abs));
		if (!cur || !cur.holder || cur.holder !== me.id) return;
		await writeLease(bin, destKey, path.basename(abs), makeLease(me, true));
	} catch (_) {}
}

// Heartbeat: a long-running owner (the web server) refreshes its lease with a SHORT TTL while the
// vault is mounted, so liveness is precise and another machine can take over quickly after a crash.
// Best-effort. Return values, all distinct so the caller reacts correctly:
//   • false        — another machine has clearly TAKEN the lease (the caller warns and stops heartbeating).
//   • 'no-lease'   — this vault has NO mirror to coordinate, so there is nothing to lease; the caller stops
//                    heartbeating QUIETLY (returning false here would fire a bogus split-brain warning on every
//                    ordinary, non-mirrored writable mount — a false alarm).
//   • true         — the lease was refreshed successfully.
//   • null         — a transient failure (e.g. the destination is unreachable); the caller keeps beating but does
//                    NOT treat it as a success, so a persistent failure still trips the staleness watch.
// Recommended interval and TTL are LEASE_HEARTBEAT_MS / LEASE_TTL_HEARTBEAT.
async function refreshLease(vaultDir) {
	try {
		const abs = resolveVaultDir(vaultDir);
		const destKey = await mirrorDestFor(abs);
		if (!destKey) return 'no-lease'; // no mirror configured — nothing to coordinate (NOT a takeover)
		const bin = await ensureEngine();
		const me = await machineIdentity();
		const cur = await readLease(bin, destKey, path.basename(abs));
		if (cur && cur.holder && cur.holder !== me.id && leaseActive(cur)) return false; // another machine holds it now
		await writeLease(bin, destKey, path.basename(abs), makeLease(me, false, LEASE_TTL_HEARTBEAT));
		return true; // refreshed successfully
	} catch (_) { return null; } // transient failure (destination unreachable): keep beating, but signal "not refreshed" (not `true`) so a staleness watch can notice the lease going stale — only an explicit take-over returns false/stop
}
// The heartbeat cadence, exported so the owner (the web server) uses the matching interval.
const LEASE_HEARTBEAT_INTERVAL_MS = LEASE_HEARTBEAT_MS;

// Remember the mount options a user chose for a vault (favorites), so the next mount can offer the
// same one-click choice. Best-effort convenience; never blocks a mount. Only a small allow-list of
// non-secret option flags is stored, keyed by the resolved vault path.
async function recordMountPrefs(vaultDir, opts = {}) {
	try {
		const abs = resolveVaultDir(vaultDir);
		const prefs = { readOnly: !!opts.readOnly, workingDisk: !!opts.workingDisk, streaming: !!opts.streaming };
		if (opts.fuseBackend === 'smb') prefs.fuseBackend = 'smb'; // remember the SMB backend choice (macOS/FUSE-T)
		await setStoreEntry('mountPrefs', abs, prefs);
	} catch (_) {}
}

// Mark a vault as a favorite (or clear it). Favorites are surfaced first and offer one-tap unlock — the
// tool still stores no password, so a favorite with biometric unlock enrolled opens with a single Touch
// ID / Windows Hello tap. Non-secret preference, keyed by the resolved vault path.
async function setFavorite(vaultDir, on) {
	const abs = resolveVaultDir(vaultDir);
	await mutateSettings(cur => {
		const favs = { ...(cur.favorites || {}) };
		if (on) favs[abs] = true; else delete favs[abs];
		return { ...cur, favorites: favs };
	});
	return { favorite: !!on };
}

// --- Off-site SFTP destinations (credentials encrypted at rest) ----------------------------
// SFTP transport is handled by the bundled engine (no extra dependency). Credentials are
// encrypted with AES-256-GCM under a random, machine-scoped key kept owner-only in data/, so a
// scheduled backup can still connect unattended while the settings file never holds a readable
// password. (This protects the credentials from casual inspection and from a copied settings
// file; a determined local attacker who can also read the key file is out of scope — the backup
// itself only ever holds ciphertext regardless.)
function credKeyPath() { return path.join(Common.dataDir(), 'credkey'); }
async function machineCredKey() {
	await fsp.mkdir(Common.dataDir(), { recursive: true });
	try { await Common.hardenDir(Common.dataDir()); } catch (_) {} // owner-only: POSIX 0700; Windows sets the ACL (mode bits are a no-op there)
	// Reuse an existing key. A present-but-INVALID key is NOT silently replaced — doing so would
	// make every stored credential undecryptable — it is reported so the user can restore or reset.
	let raw = null;
	try { raw = (await fsp.readFile(credKeyPath(), 'utf8')).trim(); } catch (e) { if (e.code !== 'ENOENT') throw e; }
	if (raw != null) {
		const b = Buffer.from(raw, 'base64');
		if (b.length === 32) return b;
		throw new Error('The credential key (data/credkey) is corrupt. Restore it from a backup, or delete it to reset your saved off-site logins (they will need re-entering).');
	}
	// First run: create it EXCLUSIVELY ('wx') so two concurrent starts can't each write a different key — that
	// exclusivity is why this is not a temp+rename (which would let both starts win). Flush it to disk before
	// returning, so a power loss right after can't lose the key and orphan every credential saved under it.
	const key = crypto.randomBytes(32);
	let fh = null;
	try { fh = await fsp.open(credKeyPath(), 'wx', 0o600); }
	catch (e) {
		if (e.code === 'EEXIST') {
			// Another start created it first, and may still be mid-write (the file exists but its 32 bytes are not
			// flushed yet). Read with a few short retries until the full key appears, rather than failing on a
			// transient empty read. Bounded (~0.5s), then fall through to throw if it never fills in.
			for (let i = 0; i < 20; i++) {
				try { const b = Buffer.from((await fsp.readFile(credKeyPath(), 'utf8')).trim(), 'base64'); if (b.length === 32) return b; } catch (_) {}
				await Common.sleep(25);
			}
		}
		throw e;
	}
	try { await fh.writeFile(key.toString('base64')); await fh.sync(); } finally { await fh.close(); }
	try { await fsp.chmod(credKeyPath(), 0o600); } catch (_) {}
	return key;
}
function encCred(v, key) { return v ? Kdf.wrapSecret(String(v), key) : ''; }               // reuse the vault's GCM wrap
// Decrypt a stored credential. An empty stored value means "no secret was saved" and returns ''.
// A NON-empty value that will not decrypt means the machine key changed (data/credkey replaced or
// restored) — fail loudly with a clear message instead of silently omitting the password, which
// would surface later only as an opaque "could not connect".
function decCred(v, key) {
	if (!v) return '';
	try { return Kdf.unwrapSecret(v, key); }
	catch (_) { throw new Error('The saved login for this off-site destination could not be decrypted — re-enter it. This happens if this computer\'s credential key was replaced or restored from another machine.'); }
}

// The stored SFTP destinations, WITHOUT any secret (safe to send to the UI).
async function listSftpDests() {
	const dests = (await getSettings()).sftpDests || {};
	return Object.keys(dests).map(id => {
		const d = dests[id];
		return { id, label: d.label || d.host, host: d.host, port: d.port || 22, user: d.user, remotePath: d.remotePath || '', authType: d.authType || 'password', hasPassword: !!d.password, hasPassphrase: !!d.passphrase, keyFile: d.keyFile || '', hasHostKey: !!d.hostKey };
	});
}

// Reject a control character (CR/LF) in a value that becomes an engine config line — a newline
// would inject arbitrary engine directives, the same guard the crypt config uses.
function noNewlines(v, field) { if (/[\r\n]/.test(String(v == null ? '' : v))) throw new Error('The ' + field + ' must not contain a line break.'); return String(v == null ? '' : v); }

// ---- Cloud storage backends (a vault's encrypted store can live on a cloud remote) ----
//
// A cloud remote is a saved, reusable reference to a storage backend the bundled engine already speaks (s3,
// b2, webdav, sftp, alias, …). It is stored in settings.cloudRemotes, exactly parallel to the off-site SFTP
// destinations, with the same at-rest encryption of secrets (`encCred` over the machine credential key). A
// cloud VAULT keeps its manifest and key slots LOCAL and points its crypt store at `backend:<path>`, so only
// ciphertext ever reaches the cloud. Fields are split so the config is emitted correctly: `opts` are plain
// non-secret lines (region, endpoint, provider…); `secretsPlain` are encrypted at rest but written verbatim
// (API keys/tokens the backend wants raw); `secretsObscure` are encrypted at rest and written engine-obscured
// (passwords). Everything is newline-guarded so a stored value can never inject an engine directive.
function encMap(obj, key) { const o = {}; for (const [k, v] of Object.entries(obj || {})) if (v != null && String(v) !== '') o[noNewlines(k, 'field name')] = encCred(String(v), key); return o; }

async function saveCloudRemote(remote = {}) {
	const type = noNewlines(remote.type || '', 'storage type').trim();
	if (!type) throw new Error('A storage type (for example s3, b2, or webdav) is required.');
	const label = noNewlines(remote.label || type, 'label');
	const key = await machineCredKey();
	const id = remote.id || crypto.randomBytes(6).toString('hex');
	const opts = {}; for (const [k, v] of Object.entries(remote.opts || {})) if (v != null && String(v) !== '') opts[noNewlines(k, 'option')] = noNewlines(String(v), 'option ' + k);
	const plain = encMap(remote.secretsPlain, key), obscure = encMap(remote.secretsObscure, key);
	await mutateSettings(cur => {
		const remotes = { ...(cur.cloudRemotes || {}) };
		const prev = remotes[id] || {};
		remotes[id] = { label, type, opts: remote.opts ? opts : (prev.opts || {}),
			secretsPlain: { ...(prev.secretsPlain || {}), ...plain },
			secretsObscure: { ...(prev.secretsObscure || {}), ...obscure } };
		return { ...cur, cloudRemotes: remotes };
	});
	return { id, label, type };
}
// The stored cloud remotes, WITHOUT any secret (safe to send to the UI).
async function listCloudRemotes() {
	const remotes = (await getSettings()).cloudRemotes || {};
	return Object.keys(remotes).map(id => { const r = remotes[id]; return { id, label: r.label || r.type, type: r.type, opts: r.opts || {}, hasSecrets: !!(Object.keys(r.secretsPlain || {}).length || Object.keys(r.secretsObscure || {}).length) }; });
}
async function getCloudRemoteRaw(id) { return ((await getSettings()).cloudRemotes || {})[id] || null; }

// Sign in to a browser-OAuth backend (Google Drive, OneDrive, Dropbox, …) and return the token to store. The
// engine opens the provider's consent page; onUrl(link) is called so the caller can present/open it. The token
// is the only long-lived secret — the caller stores it via saveCloudOAuth, encrypted at rest like any secret.
async function cloudAuthorize(type, { clientId, clientSecret, onUrl } = {}) {
	const t = String(type || '').toLowerCase();
	if (!isOAuthBackend(t)) throw new Error('That storage type signs in with an API key, not a browser account.');
	const bin = await ensureEngine();
	return Rclone.authorize(bin, t, { clientId, clientSecret, onUrl });
}
// Store (or update) an OAuth cloud remote. The token JSON and client secret are verbatim secrets (encrypted at
// rest, written to the engine config verbatim); the client id and provider metadata (scope, drive_id, region…)
// are non-secret options. Re-saving with a fresh token just updates it — this is also the token write-back path.
async function saveCloudOAuth({ id, label, type, token, clientId, clientSecret, opts } = {}) {
	if (!token) throw new Error('A sign-in token is required. Connect the account first.');
	const secretsPlain = { token };
	if (clientSecret) secretsPlain.client_secret = clientSecret;
	const o = { ...(opts || {}) };
	if (clientId) o.client_id = clientId;
	// OneDrive addresses a SPECIFIC drive, so the backend refuses to work without drive_id/drive_type. The
	// browser sign-in returns only a token, so resolve the account's drive from Microsoft Graph using the fresh
	// access token and record it. Best-effort and only when not already set: a later token write-back re-saves
	// with an expired access token, but drive_id is already stored by then, so it is kept as-is.
	if (String(type || '').toLowerCase() === 'onedrive' && (!o.drive_id || !o.drive_type)) {
		const d = await resolveOneDriveDrive(token);
		if (d) { o.drive_id = d.drive_id; o.drive_type = d.drive_type; }
	}
	return saveCloudRemote({ id, label, type, opts: o, secretsPlain });
}
// Resolve which OneDrive to use (drive_id + drive_type) from a fresh OAuth token, by asking Microsoft Graph for
// the signed-in account's default drive. The token is a JSON string holding a short-lived access_token; this is
// called right after sign-in while that token is still valid. Best-effort: returns null on any failure so a
// connect never hard-fails here — a missing drive_id surfaces later as a clear "reconnect" error at use time.
async function resolveOneDriveDrive(tokenJson) {
	let accessToken; try { accessToken = JSON.parse(tokenJson).access_token; } catch (_) {}
	if (!accessToken || typeof fetch !== 'function') return null;
	const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 20000);
	try {
		const res = await fetch('https://graph.microsoft.com/v1.0/me/drive', { headers: { Authorization: 'Bearer ' + accessToken }, signal: ctrl.signal });
		if (!res.ok) return null;
		const j = await res.json();
		return j && j.id ? { drive_id: j.id, drive_type: j.driveType || 'personal' } : null;
	} catch (_) { return null; } finally { clearTimeout(timer); }
}
// Whether a vault's backing remote rotates its refresh token (so a live mount must persist the rotated token).
async function cloudVaultRotatesToken(manifest) {
	if (!isCloudVault(manifest)) return false;
	const entry = await getCloudRemoteRaw(manifest.crypt.backend.remoteId);
	return !!(entry && ROTATING_TOKEN_BACKENDS.has(String(entry.type || '').toLowerCase()));
}
async function removeCloudRemote(id) { await deleteSettingsKey('cloudRemotes', id); return { ok: true }; } // same shared delete the other dest removers use

// Best-effort: after a clean drain and while the engine is still alive, capture its current in-memory sign-in
// token for a rotating-token cloud backend (OneDrive) and re-save it — so a token that rotated mid-session does
// not leave the stored one stale for the next mount. The vault's manifest names which cloud remote backs it; the
// live token is read from the mount's rc control endpoint (config/get), which returns the in-memory value even
// though the on-disk config was deleted after startup. Only rewrites when the token actually changed. Every
// failure is swallowed by the caller: this must never disturb an unmount, and a stale token is a reconnect
// prompt, not data loss (the vault's encryption keys live in the local manifest, independent of the token).
async function harvestRotatedCloudToken(bin, endpoint, entry, mountpoint) {
	const sk = sessionKeys.get(mountpoint);
	const vaultPath = (sk && sk.backing) || (entry && entry.vault);
	if (!vaultPath) return;
	let manifest; try { manifest = await readManifest(vaultPath); } catch (_) { return; }
	if (!manifest || !(await cloudVaultRotatesToken(manifest))) return;
	const remoteId = manifest.crypt.backend.remoteId;
	const section = await Rclone.rcConfigGet(bin, endpoint, 'backend'); // the backend remote is named "backend" in our config
	const tokenJson = section && section.token;
	if (!tokenJson) return;
	const raw = await getCloudRemoteRaw(remoteId);
	if (!raw) return;
	const key = await machineCredKey();
	let saved = null; try { saved = decCred(raw.secretsPlain.token, key); } catch (_) {}
	if (saved === tokenJson) return; // nothing rotated this session — skip the write
	await saveCloudOAuth({ id: remoteId, type: raw.type, token: tokenJson, label: raw.label, opts: raw.opts });
	Common.log('Refreshed the saved ' + raw.type + ' sign-in (its token had rotated this session).');
}

// Best-effort PERIODIC capture of a rotating-token cloud sign-in (OneDrive) from a live mount. The token is otherwise
// only re-saved on a clean unmount; if the service is killed after the token rotates but before that unmount, the
// stored token is left stale — a reconnect prompt next time, never data loss (the vault's keys live in the local
// manifest, independent of the sign-in). This runs the SAME idempotent harvest as unmount, throttled to a few minutes,
// so a mid-session rotation survives a hard crash. Fully guarded: only mounts that expose a control endpoint are
// probed, every failure is swallowed, and it reads config and writes ONLY when the token actually changed — so it can
// never disturb a mount. Called each health tick; it self-skips until the throttle window elapses.
let _lastCloudTokenSweepAt = 0;
let _cloudTokenSweeping = false; // true in-flight mutex, so a sweep that runs longer than the window can't overlap the next tick
const CLOUD_TOKEN_SWEEP_MS = 4 * 60 * 1000;
async function cloudTokenTick(mounts) {
	if (_cloudTokenSweeping) return;
	if (Date.now() - _lastCloudTokenSweepAt < CLOUD_TOKEN_SWEEP_MS) return;
	_cloudTokenSweeping = true;
	_lastCloudTokenSweepAt = Date.now();
	try {
		let bin; try { bin = (await RcloneSetup.ensure()).rclone; } catch (_) { return; }
		if (!bin) return;
		for (const m of mounts || []) {
			if (!m || !m.mountpoint) continue;
			const endpoint = m.rcSocket || (m.rcTcp && m.rcTcp.addr ? m.rcTcp : null);
			if (!endpoint) continue; // a streaming mount, or an endpoint we could not recover — nothing to read from
			try { await harvestRotatedCloudToken(bin, endpoint, m, m.mountpoint); } catch (_) {}
		}
	} finally { _cloudTokenSweeping = false; }
}

// Compose the engine `[<name>]` backend section for a cloud remote, decrypting its secrets and obscuring the
// password-type ones. Returns config text (no crypt layer — that wraps `<name>:` separately).
async function backendSectionText(bin, name, entry, key) {
	const lines = ['[' + name + ']', 'type = ' + noNewlines(entry.type, 'storage type')];
	for (const [k, v] of Object.entries(entry.opts || {})) lines.push(noNewlines(k, 'option') + ' = ' + noNewlines(String(v), 'option ' + k));
	for (const [k, c] of Object.entries(entry.secretsPlain || {})) { const v = decCred(c, key); if (v) lines.push(noNewlines(k, 'field') + ' = ' + noNewlines(v, 'field ' + k)); }
	for (const [k, c] of Object.entries(entry.secretsObscure || {})) { const v = decCred(c, key); if (v) lines.push(noNewlines(k, 'field') + ' = ' + await Rclone.obscure(bin, v)); }
	return lines.join('\n') + '\n';
}
// The WORM (write-once-read-many) backend config for a cloud vault that requested Object Lock. These are s3
// backend options, so they apply to EVERY object rclone uploads — including the mount's write-back — making each
// new object version immutable for the retention window (edits and deletes become new versions and delete
// markers; the locked versions cannot be removed until the window expires). The retention is a DURATION (Nd),
// resolved to now + N at each upload, so a long-running mount always stamps a fresh window (an absolute date
// would go stale). Object Lock is s3-only, so this is a no-op for any other backend type.
// Object Lock support landed in rclone 1.74. Refuse a WORM vault on an older engine rather than silently
// creating one whose objects are NOT actually locked (unknown backend keys are ignored). Best-effort: if the
// version cannot be read, do not block — the pinned bundled engine is newer than this.
async function assertEngineObjectLock(bin) {
	let out = '';
	try { out = String((await Rclone.run(bin, ['version'], { timeoutMs: 8000 })).stdout || ''); } catch (_) { return; }
	const m = /rclone\s+v(\d+)\.(\d+)/i.exec(out);
	if (!m) return; // couldn't parse — assume the bundled (new) engine
	const major = +m[1], minor = +m[2];
	if (major > 1 || (major === 1 && minor >= 74)) return;
	throw new Error('The storage engine is older than the version that supports tamper-proof (WORM) Object Lock. Run "' + Brand.cli + ' setup --latest" to update it, then try again.');
}
function wormBackendLines(worm, entryType) {
	if (!worm || !worm.retainDays || String(entryType || '').toLowerCase() !== 's3') return '';
	const mode = String(worm.mode || 'governance').toUpperCase() === 'COMPLIANCE' ? 'COMPLIANCE' : 'GOVERNANCE';
	const days = Math.max(1, Math.round(Number(worm.retainDays)));
	const lines = ['object_lock_mode = ' + mode, 'object_lock_retain_until_date = ' + days + 'd'];
	if (worm.setAfterUpload) lines.push('object_lock_set_after_upload = true'); // for S3-compatible providers that reject inline lock headers on PUT
	return lines.join('\n') + '\n';
}
// A cloud vault records its store as manifest.crypt.backend = { remoteId, remotePath, worm? }. Returns the
// composed backend config text (plus any Object Lock keys) and the "<name>:<path>" spec the crypt remote wraps,
// or null for a local vault.
async function cloudCryptTargetText(bin, manifest) {
	const b = manifest && manifest.crypt && manifest.crypt.backend;
	if (!b || !b.remoteId) return null;
	const entry = await getCloudRemoteRaw(b.remoteId);
	if (!entry) throw new Error('The cloud storage for this vault is not set up on this computer. Add the cloud remote "' + b.remoteId + '" under Cloud storage, then try again.');
	const key = await machineCredKey();
	const backendText = await backendSectionText(bin, 'backend', entry, key) + wormBackendLines(b.worm, entry.type);
	const remoteSpec = backendRemoteSpec(b.remotePath);
	return { backendText, remoteSpec };
}
function isCloudVault(manifest) { return !!(manifest && manifest.crypt && manifest.crypt.backend && manifest.crypt.backend.remoteId); }
// The engine remote-spec for a cloud vault's ciphertext directory: the ephemeral "backend" remote plus the
// configured remote path, with leading/trailing slashes trimmed so it is a clean "backend:path". Single-sourced
// so the probe, backup, and mount sites can never build it differently.
function backendRemoteSpec(remotePath) { return 'backend:' + String(remotePath || '').replace(/^\/+|\/+$/g, ''); }
// Test a cloud remote by listing a path on it (bounded). Returns { ok, detail }.
async function testCloudRemote(id, remotePath) {
	const bin = await ensureEngine();
	const entry = await getCloudRemoteRaw(id);
	if (!entry) throw new Error('That cloud remote is not configured.');
	const key = await machineCredKey();
	const cfg = await Rclone.writeEphemeralConfig(await backendSectionText(bin, 'backend', entry, key));
	try {
		const spec = backendRemoteSpec(remotePath);
		const r = await Rclone.run(bin, ['lsf', spec, '--max-depth', '1'], { configPath: cfg, timeoutMs: 30000, maxOutBytes: MAX_LISTING_BYTES });
		if (r.status === 0) return { ok: true, detail: 'Reachable.' };
		// A missing target folder is fine (it is created on first write) — the point of the test is that the
		// backend and credentials work. Only an auth/network failure counts as unreachable.
		if (/not found|doesn't exist|directory not found/i.test(String(r.stderr || ''))) return { ok: true, detail: 'Reachable (the folder does not exist yet).' };
		return { ok: false, detail: engineTail(r) };
	} finally { await Rclone.removeConfig(cfg); }
}
// Health helpers for the self-check watchdogs. checkCloudCreds confirms every saved cloud remote's secrets
// still decrypt with this machine's credential key (a replaced/restored credkey is caught before a mount
// fails confusingly). mountedCloudRemotes reports which currently-mounted vaults are cloud-backed, so the
// reachability watchdog probes only remotes actually in use.
async function checkCloudCreds() {
	const remotes = (await getSettings()).cloudRemotes || {};
	const key = await machineCredKey().catch(() => null);
	const out = [];
	for (const [id, r] of Object.entries(remotes)) {
		let ok = true;
		try { for (const c of Object.values({ ...(r.secretsPlain || {}), ...(r.secretsObscure || {}) })) decCred(c, key); } catch (_) { ok = false; }
		out.push({ id, label: r.label || r.type, ok });
	}
	return out;
}
async function mountedCloudRemotes() {
	const out = [];
	for (const m of (await State.readAll())) {
		try { const man = await readManifest(m.vault); if (isCloudVault(man)) out.push({ vault: m.vault, name: displayName(m.vault), remoteId: man.crypt.backend.remoteId, remotePath: man.crypt.backend.remotePath || '' }); } catch (_) {}
	}
	return out;
}

// Create or update an SFTP destination. Secrets (password, key passphrase) are encrypted before
// they are stored; an omitted secret on an update keeps the existing one.
async function saveSftpDest(dest = {}) {
	if (!dest.host || !dest.user) throw new Error('An SFTP host and username are required.');
	const host = noNewlines(dest.host, 'host'), user = noNewlines(dest.user, 'username');
	const remotePath = noNewlines(String(dest.remotePath || '').trim(), 'remote folder');
	const keyFile = noNewlines(dest.keyFile || '', 'key file path').trim();
	const label = noNewlines(dest.label || dest.host, 'label');
	const key = await machineCredKey();
	const authType = dest.authType === 'key' ? 'key' : 'password';
	const id = dest.id || crypto.randomBytes(6).toString('hex');
	// The host key is not secret; keep only host-key-shaped lines (drop blanks/comments) so a paste
	// of `ssh-keyscan <host>` output stores cleanly. Empty clears any previously pinned key.
	const hostKey = sanitizeHostKey(dest.hostKey);
	const password = dest.password, passphrase = dest.passphrase; // captured before the (possibly deferred) mutate
	await mutateSettings(cur => {
		const dests = { ...(cur.sftpDests || {}) };
		const prev = dests[id] || {};
		dests[id] = {
			label, host, port: clampInt(dest.port, 1, 65535, 22), user, remotePath, authType,
			hostKey: dest.hostKey === undefined ? (prev.hostKey || '') : hostKey, // omitted on update = keep existing
			password: authType === 'password' ? (password != null && password !== '' ? encCred(password, key) : (prev.password || '')) : '',
			keyFile: authType === 'key' ? keyFile : '',
			passphrase: authType === 'key' ? (passphrase != null && passphrase !== '' ? encCred(passphrase, key) : (prev.passphrase || '')) : ''
		};
		return { ...cur, sftpDests: dests };
	});
	return { id };
}

// Keep only host-key-shaped lines from a pasted host key / ssh-keyscan output (drop blanks and
// comments). Non-secret, so stored in the clear. Bounded so a settings file can't grow unbounded.
function sanitizeHostKey(hostKey) {
	if (!hostKey) return '';
	return String(hostKey).split(/\r?\n/).map(l => l.trim())
		.filter(l => l && !l.startsWith('#') && /(ssh-(rsa|ed25519|dss)|ecdsa-|sk-)/.test(l))
		.slice(0, 20).join('\n');
}

// A known_hosts file body pinning `hostKey` to this destination's host:port. Each line is given the
// right host prefix (OpenSSH uses [host]:port for a non-default port) so the engine will accept the
// server ONLY if it presents one of these keys — defeating an impersonating server on the network.
function knownHostsBody(hostKey, host, port) {
	const spec = (port && Number(port) !== 22) ? '[' + host + ']:' + port : host;
	const out = [];
	for (const line of sanitizeHostKey(hostKey).split(/\r?\n/)) {
		if (!line) continue;
		const first = line.split(/\s+/)[0];
		out.push(/^(ssh-|ecdsa-|sk-)/.test(first) ? spec + ' ' + line : line); // prepend host if the line is just "keytype key"
	}
	return out.join('\n') + '\n';
}

// ── Tier 2 "Anywhere access": peer (WebDAV) destinations + serving a vault as a node ────────────
// A peer is another node running `serve` (below). It is remembered like an SFTP destination — url +
// login, with the password encrypted at rest — and used as a mirror destination (`webdav:<id>`). The
// served endpoint IS the remote vault's folder, so the client mirrors its local vault against the
// peer's root.

async function listPeers() {
	const peers = (await getSettings()).peers || {};
	return Object.keys(peers).map(id => { const d = peers[id]; return { id, label: d.label || d.url, url: d.url, user: d.user, hasPassword: !!d.password }; });
}

// Create or update a peer. The password is encrypted before it is stored; an omitted password on an
// update keeps the existing one.
async function savePeer(peer = {}) {
	const url = noNewlines(String(peer.url || '').trim(), 'peer address');
	if (!url) throw new Error('A peer address (a WebDAV URL like https://host:port/) is required.');
	if (!/^https?:\/\//i.test(url)) throw new Error('The peer address must start with http:// or https://');
	const user = noNewlines(peer.user || '', 'username');
	const label = noNewlines(peer.label || url, 'label');
	const key = await machineCredKey();
	const id = peer.id || crypto.randomBytes(6).toString('hex');
	const password = peer.password;
	// The pinned certificate (public, not a secret) that this peer serves over the relay, if any — the
	// client trusts ONLY this cert, so the relay hop is encrypted and cannot be intercepted.
	const ca = peer.ca != null ? String(peer.ca) : undefined;
	await mutateSettings(cur => {
		const peers = { ...(cur.peers || {}) };
		const prev = peers[id] || {};
		peers[id] = { label, url, user, password: (password != null && password !== '') ? encCred(password, key) : (prev.password || ''), ca: ca !== undefined ? ca : (prev.ca || '') };
		return { ...cur, peers };
	});
	return { id };
}

async function removePeer(id) {
	await deleteSettingsKey('peers', id);
	return { ok: true };
}

// A single copy-paste "connection code" that carries everything the other machine needs to add this
// node as a peer — the address, login, and pinned certificate — so setup is one paste. It contains
// the serve password, so treat it as you would the password.
function makePeerCode({ url, user, pass, ca } = {}) { return Buffer.from(JSON.stringify({ v: 1, url, user, pass, ca: ca || undefined })).toString('base64'); }
function parsePeerCode(code) { try { const o = JSON.parse(Buffer.from(String(code || '').trim(), 'base64').toString('utf8')); if (o && o.url) return { url: o.url, user: o.user || 'vd', password: o.pass || '', ca: o.ca || '' }; } catch (_) {} return null; }

// A single remembered relay hub (host[:port] + token, token encrypted at rest) so a node can be
// served through it from the UI without re-entering it each time.
async function setRelay({ host, token } = {}) {
	const key = await machineCredKey();
	const h = noNewlines(String(host || '').trim(), 'relay host');
	await mutateSettings(cur => ({ ...cur, relay: { host: h, token: (token != null && token !== '') ? encCred(token, key) : ((cur.relay || {}).token || '') } }));
	return { ok: true };
}
async function getRelay() { const r = (await getSettings()).relay || {}; return { host: r.host || '', hasToken: !!r.token }; }
// The decrypted relay endpoint for serving, or null if none is set up.
async function relayForServe() {
	const r = (await getSettings()).relay || {};
	if (!r.host) return null;
	const key = await machineCredKey();
	// Bracket-aware split so an IPv6 hub literal (which contains colons) parses correctly.
	const { host, port } = Common.splitHostPort(r.host, 7443);
	return { host, port: clampInt(port, 1, 65535, 7443), token: decCred(r.token, key) };
}

// ── Web-interface login (optional) ────────────────────────────────────────────
// A password for the local web UI. Off by default — the UI binds to loopback and needs no login —
// but required before the UI may bind to a network address. The password is stored only as a
// memory-hard verifier (never in the clear), alongside a random signing secret for session cookies.
// Rotating that secret on every change logs out all existing sessions.
async function getUiAuth() {
	const ui = (await getSettings()).ui || {};
	return { enabled: !!(ui.password && ui.secret), password: ui.password || null, secret: ui.secret || null, webauthn: Array.isArray(ui.webauthn) ? ui.webauthn : [] };
}
// Passwordless / biometric web-interface login (Touch ID, Windows Hello, a roaming security key), added on top
// of the password so you can sign in without typing it. It REUSES the vault's WebAuthn PRF: the authenticator
// releases a stable per-credential secret only after the biometric/PIN check, and that secret is hashed exactly
// like the password (UiAuth.hashPassword), so no new verification primitive is introduced. The stored descriptor
// (credential id + PRF salt) is not secret — the login page needs it to run the ceremony before you are signed
// in. The password remains the root credential and the network-exposed bind still requires it, so this is a
// convenience/second sign-in method, never a way to remove the password.
async function addUiWebauthn({ secret, credentialId, prfSalt, label, password } = {}) {
	if (!secret || !credentialId || !prfSalt) throw new Error('Incomplete security-key enrollment.');
	const auth = await getUiAuth();
	if (!auth.enabled) throw new Error('Set a web-interface password first, then add a security key or Touch ID as an extra way to sign in.');
	// Require the web password to enroll a PASSWORDLESS sign-in method. Enrollment stores a client-supplied secret,
	// so a session alone must not be enough: otherwise a momentarily hijacked session could plant a credential with
	// a known secret and sign in without the password ever after — a backdoor that a logout would not revoke.
	if (!(await UiAuth.verifyPassword(String(password || ''), auth.password))) throw new Error('Enter your current web password to add a passwordless sign-in method.');
	const hash = await UiAuth.hashPassword(String(secret));
	const entry = { id: String(credentialId).slice(0, 512), prfSalt: String(prfSalt).slice(0, 512), hash, label: [...String(label || 'Security key')].slice(0, 60).join(''), addedAt: new Date().toISOString() };
	await mutateSettings(cur => { const ui = cur.ui || {}; const list = (Array.isArray(ui.webauthn) ? ui.webauthn : []).filter(w => w.id !== entry.id).slice(0, 19); list.push(entry); return { ...cur, ui: { ...ui, webauthn: list } }; });
	return { ok: true, id: entry.id, label: entry.label };
}
async function removeUiWebauthn(id) {
	await mutateSettings(cur => { const ui = cur.ui || {}; return { ...cur, ui: { ...ui, webauthn: (Array.isArray(ui.webauthn) ? ui.webauthn : []).filter(w => w.id !== String(id)) } }; });
	return { ok: true };
}
// Descriptors for the login ceremony (served to an UNAUTHENTICATED login page), so they carry only what the
// ceremony needs — the credential id and PRF salt — and NOT the label, which would disclose how many keys exist
// and when they were added to anyone who can reach the login page. The label is shown only in the authenticated
// management list (listUiWebauthn).
function uiWebauthnDescriptors(auth) { return (auth.webauthn || []).map(w => ({ id: w.id, prfSalt: w.prfSalt })); }
function listUiWebauthn(auth) { return (auth.webauthn || []).map(w => ({ id: w.id, label: w.label })); }
// True if the PRF-derived secret matches ANY enrolled credential. Iterates a small (capped) list.
async function verifyUiWebauthn(secret) {
	const auth = await getUiAuth();
	for (const w of (auth.webauthn || [])) { try { if (await UiAuth.verifyPassword(String(secret || ''), w.hash)) return true; } catch (_) {} }
	return false;
}
async function setUiPassword(plain) {
	const pw = String(plain == null ? '' : plain);
	if (pw.length < 8) throw new Error('The web-interface password must be at least 8 characters.');
	const password = await UiAuth.hashPassword(pw);
	const secret = UiAuth.newSecret(); // fresh secret => any existing browser session is invalidated
	// Changing the web password is the "lock everyone out" action, so it also REVOKES every enrolled Touch ID /
	// security key. Otherwise a passwordless credential (a legitimate one, or one an attacker planted from a
	// stolen session) would still sign in after the password change, defeating the recovery. The user re-enrolls
	// their own key afterward. Clearing an empty list on the first set is a harmless no-op.
	await mutateSettings(cur => ({ ...cur, ui: { ...(cur.ui || {}), password, secret, webauthn: [] } }));
	return { ok: true };
}
async function clearUiPassword() {
	// Removing the password removes every sign-in method — including the enrolled keys, so a later password can
	// never silently revive stale credentials.
	await mutateSettings(cur => { const next = { ...cur, ui: { ...(cur.ui || {}) } }; delete next.ui.password; delete next.ui.secret; delete next.ui.webauthn; return next; });
	return { ok: true };
}
// Mint a fresh session-signing secret WITHOUT changing the password, so every existing browser session is
// invalidated server-side. Used by "Sign out" so a logout is real (not just a cleared cookie that a captured
// token could outlive). No-op when no password is set — there are then no sessions to invalidate.
async function rotateUiSecret() {
	await mutateSettings(cur => { const ui = cur.ui || {}; return ui.password ? { ...cur, ui: { ...ui, secret: UiAuth.newSecret() } } : cur; });
	return { ok: true };
}

// Build an ephemeral engine config for a peer's WebDAV endpoint (password decrypted then obscured for
// the engine). Returns { cfg, remote, cleanup } — `remote` is the peer's root (the served vault).
async function buildWebdavConfig(bin, d) {
	const key = await machineCredKey();
	const name = 'peer';
	const lines = ['[' + name + ']', 'type = webdav', 'url = ' + noNewlines(d.url, 'peer address'), 'vendor = rclone'];
	if (d.user) lines.push('user = ' + noNewlines(d.user, 'username'));
	const pw = decCred(d.password, key);
	if (pw) lines.push('pass = ' + await Rclone.obscure(bin, pw));
	const cfg = await Rclone.writeEphemeralConfig(lines.join('\n') + '\n');
	// If the peer pinned a certificate, write it to a temp file so callers can pass --ca-cert (which
	// trusts ONLY this cert), encrypting and authenticating the relay hop end to end.
	let caPath = null;
	if (d.ca) {
		caPath = path.join(Common.runDir(), 'peer-ca.' + crypto.randomBytes(6).toString('hex') + '.pem');
		await fsp.mkdir(path.dirname(caPath), { recursive: true });
		await fsp.writeFile(caPath, d.ca, { mode: 0o600 });
	}
	const cleanup = async () => { await Rclone.removeConfig(cfg); if (caPath) { try { await fsp.unlink(caPath); } catch (_) {} } };
	return { cfg, remote: name + ':', cleanup, caPath };
}
// The extra rclone args needed to pin a peer's certificate on a call (empty when the peer is plain).
function caArgs(caPath) { return caPath ? ['--ca-cert', caPath] : []; }
// The optional sync bandwidth limit, applied to the off-site/remote bulk transfers (backup, mirror) so a sync
// never saturates the connection. The value is passed straight to the engine, which accepts a plain rate
// ("1M", "512k") OR an off-peak timetable ("08:00,512k 23:00,off"), so scheduled windows come for free and any
// future engine bwlimit syntax keeps working. Empty = unlimited. Never applied to a live cloud mount (that would
// throttle file access) or a local-to-local copy.
function bwlimitOf(settings) { const v = settings && settings.bwlimit; return (v && String(v).trim()) ? String(v).trim() : ''; }
function bwArgs(settings) { const v = bwlimitOf(settings); return v ? ['--bwlimit', v] : []; }

// Verify a peer is reachable and the login works (a short directory listing). Never throws for a bad
// connection — returns { ok } or { ok:false, error }.
async function testPeer(id) {
	const d = ((await getSettings()).peers || {})[id];
	if (!d) throw new Error('That peer no longer exists.');
	const bin = await ensureEngine();
	const { cfg, remote, cleanup, caPath } = await buildWebdavConfig(bin, d);
	try {
		const r = await Rclone.run(bin, ['lsd', remote, '--low-level-retries', '1', '--contimeout', '15s', '--timeout', '20s', ...caArgs(caPath)], { configPath: cfg, timeoutMs: 30000, maxOutBytes: MAX_LISTING_BYTES });
		return r.status === 0 ? { ok: true } : { ok: false, error: engineTail(r) || 'could not connect (is the other node serving this vault?)' };
	} finally { await cleanup(); }
}

// Stable per-vault credentials for serving this vault, so a client's saved peer keeps working across
// serve restarts. Generated and saved (password encrypted) on first use.
async function serveCredsFor(abs) {
	const s = await getSettings();
	const existing = (s.serveCreds || {})[abs];
	if (existing && existing.user && existing.password) {
		const key = await machineCredKey();
		return { user: existing.user, pass: decCred(existing.password, key) };
	}
	const user = 'vd', pass = Serve.genCred();
	const key = await machineCredKey();
	await setStoreEntry('serveCreds', abs, { user, password: encCred(pass, key) });
	return { user, pass };
}

// Serve a vault's ciphertext over WebDAV so another node can mirror against it. The path may be an
// existing vault (served as-is; it must be unmounted so its state is settled) or an empty/new folder
// that a first mirror will prime into a vault. Returns the serve handle from Serve.serveWebdav
// (including url, user, pass, stop()).
// A stable node id per served vault, so its relay public address stays the same across restarts.
async function serveNodeIdFor(abs) {
	const s = await getSettings();
	const existing = (s.serveNodeIds || {})[abs];
	if (existing) return existing;
	const id = Relay.nodeId();
	await setStoreEntry('serveNodeIds', abs, id);
	return id;
}

async function serveVault(vaultDir, { bind, port, readOnly, onLine, onEvent, relay } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const isVault = await looksLikeVault(abs);
	if (isVault) {
		await assertUnmounted(abs, 'before serving it');
		// A cloud vault keeps only its manifest on this machine — the encrypted files live at the provider — so
		// serving it as a node would expose no data for a peer to mirror. Refuse, consistent with backup/mirror/
		// pack/disperse, and point a peer at the same cloud instead. (Guarded here, not for a fresh empty peer.)
		if (isCloudVault(await readManifest(abs))) throw new Error('This vault\'s data lives in your cloud provider, so it cannot be served as a node here — only its manifest is on this machine, not the encrypted files a peer would mirror. Point the other machine at the same cloud storage instead.');
	} else await fsp.mkdir(abs, { recursive: true }); // a fresh peer: an empty target a first mirror will prime
	const bin = await ensureEngine();
	const { user, pass } = await serveCredsFor(abs);
	// With a relay the serve stays on loopback and the hub exposes it; without, it binds where asked.
	const host = relay ? '127.0.0.1' : (bind || '127.0.0.1');
	// For a relay, encrypt the hop end to end: the node serves over TLS with a self-signed cert the
	// client pins, so the hub (and the network) only ever splice opaque bytes. Certificate generation is
	// pure Node (cross-platform, no external tool), so this normally always succeeds; it fails soft to plain
	// HTTP only if a certificate could not be produced at all.
	const certInfo = (relay && relay.host) ? await Cert.ensureCert(relay.host) : null;
	// If a relay was requested but no certificate could be made, the hop falls back to plain HTTP. Say so loudly
	// rather than silently: only ciphertext vault bytes cross the relay, but the serve login would travel
	// unencrypted, so the user should know to retry or reach the node another way.
	if (relay && relay.host && !certInfo) {
		Common.warn('Serving over the relay WITHOUT TLS: a self-signed certificate could not be created. Only encrypted vault data crosses the relay, but the serve login is not encrypted on that hop. Serve again, or reach the node through a tunnel or VPN you trust instead.');
	}
	// A WRITABLE share is only safe when the transport is encrypted (a relay hop with TLS) or the serve never
	// leaves this machine (bound to loopback, no relay). Otherwise a network sniffer could capture the basic-auth
	// login and use it to PUT or DELETE ciphertext on the served vault — an integrity and availability loss, not
	// just the confidentiality the fallback warning above describes. When a writable serve would be exposed over an
	// unencrypted hop, force it read-only and say why: the vault's data can still be pulled, but never altered
	// remotely. A relay hop with TLS, or a loopback-only direct serve, stays writable so two-way mirroring works.
	// Only a genuine loopback host keeps a direct (relay-less) serve writable. Anything else — 0.0.0.0, a LAN
	// address, a hostname — reads as exposed, so a writable serve there is downgraded to read-only unless the hop
	// is TLS-encrypted. The shared, DNS-safe predicate means a bare hostname can never masquerade as loopback.
	const exposedInsecure = (relay && relay.host) ? !certInfo : !Common.isLoopbackHost(host);
	let effReadOnly = !!readOnly;
	if (exposedInsecure && !effReadOnly) {
		effReadOnly = true;
		Common.warn('Serving READ-ONLY: a writable share needs an encrypted connection so that a sniffed login cannot be used to change or delete your data. To serve writable, use a relay hop (its TLS certificate is made automatically), or reach the node through a tunnel or VPN you trust.');
	}
	// Supervised: if the engine dies, it is restarted on the same endpoint (crash-resilient node).
	const served = await Serve.superviseWebdav(bin, abs, { host, port, user, pass, readOnly: effReadOnly, onLine, onEvent, cert: certInfo && certInfo.certFile, key: certInfo && certInfo.keyFile });
	if (!relay || !relay.host) return { ...served, isVault };
	// Reach it from anywhere through a self-hosted hub — no port forwarding. Register the loopback
	// serve with the hub; the hub assigns a stable public port, and clients mirror to that address.
	// registerNode returns { ready, stop } with stop available immediately, so a registration that
	// times out (hub unreachable, or answering after the deadline) can still be torn down — otherwise
	// its control-reconnect loop and worker pool would run for the life of the process.
	const nid = await serveNodeIdFor(abs);
	const registration = Relay.registerNode({ hubHost: relay.host, hubPort: clampInt(relay.port, 1, 65535, 7443), token: relay.token, nodeId: nid, localPort: served.port, onEvent });
	try {
		const reg = await Common.withTimeout(registration.ready, 15000);
		const publicUrl = (certInfo ? 'https://' : 'http://') + relay.host + ':' + reg.publicPort + '/';
		const stop = async () => { try { registration.stop(); } catch (_) {} try { await served.stop(); } catch (_) {} };
		return { ...served, url: publicUrl, localUrl: served.url, ca: certInfo ? certInfo.certPem : null, secure: !!certInfo, relay: { host: relay.host, publicPort: reg.publicPort }, stop, user, pass, isVault };
	} catch (e) {
		try { registration.stop(); } catch (_) {} // tear down the relay registration (reconnect loop + workers)
		try { await served.stop(); } catch (_) {} // and don't leave the loopback serve running either
		throw new Error('Could not reach the relay hub at ' + relay.host + ':' + (relay.port || 7443) + ' — check it is running and the token is correct. ' + (e && e.message || ''));
	}
}

async function removeSftpDest(id) {
	await deleteSettingsKey('sftpDests', id);
	return { ok: true };
}

// Build an ephemeral engine config for an SFTP destination (secrets decrypted then obscured for
// the engine, exactly as the crypt config does), returning the config path and the "remote:base"
// prefix to sync into. The caller removes the config afterwards.
async function buildSftpConfig(bin, d) {
	const key = await machineCredKey();
	const name = 'sftpdest';
	const port = clampInt(d.port, 1, 65535, 22);
	// Defense in depth: values are newline-guarded when saved, but guard again here so a
	// hand-edited settings file can never turn a field into an injected config directive.
	const lines = ['[' + name + ']', 'type = sftp', 'host = ' + noNewlines(d.host, 'host'), 'user = ' + noNewlines(d.user, 'username'), 'port = ' + port];
	if (d.authType === 'key') {
		if (d.keyFile) lines.push('key_file = ' + noNewlines(d.keyFile, 'key file path'));
		const pp = decCred(d.passphrase, key);
		if (pp) lines.push('key_file_pass = ' + await Rclone.obscure(bin, pp));
	} else {
		const pw = decCred(d.password, key);
		if (pw) lines.push('pass = ' + await Rclone.obscure(bin, pw));
	}
	// Host-key pinning: when a host key is stored, write a known_hosts file and point the engine at
	// it, so the connection is accepted only if the server presents that key — this stops an
	// impersonating server on the network from capturing the login. Without a pinned key, behavior
	// is unchanged (the server identity is not verified — documented as a limitation).
	let khPath = null;
	if (d.hostKey) {
		khPath = path.join(Common.runDir(), 'known_hosts.' + crypto.randomBytes(6).toString('hex'));
		await fsp.mkdir(path.dirname(khPath), { recursive: true });
		await fsp.writeFile(khPath, knownHostsBody(d.hostKey, d.host, port), { mode: 0o600 });
		lines.push('known_hosts_file = ' + khPath);
	}
	let cfg;
	try { cfg = await Rclone.writeEphemeralConfig(lines.join('\n') + '\n'); }
	catch (e) { if (khPath) { try { await fsp.unlink(khPath); } catch (_) {} } throw e; } // don't leak the known_hosts file if the config write fails
	const base = noNewlines(d.remotePath || '', 'remote folder').replace(/^\/+|\/+$/g, '');
	const cleanup = async () => { await Rclone.removeConfig(cfg); if (khPath) { try { await fsp.unlink(khPath); } catch (_) {} } };
	return { cfg, remote: name + ':' + (base ? base + '/' : ''), cleanup };
}

// Verify an SFTP destination's connection and credentials (a directory listing with a short
// timeout). Returns { ok } or { ok:false, error } — never throws for a bad connection.
async function testSftpDest(id) {
	const d = ((await getSettings()).sftpDests || {})[id];
	if (!d) throw new Error('That SFTP destination no longer exists.');
	const bin = await ensureEngine();
	const { cfg, remote, cleanup } = await buildSftpConfig(bin, d);
	try {
		const r = await Rclone.run(bin, ['lsd', remote, '--low-level-retries', '1', '--contimeout', '15s', '--timeout', '20s'], { configPath: cfg, timeoutMs: 30000, maxOutBytes: MAX_LISTING_BYTES });
		if (r.status === 0) return { ok: true };
		return { ok: false, error: engineTail(r) || 'could not connect' };
	} finally { await cleanup(); }
}

// Back up a vault, still encrypted, to an SFTP destination: mirror its folder into
// <remotePath>/<name>.vault on the server. Must be unmounted (settled state).
async function backupToSftp(vaultDir, destId) {
	const abs = resolveVaultDir(vaultDir);
	// Claim the vault EXCLUSIVELY for the whole off-site sync, exactly as the local backup does: it runs for
	// minutes to hours and now also moves prior versions into `.versions`, so a mount that began partway through
	// could capture a torn cipher store. mount refuses while this claim is held.
	return withVaultBusy(abs, 'This vault is busy with another operation (a mount, backup, or mirror). Wait for it to finish, then try again.', async () => {
		const manifest = await readManifest(abs);
		const d = ((await getSettings()).sftpDests || {})[destId];
		if (!d) throw new Error('That backup destination no longer exists.');
		await assertUnmounted(abs, 'before backing it up');
		await assertBackupSourceIntact(abs); // never mirror-delete the off-site backup when the source silently lost protected files
		const bin = await ensureEngine();
		const { cfg, remote, cleanup } = await buildSftpConfig(bin, d);
		try {
			const target = remote + path.basename(abs);
			// Refuse to mirror-delete a DIFFERENT vault that happens to sit under the same folder name at this remote
			// (the off-site parallel to the local assertVaultDestSafe check). Fail-open: only a confirmed foreign vault
			// blocks the backup; a fresh or unreadable destination proceeds.
			if (!(await remoteVaultSafeToOverwrite(bin, cfg, target, manifest))) {
				throw new Error('The off-site destination already holds a different vault under this name, so the backup was refused rather than overwrite it. Back up to a different remote folder, or remove the other vault there first.');
			}
			const settings = await getSettings();
			const syncArgs = ['sync', abs, target, '--transfers', '4', '--checkers', '8', ...bwArgs(settings)]; // honor the sync bandwidth limit off-site
			// Version history off-site, exactly like the local backup: --backup-dir MOVES about-to-be-overwritten or
			// deleted files into a timestamped subfolder BEFORE the new ones land, so the current backup is never torn
			// and prior versions stay browsable/restorable through the vault's own key. The folder is excluded from the
			// sync so it never mirror-deletes itself.
			const vs = versionsPolicy(settings);
			if (vs.on) syncArgs.push('--backup-dir', remoteJoin(target, VERSIONS_DIR) + '/' + versionStamp(), '--filter', '- /' + VERSIONS_DIR + '/**');
			await assertBackupDeletionsSafe(bin, abs, target, { configPath: cfg }); // all-or-nothing backstop
			const r = await Rclone.run(bin, syncArgs, { configPath: cfg, timeoutMs: 12 * 60 * 60 * 1000 });
			if (r.status !== 0) throw new Error('Off-site backup failed — check the server is reachable and the login and remote folder are correct (use Test). ' + engineTail(r));
			if (vs.on) { try { await pruneVersionsRemote(bin, cfg, remoteJoin(target, VERSIONS_DIR), vs); } catch (_) {} } // best-effort; never fails the backup
		} finally { await cleanup(); }
		await recordBackup(abs, 'sftp:' + destId);
		return { vault: abs, dest: 'sftp:' + destId };
	});
}

// The folder a vault was last backed up to (for a one-click repeat), or null.
async function backupDestFor(vaultDir) {
	try { const s = await getSettings(); return (s.backupDests || {})[resolveVaultDir(vaultDir)] || null; } catch (_) { return null; }
}

// Check that a vault's backup destination still holds a COMPLETE, restorable copy of THIS vault — the failure a
// backup exists to prevent, but which nothing otherwise surfaces. Password-less and read-only: it confirms the
// destination has a valid manifest that matches this vault (same salt), and that every encrypted file in the
// live store is also present at the destination. Works for a local folder or an off-site SFTP/WebDAV target,
// reusing the mirror's path resolution and the engine's listing. Returns a verdict: RESTORABLE / INCOMPLETE /
// DIFFERENT / UNREADABLE.
async function verifyBackup(vaultDir, { dest } = {}) {
	const abs = resolveVaultDir(vaultDir);
	const manifest = await readManifest(abs);
	// Compare against a SETTLED source: a mounted vault may have writes still buffered in the mount's cache, so
	// the on-disk store would not yet match a backup and the check could read a false "incomplete".
	await assertUnmounted(abs, 'before checking its backup');
	dest = dest || await backupDestFor(abs);
	if (!dest) throw new Error('This vault has no backup on record yet. Back it up first, or choose a destination to check.');
	const bin = await ensureEngine();
	const name = path.basename(abs);
	const isRemote = isRemoteDest(dest);
	let target, configPath, cleanup = async () => {}, caPath;
	if (isRemote) { const t = await resolveMirrorTarget(bin, dest, name); target = t.path2; configPath = t.configPath; cleanup = t.cleanup; caPath = t.caPath; }
	else target = path.join(path.resolve(dest), name);
	try {
		// 1) A valid manifest at the destination, for the SAME vault?
		let destManifest = null;
		if (!isRemote) { try { destManifest = await readManifest(target); } catch (_) {} }
		else destManifest = await readRemoteManifest(bin, configPath, target, caPath);
		if (!destManifest || !(destManifest.crypt && destManifest.crypt.salt)) return { vault: abs, dest, verdict: 'UNREADABLE', reason: 'No readable vault settings were found at the backup destination — the backup may be missing, incomplete, or unreachable.' };
		if (destManifest.crypt.salt !== (manifest.crypt && manifest.crypt.salt)) return { vault: abs, dest, verdict: 'DIFFERENT', reason: 'The destination holds a DIFFERENT vault, not a backup of this one.' };
		// 2) Completeness: every encrypted file in the live store must also exist at the destination AT THE SAME
		// SIZE. Comparing sizes too catches a file that copied only part-way (a disk that filled mid-backup), which
		// a name-only check would wrongly pass. The size is put first ("size|path") so a path containing the
		// separator still parses. The listing is scoped to the cipher store, so the destination's `.versions`
		// history (which lives at the backup root, not inside it) is never counted as an extra or a mismatch.
		const listFiles = async (root, cfg, ca) => {
			try {
				const r = await Rclone.run(bin, ['lsf', '-R', '--files-only', '--format', 'sp', '--separator', '|', root, ...caArgs(ca)], { configPath: cfg, timeoutMs: 30 * 60 * 1000, maxOutBytes: MAX_LISTING_BYTES });
				if (r && r.status === 0) { const m = new Map(); for (const line of String(r.stdout || '').split(/\r?\n/)) { if (!line) continue; const i = line.indexOf('|'); if (i < 0) continue; m.set(line.slice(i + 1), Number(line.slice(0, i)) || 0); } return m; }
			} catch (_) {}
			return null;
		};
		const srcFiles = await listFiles(cipherDirOf(abs), undefined, null);
		const dstFiles = await listFiles(isRemote ? (target + '/' + CIPHER_SUBDIR) : path.join(target, CIPHER_SUBDIR), configPath, caPath);
		if (!srcFiles || !dstFiles) return { vault: abs, dest, verdict: 'UNREADABLE', reason: 'The backup could not be listed — the destination may be unreachable, or the vault is too large to check this way.' };
		let missing = 0, mismatched = 0;
		for (const [f, sz] of srcFiles) { if (!dstFiles.has(f)) missing++; else if (dstFiles.get(f) !== sz) mismatched++; }
		const bad = missing + mismatched;
		const verdict = bad ? 'INCOMPLETE' : 'RESTORABLE';
		const parts = [];
		if (missing) parts.push(missing + ' missing');
		if (mismatched) parts.push(mismatched + ' the wrong size');
		return { vault: abs, dest, verdict, total: srcFiles.size, present: srcFiles.size - bad, missing, mismatched,
			reason: bad ? (parts.join(' and ') + ' of ' + srcFiles.size + ' encrypted files at the backup, so it is incomplete or damaged. Back up again to refresh it.')
				: 'The backup holds this exact vault and every encrypted file is present at the right size — it is complete and restorable.' };
	} finally { await cleanup(); }
}

// --- Scheduled backups (dependency-free) --------------------------------------------------
// A per-vault schedule stored in settings: { mode:'off'|'interval'|'daily', intervalHours,
// hour, minute, dest, lastRunAt, lastResult, lastErrorAt }. Daily times are the MACHINE's LOCAL
// time-of-day (hour/minute) and are evaluated against the local clock — the web app and the
// browser are always the same machine, so this is unambiguous and inherently DST‑correct
// (09:00 stays 09:00 across a daylight‑saving change, with no UTC conversion to drift). The
// schedule is driven by the running web app's periodic tick; there is no separate daemon.
const RETRY_AFTER_MS = 30 * 60 * 1000; // after a failed scheduled backup, wait this long before retrying
const backupRunning = new Set();       // vaults with a scheduled backup in flight (no overlap)

function clampInt(v, lo, hi, dflt) { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt; }
// Normalize the timing fields of a schedule (interval hours, or daily hour/minute with a per-caller
// default hour) and carry forward its run-state triple. Shared by the backup and repair schedule
// savers so the two stored shapes stay identical.
function scheduleTiming(mode, src, defaultHour) {
	return {
		intervalHours: mode === 'interval' ? clampInt(src.intervalHours, 1, 720, 24) : undefined,
		hour: mode === 'daily' ? clampInt(src.hour, 0, 23, defaultHour) : undefined,
		minute: mode === 'daily' ? clampInt(src.minute, 0, 59, 0) : undefined
	};
}
function carryRunState(prev) { return { lastRunAt: prev.lastRunAt || null, lastResult: prev.lastResult || null, lastErrorAt: prev.lastErrorAt || null }; }
function sameLocalDay(a, b) { return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate(); }

// Is a scheduled backup due right now? Pure and testable. `now` is a local Date.
// Generic "is this schedule due now?" — shared by scheduled backups and scheduled shard repair. It
// only looks at the timing (interval / daily / off) and the last run; each caller adds its own extra
// precondition (a destination for backup, folders for repair). Local time, so the platform handles DST.
function isScheduleDue(sched, now) {
	if (!sched || sched.mode === 'off') return false;
	const last = sched.lastRunAt ? new Date(sched.lastRunAt) : null;
	if (sched.mode === 'interval') {
		const ms = clampInt(sched.intervalHours, 1, 720, 24) * 3600 * 1000;
		return !last || (now.getTime() - last.getTime()) >= ms;
	}
	if (sched.mode === 'daily') {
		const h = clampInt(sched.hour, 0, 23, 0), mnt = clampInt(sched.minute, 0, 59, 0);
		const todayAt = new Date(now.getFullYear(), now.getMonth(), now.getDate(), h, mnt, 0, 0);
		if (now >= todayAt) return !last || !sameLocalDay(last, now); // normal case: run once today, after the time
		// Before today's scheduled time, still catch up a run that was due YESTERDAY (or earlier) but never happened —
		// for example the machine was asleep, or the vault was mounted (which skips the tick) across local midnight.
		// Interval schedules already catch up this way; without this, a daily job silently loses a full cadence. The
		// yesterday instant is built from the local hour/minute (not "now minus 24h"), so a DST shift cannot skew it.
		const yesterdayAt = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, h, mnt, 0, 0);
		return !!last && last.getTime() < yesterdayAt.getTime(); // only a PRIOR run can be "caught up"; a never-run schedule waits for its first scheduled time
	}
	return false;
}
function isBackupDue(sched, now) { return !!(sched && sched.dest) && isScheduleDue(sched, now); }

async function patchSchedule(abs, patch) { await patchStoreEntry('backupSchedules', abs, patch); }

// Read/replace a vault's backup schedule. Preserves the run history across an edit.
async function getBackupSchedule(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	return ((await getSettings()).backupSchedules || {})[abs] || { mode: 'off' };
}
// Clamp a schedule mode to a known value ('off' for anything unrecognized). One helper so every schedule setter
// normalizes it the same way.
function normalizeScheduleMode(m) { return ['off', 'interval', 'daily'].includes(m) ? m : 'off'; }
async function setBackupSchedule(vaultDir, sched = {}) {
	const abs = resolveVaultDir(vaultDir);
	const mode = normalizeScheduleMode(sched.mode);
	let dest = null;
	if (mode !== 'off') {
		// A cloud vault can't be backed up here (the data is at the provider — see backup()), so refuse to schedule
		// one rather than let every tick fail. Turning a schedule OFF is always allowed.
		if (isCloudVault(await readManifest(abs))) throw new Error('This vault\'s data lives in your cloud provider, so it cannot be scheduled for local backup — the provider keeps the data, and a Recovery Kit protects the keys. See "' + Brand.cli + ' recovery-kit".');
		if (!sched.dest) throw new Error('A backup destination is required to schedule backups.');
		dest = (typeof sched.dest === 'string' && sched.dest.startsWith('sftp:')) ? sched.dest : path.resolve(sched.dest);
	}
	let next;
	await mutateSettings(cur => {
		const bs = cur.backupSchedules || {};
		const prev = bs[abs] || {};
		next = mode === 'off' ? { mode: 'off' } : {
			mode, dest,
			...scheduleTiming(mode, sched, 2),
			...carryRunState(prev)
		};
		return { ...cur, backupSchedules: { ...bs, [abs]: next } };
	});
	return { vault: abs, schedule: next };
}

// One scheduling pass, run by the web app's tick. Backs up any vault whose schedule is due and
// which is currently UNMOUNTED. Best-effort and fully guarded: it never throws, never overlaps a
// vault with itself, backs off after a failure, and skips a mounted or missing vault to retry
// later. Returns the vaults it backed up this pass.
// One scheduling pass, shared by the backup, scrub, and dispersal-repair ticks. It owns the parts that must stay
// identical across all three so they can never drift: read the store (returning { ran: [] } on any failure), skip
// an entry that is already running or not yet due, back off after a recent failure, hold a per-key running claim
// so a slow pass never overlaps itself, and record a uniform error on a throw. Each caller supplies only what
// differs — its store name and running set, how "due" is decided, an optional one-time `setup` (e.g. read mount
// state once for the whole pass), an optional per-entry `preflight` guard, the `handle` that does the work and
// records its own success, and the `onError` that writes the failure. `handle` returns the value to add to `ran`,
// or undefined to add nothing. Best-effort and self-contained: it never throws.
const tickInFlight = new Set(); // store names whose schedule pass is currently running — at most one pass per store
async function runScheduleTick({ store, running, isDue, setup, preflight, handle, onError }) {
	// One invocation of a tick must never overlap itself. Each tick fires DETACHED every ~12s, and the pass awaits
	// each vault's operation in turn — so a long op would otherwise let the NEXT tick start a DIFFERENT due vault
	// while this one is still parked. With many vaults all due at once (a shared nightly schedule), the concurrent
	// operations would pile up without bound and could exhaust file descriptors and processes, destabilizing the
	// host. A per-store in-flight guard keeps at most ONE pass of each tick running, so due vaults are processed
	// serially, one at a time, exactly as a single pass already does (the same guard idiom as the health/sweep loops).
	if (tickInFlight.has(store)) return { ran: [] };
	tickInFlight.add(store);
	try {
		let schedules;
		try { schedules = (await getSettings())[store] || {}; } catch (_) { return { ran: [] }; }
		if (!Object.keys(schedules).length) return { ran: [] }; // nothing scheduled — skip setup()'s state.json read entirely (this tick fires every ~12s on installs with no schedules)
		const now = new Date();
		const ctx = setup ? await setup().catch(() => null) : null;
		const ran = [];
		for (const key of Object.keys(schedules)) {
			const sched = schedules[key];
			if (running.has(key) || !isDue(sched, now)) continue;
			if (sched.lastErrorAt && (now.getTime() - new Date(sched.lastErrorAt).getTime()) < RETRY_AFTER_MS) continue; // back off after a failure
			if (preflight && !(await preflight(key, sched, ctx))) continue;
			running.add(key);
			try { const entry = await handle(key, sched, now, ctx); if (entry !== undefined) ran.push(entry); }
			catch (e) { try { await onError(key, now, e); } catch (_) {} }
			finally { running.delete(key); }
		}
		return { ran };
	} finally { tickInFlight.delete(store); }
}

// The setup + preflight shared by the backup and scrub schedule ticks: read the mount state once, then skip a vault
// that is currently mounted (both operations need a settled vault; an uncertain probe proceeds and the operation
// re-guards) or one whose manifest is gone. One definition so the two ticks can never drift on the skip rule.
const unmountedVaultTick = {
	setup: async () => { try { return await State.readAll(); } catch (_) { return []; } },
	preflight: async (abs, sched, state) => {
		if (await isVaultMounted(abs, state || []).catch(() => false)) return false;
		// Time-bound the manifest read: an UNMOUNTED vault can still live on a wedgeable network/removable path, and
		// an unbounded read here would hang this sequential pass (and, with no run recorded, re-hang every following
		// pass, stacking pinned threadpool threads). A timeout skips the vault this pass; the next pass retries.
		try { await Common.withTimeout(readManifest(abs), 5000); } catch (_) { return false; } // gone or unresponsive — skip
		return true;
	},
};
async function backupScheduleTick() {
	return runScheduleTick({
		store: 'backupSchedules', running: backupRunning, isDue: isBackupDue,
		setup: unmountedVaultTick.setup, preflight: unmountedVaultTick.preflight,
		handle: async (abs, sched) => { await backup(abs, sched.dest); return abs; }, // backup() records lastRunAt/lastResult on success
		onError: (abs, now, e) => patchSchedule(abs, { lastResult: 'error: ' + (e.message || 'failed'), lastErrorAt: now.toISOString() }),
	});
}

// --- Scheduled integrity scrub (ordinary vaults) — reuses the same schedule model as backups -------
// Self-heal recovery data only refreshes on unmount, and verify/heal/audit are on-demand, so an IDLE vault is
// never proactively checked for bit-rot. This schedules a periodic, PASSWORD-LESS integrity check of a vault's
// recovery data — and, optionally, an automatic repair from it — for any vault that has recovery data (run
// "protect" first). It reuses verifyRecovery/heal (worker-threaded, bounded) and the shared schedule model.
// Best-effort and fully guarded exactly like the scheduled backup: unmounted-only, no overlap, backs off after a
// failure, never throws.
const scrubRunning = new Set();
async function getScrubSchedule(vaultDir) {
	const abs = resolveVaultDir(vaultDir);
	return ((await getSettings()).scrubSchedules || {})[abs] || { mode: 'off' };
}
async function setScrubSchedule(vaultDir, sched = {}) {
	const abs = resolveVaultDir(vaultDir);
	const mode = normalizeScheduleMode(sched.mode);
	let next;
	await mutateSettings(cur => {
		const ss = cur.scrubSchedules || {};
		const prev = ss[abs] || {};
		next = mode === 'off' ? { mode: 'off' } : { mode, autoHeal: !!sched.autoHeal, ...scheduleTiming(mode, sched, 3), ...carryRunState(prev) };
		return { ...cur, scrubSchedules: { ...ss, [abs]: next } };
	});
	return { vault: abs, schedule: next };
}
async function patchScrubSchedule(abs, patch) { await patchStoreEntry('scrubSchedules', abs, patch); }
// Run one integrity scrub now: verify the recovery data, and (when asked) repair any damage from it. No password
// (it works over the ciphertext and the recovery parity). Returns { checked, clean, healed, repaired } or a
// { skipped } when the vault has no recovery data to check.
async function runScrub(vaultDir, { autoHeal, onProgress } = {}) {
	const abs = resolveVaultDir(vaultDir);
	if (!(await Recovery.hasRecovery(abs))) return { vault: abs, skipped: 'no recovery data — run protect first' };
	// Before an UNATTENDED auto-heal, refresh the recovery data if the vault legitimately changed since it was
	// protected. refreshRecoveryIfStale rebuilds ONLY when the change is provably safe (a trusted mount/edit session,
	// or the vault still verifies clean against the existing parity) and otherwise defers — so a real edit updates
	// the parity here instead of being seen as damage and REVERTED by the auto-heal below, while genuine bit-rot
	// (untrusted, no session) is left for the heal. It self-claims the vault, so it must run before the claim below.
	// (Thorough vaults detect a same-size in-place edit here; a normal vault keeps its documented size-based limit.)
	// `deep` forces the content-level staleness check even for a non-thorough vault, so a same-size in-place edit from
	// a recent trusted session refreshes the parity here rather than being reverted by the auto-heal below. This runs
	// only on the unattended auto-heal path (a scheduled scrub), where the extra whole-vault read is acceptable.
	if (autoHeal) { try { await refreshRecoveryIfStale(abs, { onProgress, deep: true }); } catch (_) {} }
	// Hold the vault exclusively across the WHOLE check-and-repair, so nothing (a mount, a scheduled backup, a
	// mirror) can start between the check and the repair or run alongside the repair's in-place block writes.
	return withVaultBusy(abs, RECOVERY_BUSY, async () => {
		const v = await verifyRecoveryWork(abs, { onProgress });
		const clean = !(v && v.protected && v.clean === false);
		let repaired = 0, healed = false;
		// heal returns the blocks repaired as `healed` (data + parity + size) and no `repaired` field, so read the real
		// count from there — the old `h.repaired` was always undefined, making the scrub log always say "repaired 0".
		if (!clean && autoHeal) { const h = await healWork(abs, { onProgress }); healed = true; repaired = (h && h.healed) || 0; }
		return { vault: abs, checked: true, clean, healed, repaired };
	});
}
async function scrubScheduleTick() {
	return runScheduleTick({
		store: 'scrubSchedules', running: scrubRunning, isDue: isScheduleDue,
		setup: unmountedVaultTick.setup, preflight: unmountedVaultTick.preflight,
		handle: async (abs, sched, now) => {
			const r = await runScrub(abs, { autoHeal: !!sched.autoHeal });
			const result = r.skipped ? ('skipped: ' + r.skipped) : r.clean ? 'ok' : (r.healed ? ('repaired ' + r.repaired) : 'damage found (auto-repair off)');
			// A damage-found-but-not-repaired outcome is recorded as an error so the back-off applies and it stands out.
			await patchScrubSchedule(abs, { lastRunAt: now.toISOString(), lastResult: result, lastErrorAt: (r.checked && !r.clean && !r.healed) ? now.toISOString() : null });
			return { abs, result };
		},
		onError: (abs, now, e) => patchScrubSchedule(abs, { lastResult: 'error: ' + (e.message || 'failed'), lastErrorAt: now.toISOString() }),
	});
}

// --- Scheduled shard repair (Tier 3) — reuses the same schedule model as backups ------------------
// A dispersed vault only stays durable if its shards are kept whole as nodes churn. This lets the user
// register a set of shard folders to check on a schedule; the tick inspects them and re-creates any
// missing or corrupted shards from the survivors — the same repairDispersal the manual button runs,
// off the main thread. Best-effort and fully guarded, exactly like the scheduled backup above.

// Collect the shard files (.vdshard) directly inside each given folder (top-level, bounded). Shared by
// the tick and the web routes so there is one implementation.
async function collectShards(folders) {
	const out = [];
	for (const f of (Array.isArray(folders) ? folders : [])) {
		if (!f) continue;
		// Bound the listing: shard folders live on OTHER nodes / removable / network drives, so a wedged
		// one must not hang the caller (a web request or the scheduled repair tick) or pin a thread forever.
		// A directory listing is size-independent, so a short bound never false-fires on a responsive drive.
		let names; try { names = await Common.withTimeout(fsp.readdir(path.resolve(f)), 10000); } catch (_) { continue; }
		for (const n of names) if (n.endsWith('.vdshard')) out.push(path.join(path.resolve(f), n));
	}
	return out;
}
// The full EXPECTED set of shard paths for a folder set — the existing shards plus a reconstructed path
// for each missing slot, placed into a folder that currently holds no shard. This is what lets repair
// re-create a shard whose file was deleted entirely (its slot index is gone with the file): the index
// is learned from the surviving shards' filenames (`<name>.<idx>of<n>.vdshard`). Corruption of a still-
// present file is already handled by its own header, so this only adds the truly-missing slots.
async function expectedShardPaths(folders) {
	const existing = await collectShards(folders);
	let name = null, n = null;
	// Learn the shape (name, total `n`) from a surviving shard's filename — but the filename lives on a
	// removable/network folder that could be attacker-planted, and `n` drives the loop below, so bound it to
	// the real dispersal cap (n <= 255, per Disperse). A bogus `x.0of2000000000.vdshard` is ignored, not
	// turned into a 2-billion-iteration OOM loop.
	for (const p of existing) { const m = /^(.*)\.(\d+)of(\d+)\.vdshard$/.exec(path.basename(p)); if (m) { const nn = Number(m[3]); if (Number.isInteger(nn) && nn >= 1 && nn <= 255) { name = m[1]; n = nn; break; } } }
	if (name == null || n == null) return existing; // nothing readable to learn the shape from
	const present = new Set(existing.map(p => { const r = Disperse.shardIdxFromName(p); return r ? r.idx : -1; })); // reuse the shared filename parser instead of a duplicated regex
	const missing = []; for (let i = 0; i < n; i++) if (!present.has(i)) missing.push(i);
	const emptyFolders = folders.map(f => path.resolve(f)).filter(f => !existing.some(p => Common.samePath(path.dirname(p), f)));
	const out = [...existing];
	for (let j = 0; j < missing.length && j < emptyFolders.length; j++) out.push(path.join(emptyFolders[j], name + '.' + missing[j] + 'of' + n + '.vdshard'));
	return out;
}
// Repair a dispersed set addressed by its FOLDERS (re-creating even wholly-deleted shards). Used by the
// web Repair button and the scheduled tick; the CLI repair-shards takes explicit paths instead.
async function repairFolders(folders, { onProgress } = {}) {
	return repairDispersal(await expectedShardPaths(folders), { onProgress });
}

// A stable id for a set of shard folders, so saving the same folders again updates one schedule rather
// than piling up duplicates, and the UI can set/clear it knowing only the folders.
function repairScheduleId(folders) {
	const norm = (Array.isArray(folders) ? folders : []).map(f => path.resolve(String(f || ''))).filter(Boolean).sort();
	return Common.sha256Hex(norm.join('\n')).slice(0, 12);
}
async function listRepairSchedules() {
	const rs = (await getSettings()).repairSchedules || {};
	return Object.keys(rs).map(id => ({ id, ...rs[id] }));
}
async function saveRepairSchedule({ folders, label, mode, intervalHours, hour, minute } = {}) {
	const norm = (Array.isArray(folders) ? folders : []).map(f => path.resolve(String(f || ''))).filter(Boolean);
	if (!norm.length) throw new Error('At least one shard folder is required to schedule repairs.');
	const id = repairScheduleId(norm);
	const m = normalizeScheduleMode(mode);
	await mutateSettings(cur => {
		const rs = { ...(cur.repairSchedules || {}) };
		if (m === 'off') { delete rs[id]; return { ...cur, repairSchedules: rs }; }
		const prev = rs[id] || {};
		rs[id] = {
			label: label || prev.label || '', folders: norm, mode: m,
			...scheduleTiming(m, { intervalHours, hour, minute }, 3),
			...carryRunState(prev)
		};
		return { ...cur, repairSchedules: rs };
	});
	return { id, mode: m };
}
async function removeRepairSchedule(id) {
	await deleteSettingsKey('repairSchedules', id);
	return { ok: true };
}
async function patchRepairSchedule(id, patch) { await patchStoreEntry('repairSchedules', id, patch); }
const repairRunning = new Set(); // schedule ids with a repair in flight (no overlap)
// One pass over the repair schedules. Best-effort, never throws, never overlaps a schedule with itself,
// backs off after a failure. Returns the schedule ids it actually repaired this pass.
async function dispersalRepairTick() {
	// No setup or preflight: this operates on shard folders, not vaults, so there is no mount state to read and no
	// per-vault manifest to check. It adds an id to `ran` only when it actually repaired something.
	return runScheduleTick({
		store: 'repairSchedules', running: repairRunning, isDue: isScheduleDue,
		handle: async (id, sched, now) => {
			const shards = await expectedShardPaths(sched.folders); // includes truly-missing slots so they can be re-created
			const status = await inspectShards(shards);
			if (!status.recoverable) { await patchRepairSchedule(id, { lastRunAt: now.toISOString(), lastResult: 'not repairable: ' + status.good + ' of ' + (status.n || '?') + ' shards readable' }); return undefined; }
			if (status.good < status.n) { const r = await repairDispersal(shards); await patchRepairSchedule(id, { lastRunAt: now.toISOString(), lastResult: 'repaired ' + r.repaired + ' shard(s)', lastErrorAt: null }); return id; }
			await patchRepairSchedule(id, { lastRunAt: now.toISOString(), lastResult: 'all ' + status.n + ' shards healthy', lastErrorAt: null }); return undefined;
		},
		onError: (id, now, e) => patchRepairSchedule(id, { lastResult: 'error: ' + (e.message || 'failed'), lastErrorAt: now.toISOString() }),
	});
}

// Restore a backed-up vault into destRoot/<name>.vault and register it. The copy is
// non-destructive; an existing vault at the target is refused unless overwrite is set.
async function restore(backupVaultPath, destRoot, opts = {}) {
	const src = path.resolve(backupVaultPath);
	if (!(await looksLikeVault(src))) {
		throw new Error('That folder is not a vault backup (no vault settings were found in it).');
	}
	if (!destRoot) throw new Error('A destination folder is required.');
	const dest = path.join(path.resolve(destRoot), path.basename(src));
	// Treat the destination as an existing vault if EITHER manifest is present — a vault can validly
	// exist with only its backup manifest (readManifest self-heals from it), so checking just
	// vault.json would let a restore silently overwrite and orphan a real vault without --force.
	const destLooksVault = await looksLikeVault(dest);
	if (destLooksVault && !opts.overwrite) {
		throw new Error('A vault already exists at ' + dest + ' (use --force to overwrite).');
	}
	// Even with --force, never let a restore clobber a DIFFERENT vault that happens to share the target folder
	// name — the copy is additive, so an unrelated vault's manifest and files would be silently orphaned. Every
	// other clobbering path (backup, mirror, off-site) enforces this same-identity check; restore is no exception.
	if (destLooksVault && opts.overwrite) {
		// Read the source manifest RAW, so inspecting the backup we are restoring FROM never self-heal-writes
		// into it — a backup folder should stay exactly as the user left it.
		const srcManifest = await readManifestRaw(src);
		if (!(await sameVaultIdentity(dest, srcManifest))) {
			throw new Error('The destination already holds a DIFFERENT vault at ' + dest + '. Restore into an empty folder, or over this vault\'s own copy, so an unrelated vault is never overwritten.');
		}
	}
	// Claim the destination EXCLUSIVELY and refuse a mounted target for the whole copy. Restoring over an
	// existing vault (the --force case) must never rewrite the encrypted store underneath a live mount — that
	// races the mount's buffered write-back and tears the store. Every other vault-writing path takes this same
	// claim; restore is no exception. Only `dest` is guarded (`src`, the backup, is read-only). The claim also
	// stops a mount from beginning midway through the copy.
	return withVaultBusy(dest, 'The destination vault is busy with another operation (a mount or a sync). Wait for it to finish, then restore again.', async () => {
		await assertUnmounted(dest, 'before restoring over it');
		await fsp.mkdir(dest, { recursive: true });
		const bin = await ensureEngine();
		const r = await Rclone.run(bin, ['copy', src, dest, '--transfers', '8', '--checkers', '8'], { timeoutMs: 12 * 60 * 60 * 1000 });
		if (r.status !== 0) throw new Error('Restore failed — check the backup folder and the destination are reachable and have free space. ' + engineTail(r));
		await readManifest(dest); // validate the restored payload
		await markAsPackage(dest);
		await State.addVault(dest);
		return { vault: dest };
	});
}

module.exports = {
	create, importFolder, changePassword, addKey, removeKey, addRecoveryKey, addDeviceKey, addKeyfile, keyfileDigestFromFile, addReadOnlyKey, makeReadCap, makeWebReadCap, shareSeal, shareOpen, enableTeam, addMember, listMembers, removeMember, setMemberOwner, addDevice, removeDevice, setupOwnerRecovery, getRecoveryShare, recoverOwner, unlockByMemberKey, mobilePrepare, parseReadCap, listShares, revokeShare, pruneShares, rotate, verifySuccession, resumeRekey, listKeys, deviceDescriptors, backup, restore, backupDestFor, verifyBackup, vaultSize, listVersions, restoreVersion, versionsToPrune, getBackupSchedule, setBackupSchedule, backupScheduleTick, isBackupDue, getScrubSchedule, setScrubSchedule, runScrub, scrubScheduleTick, collectShards, repairFolders, listRepairSchedules, saveRepairSchedule, removeRepairSchedule, dispersalRepairTick,
	listSftpDests, saveSftpDest, removeSftpDest, testSftpDest, listCloudRemotes, saveCloudRemote, removeCloudRemote, testCloudRemote, checkCloudCreds, mountedCloudRemotes, cloudAuthorize, saveCloudOAuth, isOAuthBackend, cloudFilenameEncoding, wormBackendLines, mount, unmount, unmountAll, unmountOrphans, lockAll, autoLockTick, getSettings, setSettings, recordMountPrefs, setFavorite, status, listMounts, listMountsAndVaults, isUnmounting, cloudTokenTick, list, searchNames, contentReindex, contentSearch, contentIndexStatus, verify, snapshot, seal, unseal, audit, fingerprint, recoveryKit, attest, attestations, makeBundle, verifyBundle, notesList, noteGet, noteSave, noteDelete, tamperLog, scanSyncArtifacts, protect, recoveryStatus, verifyRecovery, heal, unprotect, secureRemove, refreshRecoveryIfStale, mirrorDestFor, mirrorStatus, setMirrorDest, removeMirror, syncMirror, syncMirrorIfConfigured, listPeers, savePeer, removePeer, testPeer, serveVault, setRelay, getRelay, relayForServe, makePeerCode, parsePeerCode, getUiAuth, setUiPassword, clearUiPassword, rotateUiSecret, addUiWebauthn, removeUiWebauthn, uiWebauthnDescriptors, verifyUiWebauthn, listUiWebauthn, disperse, reconstructFromShards, inspectShards, repairDispersal, dispersalGuidance, addThresholdKey, unlockSecretFromShares, mirrorLeaseStatus, claimLeaseForMount, releaseLease, refreshLease, LEASE_HEARTBEAT_INTERVAL_MS, ownerTag, touchOwnerAlive, clearOwnerAlive, isOwnerAlive, pack, unpack, importFiles, doctor, startEngineSetup, reveal, fileManagerCommand, sweep,
	decoyProtected, decoySet, decoyRemove, decoyList,
	travelEnable, travelRestore, travelStatus,
	emergencyKeypair, emergencyEnroll, emergencyArm, emergencyCheckIn, emergencyStatus, emergencyTick, emergencyNoteClockDrift, emergencyOpen, emergencyDisarm,
	readManifest, readManifestForPoll, checkManifestSeal, updateManifestFields, displayName, defaultMountRoot, normalizeMountpoint, resolveVaultDir, assertReadable, checkOnMount, isIgnoredVaultPath,
	vaultsDir: Common.vaultsDir,
	addKnownVault, removeKnownVault, listKnownVaults, rekeyPending
};

// The canonical seal / succession / attestation input-builders, exposed ONLY so the verify-bundle parity test can
// assert the standalone verifier's re-vendored copies stay byte-identical to these (a drift would let the offline
// verifier disagree — GENUINE vs TAMPERED — on a bundle). Not part of the public API.
module.exports._sealParity = { manifestSealInput, manifestSealInputLegacy, manifestSealVerifies, successionInput, attestGenesis, attestChainHash, attestDigest, tokenHashOf };
