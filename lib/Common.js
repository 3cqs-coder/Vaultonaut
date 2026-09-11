'use strict';
// lib/Common.js — small shared helpers: project paths, a timestamped logger,
// and a couple of filesystem conveniences used across the tool. Kept tiny on
// purpose so every module can lean on the same conventions.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');
const Brand = require('./Brand');

// The project root is the parent of lib/, resolved from this file so the tool
// works no matter which directory it is launched from.
const ROOT = path.resolve(__dirname, '..');

function root() { return ROOT; }
// The app's CLI entry script — used by the autostart, shortcut, and detached-service launchers so the path is
// derived in one place.
function appScriptPath() { return path.join(ROOT, 'vaultonaut.js'); }

// Is the service running as the packaged native desktop app (rather than a headless/CLI install)? The desktop
// shell sets this once at startup (from its --desktop launch flag). It is read where the two installs must
// differ — notably, autostart adds a clickable browser-launcher for a command-line install but must NOT for the
// desktop app, which is already that clickable app. Single-sourced here so every caller agrees.
let _desktopApp = false;
function setDesktopApp(on) { _desktopApp = !!on; }
function isDesktopApp() { return _desktopApp; }

// --- Cross-platform path comparison -----------------------------------------------------------
// Windows and the DEFAULT macOS volume (APFS/HFS+) are case-INSENSITIVE, so two paths differing only in case
// point to the SAME location there. Fold case on both (matching isMountJunk's darwin handling) so samePath /
// pathWithin — and the data-loss guards built on them (e.g. the secure-remove "keep OUTSIDE the vault" check) —
// treat a case-variant path as the same file. Linux is case-sensitive, so it is left as-is. On an opt-in
// case-sensitive APFS volume this folds slightly too eagerly, but for a safety guard that errs the safe way (it
// refuses/de-dupes more, never destroys or overwrites more).
function foldPath(p) {
	// Unify Unicode FORM first (NFC): macOS stores file names decomposed (NFD) while Linux and Windows keep them
	// composed (NFC), so the SAME non-ASCII vault or file name read on two systems is different bytes — a raw
	// comparison would then treat one vault as two, or miss a mounted vault by name. Normalizing both sides to
	// NFC makes them match; it is a no-op for ASCII and idempotent, and this value is only ever COMPARED (never
	// used to open a file), so it cannot change a real path. Then case-fold on the case-insensitive platforms.
	const s = String(p).normalize('NFC');
	return (process.platform === 'win32' || process.platform === 'darwin') ? s.toLowerCase() : s;
}
// Do two paths resolve to the same location? Shared by mount-state lookups, known-vault de-duplication,
// and unmount-by-path so a differently-cased path on Windows is never treated as a different vault.
function samePath(a, b) { return a != null && b != null && foldPath(path.resolve(String(a))) === foldPath(path.resolve(String(b))); }
// Is `child` the same as, or contained within, `parent`? Boundary-aware — a sibling that merely shares
// a name prefix ("/a/foobar" under "/a/foo") is NOT inside. Case-folded on Windows.
function pathWithin(child, parent) {
	const c = foldPath(path.resolve(String(child))), p = foldPath(path.resolve(String(parent)));
	return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
}
// Fully resolve a path THROUGH symlinks, even when the leaf (or several trailing components) does not exist
// yet — walk up until a real ancestor resolves, then re-append the missing tail. Returns the resolved absolute
// path, or null when it cannot be safely resolved (a non-ENOENT error anywhere on the way). This is what a
// containment guard must use instead of path.resolve alone: path.resolve only collapses "..", so a symlink whose
// textual location is outside a protected folder but which resolves INSIDE it would slip a lexical-only check.
async function resolveThroughSymlinks(p) {
	let cur = path.resolve(String(p)); const tail = [];
	for (let hops = 0; hops < 8192; hops++) {
		try { const real = await fsp.realpath(cur); return tail.length ? path.join(real, ...tail) : real; }
		catch (e) {
			if (e && e.code === 'ENOENT') { tail.unshift(path.basename(cur)); const up = path.dirname(cur); if (up === cur) return null; cur = up; continue; }
			return null; // any other error: not safely resolvable
		}
	}
	return null;
}

// Constant-time equality, length-guarded and never throwing. Each side is read as bytes (a Buffer or typed array
// is used as-is; a string is read as UTF-8), and the comparison runs only when the lengths match — a length
// mismatch returns false WITHOUT calling crypto.timingSafeEqual, which throws on unequal lengths. Use it to check
// a presented secret or signature against the expected one when both are fixed-width (or a length difference is
// not itself sensitive). One audited primitive replaces the hand-rolled length guard that each auth site carried.
function timingSafeEqual(a, b) {
	try {
		const ba = Buffer.isBuffer(a) ? a : Buffer.from(a);
		const bb = Buffer.isBuffer(b) ? b : Buffer.from(b);
		return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
	} catch (_) { return false; }
}
// Constant-time equality that first hashes each side to a fixed 32 bytes, so neither the length nor a shared
// prefix of the secret can leak through comparison timing. Use it when the compared values are variable-length
// secrets (a shared token) whose length must also stay private. Inputs are read as text; null/undefined hash as
// the empty string. This is the "hash both sides, then compare" idiom the public-facing token checks share.
function timingSafeEqualHashed(a, b) {
	try {
		const h = (x) => sha256(String(x == null ? '' : x));
		return crypto.timingSafeEqual(h(a), h(b));
	} catch (_) { return false; }
}

// Map `fn` over `items` with at most `limit` running at once, preserving result order. Caps the number of
// in-flight operations so a fan-out over many entries cannot flood the small libuv threadpool — a per-call
// timeout does NOT free a wedged filesystem syscall's thread (the OS holds it until it gives up), so the
// CONCURRENCY itself has to be bounded, not just each call. Used for directory fan-outs (the folder picker) where
// one dir can hold thousands of entries. If `fn` rejects, this rejects (same as Promise.all); callers that must
// not abort the batch should catch inside `fn`.
async function mapLimit(items, limit, fn) {
	const list = Array.isArray(items) ? items : [];
	const out = new Array(list.length);
	const n = Math.max(1, Math.min(limit | 0 || 1, list.length || 1));
	let next = 0;
	async function worker() { for (let i = next++; i < list.length; i = next++) out[i] = await fn(list[i], i); }
	await Promise.all(Array.from({ length: n }, worker));
	return out;
}

// A standing concurrency gate for work that arrives OVER TIME (not a one-shot list, which is what mapLimit bounds).
// Returns `run(fn)` which resolves to fn()'s result but lets at most `max` invocations run at once; the rest queue in
// arrival order. Like mapLimit, this bounds the CONCURRENCY itself — the only thing that helps against wedged
// filesystem syscalls, whose threads a timeout cannot free — so keeping `max` below the libuv pool size guarantees
// other file work always keeps a thread. `run` always releases its slot, even if `fn` throws (the rejection passes through).
function semaphore(max) {
	const limit = Math.max(1, max | 0 || 1);
	let active = 0; const queue = [];
	const release = () => { active--; const next = queue.shift(); if (next) { active++; next(); } };
	return function run(fn) {
		return new Promise((resolve, reject) => {
			const start = () => { Promise.resolve().then(fn).then((v) => { release(); resolve(v); }, (e) => { release(); reject(e); }); };
			if (active < limit) { active++; start(); } else queue.push(start);
		});
	};
}

// SHA-256 of a string or Buffer, as a Buffer (sha256) or hex string (sha256Hex). For INCIDENTAL hashing only —
// deriving a stable id, filename, port, or cache-invalidation fingerprint, or a value fed to a constant-time
// compare — NEVER a security binding, which builds its own domain-separated signing input elsewhere. One seam so
// the many identical createHash('sha256') one-liners do not drift.
function sha256(data) { return crypto.createHash('sha256').update(data).digest(); }
function sha256Hex(data) { return sha256(data).toString('hex'); }

// The DATA directory is kept OUTSIDE the program folder, in the per-user location each OS reserves for
// application data — so upgrading or deleting the program never touches the user's vaults, keys, or settings, and
// the two have independent lifecycles. The program code lives at ROOT; only data lives here. A `--data-dir <path>`
// argument overrides it (set once at startup via setDataDir), for a portable or custom location.
//   macOS:   ~/Library/Application Support/Vaultonaut
//   Windows: %LOCALAPPDATA%\Vaultonaut  (falls back to %APPDATA%, then the home dir)
//   Linux:   $XDG_DATA_HOME/vaultonaut  (falls back to ~/.local/share/vaultonaut)
function defaultDataDir() {
	const home = os.homedir() || process.cwd(); // homedir is essentially always set; fall back defensively so a path is always returned
	if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', Brand.name);
	if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || process.env.APPDATA || home, Brand.name);
	// Linux/other: the XDG base-directory spec says a relative XDG_DATA_HOME must be IGNORED, so only honor an
	// absolute one; otherwise use the spec default ~/.local/share.
	const xdg = process.env.XDG_DATA_HOME;
	const base = (xdg && path.isAbsolute(xdg)) ? xdg : path.join(home, '.local', 'share');
	return path.join(base, Brand.slug);
}
// Create the data directory if it does not exist yet (first run on a fresh machine, now that data lives outside
// the program folder), OWNER-ONLY. It holds the credential key, settings with encrypted logins, and the integrity
// ledgers, so lock it to 0700 on POSIX at creation AND fix an existing dir's mode — on Linux ~/.local/share is
// commonly world-readable, which would otherwise let another local user enumerate vault folder names and read the
// ledgers. On Windows the per-user %LOCALAPPDATA% location is already owner-scoped. Best-effort and idempotent.
function ensureDataDir() {
	const d = dataDir();
	try { fs.mkdirSync(d, { recursive: true, mode: 0o700 }); } catch (_) {}
	if (process.platform !== 'win32') { try { fs.chmodSync(d, 0o700); } catch (_) {} return; }
	// Windows: the 0700 mode above is a no-op, so set an explicit owner-only NTFS ACL — same treatment runDir gets.
	// The default %LOCALAPPDATA% location already inherits the owner-scoped profile ACL, but a custom --data-dir on a
	// shared or non-profile drive would otherwise inherit that folder's possibly-permissive ACL, exposing the
	// credential key, encrypted logins, and integrity ledgers stored here. icacls is async (no spawnSync on any path),
	// so this is best-effort and fire-and-forget, like the POSIX chmod above; the dir already exists from mkdirSync.
	hardenDir(d).catch(() => {});
}
let dataDirOverride = null;
// Point the data directory at an explicit path (from a --data-dir argument). Call once at startup, before any
// data path is used. Pass a falsy value to clear the override and fall back to the per-OS default.
function setDataDir(p) { dataDirOverride = p ? path.resolve(String(p)) : null; }
function dataDir() { return dataDirOverride || defaultDataDir(); }
// The explicit --data-dir override path, or null when using the per-OS default. Autostart/shortcut installers use
// this to embed --data-dir into the service command ONLY when the user chose a custom dir — a default install
// carries no path, so it always tracks the current default (robust across a version that changes the default).
function dataDirOverridePath() { return dataDirOverride; }
// The engine binary lives under the data directory by default (so a single per-user location holds everything).
// binDir can be pinned INDEPENDENTLY of dataDir — used by the test suite to share one already-downloaded engine
// across tests that each isolate their own data directory, so a test never re-downloads or needs a system rclone.
// Production never sets this, so the engine stays in the data directory.
let binDirOverride = null;
function setBinDir(p) { binDirOverride = p ? path.resolve(String(p)) : null; }
function binDir() { return binDirOverride || path.join(dataDir(), 'bin'); }
function vaultsDir() { return path.join(dataDir(), 'vaults'); } // default home for vault storage
function runDir() { return path.join(dataDir(), 'run'); }     // ephemeral configs
function statePath() { return path.join(dataDir(), 'state.json'); }

// Two-digit zero-padded number, for the log stamp.
function pad(n) { return n < 10 ? '0' + n : '' + n; }

// A compact local timestamp, e.g. "2026-08-29 08:57:14".
function logStamp() {
	const d = new Date();
	return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
		' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function log(msg) { try { console.log(logStamp() + ' ' + msg); } catch (_) {} }
function warn(msg) { try { console.warn(logStamp() + ' ' + msg); } catch (_) {} }

// ---------------------------------------------------------------------------
// Schema versioning for the local sidecar JSON stores (state, settings, the
// rollback ledger, the tamper log). The vault manifest and snapshot record
// carry their own format/version and hard-refuse a newer format; these stores
// are rebuildable local convenience data, so instead of refusing we version
// them softly: stamp a version on write, never lower a newer file's version,
// preserve fields we don't recognize, and warn ONCE if a file was written by a
// newer build — so an older build (a downgrade, or an older CLI beside a newer
// service) can detect the case and never silently clobber newer data.
// ---------------------------------------------------------------------------
const SCHEMA_VERSION = 1;
// The default port the local web interface listens on when none is given. One source so the CLI (`ui`,
// autostart install) and the autostart service can never disagree on it.
const DEFAULT_UI_PORT = 7420;
// The custom header the CLI's owner-IPC client sends and the local API requires, as a simple anti-CSRF check: a
// browser form or a cross-site fetch cannot set a custom header without a passing CORS preflight, which the local
// API does not grant, so only a real same-origin/same-tool caller reaches these routes. Single-sourced here as a
// name/value pair so the sender (OwnerClient) and the checker (the web server) can never drift apart — a mismatch
// would silently 403 every owner-routed mount/unmount.
const OWNER_CSRF_HEADER = 'x-vdisk';
const OWNER_CSRF_VALUE = '1';
const schemaWarned = new Set(); // one warning per store per process, so it never spams
// The version to stamp back onto `obj` for `label` (never below what is already on disk), warning
// once when the on-disk object predates neither — i.e. was written by a NEWER build than this one.
function schemaVersionFor(label, obj) {
	const onDisk = (obj && Number.isInteger(obj.schemaVersion)) ? obj.schemaVersion : 0;
	if (onDisk > SCHEMA_VERSION && !schemaWarned.has(label)) {
		schemaWarned.add(label);
		warn('The ' + label + ' file was written by a newer version of ' + Brand.name + ' (schema v' + onDisk + '; this build understands v' + SCHEMA_VERSION + '). Fields it does not recognize are preserved, not removed.');
	}
	return Math.max(onDisk, SCHEMA_VERSION);
}

function ensureDir(p) { try { fs.mkdirSync(p, { recursive: true }); } catch (_) {} }
function exeName(base) { return process.platform === 'win32' ? base + '.exe' : base; }

// Restrict a directory to the current user. On POSIX this is chmod 0700. On Windows,
// Unix mode bits are a no-op, so we set an explicit owner-only ACL via icacls (there
// is no Node API for NTFS ACLs): remove inherited permissions and grant only the
// current user, with inheritance so new files inside are owner-only too. This is what
// keeps the transient decrypted write buffer and the short-lived engine config from
// being readable by other local accounts. Best-effort and async — it never throws, so
// it can never break an operation, and it is safe to call before the dir exists.
let winUserSid; // cached across calls: the current user's SID, '' if it could not be resolved
function resolveWinSid() {
	return new Promise((resolve) => {
		if (winUserSid !== undefined) return resolve(winUserSid || null);
		try {
			execFile('whoami', ['/user', '/fo', 'csv', '/nh'], { timeout: 10000, windowsHide: true }, (err, stdout) => {
				let sid = null;
				try { const m = /"(S-1-[0-9-]+)"/.exec(String(stdout || '')); if (m) sid = m[1]; } catch (_) {}
				winUserSid = sid || '';
				resolve(sid);
			});
		} catch (_) { winUserSid = ''; resolve(null); }
	});
}

// Returns whether the directory was actually restricted, so callers don't latch a
// "hardened" flag on a silent failure.
async function hardenDir(dir) {
	try { await fsp.mkdir(dir, { recursive: true }); } catch (_) {}
	if (process.platform !== 'win32') {
		try { await fsp.chmod(dir, 0o700); return true; } catch (_) { return false; }
	}
	// Windows: Unix mode bits are a no-op, so set an explicit owner-only NTFS ACL via
	// icacls. Grant to the current user's SID — a bare username can fail to resolve on a
	// domain-joined machine — falling back to the username only if the SID is unavailable.
	let principal = await resolveWinSid();
	if (!principal) { try { principal = os.userInfo().username; } catch (_) { principal = null; } }
	if (!principal) return false;
	const grantee = /^S-1-/.test(principal) ? '*' + principal : principal; // icacls takes a SID prefixed with '*'
	return await new Promise((resolve) => {
		try { execFile('icacls', [dir, '/inheritance:r', '/grant:r', grantee + ':(OI)(CI)F'], { timeout: 15000, windowsHide: true }, (err) => resolve(!err)); }
		catch (_) { resolve(false); }
	});
}

// Run an external command with a bounded timeout, ASYNC so it always yields the event loop (never spawnSync,
// which would freeze every other request while it runs). One definition so the spawn options — the timeout and
// windowsHide — and the result shape live in a single place. It never throws: it resolves { ok, code, stdout,
// stderr } where `ok` means the command exited 0 within the timeout. Use this for probes and best-effort calls.
function runCmd(cmd, args, { timeout = 20000, windowsHide = true } = {}) {
	return new Promise((resolve) => {
		try {
			execFile(cmd, args, { timeout, windowsHide, killSignal: 'SIGKILL' }, (err, stdout, stderr) => { // SIGKILL on timeout so a child that ignores SIGTERM can't leave the probe hanging forever
				resolve({ ok: !err, code: err && typeof err.code === 'number' ? err.code : (err ? 1 : 0), stdout: stdout || '', stderr: stderr || '', error: err || null });
			});
		} catch (e) { resolve({ ok: false, code: 1, stdout: '', stderr: '', error: e }); }
	});
}
// The same runner for steps that must SUCCEED: resolves { stdout, stderr } on exit 0, and rejects with the
// command's error text otherwise (unless ignoreError). Used by install/shortcut steps that want to fail loudly.
async function runCmdOrThrow(cmd, args, { timeout = 20000, ignoreError = false } = {}) {
	const r = await runCmd(cmd, args, { timeout });
	if (!r.ok && !ignoreError) throw new Error(((r.stderr || (r.error && r.error.message) || '')).toString().trim());
	return { stdout: r.stdout, stderr: r.stderr };
}

// Shared timing/process/IO primitives, used everywhere so the contracts live once.

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
// Yield to the event loop so a long CPU pass (hashing, sorting, parsing, building large arrays) runs cooperatively
// instead of as one uninterruptible burst that stalls every request and the health watch. One helper so every
// cooperative loop yields the same way; call it every N iterations of the heavy work.
function yieldToLoop() { return new Promise(r => setImmediate(r)); }

// Resolve `promise`, but reject with a timeout error if it does not settle within ms — used
// to bound filesystem calls on a possibly-unresponsive mount so nothing can ever hang.
function withTimeout(promise, ms) {
	let timer;
	const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timed out after ' + ms + 'ms')), ms); if (timer && timer.unref) timer.unref(); });
	return Promise.race([Promise.resolve(promise), timeout]).finally(() => clearTimeout(timer));
}

// A bounded outbound fetch: aborts the request after `ms` and never leaves a timer pinning the event loop (the timer
// is unref'd). Requires the runtime's built-in fetch; callers guard for its absence and treat a throw (including the
// AbortError a timeout raises) as a failed request. Single-sourced so every outbound request shares one abort + timer
// discipline.
//
// Pass a `consume(res)` callback whenever you READ THE BODY: the abort deadline then covers the body read too, because
// the timer is not cleared until consume resolves. This matters because a fetch resolves as soon as the response
// HEADERS arrive — a hostile or misconfigured endpoint can send headers promptly, then drip the body one byte at a
// time forever. Without consume, the deadline would only bound the connect phase and a slow-drip body could hang the
// caller indefinitely. With consume, the same timer aborts a stuck body read. Returns consume's result. Omit consume
// only when you truly need just the Response object (e.g. to inspect status/headers) and will not read the body here.
async function fetchWithTimeout(url, opts = {}, ms = 10000, consume = null) {
	if (typeof fetch !== 'function') throw new Error('fetch is not available in this runtime');
	const ctrl = new AbortController();
	const timer = setTimeout(() => { try { ctrl.abort(); } catch (_) {} }, Math.max(1, ms));
	if (timer && timer.unref) timer.unref();
	try {
		const res = await fetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
		return consume ? await consume(res) : res;
	} finally { clearTimeout(timer); }
}

// Read an HTTP response body as text, bounded to `cap` bytes, so a hostile or broken endpoint cannot stream
// unbounded data into memory. Returns null when the body is (or declares itself) over the cap, or on any read
// error — the ONE shared implementation for every outbound fetch (update check, breach check), so a fix to the
// ceiling logic lands in one place. Reject a declared oversize before reading a byte, and stream-count so a body
// that lies about (or omits) its length still cannot exceed the cap.
async function readCappedText(res, cap) {
	try {
		const len = Number(res && res.headers && res.headers.get && res.headers.get('content-length'));
		if (Number.isFinite(len) && len > cap) return null;
		if (res && res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
			const chunks = []; let total = 0;
			for await (const chunk of res.body) { total += chunk.length; if (total > cap) return null; chunks.push(Buffer.from(chunk)); }
			return Buffer.concat(chunks).toString('utf8');
		}
		const text = await res.text();
		return Buffer.byteLength(text, 'utf8') > cap ? null : text;
	} catch (_) { return null; }
}

// Does a path exist, answered within a bounded time? A plain stat can hang on a wedged removable or network
// drive, so this races it against a timeout and treats a timeout (or any error) as "not there". Single-sourced
// so the self-check and the folder picker probe removable paths the same safe way.
async function pathExistsBounded(p, ms = 2000) {
	// access(F_OK), not stat: a WinFsp mount can fail stat() on a file that is present, so a pure existence check
	// uses the lighter access() call, which WinFsp answers reliably (the same reason the indexer avoids stat).
	try { await withTimeout(fsp.access(p), ms); return true; } catch (_) { return false; }
}

// A host that stays on THIS machine only: the loopback range (127.0.0.0/8), IPv6 loopback, and the name
// "localhost" (empty counts as loopback — an unset bind defaults to loopback). Single-sourced so every place
// that gates a security decision on "is this local?" agrees, and so the check stays safe: only genuine numeric
// 127.x.x.x literals match, so a DNS name like "127.example.com" can never be mistaken for loopback (which would
// wrongly skip the mandatory login/TLS on an exposed interface, or allow a writable serve to a non-local host).
function isLoopbackHost(host) {
	let a = String(host == null ? '' : host).trim().toLowerCase();
	// A plain IPv4 peer reaches a dual-stack listener (a "--bind ::" server) as an IPv4-mapped IPv6 address such as
	// "::ffff:127.0.0.1"; unwrap that prefix so a same-machine caller is still recognized as loopback there, not just
	// on the default IPv4 bind. The strict numeric test below still applies afterward, so a DNS name can never be
	// mistaken for loopback. Only unwrap when a suffix is actually present, so a malformed bare "::ffff:" is not
	// treated as the empty (unset-bind) loopback case.
	if (a.startsWith('::ffff:') && a.length > 7) a = a.slice(7);
	if (a === 'localhost' || a === '::1' || a === '') return true;
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
	return !!m && m[1] === '127' && m.slice(1).every(o => Number(o) <= 255);
}

// Replace each of `roots` (absolute path prefixes) wherever it appears in `str` with an ellipsis, longest root
// first so a nested root is redacted before its parent. Used to keep absolute filesystem paths out of a message
// shown to a remote caller on an exposed interface, without mangling the rest of the message. Pure and testable.
function redactPaths(str, roots) {
	let s = String(str == null ? '' : str);
	const list = (roots || []).filter(r => typeof r === 'string' && r).sort((a, b) => b.length - a.length);
	for (const r of list) s = s.split(r).join('…');
	return s;
}

// Read a whole file into memory, but ONLY after confirming its size is within `maxBytes` — for files from an
// UNTRUSTED source (a shared vault's plaintext manifest/recovery index, a downloaded/imported archive). A
// hostile file could otherwise be arbitrarily large and spike memory the instant it is read (a no-password
// DoS on a shared vault). Fails closed above the cap instead of reading. `encoding` is optional: pass a string
// encoding (e.g. 'utf8') for text, or omit it for a Buffer. Single-sourced so every untrusted read is bounded
// the same way; a size check is a cheap stat and never blocks a hot path.
async function readFileCapped(p, maxBytes, encoding) {
	let fh = null;
	try {
		fh = await fsp.open(p, 'r');
		const st = await fh.stat();
		if (st.size > maxBytes) throw new Error('This file is larger than the allowed ' + maxBytes + '-byte limit (' + st.size + ' bytes) and was refused: ' + p);
		// Read from the SAME descriptor we just stat'd, for exactly the measured size — so a concurrent writer
		// that grows the file between the stat and the read cannot push the read past the cap (the classic
		// stat-then-read TOCTOU). Asking the fd for a fixed byte count is bounded no matter what happens to the
		// path afterward; a truncation just yields fewer bytes, which we return as-is.
		const buf = Buffer.allocUnsafe(st.size);
		let off = 0;
		while (off < st.size) { const { bytesRead } = await fh.read(buf, off, st.size - off, off); if (bytesRead <= 0) break; off += bytesRead; }
		const out = off === buf.length ? buf : buf.subarray(0, off);
		return encoding ? out.toString(encoding) : out;
	} finally { if (fh) { try { await fh.close(); } catch (_) {} } }
}

// Read and parse a JSON file, moving a CORRUPT file aside instead of silently discarding it. Returns the
// parsed object, or null when the file is missing OR unparseable. On a parse failure of an existing file, if
// `repair` is set the file is renamed to "<path>.corrupt-<ts>" and a warning is logged, so the data is not
// lost silently and the next write starts fresh; other read errors propagate. Pass repair:true ONLY from a
// caller that holds the relevant write lock — never from an unlocked reader, which could otherwise rename a
// file a concurrent write just healed (unlocked readers pass repair:false and simply see "no data"). Shared
// so State, the tamper/rollback ledger, and the tamper log all handle corruption the same, tested way.
// A generous ceiling for these small control files (manifest, state, tamper ledger and log). Each is normally a few
// KB and bounded by its own writer, so this only guards against a pathologically large or corrupt file — reading it
// through the capped reader keeps a giant file from spiking memory or blocking the loop with a huge JSON.parse.
const MAX_JSON_BYTES = 16 * 1024 * 1024;
async function readJsonCorruptAside(p, { repair = false, label = 'data' } = {}) {
	let txt;
	try { txt = await readFileCapped(p, MAX_JSON_BYTES, 'utf8'); }
	catch (e) {
		if (e && e.code === 'ENOENT') return null;
		if (e && e.code) throw e; // a real filesystem error (permissions, I/O) — propagate as before
		// No error code means the size-cap refusal: treat an over-large control file like a corrupt one — move it
		// aside when we hold the write lock so the next write starts clean, and report "no data" rather than read it.
		if (repair) { try { await fsp.rename(p, p + '.corrupt-' + Date.now()); warn('A ' + label + ' file was unreadable (too large) and was moved aside (kept as a .corrupt-* copy); starting fresh.'); } catch (_) {} }
		return null;
	}
	try { return JSON.parse(txt); }
	catch (_) {
		if (repair) { try { await fsp.rename(p, p + '.corrupt-' + Date.now()); warn('A ' + label + ' file was corrupt and was moved aside (kept as a .corrupt-* copy); starting fresh.'); } catch (_) {} }
		return null;
	}
}

// A stale-while-revalidate async cache keyed by string, for values read on a frequently-repeated path (a
// UI poll) from a source that might wedge. get(key) returns the LAST-KNOWN value immediately and refreshes
// in the background via compute(key); at most ONE compute is ever outstanding per key (in-flight dedup), so
// a slow or hung compute pins a single operation — never one per call, which is what would otherwise
// exhaust the thread pool when the source is a wedged drive (Node can't cancel an in-flight fs read, so the
// dedup, not a per-call timeout, is the real bound). The first get for a key waits up to firstWaitMs for
// that initial compute (so a responsive source returns data at once) and never waits again for that key.
// compute MUST resolve (catch internally); a value that stays undefined means it is still running. The map
// holds one small entry per distinct key.
function freshCache(compute, { firstWaitMs = 2500 } = {}) {
	const map = new Map();
	async function get(key) {
		let st = map.get(key);
		if (!st) { st = { value: undefined, inflight: null, awaitedOnce: false }; map.set(key, st); }
		if (!st.inflight) st.inflight = Promise.resolve().then(() => compute(key)).then(v => { st.value = v; }, () => {}).finally(() => { st.inflight = null; });
		if (st.value === undefined && !st.awaitedOnce) { st.awaitedOnce = true; try { await withTimeout(st.inflight, firstWaitMs); } catch (_) {} }
		return st.value;
	}
	// Drop a key's cached entry so the map can't retain one per distinct key (e.g. per vault path) forever on a
	// long-running process — call it when a key is retired (a vault removed). Any compute already in flight simply
	// updates the now-detached old entry and is discarded; the next get(key) starts fresh. Safe to call for an
	// absent key.
	get.evict = (key) => { map.delete(key); };
	return get;
}

// True while a process id still exists (responds to signal 0). Guard non-positive pids: signal 0 to pid 0 targets
// the whole process group (a false "alive"), and a negative pid is a group too — neither is a real child/engine
// pid, so treat them as not-alive. (An EPERM from a live process owned by another user is still reported dead here,
// which is acceptable: every caller passes a pid this app itself spawned and owns.)
function isProcessAlive(pid) { if (!(pid > 0)) return false; try { process.kill(pid, 0); return true; } catch (_) { return false; } }

// Poll an async (or sync) predicate until it returns truthy or the timeout elapses.
// Returns the final boolean. Timer-based — never blocks the event loop.
async function pollUntil(predicate, { timeoutMs, stepMs = 200 } = {}) {
	for (let waited = 0; waited < timeoutMs; waited += stepMs) {
		if (await predicate()) return true;
		await sleep(stepMs);
	}
	return !!(await predicate());
}

// Write JSON atomically: temp file in the same directory + rename, so a reader — or a concurrent writer —
// never sees a half-written file. The rename swaps in the complete new content in one step, leaving either
// the old file or the new one, never a torn mix. Set chmod:true to enforce the mode after rename (defends
// against umask on the create). NOTE: this guarantees ATOMICITY, not power-loss durability — there is no
// fsync before the rename, so an OS crash immediately after it can still leave a zero-length file on some
// filesystems (readers treat that as "no data", which the callers already handle by re-initializing).
// A unique sibling temp path (pid + random, ".tmp" suffix) for an atomic write: two concurrent writers —
// even in different OS processes — never share a temp name, so their in-progress files can't interleave
// into a corrupt result. The ".tmp" suffix is what the recovery folder's stale-temp sweep recognizes.
function uniqueTempPath(base) { return base + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp'; }

// fsync:true makes the write POWER-LOSS DURABLE (flush the data to disk before the rename, and flush the
// rename itself after) — use it for the few files whose loss is unrecoverable, above all the vault manifest,
// which is the ONLY copy of the salt/KDF params. Cross-platform: the file sync works everywhere; a directory
// sync is POSIX-only and simply skipped where the OS rejects it (e.g. Windows). Off by default so ordinary
// hot-path writes keep their speed.
// Atomic temp→destination rename, with a short bounded retry on Windows. There an antivirus scanner or
// indexer can transiently hold the destination open, making the replace throw EPERM/EBUSY/EACCES for a
// moment; a few backed-off retries ride that out. Every other platform (and every other error code) takes
// the single-attempt path unchanged, and the retry is bounded (~1s total) so it can never wedge.
async function renameWithRetry(from, to) {
	if (process.platform !== 'win32') return fsp.rename(from, to);
	for (let i = 0; ; i++) {
		try { return await fsp.rename(from, to); }
		catch (e) { if (i >= 10 || !['EPERM', 'EBUSY', 'EACCES'].includes(e.code)) throw e; await new Promise(r => setTimeout(r, 20 * (i + 1))); }
	}
}
// Best-effort fsync of a path — flush a FILE's data (before an atomic rename, so a power loss cannot leave a
// zero-length or torn file where a good one was) or a DIRECTORY's entries (after a rename, so the new name
// survives). Tries a writable handle first, because flushing a file on Windows needs write access; falls back to
// a read handle for a directory (whose flush is POSIX-only). Never throws: where fsync is unavailable the atomic
// rename still holds and only the durability barrier is skipped.
async function fsyncPath(p) {
	for (const flags of ['r+', 'r']) {
		try { const fh = await fsp.open(p, flags); try { await fh.sync(); } finally { await fh.close(); } return; } catch (_) {}
	}
}

// Build a VBS one-liner that runs `<node> <script> <args>` HIDDEN (no console window) via WScript.Shell, the
// standard scriptable launcher on Windows (so no extra dependency). The node and script paths are wrapped in
// doubled double-quotes (""…""), VBS's own way to put a quote inside a quoted string, so paths with spaces work.
// SHARED by the autostart and desktop-shortcut installers so the subtle quoting lives in ONE place and a fix can
// never land in one and miss the other. The caller passes the already-built args tail (using the same ""
// convention for any embedded path).
function windowsHiddenRunVbs(node, script, args) {
	return 'Set WshShell = CreateObject("WScript.Shell")\r\nWshShell.Run """' + node + '"" ""' + script + '"" ' + args + '", 0, False\r\n';
}
async function writeJsonAtomic(p, obj, { mode = 0o644, chmod = false, fsync = false } = {}) {
	await fsp.mkdir(path.dirname(p), { recursive: true });
	const tmp = uniqueTempPath(p); // unique so concurrent writes to the same file never share a temp
	try {
		if (fsync) {
			const fh = await fsp.open(tmp, 'w', mode);
			try { await fh.writeFile(JSON.stringify(obj, null, 2)); await fh.sync(); } finally { await fh.close(); }
		} else {
			await fsp.writeFile(tmp, JSON.stringify(obj, null, 2), { mode });
		}
		await renameWithRetry(tmp, p);
		if (chmod) { try { await fsp.chmod(p, mode); } catch (_) {} }
		// Flush the rename (the new directory entry) so a crash right after can't lose it. Directory fsync is
		// POSIX-only; on platforms that reject it the atomic rename still holds, only the flush is best-effort.
		if (fsync) { try { const dh = await fsp.open(path.dirname(p), 'r'); try { await dh.sync(); } finally { await dh.close(); } } catch (_) {} }
	} catch (e) { try { await fsp.unlink(tmp); } catch (_) {} throw e; }
}

// A serial queue: each task waits for the previous one to SETTLE before it runs, so their
// read-modify-write sequences can never interleave and lose an update. A task's own error
// propagates to ITS caller, but never wedges the queue for the tasks behind it (the internal
// chain is always kept resolved). Returns a bound run(fn) — the one contract used for the
// state file, the settings file, the rollback ledger, and the mount establishment sequence.
function serialQueue() {
	let chain = Promise.resolve();
	return function run(fn) {
		const result = chain.then(fn, fn);   // start after the previous settles (chain never rejects)
		chain = result.then(() => {}, () => {}); // keep the queue alive regardless of this task's outcome
		return result;
	};
}
// One independent serial queue per key (created on first use), for per-vault serialization where
// different vaults must not block each other. Each key's queue SELF-EVICTS once it has no pending
// tasks, so the map can never grow one dead entry per distinct key (e.g. per vault path) over the
// life of a long-running process — while a key with work in flight always reuses the same queue, so
// serialization is never broken by eviction. The count is decremented after the task settles; a new
// task arriving before that keeps the count above zero and reuses the live queue.
function serialQueueByKey() {
	const queues = new Map();
	return function run(key, fn) {
		let e = queues.get(key);
		if (!e) { e = { q: serialQueue(), pending: 0 }; queues.set(key, e); }
		e.pending++;
		const settle = () => { if (--e.pending === 0 && queues.get(key) === e) queues.delete(key); };
		return e.q(fn).then(v => { settle(); return v; }, err => { settle(); throw err; });
	};
}

// Sanitize a user-supplied sync bandwidth limit before it reaches the engine's argument list. The engine accepts
// a plain rate ("1M", "512k") or an off-peak timetable ("08:00,512k 23:00,off"), so keep only the characters
// those forms use, trim, and cap the length — so nothing odd (or injected) can be passed on. Single-sourced so
// the CLI and the web interface harden this identically.
// Keep the hyphen: the engine's weekday timetable prefix ("Mon-23:00,off") needs it, and validateBwlimit below
// only accepts a leading weekday-with-hyphen, never a bare leading "-", so a value that could look like a flag
// to the engine is rejected there rather than passed through. Stripping it here used to mangle a valid weekday
// spec into one the engine rejects.
function sanitizeBwlimit(s) { return String(s == null ? '' : s).replace(/[^0-9A-Za-z:.,\s-]/g, '').trim().slice(0, 200); }
// Validate a bandwidth limit for the engine's --bwlimit and return the cleaned value, or throw a clear error.
// Accepts a single RATE (a number with an optional B/K/M/G/T/P[i][B] unit, e.g. "512k", "1M", "10MiB") or a
// TIMETABLE of "HH:MM,rate" entries with an optional weekday prefix (e.g. "08:00,512k 23:00,off"). This rejects
// garbage like "fast" up front — where the un-validated value used to be stored and only fail opaquely at sync
// time. Callers handle "off"/"none"/"unlimited"/empty as "no limit" before calling, so those never reach here.
function validateBwlimit(s) {
	const clean = sanitizeBwlimit(s);
	if (!clean) throw new Error('Enter a bandwidth limit like "512k", "1M", or a timetable like "08:00,512k 23:00,off". Use "off" for no limit.');
	// A rate is a number with an optional unit — decimal (k/M/G/T/P) or binary (Ki/Mi/Gi, KiB/MiB), or bytes (b),
	// matching the engine's size-suffix parser. A bandwidth spec is a rate, or an asymmetric upload:download pair
	// (e.g. "10M:1M"), with "off" allowed on either side. A timetable is space-separated "HH:MM,spec" entries.
	const RATE = '\\d+(?:\\.\\d+)?[bkmgtp]?i?b?';
	const spec = '(?:' + RATE + '|off)(?::(?:' + RATE + '|off))?';
	const rate = new RegExp('^' + spec + '$', 'i');                                                            // 512k, 1M, 10MiB, 1Gi, 10M:1M
	const slot = new RegExp('^(?:(?:mon|tue|wed|thu|fri|sat|sun)-)?(?:[01]?\\d|2[0-3]):[0-5]\\d,' + spec + '$', 'i'); // 08:00,512k  Mon-23:00,off  08:00,10M:1M — the time is bounded (00-23:00-59) so a nonsense slot like 25:99 is refused up front, not deferred to the engine (a weekday, if present, carries its hyphen; no bare leading "-")
	for (const tok of clean.split(/\s+/)) {
		if (!rate.test(tok) && !slot.test(tok)) throw new Error('"' + tok + '" is not a valid bandwidth limit. Use a rate like "512k", "1M", or "10MiB" (an asymmetric "upload:download" like "10M:1M" works too), or a timetable like "08:00,512k 23:00,off". Use "off" for no limit.');
	}
	return clean;
}

// Open a URL (or file) in the user's default handler — the system browser for an http(s) URL — cross-platform. This
// is how a WebView-hosted app hands a document to a REAL browser: a packaged desktop WebView cannot open a separate
// window, and an in-app frame is unreliable across the platform WebViews, so the Recovery Kit (which renders and prints
// dependably in a real browser) is opened this way on the desktop app. Fire-and-forget (detached, output ignored) and
// best-effort: returns true if the launcher was spawned, false on any failure so the caller can fall back. The launch
// commands are the platform standards — `open` (macOS), `xdg-open` (Linux), and `start` via cmd (Windows) — so no
// extra dependency or WebView plugin is needed, and the same call works from the CLI service and the desktop app.
function openExternal(url) {
	const plat = process.platform;
	const [cmd, args] = plat === 'darwin' ? ['open', [url]]
		: plat === 'win32' ? ['cmd', ['/c', 'start', '""', '"' + url + '"']] // quoted empty title, then the quoted target, so a URL/path with a space or a cmd metacharacter can't mis-split
		: ['xdg-open', [url]];
	try { const c = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true }); c.on('error', () => {}); c.unref(); return true; }
	catch (_) { return false; }
}

// Free space on the filesystem backing `path`, via statfs — cross-platform and no shell spawn.
// Returns { freeBytes, totalBytes, pctFree } (pctFree is 0–100), or null if it cannot be determined.
async function diskFree(p) {
	try {
		// Bound the statfs: a vault (and so its disk-space check) can live on a removable or network drive that
		// wedges, where an unbounded statfs would block forever and pin a libuv threadpool slot — and this runs
		// per registered vault in the periodic self-check. A timeout returns null (unknown), like any other failure.
		const s = await withTimeout(fsp.statfs(p), 4000);
		const freeBytes = s.bsize * s.bavail;      // bavail = blocks available to an unprivileged user
		const totalBytes = s.bsize * s.blocks;
		return { freeBytes, totalBytes, pctFree: totalBytes > 0 ? (100 * freeBytes / totalBytes) : 100 };
	} catch (_) { return null; }
}

// Split "host", "host:port", or "[ipv6]:port" into { host, port }. Bracket-aware, so an IPv6
// literal (which itself contains colons) is never mistaken for a host:port pair. Falls back to
// defaultPort when no port is present. A bare IPv6 with no brackets and no port is treated as a host.
function splitHostPort(s, defaultPort) {
	const str = String(s || '').trim();
	if (str.startsWith('[')) {
		const i = str.indexOf(']');
		if (i >= 0) { const m = /^:(\d+)$/.exec(str.slice(i + 1)); return { host: str.slice(1, i), port: m ? Number(m[1]) : defaultPort }; }
	}
	const idx = str.indexOf(':');
	if (idx >= 0 && idx === str.lastIndexOf(':')) return { host: str.slice(0, idx), port: Number(str.slice(idx + 1)) || defaultPort };
	return { host: str, port: defaultPort }; // bare host, or a bare IPv6 literal with no port
}

// Is a proposed deletion of `deleted` out of `total` files a SUSPICIOUS mass deletion — the sign of an emptied or
// damaged source rather than an ordinary edit? A TOTAL wipe at any count; 90% or more once there are at least ten
// files; more than half once there are at least twenty. The threshold tightens as the set shrinks, so a small vault
// is still protected from losing almost everything without tripping on routine edits. Single-sourced so the off-site
// backup guard and the mirror source-loss guard stay in exact lockstep — neither more nor less trusting than the other.
function suspiciousMassDeletion(total, deleted) {
	if (!(total > 0) || !(deleted > 0)) return false;
	const frac = deleted / total;
	return deleted === total || (total >= 10 && frac >= 0.9) || (total >= 20 && frac > 0.5);
}

// A per-key failure backoff with a bounded map — one audited implementation shared by every online-guessing gate
// (the desktop login and the mobile pairing endpoint). After `threshold` consecutive failures a key is blocked for
// an exponentially growing, capped delay; a success clears it. The map is kept from growing without bound on an
// exposed interface: once it exceeds `maxEntries` it first drops entries whose backoff has expired, then hard-caps
// by evicting oldest-inserted entries (Map preserves insertion order).
function failureBackoff({ threshold = 5, maxDelayMs = 300000, maxEntries = 5000 } = {}) {
	const map = new Map(); // key -> { count, until }
	return {
		blocked(key, now = Date.now()) { const r = map.get(key); return !!(r && r.until > now); },
		fail(key, now = Date.now()) {
			const r = map.get(key) || { count: 0, until: 0 };
			r.count++;
			if (r.count >= threshold) r.until = now + Math.min(maxDelayMs, 1000 * Math.pow(2, r.count - threshold));
			map.set(key, r);
			if (map.size > maxEntries) {
				for (const [k, v] of map) if (v.until < now) map.delete(k); // drop expired first
				if (map.size > maxEntries) for (const k of map.keys()) { if (map.size <= maxEntries) break; map.delete(k); } // hard cap, oldest-first
			}
			return r;
		},
		clear(key) { map.delete(key); },
	};
}

module.exports = {
	root, appScriptPath, setDesktopApp, isDesktopApp, dataDir, setDataDir, dataDirOverridePath, ensureDataDir, binDir, setBinDir, vaultsDir, runDir, statePath, samePath, pathWithin, resolveThroughSymlinks, pathExistsBounded, isLoopbackHost, redactPaths, sanitizeBwlimit, validateBwlimit, foldPath,
	timingSafeEqual, timingSafeEqualHashed, sha256, sha256Hex, mapLimit, semaphore,
	log, warn, ensureDir, exeName, hardenDir,
	sleep, yieldToLoop, withTimeout, fetchWithTimeout, readCappedText, readFileCapped, readJsonCorruptAside, freshCache, isProcessAlive, pollUntil, writeJsonAtomic, fsyncPath, windowsHiddenRunVbs, uniqueTempPath, renameWithRetry,
	serialQueue, serialQueueByKey, splitHostPort, diskFree, openExternal, runCmd, runCmdOrThrow, suspiciousMassDeletion, failureBackoff,
	SCHEMA_VERSION, schemaVersionFor, DEFAULT_UI_PORT, OWNER_CSRF_HEADER, OWNER_CSRF_VALUE
};
