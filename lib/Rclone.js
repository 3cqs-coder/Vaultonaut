'use strict';
// lib/Rclone.js — thin, focused, fully NON-BLOCKING wrappers around the rclone
// binary. Every child-process call returns a promise (no spawnSync on any hot or
// library path), the mount runs as a detached background child, and waits are
// timer-based polls — nothing ever blocks the Node event loop. This module owns:
//   1. Obscuring a password so it can live in an rclone config (never on argv).
//   2. Writing a short-lived, private (0600) config for a single operation and
//      deleting it as soon as rclone has read it — the password is never persisted
//      to disk beyond that brief window.
//   3. Running rclone (async) and reporting whether a mount point is live.
//
// The encrypted vault on disk holds no secret: it is just a directory of encrypted
// files plus a random per-vault salt. The password exists only in memory and,
// momentarily, inside the ephemeral config.

const fsp = require('fs').promises;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { performance } = require('perf_hooks'); // monotonic clock for time budgets, so a wall-clock jump can't defeat a bounded wait
const { spawn } = require('child_process');
const Common = require('./Common');
const ProcRegistry = require('./ProcRegistry');

// Cap retained stderr for a non-streaming engine call. Error text is for diagnostics, so a few megabytes of head is
// ample; the cap keeps a chatty or hostile error stream from growing the accumulator without bound, matching the
// stdout cap in spawnP.
const MAX_STDERR_BYTES = 4 * 1024 * 1024;

// Path for a mount's remote-control endpoint, as a UNIX DOMAIN SOCKET. Access is
// controlled by the socket file's owner-only permissions — so no password is needed
// (and none is placed on argv or in the environment, which would leak it). Returns
// null on Windows, where we do not use the control endpoint (durability there rests
// on flush-on-close); rclone's unix-socket support there is untested and a bind
// failure would abort the mount. The path is kept short because unix socket paths
// have an ~104-character limit.
async function rcSocketPath() {
	if (process.platform === 'win32') return null;
	// Place the socket inside a per-user owner-only (0700) directory rather than loose in the shared temp dir.
	// rclone creates the socket with the process umask, so under a permissive umask a loose socket could be
	// group/world-connectable for the window before we chmod it — and on a rotating-token cloud mount (which runs
	// the rc server with --rc-no-auth) that would let another local user read the OAuth token via config/get. A
	// 0700 PARENT gates access from birth, regardless of umask, with no window. The dir is verified to be a real
	// directory we own with no group/other access and no symlink, so a squatted path on the shared temp dir is
	// refused (returning null simply means this mount runs without a control endpoint).
	const uid = process.getuid ? process.getuid() : 0;
	const dir = path.join(os.tmpdir(), 'vdisk-rc-' + uid);
	try {
		await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
		await fsp.chmod(dir, 0o700);
		const st = await fsp.lstat(dir);
		if (!st.isDirectory() || st.isSymbolicLink() || (process.getuid && st.uid !== process.getuid()) || (st.mode & 0o077)) return null;
	} catch (_) { return null; }
	const p = path.join(dir, 'vd-' + crypto.randomBytes(6).toString('hex') + '.sock');
	return p.length > 100 ? null : p; // past the unix-socket path length limit -> no endpoint (caller falls back)
}
// Prepare a Windows control endpoint's CREDENTIAL. The engine is told to bind 127.0.0.1:0 (it picks a free
// port itself, atomically — no pre-bind/close race), and the actual port is read back from its log via
// parseRcPort(). A random user/pass means only this process, which holds the credential, can drive the mount's
// rc — mirroring the owner-only unix socket used on macOS/Linux.
function rcTcpEndpoint() { return { user: 'vdisk', pass: crypto.randomBytes(16).toString('hex') }; }
// Read the port rclone actually bound its rc server to, from the mount's log ("Serving remote control on
// http://127.0.0.1:PORT/"). Retries briefly because the line is written during mount startup. Returns
// "127.0.0.1:PORT" or null (in which case the caller simply has no drain channel and falls back to the settle).
async function parseRcPort(logFile, tries = 12) {
	// Tolerant match: the engine is always told to bind loopback (127.0.0.1:0), but accept the localhost and
	// IPv6-loopback spellings and a looser lead-in too, so a future wording change in this one log line can never
	// leave a Windows caching mount with no drain channel (which would force an unmount to defer or lose writes).
	// The port is captured regardless of which loopback host is printed.
	const re = /control on https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]|::1):(\d+)/i;
	for (let i = 0; i < tries; i++) {
		try {
			const m = (await fsp.readFile(logFile, 'utf8')).match(re);
			if (m) return '127.0.0.1:' + m[1];
		} catch (_) {}
		await Common.sleep(150);
	}
	return null;
}
// The `rclone rc <cmd>` CLIENT args for a control endpoint — a unix socket path (macOS/Linux) or a TCP
// descriptor { addr, user, pass } (Windows). Returns null for no endpoint.
function rcClientArgs(endpoint) {
	if (!endpoint) return null;
	if (typeof endpoint === 'string') return ['--unix-socket', endpoint];
	if (endpoint.socket) return ['--unix-socket', endpoint.socket];
	if (endpoint.addr) return ['--url', 'http://' + endpoint.addr + '/', '--user', endpoint.user, '--pass', endpoint.pass];
	return null;
}

// Promise-based spawn used by every short-lived engine call. It resolves with
// { status, stdout, stderr } and never rejects on a non-zero exit (callers inspect
// status), so it composes cleanly with await. Two safety properties come for free
// to all callers because they share this one helper: the process is tracked for
// shutdown cleanup, and it has a timeout so a stuck call can never hang the tool.
function spawnP(bin, args, { input, stdio, timeoutMs = 60000, discardStdout = false, onLine, dropLine, maxOutBytes = 0 } = {}) {
	return new Promise((resolve, reject) => {
		let child;
		const useStdio = stdio || (discardStdout ? ['pipe', 'ignore', 'pipe'] : ['pipe', 'pipe', 'pipe']);
		try {
			child = spawn(bin, args, { stdio: useStdio, windowsHide: true }); // windowsHide: the app runs windowless, so a console-subsystem child would otherwise pop a console window on Windows (stdio redirection does not suppress it)
		} catch (e) { return reject(e); }
		ProcRegistry.track(child);
		let out = '', err = '', timedOut = false;
		const streaming = !!onLine;
		// Streaming mode (used for progress): split on newlines AND carriage returns — the engine's one-line
		// progress overwrites in place with '\r' — feed each complete line to onLine, and accumulate for the
		// result only the lines dropLine does NOT match. That keeps high-frequency progress/stats lines out
		// of the retained stdout/stderr, so the diagnostic tail stays useful and memory can't grow with them.
		let obuf = '', ebuf = '';
		const feed = (chunk, isErr) => {
			let buf = (isErr ? ebuf : obuf) + chunk;
			const parts = buf.split(/\r\n|\r|\n/);
			const rest = parts.pop();
			if (isErr) ebuf = rest; else obuf = rest;
			for (const ln of parts) {
				if (ln) { try { onLine(ln); } catch (_) {} }
				if (!dropLine || !dropLine(ln)) { if (isErr) err += ln + '\n'; else out += ln + '\n'; }
			}
		};
		const timer = setTimeout(() => { timedOut = true; try { child.kill('SIGKILL'); } catch (_) {} }, timeoutMs);
		if (streaming) {
			if (child.stdout) child.stdout.on('data', d => feed(d.toString(), false));
			if (child.stderr) child.stderr.on('data', d => feed(d.toString(), true));
		} else {
			if (child.stdout) child.stdout.on('data', d => { out += d; if (maxOutBytes && out.length > maxOutBytes) { try { child.kill('SIGKILL'); } catch (_) {} } }); // bound the accumulator so a hostile/huge output (e.g. a peer-controlled lease file) can't grow memory unbounded — the truncated result then fails to parse and is treated as absent
			if (child.stderr) child.stderr.on('data', d => { if (err.length < MAX_STDERR_BYTES) err += d; }); // bound stderr like stdout above, so a chatty or hostile error stream can't grow memory unbounded; the head is kept for diagnostics (no kill: a stderr flood is not itself a reason to abort a legitimate long-running op)
		}
		child.on('error', (e) => { clearTimeout(timer); reject(e); });
		child.on('close', (status) => {
			clearTimeout(timer);
			if (streaming) { // flush any trailing partial line into the retained output
				if (obuf && (!dropLine || !dropLine(obuf))) out += obuf;
				if (ebuf && (!dropLine || !dropLine(ebuf))) err += ebuf;
			}
			resolve({ status: timedOut ? -1 : status, stdout: out, stderr: timedOut ? (err + '\n[timed out]') : err });
		});
		// Guard stdin against EPIPE: if the child is killed mid-write (e.g. the timeout handler above
		// SIGKILLs it), the pipe errors — swallow it so it can never surface as an uncaughtException.
		if (input != null && child.stdin) { child.stdin.on('error', () => {}); child.stdin.end(input); }
	});
}

// Obscure a secret for use in an rclone config. rclone's obscuring is reversible
// (not a security boundary) — the real protection is that we never store the
// primary password and keep the config private and short-lived.
async function obscure(bin, secret) {
	const r = await spawnP(bin, ['obscure', '-'], { input: secret });
	if (r.status !== 0) throw new Error('Failed to encode the engine credentials: ' + (r.stderr || r.status));
	return r.stdout.trim();
}
// Reverse of obscure. The engine's obscuring is a fixed, publicly known AES-256-CTR transform (a 16-byte
// IV prefix, base64url, no padding) — not a security boundary — so it can be undone here with no engine
// spawn. Used only to hand a web read capability the DE-OBSCURED salt, so a browser decryptor needs no
// engine. The static key below is rclone's own well-known obscure key.
const OBSCURE_KEY = Buffer.from('9c935b48730a554d6bfd7c63c886a92bd390198eb8128afbf4de162b8b95f638', 'hex');
function reveal(obscured) {
	const buf = Buffer.from(String(obscured || ''), 'base64url');
	if (buf.length < 16) throw new Error('The obscured value is too short to reveal.');
	const iv = buf.subarray(0, 16);
	const d = crypto.createDecipheriv('aes-256-ctr', OBSCURE_KEY, iv);
	return Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString('utf8');
}

// Drive the engine's headless OAuth to obtain a token for a browser-based backend (drive/onedrive/dropbox).
// `rclone authorize <backend> [clientId clientSecret]` starts a one-shot loopback web server, prints a consent
// URL, waits for the browser redirect, then prints the token JSON. We run it with --auth-no-open-browser so the
// APP controls opening the URL (onUrl is called with it), capture the token JSON from stdout, and resolve with
// it. The token is the only long-lived secret; the caller stores it encrypted. Bounded by a timeout so a user
// who never finishes consent cannot leave the process running forever. Returns { token } (a JSON string).
function authorize(bin, backend, { clientId, clientSecret, onUrl, timeoutMs = 300000 } = {}) {
	return new Promise((resolve, reject) => {
		const args = ['authorize', String(backend), '--auth-no-open-browser'];
		if (clientId && clientSecret) { args.push(String(clientId), String(clientSecret)); }
		let child; try { child = spawn(bin, args, { windowsHide: true }); } catch (e) { return reject(e); } // windowsHide: no console window during the OAuth consent flow on Windows
		try { ProcRegistry.track(child); } catch (_) {} // track like spawnP so a shutdown mid-OAuth kills this child (it self-removes on close/error); otherwise it could orphan holding the loopback consent port
		let out = '', err = '', done = false, urlSent = false;
		// Bound both accumulators to a generous tail. The consent URL is printed first and latches into `urlSent`
		// the moment it is seen, and the token JSON is the LAST complete object printed — so keeping only the tail
		// can never lose either, while a flood of output (a chatty or hostile backend) cannot grow memory without
		// bound and the per-chunk scan() below stays bounded instead of re-scanning an ever-growing string.
		const AUTH_MAX_BYTES = 1 << 20; // 1 MiB — the real payload is a few KB; this only caps abnormal volume, never aborts a legitimate flow
		const cap = (s) => (s.length > AUTH_MAX_BYTES ? s.slice(s.length - AUTH_MAX_BYTES) : s);
		const finish = (fn, val) => { if (done) return; done = true; clearTimeout(timer); try { child.kill('SIGKILL'); } catch (_) {} fn(val); };
		const timer = setTimeout(() => finish(reject, new Error('Authorization timed out — no response from the browser. Try connecting again.')), timeoutMs);
		if (timer.unref) timer.unref();
		const scan = () => {
			if (!urlSent) { const m = /(https?:\/\/127\.0\.0\.1:\d+\/auth\?[^\s"']+)/.exec(out + '\n' + err); if (m) { urlSent = true; if (onUrl) { try { onUrl(m[1]); } catch (_) {} } } }
			// The token JSON is a single flat object with a token_type/access_token; grab the last complete one.
			const tm = /\{[^{}]*"(?:access_token|token_type|refresh_token)"[^{}]*\}/g; let last = null, mm;
			while ((mm = tm.exec(out)) !== null) last = mm[0];
			if (last) { try { const t = JSON.parse(last); if (t && (t.access_token || t.refresh_token)) return finish(resolve, { token: last }); } catch (_) {} }
		};
		// Null-guard the pipes and swallow a stream 'error' (e.g. one emitted after the timeout SIGKILLs the child
		// mid-read), so a readable-stream error can never surface as an uncaughtException — the child's own
		// 'error'/'exit' and the timeout already drive completion. Matches the module's spawnP standard.
		if (child.stdout) { child.stdout.on('data', d => { out = cap(out + d.toString()); scan(); }); child.stdout.on('error', () => {}); }
		if (child.stderr) { child.stderr.on('data', d => { err = cap(err + d.toString()); scan(); }); child.stderr.on('error', () => {}); }
		child.on('error', e => finish(reject, e));
		child.on('exit', () => { scan(); if (!done) finish(reject, new Error('Authorization did not complete. ' + (err.trim().split('\n').pop() || ''))); });
	});
}
// Read a (possibly refreshed/rotated) token back out of a config file after a mount has ended, so the rotated
// refresh token is never lost. `rclone config dump` returns every remote as JSON; each backend's `token` field
// is a JSON string. Returns the token string for the named section (or the first OAuth-type section), or null.
async function harvestToken(bin, configPath, sectionName) {
	const r = await spawnP(bin, ['config', 'dump', '--config', configPath], {});
	if (r.status !== 0) return null;
	let dump; try { dump = JSON.parse(r.stdout); } catch (_) { return null; }
	const pick = (sec) => (sec && typeof sec.token === 'string' && sec.token) ? sec.token : null;
	if (sectionName && dump[sectionName]) { const t = pick(dump[sectionName]); if (t) return t; }
	for (const sec of Object.values(dump)) { const t = pick(sec); if (t) return t; }
	return null;
}

// Build ONE crypt remote section under a given name. Guards against config-line injection: a newline in
// any interpolated field could add arbitrary rclone directives to the remote definition, so reject rather
// than silently accept a crafted path or manifest value. Shared by the normal single-remote config and
// the two-remote (old + new) config a key rotation uses to re-encrypt a store in place.
function cryptRemoteSection(name, { cipherDir, passwordObscured, saltObscured, filenameEnc, dirNameEnc, filenameEncoding }) {
	for (const [k, v] of Object.entries({ name, cipherDir, passwordObscured, saltObscured, filenameEnc, filenameEncoding })) {
		if (v != null && /[\r\n]/.test(String(v))) throw new Error('Illegal newline in vault config field "' + k + '".');
	}
	const lines = [
		'[' + name + ']',
		'type = crypt',
		'remote = ' + cipherDir,
		'filename_encryption = ' + (filenameEnc || 'standard'),
		'directory_name_encryption = ' + (dirNameEnc === false ? 'false' : 'true'),
		'password = ' + passwordObscured
	];
	// The byte→name encoding. Default (base32) is left implicit for compatibility; base32768 (for backends that
	// count UTF-16 length, e.g. OneDrive/Dropbox) is emitted so long encrypted names fit. Immutable per vault.
	if (filenameEncoding && filenameEncoding !== 'base32') lines.push('filename_encoding = ' + filenameEncoding);
	if (saltObscured) lines.push('password2 = ' + saltObscured);
	return lines.join('\n') + '\n';
}
// Build the crypt remote definition. The remote is named "vault" throughout.
function buildConfig(opts) { return cryptRemoteSection('vault', opts); }

// Write a private, short-lived config file in an owner-only directory. Caller MUST
// delete it via removeConfig once rclone has consumed it.
let runDirHardened = false;
async function writeEphemeralConfig(text) {
	await fsp.mkdir(Common.runDir(), { recursive: true, mode: 0o700 });
	// Owner-only, incl. an explicit NTFS ACL on Windows where mode bits are a no-op —
	// the config briefly holds the obscured engine secret. Done once per process (the
	// ACL is inherited by the config files created under it), so this stays cheap on a
	// hot path that runs on every mount/list/verify.
	if (!runDirHardened) { runDirHardened = await Common.hardenDir(Common.runDir()); }
	const p = path.join(Common.runDir(), '.cfg-' + crypto.randomBytes(8).toString('hex') + '.conf');
	await fsp.writeFile(p, text, { mode: 0o600 });
	try { await fsp.chmod(p, 0o600); } catch (_) {}
	return p;
}

async function removeConfig(p) { try { if (p) await fsp.unlink(p); } catch (_) {} }

// Crash safety: sweep leftovers in data/run older than a grace window — orphaned
// ephemeral configs (which hold an obscured secret) and stale mount logs — so a
// secret never rots on disk and the directory does not grow without bound. Files
// newer than the window may be in active use by a concurrent operation.
async function sweepStaleConfigs(graceMs = 30000) {
	try {
		const dir = Common.runDir();
		const now = Date.now();
		const entries = await fsp.readdir(dir).catch(() => []);
		for (const name of entries) {
			const isConfig = name.startsWith('.cfg-');
			const isLog = name.startsWith('mount-') && name.endsWith('.log');
			// Per-instance owner-liveness heartbeat files: a running service rewrites its own every health tick
			// (~12s), so one older than the grace below belongs to an instance that is gone — reap it so data/run
			// doesn't grow without bound after hard crashes.
			const isHb = /^uihb-[0-9a-f]+$/.test(name);
			if (!isConfig && !isLog && !isHb) continue;
			const grace = isLog ? Math.max(graceMs, 3600000) : (isHb ? Math.max(graceMs, 300000) : graceMs); // keep logs an hour; reap a heartbeat only after 5 min stale (well past its ~12s refresh)
			const p = path.join(dir, name);
			try { const st = await fsp.stat(p); if (now - st.mtimeMs > grace) await fsp.unlink(p); } catch (_) {}
		}
	} catch (_) {}
}

// Run rclone asynchronously for quick commands (lsf, cat, rcat, version…).
// `input`, when given, is written to rclone's stdin (used by rcat).
async function run(bin, args, { configPath, input, discardStdout, timeoutMs, onLine, dropLine, maxOutBytes } = {}) {
	const full = [];
	if (configPath) full.push('--config', configPath);
	full.push(...args);
	return spawnP(bin, full, { input, discardStdout, timeoutMs, onLine, dropLine, maxOutBytes });
}

// Return the ENCRYPTED on-disk names for a set of plaintext vault filenames. Crypt name encryption is
// deterministic, so these are stable per vault. Used to leave the tool's own metadata blobs out of the
// self-healing recovery parity. Best-effort: returns [] on any failure. `cryptdecode --reverse` prints
// one "<plaintext>\t<encrypted>" line per name.
async function cryptEncodeNames(bin, configPath, plainNames) {
	if (!Array.isArray(plainNames) || !plainNames.length) return [];
	// `rclone cryptdecode` accepts the remote plus a bounded number of filenames per call (it errors
	// with a usage message past its cobra arg limit). Chunk conservatively so any list length works —
	// this keeps the exclude list free to grow (e.g. the cross-platform OS-metadata set) without a caller
	// ever silently getting an empty result because one oversized batch tripped the limit.
	const CHUNK = 8;
	const requested = new Set(plainNames); // validate by STRUCTURE, not by pattern-matching the ciphertext
	const out = [];
	try {
		for (let i = 0; i < plainNames.length; i += CHUNK) {
			const batch = plainNames.slice(i, i + CHUNK);
			const r = await run(bin, ['cryptdecode', '--reverse', 'vault:', ...batch], { configPath, timeoutMs: 15000 });
			if (r.status !== 0) continue; // a bad batch is skipped, not fatal to the rest
			for (const line of String(r.stdout).split(/\r?\n/)) {
				// A success line is exactly "<plaintext>\t<encrypted>" — two whitespace-separated fields whose
				// first is a name we asked for. A failure line ("<plaintext>\tFailed to encrypt …") has more
				// fields and is skipped; and a valid base32 encrypted name is accepted even if it happens to
				// contain letters like "error". (Our plaintext names contain no whitespace, so a 2-field split is safe.)
				const parts = line.trim().split(/\s+/);
				if (parts.length === 2 && requested.has(parts[0]) && parts[1]) out.push(parts[1]);
			}
		}
		return out;
	} catch (_) { return out; }
}

// Run ANY external command (not rclone) with the same tracking + timeout as run().
// Kept separate so `run` stays honestly rclone-only. Used for platform tools like
// taskkill, xattr, and the file-manager opener.
function exec(bin, args, opts) { return spawnP(bin, args, opts); }

// Start a long-lived `rclone mount` as a detached child so it survives the CLI
// process. Returns { pid, logFile }; the caller waits for the mount to go live
// and then removes the ephemeral config. This is inherently non-blocking.
//
// The permission/metadata flags make the mounted volume behave as much like a
// real filesystem as the engine allows: --metadata preserves each file's mode,
// owner, group and timestamps in the encrypted store, and --default-permissions
// makes the kernel enforce access checks from those mode bits. These POSIX
// concepts are only applied off Windows, where the platform driver maps
// ownership its own way.
async function spawnMount(bin, opts) {
	const { configPath, mountpoint, volname, readOnly, vfsCacheMode, cacheDir, rcSocket, rcTcp,
		metadata = false, defaultPermissions = true, allowOther = false, rcNoAuth = false,
		filePerms, dirPerms, uid, gid } = opts;
	const args = ['--config', configPath, 'mount', 'vault:', mountpoint,
		// The cache mode is chosen per vault by the caller. The tool's default is 'writes': files
		// opened for writing are buffered so in-place writes work, while reads stream in memory and
		// are never cached. A "working disk" uses 'full' (reads buffered too, for databases / VM
		// images); 'streaming' uses 'off' (nothing cached). The caller points --cache-dir at a RAM
		// disk for the caching modes, so the buffer never touches the persistent disk.
		'--vfs-cache-mode', vfsCacheMode || 'off',
		// Flush each file to the encrypted store as soon as it is closed, instead of
		// after the multi-second default delay. Combined with the drain-before-
		// unmount step this makes the disk crash-proof: a closed file is durably
		// encrypted, and the write buffer lets rclone resume any interrupted upload on
		// the next mount.
		'--vfs-write-back', opts.vfsWriteBack || '0s',
		'--vfs-cache-max-size', opts.vfsCacheMaxSize || '20G', // bound the write buffer; sized to the RAM disk when one is used, so the engine evicts before it fills
		'--vfs-cache-max-age', opts.vfsCacheMaxAge || '1h',    // evict a flushed write buffer promptly
		'--vfs-cache-poll-interval', opts.vfsCachePollInterval || '1m',
		'--dir-cache-time', opts.cloud ? '5m' : '30s',   // reflect out-of-band changes quickly (cloud listings are expensive → cache longer)
		'--attr-timeout', '1s',      // tested default; higher risks stale size/mtime
		'--poll-interval', '0',      // the local backend cannot poll for changes; avoid a dead timer
		'--use-mmap',                // steadier memory use
		// Bound the long-lived mount log. rclone honors RCLONE_LOG_LEVEL / RCLONE_VERBOSE from the ENVIRONMENT even
		// with an explicit --config, so a user whose shell sets a verbose level would otherwise make this per-mount
		// log grow quickly over a session that stays up for days. Pinning the level on argv overrides any such env
		// (an explicit flag always wins) so growth stays at the normal quiet baseline, and --stats 0 disables the
		// periodic stats printer so it can never contribute regardless of the stats log level. Neither flag touches
		// the log file handle, so this cannot affect the running mount.
		'--log-level', 'NOTICE', '--stats', '0'];
	// A CLOUD-backed store is far less reliable than a local disk, so ride out network blips and slow
	// transfers instead of surfacing an I/O error to the app on the first hiccup: retry low-level and
	// whole operations, allow generous connect/overall timeouts, and read large files in chunks with a
	// growing readahead so seek-heavy media does not refetch from the start. The write buffer (cache mode
	// 'writes'/'full') already retries a failed UPLOAD with backoff; these cover reads and connections.
	if (opts.cloud) args.push(
		'--low-level-retries', '10', '--retries', '3',
		'--timeout', '5m', '--contimeout', '60s',
		'--vfs-read-chunk-size', '128M', '--vfs-read-chunk-size-limit', '2G');
	// Support symlinks so real content copies whole — most importantly macOS app bundles
	// and frameworks, which are full of symlinks (without this, Finder aborts a copy with
	// "Input/output error" / error code -36). The VFS stores each symlink as a small
	// ".rclonelink" file in the encrypted store and presents it as a symlink on the mount;
	// because this tool always mounts with it on, symlinks stay transparent everywhere.
	if (opts.vfsLinks !== false) args.push('--vfs-links');
	if (cacheDir) args.push('--cache-dir', cacheDir);
	// Control endpoint used for the drain-before-unmount flush. On macOS/Linux it is an owner-only unix
	// socket (access gated by file permissions, nothing secret on argv). On Windows, where rclone has no
	// unix-socket support, it is a loopback TCP port protected by a random user/pass so only this process can
	// drive it. The pass is on argv, which on Windows is readable only by the same user (who already owns the
	// mount) and administrators — so it grants no access they do not already have.
	if (rcSocket) {
		args.push('--rc', '--rc-addr', 'unix://' + rcSocket);
		// A "sensitive" rc command (config/get, used to harvest a rotating cloud token on unmount) is refused
		// unless the rc server has auth or --rc-no-auth. The unix socket is owner-only (chmod 0700 right after
		// mount), so access is already gated by file permissions — the same trust boundary as the config file —
		// and --rc-no-auth is safe here. Only enabled for a rotating-token cloud mount that needs the harvest;
		// every other mount keeps the socket to the non-sensitive drain commands, which never required auth.
		if (rcNoAuth) args.push('--rc-no-auth');
	} else if (rcTcp && rcTcp.user) args.push('--rc', '--rc-addr', '127.0.0.1:0', '--rc-user', rcTcp.user, '--rc-pass', rcTcp.pass); // :0 = the engine picks a free port; parseRcPort reads it back; its user/pass auth already permits config/get on Windows
	if (volname) args.push('--volname', volname);
	if (readOnly) args.push('--read-only');
	if (metadata) args.push('--metadata');
	if (process.platform === 'win32') {
		// Restrict the mounted drive to its owner so other local accounts cannot read
		// the decrypted contents.
		args.push('-o', 'FileSecurity=D:P(A;;FA;;;OW)');
	} else {
		if (defaultPermissions) args.push('--default-permissions');
		if (allowOther) args.push('--allow-other');
		if (filePerms) args.push('--file-perms', String(filePerms));
		if (dirPerms) args.push('--dir-perms', String(dirPerms));
		if (uid != null) args.push('--uid', String(uid));
		if (gid != null) args.push('--gid', String(gid));
	}
	// macOS/FUSE-T only: choose FUSE-T's transport backend. Its default NFS backend can fail a large
	// write intermittently with an I/O error on some macOS versions; the 'smb' backend uses FUSE-T's
	// SMB transport instead, which some setups find reliable where NFS is not. Only meaningful when
	// FUSE-T is the driver (fusetLib set); ignored on macFUSE/other platforms.
	if (process.platform === 'darwin' && opts.fusetLib && opts.fuseBackend === 'smb') args.push('-o', 'backend=smb');
	await fsp.mkdir(Common.runDir(), { recursive: true, mode: 0o700 });
	// Unique, freshly-truncated log per mount attempt, so diagnostics never show a
	// stale failure from an earlier run at the same mount point.
	const safe = path.basename(mountpoint).replace(/[^A-Za-z0-9_.-]/g, '_');
	const logFile = path.join(Common.runDir(), 'mount-' + safe + '-' + crypto.randomBytes(4).toString('hex') + '.log');
	const out = fs.openSync(logFile, 'w');
	const spawnOpts = { detached: true, stdio: ['ignore', out, out], windowsHide: true }; // windowsHide so the long-lived detached mount engine never leaves a console window open on Windows
	// Point THIS engine process at FUSE-T on macOS. The FUSE library inside rclone
	// (cgofuse) selects its driver only via this variable or a fixed search order in
	// which macFUSE always wins — there is no command-line flag for it. Setting it here,
	// on this one child process, makes our vaults use FUSE-T (so macOS Finder copies,
	// which write extended attributes rclone itself does not implement, succeed) while
	// leaving macFUSE installed and untouched for the user's other apps. This is the sole,
	// deliberate exception to the project's "no environment variables" rule: it carries a
	// library PATH — not configuration and not a secret — and no CLI alternative exists.
	if (process.platform === 'darwin' && opts.fusetLib) {
		spawnOpts.env = Object.assign({}, process.env, { CGOFUSE_LIBFUSE_PATH: opts.fusetLib });
	}
	let child;
	try { child = spawn(bin, args, spawnOpts); }
	catch (e) { try { fs.closeSync(out); } catch (_) {} throw e; } // spawn can throw SYNCHRONOUSLY (bad opts/args) before the child dups the fd; close the parent's copy so a repeated failure can't leak fds on the long-running service
	// A detached child with no 'error' listener would throw an uncaughtException on a
	// spawn failure (bad path, permissions), which would tear the host process down.
	child.on('error', (e) => { try { fs.appendFileSync(logFile, '\nspawn error: ' + (e && e.message) + '\n'); } catch (_) {} });
	child.unref();
	try { fs.closeSync(out); } catch (_) {} // the child dup'd the fd; close the parent's copy so the long-running UI never leaks fds
	return { pid: child.pid, logFile };
}

// Stat a path for its device id, with a timeout so a hung (unresponsive) mount cannot block us forever. Returns
// the numeric dev; null if the path is missing; the string 'stale' for a dead FUSE mount whose server is gone
// (ENOTCONN/ESTALE/ETIMEDOUT — the path still exists in the mount table, so callers treat it as mounted and clear
// it); or the string 'timeout' if the stat did not return in time.
// De-dupe the RAW stat per path (same reasoning as mountResponds below): withTimeout bounds the RESULT, not the
// underlying stat(2), and a wedged mount's stat never returns — it holds a libuv threadpool slot (only 4 by
// default) until the OS gives up. Concurrent callers for the SAME path therefore SHARE one in-flight stat, so a
// wedged mount pins ONE slot no matter how often it is probed, and every caller still gets a result (they each
// apply their own timeout to the shared, already-classified promise). The entry clears when the syscall settles.
const statDevInflight = new Map(); // path -> the raw fsp.stat promise still pending (the real slot holder)
function statDev(p, timeoutMs = 4000) {
	let raw = statDevInflight.get(p);
	if (!raw) {
		raw = fsp.stat(p);
		statDevInflight.set(p, raw);
		raw.then(() => {}, () => {}).finally(() => { statDevInflight.delete(p); }); // clear only when the SYSCALL itself settles
	}
	// Classify the stat — the error handler returns a value, so `classified` never rejects:
	// ENOTCONN = a dead FUSE mount whose server is gone (the path still exists in the mount table);
	// report it as 'stale' so callers treat it as mounted and clear it, rather than as "not mounted"
	// (which would skip cleanup). Then bound it with the shared timeout helper — a timeout is the
	// only rejection that can reach the catch, so it maps cleanly to 'timeout'.
	const classified = raw.then(
		s => s.dev,
		(e) => (e && (e.code === 'ENOTCONN' || e.code === 'ESTALE' || e.code === 'ETIMEDOUT')) ? 'stale' : null);
	return Common.withTimeout(classified, timeoutMs).catch(() => 'timeout');
}

// Is a path (or drive letter, on Windows) currently a live mount? Pure Node — no
// external command: a path is a mount point when its device id differs from its
// parent's. This works identically on every platform and sidesteps the quirks of
// parsing the platform mount table (path escaping, symlink canonicalization).
async function isMounted(mountpoint, timeoutMs = 4000) {
	if (process.platform === 'win32') {
		// Bounded async probe, not fs.existsSync: a wedged/unresponsive network drive letter can make the
		// synchronous call block the whole event loop indefinitely, which would violate the never-freeze
		// invariant on a path reachable from user requests. Only a definitively-absent drive (ENOENT) reads as
		// not mounted; an unresponsive one — a reject with any other error, or a timeout — reads as mounted, so
		// the caller tears it down, exactly as the POSIX branch treats a stale/timed-out mount. Reuses the shared
		// mountProbeCall (access + drive-letter normalization) so detection and the Watchdog agree on one probe.
		const probe = mountProbeCall(mountpoint).then(() => true, (e) => !(e && e.code === 'ENOENT'));
		return Common.withTimeout(probe, timeoutMs).catch(() => true);
	}
	const dev = await statDev(mountpoint);
	if (dev === 'timeout' || dev === 'stale') return true; // present but unresponsive/dead -> treat as mounted so it gets cleared
	if (dev === null) return false;                         // path missing -> not mounted
	const parentDev = await statDev(path.dirname(mountpoint));
	if (parentDev === 'timeout' || parentDev === 'stale' || parentDev === null) return true;
	return dev !== parentDev;
}

// Confirm a unix socket has a live listener by connecting to it (no data sent). Pure Node — no
// child process. Resolves true if the connection is accepted, false on a missing/refused socket
// or timeout. This proves a mount's ORIGINAL engine is still running.
function socketListening(sockPath, timeoutMs = 1500) {
	return new Promise((resolve) => {
		let settled = false;
		const finish = (v) => { if (settled) return; settled = true; clearTimeout(timer); try { sock.destroy(); } catch (_) {} resolve(v); };
		const sock = net.connect(sockPath);
		sock.on('connect', () => finish(true));
		sock.on('error', () => finish(false)); // ENOENT (socket gone) / ECONNREFUSED (nothing listening)
		const timer = setTimeout(() => finish(false), timeoutMs);
		if (timer.unref) timer.unref();
	});
}

// Windows: the image (executable) name of a running pid, lowercased, or null if it can't be read.
// Used to confirm a live pid is actually our engine before killing it, since Windows has no
// per-mount control socket. tasklist is a built-in, so this is dependency-free.
async function windowsImageName(pid) {
	try {
		const r = await spawnP('tasklist', ['/FI', 'PID eq ' + pid, '/FO', 'CSV', '/NH'], { timeoutMs: 5000 });
		const m = r.status === 0 && r.stdout && r.stdout.match(/^"([^"]+)"/); // first CSV field is the image name
		return m ? m[1].toLowerCase() : null;
	} catch (_) { return null; }
}

// A bounded probe of a mountpoint: true only if it answers promptly (the drive works). withTimeout bounds the
// RESULT, not the underlying syscall — a wedged mount's access() never returns and holds a libuv threadpool slot
// (only 4 by default) until the OS gives up. So DEDUPE by mountpoint on the RAW syscall: while a prior probe on
// this mount is still pending, report "not responding" instead of launching another. This caps a wedged mount
// at ONE leaked slot no matter how often the health tick probes it, so repeated ticks can never exhaust the
// pool and stall every other filesystem operation (the never-freeze invariant).
// The ONE filesystem call every mount-liveness check makes: a bare access() of the mount root, normalized for a
// Windows drive letter ("X:" is drive-RELATIVE, so probe "X:\"). access() (GetFileAttributes on Windows) is used
// rather than stat(), because a WinFsp directory mount answers access() but can FAIL the heavier
// GetFileInformationByHandle that stat() issues — which made a perfectly healthy Windows drive read as "not
// responding". A healthy mount answers in milliseconds; a wedged one never returns, so each caller bounds this
// with its own timeout. Returns the RAW promise so the caller owns dedupe and timeout. Single-sourced so the
// responsiveness probe here, the Windows mount-detection in isMounted, and the Watchdog all agree on one primitive.
function mountProbeCall(mp) {
	const root = (process.platform === 'win32' && /^[A-Za-z]:$/.test(String(mp))) ? mp + '\\' : mp;
	return fsp.access(root);
}

const mountProbeInflight = new Map(); // mountpoint -> the raw access() promise still pending (the real slot holder)
async function mountResponds(mp) {
	if (!mp) return false;
	if (mountProbeInflight.has(mp)) return 'pending'; // a prior probe's syscall hasn't returned yet — DISTINCT from a definite failure, so a concurrent caller doesn't misread it as "dead" and force-release a healthy mount
	const raw = mountProbeCall(mp);
	mountProbeInflight.set(mp, raw);
	raw.then(() => {}, () => {}).finally(() => { mountProbeInflight.delete(mp); }); // clear only when the SYSCALL itself settles
	try { await Common.withTimeout(raw, 3000); return true; } catch (_) { return false; }
}

// Refresh the mtime of each live mount's control socket so an OS temp-file cleaner does not delete
// it out from under a healthy long-running engine. Best-effort; never throws.
async function touchSockets(mounts) {
	const now = new Date();
	await Promise.all((Array.isArray(mounts) ? mounts : []).map(async (m) => {
		if (m && m.rcSocket) { try { await fsp.utimes(m.rcSocket, now, now); } catch (_) {} }
	}));
}
// True only if the ORIGINAL engine process for a mount is still running — NOT merely that some
// process holds its (possibly recycled) pid. A pid alone is unsafe: the OS can reuse a dead
// engine's pid for an unrelated process, which would make a liveness check lie and, worse, make a
// force-unmount SIGKILL that innocent process. On Unix each engine listens on a unique per-mount
// control socket, so a successful connect proves identity — a reused pid would not be listening.
// On Windows there is no socket, so we compare the pid's image name against the one recorded at
// mount: if it no longer matches, the pid was recycled by an unrelated process and is NOT ours.
async function engineAlive(entry, mountProbe) {
	if (!entry || !entry.pid) return false;
	if (!Common.isProcessAlive(entry.pid)) return false; // pid gone -> definitely not running
	if (entry.rcSocket) {
		if (await socketListening(entry.rcSocket)) return true; // socket answers -> definitely OURS, alive
		// The socket did not answer, but the pid is alive. The control socket lives in the OS temp
		// directory and its mtime is never refreshed, so a long-running mount's idle socket can be
		// deleted by a temp-file cleaner (macOS ~3 days, systemd-tmpfiles ~10) while the engine is
		// perfectly healthy. Concluding "dead" here would force-release a working drive and its write
		// cache. So corroborate with the mount itself: if OUR mountpoint still answers a bounded stat,
		// this live pid is our engine (the socket was merely reaped) and it is alive.
		// If the caller ALREADY probed the mountpoint (the Watchdog does, under its own outstanding-probe
		// cap), reuse that result instead of issuing a SECOND stat on the same possibly-wedged mount — a
		// redundant stat would pin an extra libuv threadpool slot per wedged mount, uncounted by that cap,
		// so two wedged mounts could exhaust the default pool. 'ok' means the mount answered (ours/alive);
		// anything else means it did not answer this pass.
		if (mountProbe !== undefined) return mountProbe === 'ok';
		const r = await mountResponds(entry.mountpoint);
		return r === 'pending' ? true : r; // a concurrent probe is still in flight AND the pid is alive -> assume ours/alive rather than force-releasing a healthy mount
	}
	if (process.platform === 'win32' && entry.image) {
		let img = await windowsImageName(entry.pid);
		// A transient tasklist hiccup (busy system, momentary access error) returns nothing for a pid that IS ours.
		// Retry once after a short pause before concluding — otherwise a recycled pid (our engine died, the OS reused
		// its number) whose image simply couldn't be read this instant would be treated as our still-running engine,
		// and pruneDeadMounts would skip a genuinely dead mount until tasklist next answers.
		if (!img) { await Common.sleep(300); img = await windowsImageName(entry.pid); }
		if (img) return img === String(entry.image).toLowerCase(); // decisive: matches our engine or not
		// Still no answer after a retry — fall back to pid-alive rather than block recovery of our own engine.
	}
	return true;
}

// Wait for one of three outcomes so a failed mount is detected immediately instead
// of blocking for the whole timeout: 'mounted' (success), 'exited' (the engine
// process died before mounting — e.g. a transient "device busy"), or 'timeout'.
// This keeps mount retries fast and reliable.
async function waitForMountOrExit(mountpoint, pid, timeoutMs = 15000) {
	const step = 250;
	for (let waited = 0; waited < timeoutMs; waited += step) {
		if (await isMounted(mountpoint)) return 'mounted';
		if (!Common.isProcessAlive(pid)) return (await isMounted(mountpoint)) ? 'mounted' : 'exited';
		await Common.sleep(step);
	}
	return (await isMounted(mountpoint)) ? 'mounted' : 'timeout';
}

// Run one `rclone rc <cmd>` against a mount's control endpoint. Returns the run() result, or null when there is
// no engine/endpoint to talk to. Shared by drain() and rcQuit() so the client-args resolution lives in one place.
async function rcCall(bin, endpoint, cmd, timeoutMs = 2500) {
	const client = rcClientArgs(endpoint);
	if (!bin || !client) return null;
	return run(bin, ['rc', ...client, cmd], { timeoutMs });
}

// Read one remote's live, in-memory config from a running mount via its control endpoint — used on unmount to
// harvest a rotating cloud token (the engine holds the current token in memory even though the on-disk config was
// deleted after startup). config/get is a "sensitive" rc command, so the mount must have been started with either
// auth (the Windows loopback TCP endpoint) or --rc-no-auth (the owner-only unix socket). Returns the parsed
// section object (e.g. { type, token, drive_id, … }) or null on any failure — callers treat it as best-effort.
async function rcConfigGet(bin, endpoint, name, timeoutMs = 8000) {
	const client = rcClientArgs(endpoint);
	if (!bin || !client) return null;
	const r = await run(bin, ['rc', ...client, 'config/get', 'name=' + name], { timeoutMs });
	if (!r || r.status !== 0) return null;
	try { return JSON.parse(r.stdout || '{}'); } catch (_) { return null; }
}

// Wait until every buffered write has fully reached the encrypted store, before tearing a mount down. This is
// the durability guarantee: no unmount primitive flushes for us — an OS unmount, a signal, and rc core/quit all
// run rclone's VFS.Shutdown, which CANCELS an in-flight write-back rather than finishing it — so tearing down
// early either orphans a full-size ".partial" (hard kill, no rename) or discards the file (core/quit, cancel).
//
// rclone reports pending work through TWO independent channels, and a large write shows up in only one of them,
// so we watch both and wait for both to be idle:
//   - vfs/stats diskCache.uploads{InProgress,Queued}: the write-back queue, populated when a file is CLOSED.
//   - core/stats transferring: an in-flight copy to the backend. A large sequential write streams straight
//     through as a transfer and never raises the write-back counters (and diskCache.bytesUsed lags a minute,
//     so it is useless as a signal) — this is the channel that catches a multi-gigabyte file mid-flush.
//
// Returns one of: 'drained' (both channels CONFIRMED idle, or there was nothing to talk to) — safe to tear down
// and wipe the cache; 'engine-gone' (the engine exited on its own mid-wait) — safe to tear down, but it did NOT
// flush cleanly, so an on-disk cache may hold replayable writes and must be PRESERVED; or false (did not settle
// within timeoutMs) — the caller DEFERS the unmount rather than lose data. onProgress(pending) is called while
// busy. A failed/timed-out rc call is treated as "still busy", NEVER as idle — a momentary stall of the control
// channel while the engine is alive must never be mistaken for "flushed" (that would tear down mid-write and
// lose data); only the pid actually being gone ends the wait early.
//
// The budget is REAL elapsed time, not a fixed poll count: each poll may also spend up to two rc-call timeouts,
// so counting only the sleeps would let a stalled-but-alive channel run many times past timeoutMs.
//
// Either channel can read idle for an instant in the HAND-OFF WINDOW right after a file closes — dirty on disk
// but not yet handed to the write-back queue or the transfer — so a single idle reading is not trusted: both
// must read idle on several CONSECUTIVE polls, which rides out that window yet still returns promptly when truly idle.
async function drain(bin, endpoint, entry, timeoutMs = 300000, onProgress) {
	if (!bin || !rcClientArgs(endpoint)) return 'drained'; // no way to talk to the engine — caller handles the fallback
	const pid = entry && entry.pid;
	const engineGonePid = () => pid != null && !Common.isProcessAlive(pid);
	// Measure the budget and the rc-unreachable window on the MONOTONIC clock, so a backward wall-clock jump (an NTP
	// correction, a manual change, a VM/snapshot restore) during the drain can't defeat the timeout and park the
	// unmount far past its bound — the same reason the health tick and dead-man timer use performance.now().
	const step = 200; let stableIdle = 0, rcDownSince = 0; const start = performance.now();
	while (performance.now() - start < timeoutMs) {
		const vs = await rcCall(bin, endpoint, 'vfs/stats');
		const cs = await rcCall(bin, endpoint, 'core/stats');
		if (engineGonePid()) return 'engine-gone'; // the engine exited on its own mid-wait — nothing more to flush, but not a clean flush
		// A recycled pid — the engine died and the OS reused its number for an unrelated live process — keeps
		// engineGonePid() false, which would otherwise loop the whole timeout before an interactive unmount gives up.
		// When the rc channel has been unreachable for a sustained run, corroborate with the identity-aware check
		// (control socket + our own mountpoint): a genuinely dead engine is then reaped promptly, while a healthy
		// engine whose rc merely stalled for a moment answers on the mountpoint and is never torn down early.
		const rcReachable = (vs && vs.status === 0) || (cs && cs.status === 0);
		if (rcReachable) rcDownSince = 0; else if (!rcDownSince) rcDownSince = performance.now();
		if (rcDownSince && performance.now() - rcDownSince > 15000 && entry && !(await engineAlive(entry))) return 'engine-gone';
		let busy = false, pending = 0;
		// vfs/stats: the write-back queue. A failed or unparseable call is "unknown", i.e. busy — never idle. A
		// well-formed reply with no diskCache key (a future rclone that renamed it) is not busy — core/stats covers it.
		if (!vs || vs.status !== 0) busy = true;
		else { try { const dc = JSON.parse(vs.stdout).diskCache; if (dc && typeof dc === 'object') pending += (dc.uploadsInProgress || 0) + (dc.uploadsQueued || 0); } catch (_) { busy = true; } }
		// core/stats: in-flight transfers (the channel a large streamed write shows up on). A failed or unparseable
		// call is busy, so a transient stall is never read as "no transfers". When the engine is idle rclone OMITS
		// the `transferring` key entirely, so an absent key correctly means zero active transfers — not busy.
		if (!cs || cs.status !== 0) busy = true;
		else { try { const j = JSON.parse(cs.stdout); if (Array.isArray(j.transferring)) pending += j.transferring.length; } catch (_) { busy = true; } }
		if (busy || pending > 0) { stableIdle = 0; if (onProgress && pending > 0) onProgress(pending); }
		else if (++stableIdle >= 6) return 'drained'; // both channels idle across ~1.2s of polls — past the close hand-off, truly flushed
		await Common.sleep(step);
	}
	return false;
}

// Ask the engine to quit gracefully over its rc control channel (WINDOWS teardown only). core/quit runs rclone's
// clean shutdown, which releases the WinFsp volume so the next mount does not collide with a leftover ("Vault (2)").
// It must be called ONLY after drain() has confirmed the write-back is flushed — core/quit cancels any still-in-
// flight upload — and never on macOS FUSE-T, where core/quit's self-unmount cannot complete and the process hangs.
// Bounded by run()'s timeout; returns whether the request was accepted.
async function rcQuit(bin, endpoint) {
	const r = await rcCall(bin, endpoint, 'core/quit', 6000);
	return !!r && r.status === 0;
}

// Best-effort unmount for the current platform (async).
//
// There is no Node API for unmount(2), so this must invoke the platform tool — but every
// attempt is STRICTLY time-bounded (6s) so a single call that blocks can never stall the
// teardown: the next, stronger option runs almost immediately. This bound is what makes
// recovery from a wedged mount always possible in place, so a stuck vault never requires a
// reboot.
//
// The macOS mount is a local NFS server (FUSE-T). A plain `umount`/`diskutil unmount` of an
// NFS mount whose server has stopped responding can itself hang, so on a forced teardown we
// go straight to the force/lazy releases, which drop the kernel's NFS client even when the
// server is gone; on Linux the lazy `-uz`/`-l` detaches do the same. `force` reorders those
// releases to the front (for a stuck or dead-engine mount); the graceful order is kept for a
// normal unmount, where the engine has usually already unmounted itself and this is a no-op.
// force: prefer the forced/lazy releases first (recover a stuck mount). gracefulOnly: use ONLY
// the graceful releases and never the forced/lazy ones — so a busy vault is left mounted rather
// than force-detached (used by auto-lock / panic lock, which must never interrupt active use).
async function unmount(mountpoint, { force = false, gracefulOnly = false } = {}) {
	const graceful = [], forced = [];
	if (process.platform === 'darwin') {
		graceful.push(['umount', [mountpoint]], ['diskutil', ['unmount', mountpoint]]);
		forced.push(['diskutil', ['unmount', 'force', mountpoint]], ['umount', ['-f', mountpoint]]);
	} else if (process.platform === 'linux') {
		// fusermount3 (fuse3) is what modern rclone uses; fall back to fuse2's fusermount and
		// umount, then to LAZY detaches, which free the mount point even for a busy or
		// dead-server mount so recovery and a later remount are never blocked.
		graceful.push(['fusermount3', ['-u', mountpoint]], ['fusermount', ['-u', mountpoint]], ['umount', [mountpoint]]);
		forced.push(['fusermount3', ['-uz', mountpoint]], ['fusermount', ['-uz', mountpoint]], ['umount', ['-l', mountpoint]]);
	}
	const attempts = gracefulOnly ? graceful : (force ? [...forced, ...graceful] : [...graceful, ...forced]);
	for (const [cmd, args] of attempts) {
		try { const r = await spawnP(cmd, args, { stdio: ['ignore', 'ignore', 'ignore'], timeoutMs: 6000 }); if (r.status === 0) return true; } catch (_) {}
	}
	// On Windows (and as a fallback elsewhere) the mount ends when the rclone
	// process exits; the caller handles that by terminating the recorded pid.
	return false;
}

module.exports = {
	obscure, reveal, authorize, harvestToken, buildConfig, cryptRemoteSection, writeEphemeralConfig, removeConfig, sweepStaleConfigs, run, exec, cryptEncodeNames, rcSocketPath, rcTcpEndpoint, rcClientArgs, parseRcPort, drain, rcQuit, rcConfigGet,
	spawnMount, isMounted, mountProbeCall, engineAlive, touchSockets, waitForMountOrExit, unmount
};
