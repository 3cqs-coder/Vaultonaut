'use strict';
// lib/Logger.js — diagnostic logging to daily-rotated files, so a long-running service (headless on a server, or the
// desktop app with no console) always leaves a trail even when its stdout goes nowhere. Common.log / Common.warn route
// their already-formatted, already-redacted line through here; nothing else writes log files.
//
// Design goals the whole file honors:
//   • NON-BLOCKING hot path: every line goes to a buffered per-day append stream (Node buffers the write), so a log
//     call never waits on disk. The only synchronous work is a one-time mkdir when the date rolls over (once a day).
//   • BEST-EFFORT: it never throws into a caller and never crashes the process — a disk error just drops the line and
//     the next write reopens the stream.
//   • CROSS-PLATFORM: files live under the per-user data directory (Common.logsDir), addressed with path.join; the only
//     retention signal is file mtime, which every platform provides.
//   • REUSE: the data-dir resolution and the secret-shape list are the single source used by the console path too
//     (Common.log calls redact() from here), so console, file, and any viewer are scrubbed by one set of rules.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');

const RETENTION_DAYS = 30;   // prune daily log files older than this — enough to diagnose, bounded so a server never fills
const RING_MAX = 1000;       // recent lines kept in memory for a live viewer (bounded; this lives for the whole process)
const MAX_PENDING_BYTES = 4 * 1024 * 1024; // slow-disk backpressure: DROP lines rather than let the write buffer grow without bound
const WRITE_FAIL_COOLDOWN_MS = 30 * 1000;  // after a stream write error, stop retrying the file this long so a failing disk never turns per-line writes into per-line reopen/mkdir/prune churn

const ring = [];             // { t, line } recent entries, bounded by RING_MAX
const subscribers = new Set(); // fn(entry) — a realtime viewer (e.g. the web UI) subscribes here

// PERSISTENT file logging is OPT-IN and OFF by default. A timestamped on-disk record of which vault opened and when it
// changed is itself a forensic artifact — it would let anyone reading the log files reconstruct what a vault was used
// for and when, which defeats the point of an encrypted, no-trace vault. So nothing is written to disk unless the user
// deliberately turns on diagnostics (setFileLogging(true), wired to a setting/flag). The in-memory ring still captures
// recent lines for a LIVE viewer during the session — that is RAM only, never persisted, and gone when the process
// exits, so it leaves no forensic trace. The console is unaffected (ephemeral in a terminal; a service manager that
// redirects it is the operator's own choice).
let fileEnabled = false;
function setFileLogging(on) { fileEnabled = !!on; if (!fileEnabled && stream) { try { stream.end(); } catch (_) {} stream = null; streamDay = ''; } }
function isFileLogging() { return fileEnabled; }

// The per-user logs directory, resolved LAZILY: Common requires this module at load, so requiring Common back at load
// time would be a cycle. By the time any log line is written, Common is fully loaded and cached, so this is safe.
function logsDir() { try { return require('./Common').logsDir(); } catch (_) { return null; } }

// ── Secret redaction (single choke point) ──────────────────────────────────────────────────────────────────────────
// No line — file, console, or viewer — may leak a credential, whatever a caller passed. Conservative (real secret
// shapes only) so ordinary text and vault paths are untouched, and gated by a cheap trigger so the hot path stays free.
// The trigger also fires on the JWT prefix (eyJ) and on any long continuous token run, so a label-free secret — a bare
// JWT, a raw key, a base64/hex blob with no adjacent keyword — still reaches the shape-based patterns below. A 40+ char
// unbroken run does not occur in the host vault paths, counts, or error messages this logger otherwise records, so the
// gate stays cheap and false-positive-free for ordinary lines.
const SECRET_TRIGGER = /pass|secret|token|key|bearer|authorization|:\/\/|seed|mnemonic|recovery|eyJ|[A-Za-z0-9_-]{40,}/i;
const REDACTIONS = [
	[/\b(bearer\s+)[\w.\-]+/gi, '$1[redacted]'],                                                         // Authorization: Bearer <token>
	[/\b(basic\s+)[A-Za-z0-9+/=]{8,}/gi, '$1[redacted]'],                                                // Authorization: Basic <base64>
	[/([a-z][a-z0-9+.\-]*:\/\/[^/\s:@]+:)[^/\s:@]+@/gi, '$1[redacted]@'],                                // user:pass@host in a URL
	[/([?&](?:api[_-]?key|apikey|access[_-]?token|token|password|secret|auth)=)[^&\s"']+/gi, '$1[redacted]'], // ?token=… query params
	[/("(?:password|passwd|api[_-]?key|apikey|secret|token|authorization|seed|mnemonic|recovery[_-]?key)"?\s*[:=]\s*)"[^"]*"/gi, '$1"[redacted]"'], // "key": "spaced value" — capture the whole quoted body so a space in the secret can't leak the tail
	[/((?:password|passwd|api[_-]?key|apikey|secret|token|authorization|seed|mnemonic|recovery[_-]?key)"?\s*[:=]\s*"?)([^"\s,}]+)/gi, '$1[redacted]'], // key=value / key: value (unquoted)
	[/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?/g, '[redacted]'],                          // a bare JWT (header.payload[.signature]) with no adjacent label
	[/\b[A-Za-z0-9_-]{40,}\b/g, '[redacted]'],                                                            // a bare long secret run (raw key, hex/base64url blob) — the / and . in host paths keep vault paths under 40 unbroken chars, so they stay readable
];
function redact(text) {
	if (!text) return text;
	const s = String(text);
	if (!SECRET_TRIGGER.test(s)) return s; // the vast majority of lines have no secret shape — skip the regex work
	let out = s;
	for (const [re, rep] of REDACTIONS) out = out.replace(re, rep);
	return out;
}

// ── Daily-rotated, non-blocking file stream ─────────────────────────────────────────────────────────────────────────
let stream = null, streamDay = '';
let pendingBytes = 0;      // bytes handed to the stream but not yet drained (bounds slow-disk memory)
let backpressured = false; // true after write() returned false, until the stream drains
let writeFailUntil = 0;    // skip file writes until this time after a write error (cooldown, no per-line retry)
let cleanInFlight = false; // prevents overlapping prune sweeps stacking on the threadpool
// The daily log file is named by the UTC date, so rotation rolls at UTC midnight (not the host's local midnight) and a
// day's file holds the same 24-hour window on every machine regardless of timezone — matching the UTC log-line stamps.
function dayStamp(d) { const p = (n) => String(n).padStart(2, '0'); return d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate()); }

// Append one already-formatted line. Non-blocking and never throws.
function write(line) {
	// In-memory ring + realtime subscribers first (cheap, and useful even if the file write fails).
	try {
		const entry = { t: Date.now(), line: String(line) };
		ring.push(entry); if (ring.length > RING_MAX) ring.splice(0, ring.length - RING_MAX);
		for (const fn of subscribers) { try { fn(entry); } catch (_) {} }
	} catch (_) {}
	// Buffered append to today's file — ONLY when the user has opted into persistent diagnostics. Off by default, so no
	// vault-activity trail is ever written to disk (see fileEnabled above).
	if (!fileEnabled) return;
	if (Date.now() < writeFailUntil) return; // a recent write error — back off instead of reopening/mkdir/prune on every line
	try {
		const dir = logsDir(); if (!dir) return; // data dir not resolvable yet (very early boot) — ring buffer still has it
		const day = dayStamp(new Date());
		if (!stream || streamDay !== day) {
			if (stream) { try { stream.end(); } catch (_) {} }
			try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {} // only on a real date rollover; createWriteStream needs the dir
			stream = fs.createWriteStream(path.join(dir, day + '.log'), { flags: 'a' });
			// On error: DESTROY the errored stream (free the fd) and back off for a cooldown, so a failing disk never turns
			// per-line writes into a per-line reopen/mkdir storm. Pruning is left to the daily timer, not retried here.
			stream.on('error', () => { try { stream.destroy(); } catch (_) {} stream = null; streamDay = ''; pendingBytes = 0; backpressured = false; writeFailUntil = Date.now() + WRITE_FAIL_COOLDOWN_MS; });
			stream.on('drain', () => { backpressured = false; });
			streamDay = day;
			pendingBytes = 0; backpressured = false;
		}
		// Backpressure: if the disk is slow and the buffer has grown past the cap, DROP this line rather than let memory grow
		// without bound. Best-effort logging tolerates the loss; normal diagnostic volume never reaches the cap.
		if (backpressured && pendingBytes > MAX_PENDING_BYTES) return;
		const chunk = line + '\n';
		const n = Buffer.byteLength(chunk, 'utf8');
		pendingBytes += n;
		const ok = stream.write(chunk, () => { pendingBytes -= n; if (pendingBytes < 0) pendingBytes = 0; }); // callback fires when this chunk is flushed
		if (!ok) backpressured = true; // buffer above the high-water mark — hold off until 'drain'
	} catch (_) {}
}

// ── Retention (async, off the hot path) ─────────────────────────────────────────────────────────────────────────────
async function cleanOldLogs() {
	if (cleanInFlight) return; // never let two sweeps overlap on the threadpool
	cleanInFlight = true;
	try {
		const dir = logsDir(); if (!dir) return;
		let files; try { files = await fsp.readdir(dir); } catch (_) { return; } // no dir yet — nothing to prune
		const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
		for (const f of files) {
			if (!/^\d{4}-\d{2}-\d{2}\.log$/.test(f)) continue; // only our own daily files, never anything else in the dir
			// Guard each independently: this can race a concurrent write/rollover, and a throw must never propagate.
			try { const st = await fsp.stat(path.join(dir, f)); if (st.mtimeMs < cutoff) await fsp.unlink(path.join(dir, f)); } catch (_) {}
		}
	} catch (_) {} finally { cleanInFlight = false; }
}

// ── Realtime viewer support ─────────────────────────────────────────────────────────────────────────────────────────
function recent(limit) { return limit ? ring.slice(-limit) : ring.slice(); }
function subscribe(fn) { subscribers.add(fn); return () => { try { subscribers.delete(fn); } catch (_) {} }; }

// Flush the stream on a graceful exit so the tail of the log is not lost (exit handlers must be synchronous — end()
// flushes the buffered data). A hard kill can still lose the sub-second tail, the correct trade for never blocking.
try { process.once('exit', () => { try { if (stream) stream.end(); } catch (_) {} }); } catch (_) {}
// Prune daily; unref so the timer never keeps the process alive. The first prune also runs on the first rollover above.
try { const t = setInterval(() => { cleanOldLogs(); }, 24 * 60 * 60 * 1000); if (t.unref) t.unref(); } catch (_) {}

module.exports = { write, redact, recent, subscribe, cleanOldLogs, setFileLogging, isFileLogging, RETENTION_DAYS };
