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

const ring = [];             // { t, line } recent entries, bounded by RING_MAX
const subscribers = new Set(); // fn(entry) — a realtime viewer (e.g. the web UI) subscribes here

// The per-user logs directory, resolved LAZILY: Common requires this module at load, so requiring Common back at load
// time would be a cycle. By the time any log line is written, Common is fully loaded and cached, so this is safe.
function logsDir() { try { return require('./Common').logsDir(); } catch (_) { return null; } }

// ── Secret redaction (single choke point) ──────────────────────────────────────────────────────────────────────────
// No line — file, console, or viewer — may leak a credential, whatever a caller passed. Conservative (real secret
// shapes only) so ordinary text and vault paths are untouched, and gated by a cheap trigger so the hot path stays free.
const SECRET_TRIGGER = /pass|secret|token|key|bearer|authorization|:\/\/|seed|mnemonic|recovery/i;
const REDACTIONS = [
	[/\b(bearer\s+)[\w.\-]+/gi, '$1[redacted]'],                                                         // Authorization: Bearer <token>
	[/\b(basic\s+)[A-Za-z0-9+/=]{8,}/gi, '$1[redacted]'],                                                // Authorization: Basic <base64>
	[/([a-z][a-z0-9+.\-]*:\/\/[^/\s:@]+:)[^/\s:@]+@/gi, '$1[redacted]@'],                                // user:pass@host in a URL
	[/([?&](?:api[_-]?key|apikey|access[_-]?token|token|password|secret|auth)=)[^&\s"']+/gi, '$1[redacted]'], // ?token=… query params
	[/("?(?:password|passwd|api[_-]?key|apikey|secret|token|authorization|seed|mnemonic|recovery[_-]?key)"?\s*[:=]\s*"?)([^"\s,}]+)/gi, '$1[redacted]'], // key: "value"
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
function dayStamp(d) { const p = (n) => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()); }

// Append one already-formatted line. Non-blocking and never throws.
function write(line) {
	// In-memory ring + realtime subscribers first (cheap, and useful even if the file write fails).
	try {
		const entry = { t: Date.now(), line: String(line) };
		ring.push(entry); if (ring.length > RING_MAX) ring.splice(0, ring.length - RING_MAX);
		for (const fn of subscribers) { try { fn(entry); } catch (_) {} }
	} catch (_) {}
	// Buffered append to today's file; reopen only when the date rolls over.
	try {
		const dir = logsDir(); if (!dir) return; // data dir not resolvable yet (very early boot) — ring buffer still has it
		const day = dayStamp(new Date());
		if (!stream || streamDay !== day) {
			if (stream) { try { stream.end(); } catch (_) {} }
			try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {} // once per day; createWriteStream needs the dir to exist
			stream = fs.createWriteStream(path.join(dir, day + '.log'), { flags: 'a' });
			stream.on('error', () => { stream = null; }); // drop on error; the next line reopens
			streamDay = day;
			cleanOldLogs(); // opportunistic prune on each rollover (fire-and-forget), in addition to the daily timer
		}
		stream.write(line + '\n'); // buffered by Node — does not block the event loop
	} catch (_) {}
}

// ── Retention (async, off the hot path) ─────────────────────────────────────────────────────────────────────────────
async function cleanOldLogs() {
	try {
		const dir = logsDir(); if (!dir) return;
		let files; try { files = await fsp.readdir(dir); } catch (_) { return; } // no dir yet — nothing to prune
		const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
		for (const f of files) {
			if (!/^\d{4}-\d{2}-\d{2}\.log$/.test(f)) continue; // only our own daily files, never anything else in the dir
			// Guard each independently: this can race a concurrent write/rollover, and a throw must never propagate.
			try { const st = await fsp.stat(path.join(dir, f)); if (st.mtimeMs < cutoff) await fsp.unlink(path.join(dir, f)); } catch (_) {}
		}
	} catch (_) {}
}

// ── Realtime viewer support ─────────────────────────────────────────────────────────────────────────────────────────
function recent(limit) { return limit ? ring.slice(-limit) : ring.slice(); }
function subscribe(fn) { subscribers.add(fn); return () => { try { subscribers.delete(fn); } catch (_) {} }; }

// Flush the stream on a graceful exit so the tail of the log is not lost (exit handlers must be synchronous — end()
// flushes the buffered data). A hard kill can still lose the sub-second tail, the correct trade for never blocking.
try { process.once('exit', () => { try { if (stream) stream.end(); } catch (_) {} }); } catch (_) {}
// Prune daily; unref so the timer never keeps the process alive. The first prune also runs on the first rollover above.
try { const t = setInterval(() => { cleanOldLogs(); }, 24 * 60 * 60 * 1000); if (t.unref) t.unref(); } catch (_) {}

module.exports = { write, redact, recent, subscribe, cleanOldLogs, RETENTION_DAYS };
