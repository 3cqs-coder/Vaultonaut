'use strict';
// lib/test/logger.js — the diagnostic logger must (1) never let a credential reach a log line, (2) write daily-rotated
// files under the per-user data dir, (3) prune files past the retention window, and (4) keep a bounded in-memory ring
// for a live viewer. These are the guarantees a long-running service depends on: a diagnosable trail that never leaks a
// secret and never grows without bound. Pure — no engine.
//
// Run:  node lib/test/logger.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const Common = require('../Common');
const Logger = require('../Logger');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// --- 1. Secret redaction: masks real secret shapes, leaves ordinary text and vault paths alone ---
ok('redacts a token= value', Logger.redact('mounting with token=abcdef1234567890 now') === 'mounting with token=[redacted] now');
ok('redacts a password= value', Logger.redact('password=hunter2') === 'password=[redacted]');
ok('redacts an api_key= value', Logger.redact('api_key=SECRETKEY123456') === 'api_key=[redacted]');
ok('redacts user:pass@host in a URL', /:\/\/user:\[redacted\]@host/.test(Logger.redact('sftp://user:s3cr3t@host/path')));
ok('redacts a JSON-ish "secret": "value"', /"secret":"\[redacted\]"/.test(Logger.redact('{"secret":"topsecretvalue"}')));
ok('redacts a seed/mnemonic field', Logger.redact('seed=abandonabandonabandon') === 'seed=[redacted]');
ok('leaves an ordinary line untouched', Logger.redact('Vaultonaut UI at http://localhost:7420') === 'Vaultonaut UI at http://localhost:7420');
ok('leaves a vault path untouched', Logger.redact('/Users/me/Library/Application Support/Vaultonaut/vaults/Test.vault') === '/Users/me/Library/Application Support/Vaultonaut/vaults/Test.vault');
// A long host path must stay readable — it is the whole point of an opt-in diagnostic trail. The / and . separators keep
// every run under the 40-char bare-secret threshold, so even a deeply nested, long vault name is never mistaken for a key.
ok('leaves a long nested vault path untouched', Logger.redact('/home/somebody/.local/share/Vaultonaut/vaults/MyRatherLongVaultNameForTesting.vault') === '/home/somebody/.local/share/Vaultonaut/vaults/MyRatherLongVaultNameForTesting.vault');
// Label-free secret shapes still get caught (defense in depth for any future caller that logs a raw value)
ok('redacts a bare JWT with no adjacent label', Logger.redact('got eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N here') === 'got [redacted] here');
ok('redacts a bare long secret run with no label', Logger.redact('value ' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2' + ' end') === 'value [redacted] end');
ok('redacts a quoted secret that contains a space (no tail leak)', Logger.redact('{"password": "hunter two three"}') === '{"password": "[redacted]"}');
ok('redact tolerates null/empty', Logger.redact('') === '' && Logger.redact(null) == null);

// --- Point the data dir at a temp folder so the file tests never touch the real logs ---
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-logger-'));
Common.setDataDir(tmp);
const dir = Common.logsDir();
const today = (() => { const d = new Date(), p = (n) => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()); })();
// Poll a condition up to a deadline instead of a fixed sleep, so a slow CI runner's buffered-stream flush never flakes.
const waitFor = async (cond, timeoutMs = 4000, step = 20) => { const end = Date.now() + timeoutMs; while (Date.now() < end) { try { if (cond()) return true; } catch (_) {} await new Promise((r) => setTimeout(r, step)); } return false; };

async function main() {
	const file = path.join(dir, today + '.log');

	// --- 2a. PRIVACY DEFAULT: file logging is OFF, so nothing is written to disk (no vault-activity trail) ---
	ok('file logging is OFF by default', Logger.isFileLogging() === false);
	Common.log('this must NOT reach a file while logging is off');
	await new Promise(r => setTimeout(r, 150));
	ok('no log file is created while file logging is off', !fs.existsSync(file));

	// --- 2b. Opt-in: after enabling, Common.log writes the daily file (redacted) ---
	Logger.setFileLogging(true);
	Common.log('logger-test marker line');
	Common.log('a leaked token=DONOTLOGME999 here');
	await waitFor(() => fs.existsSync(file) && fs.readFileSync(file, 'utf8').includes('logger-test marker line')); // poll for the buffered flush, not a fixed wait
	ok('a daily log file named by the local date is created once enabled', fs.existsSync(file));
	const content = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
	ok('the marker line reached the file', content.includes('logger-test marker line'));
	ok('the secret is redacted in the file (never written in the clear)', !content.includes('DONOTLOGME999') && content.includes('token=[redacted]'));
	ok('the off-default line was never written to the file', !content.includes('must NOT reach a file'));

	// --- 2c. Turning it back off stops writing new lines to disk ---
	Logger.setFileLogging(false);
	Common.log('after-off line should not be written');
	await new Promise(r => setTimeout(r, 150));
	ok('no new lines are written after file logging is turned back off', !fs.readFileSync(file, 'utf8').includes('after-off line'));

	// --- 4. In-memory ring buffer for a live viewer (always captures, regardless of file logging) ---
	const recent = Logger.recent(50);
	ok('recent() returns bounded ring entries with the marker', Array.isArray(recent) && recent.some(e => e.line.includes('logger-test marker line')));

	// --- 3. Retention: an old daily file is pruned, a recent one and a non-log file are kept ---
	const oldFile = path.join(dir, '2000-01-01.log');
	fs.writeFileSync(oldFile, 'ancient\n');
	fs.utimesSync(oldFile, new Date('2000-01-01'), new Date('2000-01-01')); // mtime far past the retention window
	const keepFile = path.join(dir, '2000-01-02.log'); // a well-formed name but with a FRESH mtime -> kept
	fs.writeFileSync(keepFile, 'fresh-mtime\n');
	const foreign = path.join(dir, 'notes.txt'); // not a daily log file -> never touched
	fs.writeFileSync(foreign, 'keep me\n');
	await Logger.cleanOldLogs();
	ok('a daily log older than the retention window is pruned', !fs.existsSync(oldFile));
	ok('a daily log with a recent mtime is kept', fs.existsSync(keepFile));
	ok('a non-log file in the directory is never touched', fs.existsSync(foreign));
	ok('the retention window is a sane number of days', Number.isInteger(Logger.RETENTION_DAYS) && Logger.RETENTION_DAYS >= 7 && Logger.RETENTION_DAYS <= 365);

	try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LOGGER CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(1); });
