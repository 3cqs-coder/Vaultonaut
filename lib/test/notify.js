'use strict';
// lib/test/notify.js — critical-event notifications. Covers:
//   1. the Notify module's config + privacy logic (opt-in gate, per-event toggles, generic-mode redaction);
//   2. end-to-end webhook delivery through Net.postJson against a real local HTTP server;
//   3. the highest-value wiring: the dead-man's-switch CHECK-IN REMINDER actually fires a webhook when release is
//      approaching (fired DETACHED from the tick, so this polls for it), fires at most once per window, and re-arms on
//      a check-in;
//   4. the backup-failed event's label is REDACTED to the vault name only (never a filesystem path).
// Fully isolated: it runs against its OWN temp data directory (never the shared .test-data), no engine, loopback only.
//
// Run:  node -r ./lib/test/_setup.js lib/test/notify.js

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const Common = require('../Common');
const Notify = require('../Notify');
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Poll until `pred()` is true or the deadline passes — used because the reminder is emitted DETACHED from emergencyTick
// (so the tick never blocks on a slow webhook), meaning the POST lands shortly AFTER the tick returns.
async function waitFor(pred, ms = 2500) { const end = Date.now() + ms; while (Date.now() < end) { if (pred()) return true; await sleep(25); } return pred(); }

// Own temp data directory, so this test never reads or writes the shared .test-data (its enroll/settings writes would
// otherwise linger — a left-behind notify webhook pointing at a now-closed port would make later tests attempt real
// POSTs). Set BEFORE requiring the app.
const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-notify-'));
Common.setDataDir(DATA);

// A tiny loopback server that records the JSON bodies POSTed to it, so a test can assert what a webhook received.
function recordingServer() {
	const received = [];
	const server = http.createServer((req, res) => {
		let body = '';
		req.on('data', (c) => { body += c; });
		req.on('end', () => { try { received.push({ method: req.method, json: JSON.parse(body || '{}') }); } catch (_) { received.push({ method: req.method, json: null, raw: body }); } res.writeHead(200); res.end('ok'); });
	});
	return new Promise((resolve) => { server.listen(0, '127.0.0.1', () => resolve({ server, received, url: 'http://127.0.0.1:' + server.address().port + '/hook' })); });
}

async function main() {
	// ── 1. Config + privacy logic (no I/O) ──────────────────────────────────────────────────────────────────────
	ok('nothing is enabled without opt-in (off by default)', Notify.eventEnabled(Notify.configFrom({}), 'checkin-reminder') === false);
	ok('a default-on event is enabled once notifications are on', Notify.eventEnabled(Notify.configFrom({ notify: { enabled: true, webhookUrl: 'http://x/y' } }), 'checkin-reminder') === true);
	ok('an explicitly disabled event stays off', Notify.eventEnabled(Notify.configFrom({ notify: { enabled: true, events: { 'checkin-reminder': false } } }), 'checkin-reminder') === false);
	const full = Notify.payloadFor(Notify.configFrom({ notify: { enabled: true } }), { type: 'checkin-reminder', message: 'SECRET detail', label: 'MyVault' });
	ok('a normal payload carries the vault label and message', full.vault === 'MyVault' && /SECRET detail/.test(full.message));
	const gen = Notify.payloadFor(Notify.configFrom({ notify: { enabled: true, generic: true } }), { type: 'checkin-reminder', message: 'SECRET detail', label: 'MyVault' });
	ok('generic mode drops the label and the specific message', gen.vault === undefined && !/SECRET|MyVault/.test(JSON.stringify(gen)));

	// ── 4. backup-failed label redaction: a scheduled backup failure notifies with the vault NAME only, never a path.
	// This mirrors the exact transform the backup tick uses, so a regression that passed the full path would be caught.
	const redact = (abs) => path.basename(String(abs)).replace(/\.vault$/i, '');
	const label = redact('/Users/someone/Secret Docs/My Bank.vault');
	ok('a backup-failed label is the vault name only (no path separator, no .vault suffix)', label === 'My Bank' && !/[\\/]/.test(label) && !/\.vault$/i.test(label));
	// The backup-failed label must be the FOLDER-derived name (displayName) — which is the opaque id for a hidden vault —
	// and NEVER the decrypted title (friendlyName). A notification goes to a webhook that may be third-party, so leaking
	// the name a user hid the folder to conceal would defeat the anonymization. Pin the exact call in the source.
	const vaultSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'Vault.js'), 'utf8');
	const backupFailEmit = (vaultSrc.match(/type: 'backup-failed'[\s\S]{0,80}/) || [''])[0];
	ok('the backup-failed notification labels by the folder name, not the decrypted title', /label: displayName\(abs\)/.test(backupFailEmit) && !/friendlyName/.test(backupFailEmit));

	const { server, received, url } = await recordingServer();
	// A rapid connect to a just-bound loopback port can transiently fail with EADDRNOTAVAIL on some hosts (a kernel
	// ephemeral-port race, not a logic error), so retry the raw probe a few times. Notify.emit already retries.
	const postWithRetry = async (u, body) => { let last; for (let i = 0; i < 4; i++) { try { return await Net.postJson(u, body, { timeoutMs: 5000 }); } catch (e) { last = e; await sleep(100); } } throw last; };
	try {
		// ── 2. End-to-end webhook delivery ──────────────────────────────────────────────────────────────────────
		const r = await postWithRetry(url, { hello: 'world' });
		ok('Net.postJson posts JSON and resolves the status', r.status === 200 && received.length === 1 && received[0].method === 'POST' && received[0].json.hello === 'world');

		received.length = 0;
		const disabled = await Notify.emit({ type: 'checkin-reminder', message: 'x' }, { notify: { enabled: false, webhookUrl: url } });
		ok('emit does nothing when notifications are off', disabled.delivered === false && received.length === 0);

		received.length = 0;
		const deliv = await Notify.emit({ type: 'checkin-reminder', message: 'check in please', label: 'Bank' }, { notify: { enabled: true, webhookUrl: url } });
		ok('emit delivers an enabled event to the webhook', deliv.delivered === true && received.length === 1 && received[0].json.type === 'checkin-reminder' && received[0].json.vault === 'Bank');

		received.length = 0;
		await Notify.emit({ type: 'checkin-reminder', message: 'check in please', label: 'Bank' }, { notify: { enabled: true, generic: true, webhookUrl: url } });
		ok('a delivered generic payload leaks neither the label nor the message', received.length === 1 && !/Bank|check in please/.test(JSON.stringify(received[0].json)));

		// A non-2xx endpoint must not leak the host in the returned reason, and must count as an ATTEMPT (so the reminder
		// records it and does not re-send every tick).
		const errServer = http.createServer((rq, rs) => { rq.resume(); rs.writeHead(500); rs.end('no'); });
		await new Promise((res) => errServer.listen(0, '127.0.0.1', res));
		const errUrl = 'http://127.0.0.1:' + errServer.address().port + '/h';
		const failed = await Notify.emit({ type: 'checkin-reminder', message: 'x', label: 'Bank' }, { notify: { enabled: true, webhookUrl: errUrl } });
		ok('a non-2xx endpoint is a real attempt (not a skip) and the reason carries no host', failed.delivered === false && failed.attempts >= 1 && /HTTP 500/.test(String(failed.error)) && !/127\.0\.0\.1|:\d/.test(String(failed.error)));
		await new Promise((res) => errServer.close(res));

		// ── 3. The check-in reminder fires (detached) through emergencyTick when release is approaching ─────────────
		const vdisk = require('../index');
		const A = vdisk.emergencyKeypair();
		await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'Heir', inactivityDays: 1, graceDays: 60 });
		await vdisk.setSettings({ notify: { enabled: true, webhookUrl: url, events: { 'checkin-reminder': true } } });
		received.length = 0;
		const now2 = Date.now() + 2 * 86400000; // 2 days later: elapsed (2d) > inactivity (1d), < inactivity+grace (61d) => grace
		const tick = await vdisk.emergencyTick(now2);
		ok('the tick is in the grace window, not releasing', tick.phase === 'grace');
		ok('a check-in reminder webhook fired as release approached', await waitFor(() => received.some((x) => x.json && x.json.type === 'checkin-reminder')));
		await sleep(150); // let the reminder's reminderSentFor commit settle before the next tick

		received.length = 0;
		await vdisk.emergencyTick(now2 + 3600000);
		await sleep(300); // give a (wrong) re-send a chance, so the assertion is meaningful
		ok('the reminder is not re-sent within the same check-in window', received.every((x) => !x.json || x.json.type !== 'checkin-reminder'));

		await vdisk.emergencyCheckIn(); // a fresh check-in moves lastCheckIn and re-arms the reminder
		received.length = 0;
		await vdisk.emergencyTick(Date.now() + 2 * 86400000);
		ok('a new check-in re-arms the reminder for the next window', await waitFor(() => received.some((x) => x.json && x.json.type === 'checkin-reminder')));
	} finally {
		try { await require('../index').emergencyDisarm(); } catch (_) {}
		try { await require('../index').setSettings({ notify: {} }); } catch (_) {} // never leave a webhook config behind
		await new Promise((res) => server.close(res));
		try { fs.rmSync(DATA, { recursive: true, force: true }); } catch (_) {}
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTIFY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
