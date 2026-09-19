'use strict';
// lib/test/notify.js — critical-event notifications. Covers three layers:
//   1. the Notify module's config + privacy logic (opt-in gate, per-event toggles, generic-mode redaction);
//   2. end-to-end webhook delivery through Net.postJson against a real local HTTP server;
//   3. the highest-value wiring: the dead-man's-switch CHECK-IN REMINDER actually fires a webhook when release is
//      approaching (in the grace window) — the alert whose whole purpose is to prevent an accidental release.
// No engine and no network beyond loopback. Deterministic (an ephemeral loopback server, a forced `now`).
//
// Run:  node -r ./lib/test/_setup.js lib/test/notify.js

const http = require('http');
const Notify = require('../Notify');
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

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
	const onCfg = Notify.configFrom({ notify: { enabled: true, webhookUrl: 'http://x/y' } });
	ok('a default-on event is enabled once notifications are on', Notify.eventEnabled(onCfg, 'checkin-reminder') === true);
	ok('an explicitly disabled event stays off', Notify.eventEnabled(Notify.configFrom({ notify: { enabled: true, events: { 'checkin-reminder': false } } }), 'checkin-reminder') === false);
	const full = Notify.payloadFor(Notify.configFrom({ notify: { enabled: true } }), { type: 'checkin-reminder', message: 'SECRET detail', label: 'MyVault' });
	ok('a normal payload carries the vault label and message', full.vault === 'MyVault' && /SECRET detail/.test(full.message));
	const gen = Notify.payloadFor(Notify.configFrom({ notify: { enabled: true, generic: true } }), { type: 'checkin-reminder', message: 'SECRET detail', label: 'MyVault' });
	ok('generic mode drops the label and the specific message', gen.vault === undefined && !/SECRET|MyVault/.test(JSON.stringify(gen)));

	// ── 2. End-to-end webhook delivery ──────────────────────────────────────────────────────────────────────────
	const { server, received, url } = await recordingServer();
	// A rapid connect to a just-bound loopback port can transiently fail with EADDRNOTAVAIL on some hosts (a kernel
	// ephemeral-port race, not a logic error), so retry the raw probe a few times. The product path (Notify.emit)
	// already retries, so its checks below need no such wrapper.
	const postWithRetry = async (u, body) => { let last; for (let i = 0; i < 4; i++) { try { return await Net.postJson(u, body, { timeoutMs: 5000 }); } catch (e) { last = e; await new Promise((r) => setTimeout(r, 100)); } } throw last; };
	try {
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

		// ── 3. The check-in reminder fires through emergencyTick when release is approaching ─────────────────────
		const vdisk = require('../index');
		const A = vdisk.emergencyKeypair();
		// Enroll with a SHORT inactivity and a WIDE grace, so a `now` two days out lands squarely in the grace window
		// (past inactivity, well before release) — the reminder window, not a release.
		await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'Heir', inactivityDays: 1, graceDays: 60 });
		await vdisk.setSettings({ notify: { enabled: true, webhookUrl: url, events: { 'checkin-reminder': true } } });
		received.length = 0;
		const now2 = Date.now() + 2 * 86400000; // 2 days later: elapsed (2d) > inactivity (1d), < inactivity+grace (61d) => grace
		const tick = await vdisk.emergencyTick(now2);
		ok('the tick is in the grace window, not releasing', tick.phase === 'grace');
		ok('a check-in reminder webhook fired as release approached', received.some(r => r.json && r.json.type === 'checkin-reminder'));

		// It must fire at most ONCE per check-in window: a second tick in the same window sends nothing more.
		received.length = 0;
		await vdisk.emergencyTick(now2 + 3600000);
		ok('the reminder is not re-sent within the same check-in window', received.every(r => !r.json || r.json.type !== 'checkin-reminder'));

		// A check-in re-arms it: a fresh check-in moves lastCheckIn, so a later approach reminds again.
		await vdisk.emergencyCheckIn();
		received.length = 0;
		const now3 = Date.now() + 2 * 86400000;
		await vdisk.emergencyTick(now3);
		ok('a new check-in re-arms the reminder for the next window', received.some(r => r.json && r.json.type === 'checkin-reminder'));

		await vdisk.emergencyDisarm().catch(() => {});
	} finally {
		await new Promise((res) => server.close(res));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTIFY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
