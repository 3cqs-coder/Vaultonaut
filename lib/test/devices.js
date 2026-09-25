'use strict';
// lib/test/devices.js — the Devices & connections view. Its logic lives in the shared, dependency-free model
// (webserver/public/shared/devices-model.js) so it is unit-tested in Node with no browser: which connections list,
// how a reachability probe's result is read (the three endpoints disagree on where they put success/failure text), the
// bounded-concurrency probe runner, and the recent-activity feed assembled only from poll data. Source scans pin the
// wiring: reachability must use a raw fetch (never api(), which throws on a not-ok body), the model loads before the
// client, and the connectivity tile opens this view. Deterministic and cross-platform.
//
// Run:  node lib/test/devices.js

const fs = require('fs');
const path = require('path');
const D = require('../webserver/public/shared/devices-model');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	console.log('[deviceList: what shows, and that no secret leaks]');
	{
		const st = {
			peers: [{ id: 'p1', label: 'Laptop', url: 'https://host:7420', hasPassword: true }],
			cloudRemotes: [{ id: 'c1', type: 's3', hasSecrets: true }],
			sftpDests: [{ id: 's1', host: 'nas', user: 'me', port: 22, hasPassword: true }],
			vaults: [{ path: '/v', name: 'Docs', serving: { serving: true, url: 'https://x' } }, { path: '/w', name: 'Off', serving: { serving: false } }]
		};
		const list = D.deviceList(st);
		const byKind = {}; list.forEach(d => { (byKind[d.kind] = byKind[d.kind] || []).push(d); });
		ok('a peer is listed, testable and removable', byKind.peer && byKind.peer[0].testable === true && byKind.peer[0].removable === true);
		ok('a cloud remote is listed and testable', byKind.cloud && byKind.cloud[0].testable === true);
		ok('an sftp destination is listed and testable', byKind.sftp && byKind.sftp[0].testable === true);
		ok('only a SERVING vault is listed, as live status (not testable)', byKind.serve && byKind.serve.length === 1 && byKind.serve[0].testable === false && byKind.serve[0].live === true);
		// No password/secret field may appear on any listed device.
		const flat = JSON.stringify(list);
		ok('no secret/password field is carried into the device list', !/password|hasPassword|secret|pass"/i.test(flat));
	}

	console.log('[reachabilityFrom: the three endpoints report success/failure differently]');
	{
		ok('a peer reach reports the transport via', (() => { const v = D.reachabilityFrom('peer', { ok: true, via: 'relay' }); return v.reachable && /relay/.test(v.note); })());
		ok('a peer failure reads its `error` field', (() => { const v = D.reachabilityFrom('peer', { ok: false, error: 'no route' }); return !v.reachable && /no route/.test(v.note); })());
		ok('a cloud result reads `detail` for success AND failure', (() => { const a = D.reachabilityFrom('cloud', { ok: true, detail: 'Reachable (the folder does not exist yet).' }); const b = D.reachabilityFrom('cloud', { ok: false, detail: 'no such bucket' }); return a.reachable && /does not exist yet/.test(a.note) && !b.reachable && /no such bucket/.test(b.note); })());
		ok('an sftp failure reads its `error` field', (() => { const v = D.reachabilityFrom('sftp', { ok: false, error: 'timeout' }); return !v.reachable && /timeout/.test(v.note); })());
		ok('a thrown/garbage probe is an inconclusive failure, never reachable', !D.reachabilityFrom('peer', null).reachable && !D.reachabilityFrom('peer', undefined).reachable);
	}

	console.log('[mapLimit: bounded concurrency, ordered, error-isolated, never rejects]');
	{
		let inflight = 0, peak = 0;
		const items = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		const res = await D.mapLimit(items, 3, async (x) => { inflight++; peak = Math.max(peak, inflight); await new Promise(r => setTimeout(r, 8)); inflight--; if (x === 5) throw new Error('boom'); return x * 2; });
		ok('at most `limit` run at once', peak <= 3 && peak >= 1);
		ok('results preserve input order', res[0] === 0 && res[4] === 8 && res[9] === 18);
		ok('a failing item is isolated as { error } and does not abort the run', res[5] && res[5].error === 'boom' && res[6] === 12);
		ok('an empty list resolves to []', (await D.mapLimit([], 4, async () => 1)).length === 0);
		// The whole point: probing many connections must not open an unbounded burst.
		let peak2 = 0, n2 = 0;
		await D.mapLimit(new Array(50).fill(0), 4, async () => { n2++; peak2 = Math.max(peak2, n2); await new Promise(r => setTimeout(r, 1)); n2--; });
		ok('a large sweep still caps in-flight work at the limit', peak2 <= 4);
	}

	console.log('[recentActivity: assembled only from poll data, newest first]');
	{
		const st = {
			selfCheck: { at: new Date(Date.now() - 5 * 60000).toISOString() },
			vaults: [
				{ name: 'A', backupSchedule: { lastRunAt: new Date(Date.now() - 60 * 60000).toISOString(), lastResult: 'ok' }, mirror: { configured: true, lastSyncAt: new Date(Date.now() - 10 * 60000).toISOString() } },
				{ name: 'B', backupSchedule: { lastRunAt: new Date(Date.now() - 2 * 60000).toISOString(), lastResult: 'error: unreachable' } }
			]
		};
		const act = D.recentActivity(st);
		ok('events are sorted newest first', act.length >= 3 && act[0].atMs >= act[act.length - 1].atMs);
		ok('a failed backup is marked as an error event', act.some(a => /Backup of B failed/.test(a.text) && a.level === 'error'));
		ok('a successful backup is a good event', act.some(a => /Backup of A ran/.test(a.text) && a.level === 'good'));
		ok('a mirror sync is recorded', act.some(a => /Mirror of A synced/.test(a.text)));
		ok('the self-check sweep is recorded', act.some(a => /System check ran/.test(a.text)));
		ok('the feed is capped', D.recentActivity({ vaults: Array.from({ length: 40 }, (_, i) => ({ name: 'V' + i, backupSchedule: { lastRunAt: new Date().toISOString(), lastResult: 'ok' } })) }, 8).length === 8);
		ok('an empty state yields no activity (no crash)', D.recentActivity({}).length === 0);
	}

	console.log('[wiring: reachability uses a raw fetch, model loads first, tile opens the view]');
	{
		const app = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');
		// api() throws on a not-ok body, so a reachability probe (whose whole job is to read ok:false) must NOT use it.
		ok('the probe helper reads the body without throwing on not-ok (its own fetch, not api())', /function probeApi\([\s\S]{0,400}fetch\(path/.test(app) && /function testDeviceRow\([\s\S]{0,300}probeApi\(/.test(app));
		ok('Check all fans out through the bounded mapLimit', /VaultDevices\.mapLimit\(rows, 4,/.test(app));
		ok('the connectivity tile action opens the devices view', /key === 'devices'[\s\S]{0,40}openDevices\(\)/.test(app));
		const model = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'shared', 'dashboard-model.js'), 'utf8');
		ok('the connectivity tile carries the devices action', /id: 'connectivity'[\s\S]{0,400}action: 'devices'/.test(model));
		const ejs = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'views', 'index.ejs'), 'utf8');
		ok('the devices model is loaded before app.js', /shared\/devices-model\.js[\s\S]{0,120}js\/app\.js/.test(ejs));
		ok('the devices dialog exists in the shell', /id="devicesDialog"/.test(ejs) && /id="devicesList"/.test(ejs));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DEVICES CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
