'use strict';
// lib/test/fleet.js — the multi-node fleet: the pure rollup model (webserver/public/shared/fleet-model.js) and the
// server-side registry + poller (lib/Fleet.js). The model is unit-tested with synthetic state; the registry is tested
// against a real mock node HTTP server in an isolated data dir. Source scans pin the wiring (routes gated, background
// poll started, cached snapshot in state, model loaded before the client). No secret (node token) may ever appear in
// listNodes()/snapshot() or the state. Deterministic, cross-platform, no browser.
//
// Run:  node lib/test/fleet.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const http = require('http');
const Common = require('../Common');
const M = require('../webserver/public/shared/fleet-model');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

async function main() {
	console.log('[model: fleet tile rollup + node list]');
	{
		const state = { fleet: [
			{ id: 'a', label: 'Laptop', url: 'https://host:7420', status: 'online', health: { status: 'ok', version: '1.1.0', warnings: 0, errors: 0 } },
			{ id: 'b', label: 'NAS', url: 'https://nas:7420', status: 'degraded', health: { status: 'error', errors: 2 } },
			{ id: 'c', label: 'VPS', url: 'https://vps:7420', status: 'unreachable', error: 'timed out' },
		] };
		const t = M.fleetTile(state);
		ok('the fleet tile counts online and total', /1 online/.test(t.value) && /3 nodes/.test(t.value));
		ok('the fleet verdict is the worst node (a degraded node is an error)', t.level === 'error');
		ok('the tile reports how many need attention', /2 nodes need attention/.test(t.detail));
		ok('the tile links to the fleet view', t.action === 'fleet');
		ok('the tile is omitted when no node is enrolled', M.fleetTile({ fleet: [] }) === null);
		const nodes = M.nodeList(state);
		ok('an online node is good, a degraded node is an error, an unreachable node is a warn', nodes[0].level === 'good' && nodes[1].level === 'error' && nodes[2].level === 'warn');
		ok('a degraded node shows its error count, an unreachable node its reason', /2 error/.test(nodes[1].detail) && /timed out/.test(nodes[2].detail));
		ok('the node list carries no token/secret', !/token|secret|password/i.test(JSON.stringify(nodes)));
	}

	console.log('[registry + poll against a real mock node]');
	{
		const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-fleet-'));
		const origDataDir = Common.dataDir;
		Common.setDataDir(dir);
		const Fleet = require('../Fleet');
		Fleet._reset();
		let gotAuth = null;
		const srv = http.createServer((req, res) => {
			if (req.url === '/health') { gotAuth = req.headers['authorization'] || null; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ status: 'warn', version: '1.1.0', checks: 39, warnings: 1, errors: 0 })); }
			else { res.writeHead(404).end(); }
		});
		try {
			await new Promise((r) => srv.listen(0, '127.0.0.1', r));
			const url = 'http://127.0.0.1:' + srv.address().port;
			const add = await Fleet.verifyAndAdd({ label: 'Mock', url: url, token: 'sekret-token' });
			ok('verifyAndAdd reaches the node and returns an id', !!add.id);
			ok('the poll sent the token as a bearer header', gotAuth === 'Bearer sekret-token');
			ok('listNodes never exposes the token', !/sekret-token|token/i.test(JSON.stringify(await Fleet.listNodes())));
			const snap = Fleet.snapshot();
			ok('the snapshot maps a reachable warn node to online with a health summary', snap[0].status === 'online' && snap[0].health && snap[0].health.warnings === 1);
			ok('the snapshot carries no token', !/sekret-token|"token"/i.test(JSON.stringify(snap)));
			// The stored registry file must be 0600 and hold the token only there (encrypted-at-rest is a documented follow-up).
			const st = fs.statSync(path.join(dir, 'fleet.json'));
			ok('the registry file is owner-only (0600) on POSIX', process.platform === 'win32' || (st.mode & 0o077) === 0);

			// An unreachable node.
			await Fleet.addNode({ label: 'Down', url: 'http://127.0.0.1:1', token: 'x' });
			await Fleet.pollAll();
			ok('a node that cannot be reached is reported unreachable', Fleet.snapshot().find((n) => n.label === 'Down').status === 'unreachable');

			// verifyAndAdd refuses an unreachable node (verify-before-save).
			let refused = false; try { await Fleet.verifyAndAdd({ label: 'Nope', url: 'http://127.0.0.1:2', token: 'x' }); } catch (_) { refused = true; }
			ok('verifyAndAdd refuses to save a node it cannot reach', refused);

			await Fleet.removeNode(add.id);
			ok('removeNode drops the node from the registry and cache', !Fleet.snapshot().some((n) => n.id === add.id));
		} finally { srv.close(); Common.dataDir = origDataDir; Fleet._reset(); await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
	}

	console.log('[alerting: a durable status change fires once; a single blip does not]');
	{
		const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-fleeta-'));
		const origDataDir = Common.dataDir;
		Common.setDataDir(dir);
		const Fleet = require('../Fleet');
		Fleet._reset();
		let mock = 'ok'; // the status the mock node reports; flip it between poll cycles
		const srv = http.createServer((req, res) => { if (req.url === '/health') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ status: mock, checks: 39, warnings: 0, errors: mock === 'error' ? 1 : 0 })); } else res.writeHead(404).end(); });
		const fired = [];
		Fleet.setAlertHook((tr) => { for (const t of tr) fired.push(t.from + '->' + t.to); });
		try {
			await new Promise((r) => srv.listen(0, '127.0.0.1', r));
			const url = 'http://127.0.0.1:' + srv.address().port;
			await Fleet.verifyAndAdd({ label: 'N1', url: url, token: 't' });
			await Fleet.tick(); // first detect: baseline online, no alert
			ok('enrolling and a first healthy poll raise no alert', fired.length === 0);
			// A single blip: one degraded poll, then healthy again — must NOT alert.
			mock = 'error'; await Fleet.tick();
			mock = 'ok'; await Fleet.tick();
			ok('a single-poll blip does not alert (hysteresis)', fired.length === 0);
			// A durable change: degraded for SUSTAIN_POLLS consecutive polls — alerts once.
			mock = 'error'; for (let i = 0; i < Fleet.SUSTAIN_POLLS; i++) await Fleet.tick();
			ok('a sustained degrade alerts exactly once', fired.length === 1 && fired[0] === 'online->degraded');
			// Recovery: healthy again for SUSTAIN_POLLS — alerts the return to online.
			mock = 'ok'; for (let i = 0; i < Fleet.SUSTAIN_POLLS; i++) await Fleet.tick();
			ok('a sustained recovery alerts the return to online', fired.length === 2 && fired[1] === 'degraded->online');
		} finally { srv.close(); Common.dataDir = origDataDir; Fleet._reset(); await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
	}

	console.log('[cross-node actions: safe, allowlisted, authenticated]');
	{
		const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-fleetact-'));
		const origDataDir = Common.dataDir;
		Common.setDataDir(dir);
		const Fleet = require('../Fleet');
		Fleet._reset();
		const hits = [];
		const srv = http.createServer((req, res) => {
			if (req.url === '/health') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ status: 'ok', version: '1.1.0' })); return; }
			if (req.method === 'POST' && (req.url === '/api/lock-all' || req.url === '/api/selfcheck')) { hits.push({ url: req.url, auth: req.headers['authorization'] || null, csrf: req.headers['x-vdisk'] || null }); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true, locked: 0, total: 0 })); return; }
			res.writeHead(404).end();
		});
		try {
			await new Promise((r) => srv.listen(0, '127.0.0.1', r));
			const url = 'http://127.0.0.1:' + srv.address().port;
			const add = await Fleet.verifyAndAdd({ label: 'N', url: url, token: 'tok' });
			ok('only safe, non-destructive actions are allowlisted (lock + refresh)', Object.keys(Fleet.FLEET_ACTIONS).sort().join(',') === 'lock-all,refresh' && !Fleet.FLEET_ACTIONS['delete'] && !Fleet.FLEET_ACTIONS['backup']);
			await Fleet.nodeAction(add.id, 'lock-all');
			ok('locking a node POSTs to its /api/lock-all with the bearer token and CSRF header', hits.some((h) => h.url === '/api/lock-all' && h.auth === 'Bearer tok' && h.csrf === '1'));
			await Fleet.nodeAction(add.id, 'refresh');
			ok('refresh maps to the node\'s /api/selfcheck', hits.some((h) => h.url === '/api/selfcheck'));
			let rejected = false; try { await Fleet.nodeAction(add.id, 'delete-everything'); } catch (e) { rejected = e.code === 'BAD_ACTION'; }
			ok('an action outside the allowlist is refused', rejected);
			let noNode = false; try { await Fleet.nodeAction('nope', 'lock-all'); } catch (e) { noNode = e.code === 'NO_NODE'; }
			ok('an unknown node is refused', noNode);
		} finally { srv.close(); Common.dataDir = origDataDir; Fleet._reset(); await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
	}

	console.log('[wiring: routes gated, poll started, state cached, model loaded]');
	{
		const idx = read('webserver/index.js');
		ok('fleet-add verifies before saving and is gated outbound', /app\.post\('\/api\/fleet-add'[\s\S]{0,160}refuseOutboundIfExposed[\s\S]{0,80}Fleet\.verifyAndAdd/.test(idx));
		ok('fleet-remove is registered', /app\.post\('\/api\/fleet-remove'[\s\S]{0,80}Fleet\.removeNode/.test(idx));
		ok('the fleet poller starts in the background and stops on shutdown', /Fleet\.start\(\)/.test(idx) && /Fleet\.stop\(\)/.test(idx));
		ok('the state serves the cached fleet snapshot (no network I/O on a page poll)', /fleet:\s*Fleet\.snapshot\(\)/.test(idx));
		ok('a node status change pushes a notification (alert hook wired to Notify)', /Fleet\.setAlertHook\(/.test(idx) && /type: 'fleet-node'/.test(idx));
		const notify = read('Notify.js');
		ok('the fleet-node notification event exists (so the toggle is real)', /'fleet-node':\s*\{[^}]*defaultOn/.test(notify));
		ok('the fleet-action route is registered, allowlisted, and gated outbound', /app\.post\('\/api\/fleet-action'[\s\S]{0,160}refuseOutboundIfExposed[\s\S]{0,80}Fleet\.nodeAction/.test(idx));
		const app = read('webserver/public/js/app.js');
		ok('the fleet dialog rows offer safe actions (refresh + lock)', /data-fleet-action="refresh"/.test(app) && /data-fleet-action="lock-all"/.test(app));
		ok('locking a node from the hub asks for confirmation first', /data-fleet-action[\s\S]{0,400}action === 'lock-all'[\s\S]{0,120}uiConfirm/.test(app));
		ok('the dashboard composes the fleet tile from its own model', /window\.VaultFleet[\s\S]{0,80}fleetTile\(state\)/.test(app) && /key === 'fleet'[\s\S]{0,30}openFleet\(\)/.test(app));
		const ejs = read('webserver/public/views/index.ejs');
		ok('the fleet model is loaded before app.js', /shared\/fleet-model\.js[\s\S]{0,80}js\/app\.js/.test(ejs));
		ok('the fleet dialog exists in the shell', /id="fleetDialog"/.test(ejs) && /id="fleetList"/.test(ejs));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FLEET CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
