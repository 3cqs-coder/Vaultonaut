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

	console.log('[move a vault between nodes: fail-safe orchestration]');
	{
		const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-fleetmv-'));
		const origDataDir = Common.dataDir; Common.setDataDir(dir);
		const Fleet = require('../Fleet'); Fleet._reset();
		try {
			const src = await Fleet.addNode({ label: 'Src', url: 'http://127.0.0.1:9', token: 'st' });
			const dst = await Fleet.addNode({ label: 'Dst', url: 'http://127.0.0.1:10', token: 'dt' });
			// A stub poster records the endpoint sequence and returns canned per-endpoint responses (the real move never
			// touches a network in this test — it exercises the ORCHESTRATION: order, fail-safety, and payload plumbing).
			const makePost = (responses) => { const calls = []; const post = async (url, token, endpoint, body) => { calls.push({ endpoint, token, body }); const r = responses[endpoint]; return r || { ok: false, error: 'no stub for ' + endpoint }; }; return { post, calls }; };

			// Happy path: serve -> receive -> retire, in that order, retire only after a verified receipt.
			{
				const { post, calls } = makePost({
					'/api/serve-for-move': { ok: true, json: { code: 'CODE123' } },
					'/api/receive-vault': { ok: true, json: { vault: '/vaults/V.vault', verdict: 'RECEIVED' } },
					'/api/remove-vault': { ok: true, json: { path: '/src/V.vault' } },
					'/api/serve-stop': { ok: true, json: {} },
				});
				const r = await Fleet.moveVault({ sourceId: src.id, destId: dst.id, vaultPath: '/src/V.vault', password: 'pw' }, { post });
				const seq = calls.map((c) => c.endpoint);
				ok('a successful move reports the received vault and a retired source', r.ok === true && r.vault === '/vaults/V.vault' && r.retired === true);
				ok('the move serves, then receives, then retires — retire only after a verified receipt', seq[0] === '/api/serve-for-move' && seq[1] === '/api/receive-vault' && seq[2] === '/api/remove-vault');
				ok('the temporary serve is always stopped afterward', seq.includes('/api/serve-stop'));
				ok('the source serve is authorized by the vault password', calls[0].body.password === 'pw' && calls[0].token === 'st');
				ok('the destination pulls the source-minted connect code (keys never touch the hub)', calls[1].body.code === 'CODE123' && calls[1].token === 'dt');
			}
			// A failed receive must NOT retire the source (no data loss), and must still stop the serve.
			{
				const { post, calls } = makePost({
					'/api/serve-for-move': { ok: true, json: { code: 'C' } },
					'/api/receive-vault': { ok: false, status: 500, json: { error: 'copy failed' } },
					'/api/serve-stop': { ok: true, json: {} },
				});
				const r = await Fleet.moveVault({ sourceId: src.id, destId: dst.id, vaultPath: '/src/V.vault', password: 'pw' }, { post });
				ok('a failed receive fails the move at the receive stage', r.ok === false && r.stage === 'receive');
				ok('a failed receive NEVER retires the source (fail-safe, no data loss)', !calls.some((c) => c.endpoint === '/api/remove-vault'));
				ok('a failed receive still stops the temporary serve', calls.some((c) => c.endpoint === '/api/serve-stop'));
			}
			// A failed serve stops before the destination is ever contacted.
			{
				const { post, calls } = makePost({ '/api/serve-for-move': { ok: false, error: 'unreachable' } });
				const r = await Fleet.moveVault({ sourceId: src.id, destId: dst.id, vaultPath: '/src/V.vault', password: 'pw' }, { post });
				ok('a failed serve fails the move at the serve stage', r.ok === false && r.stage === 'serve');
				ok('a failed serve never reaches the destination', !calls.some((c) => c.endpoint === '/api/receive-vault'));
			}
			// A verified receipt whose retire fails still succeeds — the move is done; the source is just not auto-forgotten.
			{
				const { post } = makePost({
					'/api/serve-for-move': { ok: true, json: { code: 'C' } },
					'/api/receive-vault': { ok: true, json: { vault: '/v/V.vault' } },
					'/api/remove-vault': { ok: false, error: 'busy' },
					'/api/serve-stop': { ok: true, json: {} },
				});
				const r = await Fleet.moveVault({ sourceId: src.id, destId: dst.id, vaultPath: '/src/V.vault', password: 'pw' }, { post });
				ok('a move whose retire fails still succeeds but reports the source was not retired', r.ok === true && r.retired === false && !!r.retireError);
			}
			// Moving to the same node is refused.
			{
				let same = false; try { await Fleet.moveVault({ sourceId: src.id, destId: src.id, vaultPath: '/x', password: 'p' }, { post: async () => ({ ok: true, json: {} }) }); } catch (e) { same = e.code === 'SAME_NODE'; }
				ok('moving a vault to the same node is refused', same);
			}
			// Push (local source): pushVaultToNode reports a verified receipt, and surfaces a failed one without throwing.
			{
				const okPost = async () => ({ ok: true, json: { vault: '/v/V.vault', verdict: 'RECEIVED' } });
				const r = await Fleet.pushVaultToNode(dst.id, 'CODE', 'V', { post: okPost });
				ok('pushVaultToNode reports the received vault on a verified receipt', r.ok === true && r.vault === '/v/V.vault');
				const badPost = async () => ({ ok: false, status: 500, json: { error: 'no space' } });
				const r2 = await Fleet.pushVaultToNode(dst.id, 'CODE', 'V', { post: badPost });
				ok('pushVaultToNode reports a failed receipt without throwing', r2.ok === false && /no space/.test(r2.error));
				let noNode = false; try { await Fleet.pushVaultToNode('nope', 'CODE', 'V', { post: okPost }); } catch (e) { noNode = e.code === 'NO_NODE'; }
				ok('pushVaultToNode refuses an unknown destination node', noNode);
			}
		} finally { Common.dataDir = origDataDir; Fleet._reset(); await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
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
		// Move-a-vault: the hub route is outbound-gated and calls the dedicated orchestrator; the source-side serve-for-move
		// endpoint authorizes with the vault password (requireVaultReadIfExposed) and serves read-only.
		ok('the fleet-move route is registered and gated outbound', /app\.post\('\/api\/fleet-move'[\s\S]{0,160}refuseOutboundIfExposed[\s\S]{0,80}Fleet\.moveVault/.test(idx));
		ok('serve-for-move authorizes by the vault password and serves read-only', /app\.post\('\/api\/serve-for-move'[\s\S]{0,220}requireVaultReadIfExposed[\s\S]{0,160}readOnly:\s*true/.test(idx));
		// The common push (move one of THIS machine's own vaults to a node) is outbound-gated, serves read-only, and
		// retires the local source only inside the verified-receipt branch.
		ok('the fleet-push route is registered and gated outbound', /app\.post\('\/api\/fleet-push'[\s\S]{0,120}refuseOutboundIfExposed/.test(idx));
		ok('fleet-push serves read-only, pushes, then retires the local source only after a verified receipt', /app\.post\('\/api\/fleet-push'[\s\S]{0,900}readOnly:\s*true[\s\S]{0,600}pushVaultToNode[\s\S]{0,600}removeKnownVault/.test(idx));
		// The orchestrator retires the source only AFTER a verified receive (remove-vault appears after receive-vault).
		const fleetSrc = read('Fleet.js');
		ok('moveVault retires the source only after a verified receipt', /'\/api\/receive-vault'[\s\S]{0,400}'\/api\/remove-vault'/.test(fleetSrc) && fleetSrc.indexOf("'/api/remove-vault'") > fleetSrc.indexOf("'/api/receive-vault'"));
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
