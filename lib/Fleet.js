'use strict';
// lib/Fleet.js — the multi-node fleet registry and poller. A "node" is another Vaultonaut instance (one of the user's
// own machines) that already exposes the monitoring endpoints (/health, /metrics). The hub keeps a small registry of
// nodes and polls each one's /health on a timer, caching the result so the web state can show a fleet-at-a-glance view
// WITHOUT any per-request or per-poll network I/O. The hub stores only a node's address and a scoped bearer token — never
// a vault key, and it never sees vault contents (a node's /health reports counts and status only). Everything here is
// non-blocking (async HTTP with bounded concurrency and hard timeouts), cross-platform (pure Node http/https, no shelled
// commands), and additive/backward-compatible (a new fleet.json an older client simply ignores).

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const Common = require('./Common');

const POLL_INTERVAL_MS = 20000; // how often the background loop refreshes every node's health
const POLL_TIMEOUT_MS = 8000;   // per-node request cap, so one unreachable node never stalls the sweep
const POLL_CONCURRENCY = 6;     // bounded fan-out
const STALE_AFTER_MS = 3 * POLL_INTERVAL_MS; // no successful poll within this long => unreachable

function registryPath() { return path.join(Common.dataDir(), 'fleet.json'); }
function normalizeUrl(u) { return String(u || '').trim().replace(/\/+$/, ''); }

const SUSTAIN_POLLS = 2; // a changed status must persist this many polls before it alerts — ignores a single blip

let nodes = null;      // [{ id, label, url, token, addedAt }] — lazy-loaded registry
const cache = new Map(); // id -> { status, lastSeen, health, error, at } — last poll result, in memory only
const alertMachine = new Map(); // id -> { current, pending, count } — the per-node hysteresis state for alerting
let alertHook = null;  // optional (transitions) => void, called after a poll when a node's status changes for real
let timer = null;

async function load() {
	if (nodes) return nodes;
	const data = await Common.readJsonCorruptAside(registryPath(), { repair: true, label: 'fleet registry' });
	nodes = (data && Array.isArray(data.nodes)) ? data.nodes : [];
	return nodes;
}
async function persist() { await Common.writeJsonAtomic(registryPath(), { nodes: nodes || [] }, { mode: 0o600, chmod: true }); }

async function listNodes() { return (await load()).map((n) => ({ id: n.id, label: n.label, url: n.url })); } // never leak the token

// Add (or update, by URL) a node. The caller has already verified reachability (see verifyAndAdd). Dedupe by URL so the
// same machine is never enrolled twice; updating replaces the token/label.
async function addNode({ label, url, token }) {
	await load();
	url = normalizeUrl(url);
	if (!/^https?:\/\//i.test(url)) throw Object.assign(new Error('A node URL must start with http:// or https://'), { code: 'BAD_URL' });
	const existing = nodes.find((n) => normalizeUrl(n.url) === url);
	const rec = { id: existing ? existing.id : crypto.randomBytes(8).toString('hex'), label: String(label || url).slice(0, 200), url: url, token: String(token || ''), addedAt: existing ? existing.addedAt : new Date().toISOString() };
	if (existing) Object.assign(existing, rec); else nodes.push(rec);
	await persist();
	return { id: rec.id };
}
async function removeNode(id) {
	await load();
	const before = nodes.length;
	nodes = nodes.filter((n) => n.id !== id);
	cache.delete(id);
	if (nodes.length !== before) await persist();
	return { removed: before - nodes.length };
}

// A single authenticated GET of a node endpoint. Bearer token in the header (never in the URL). TLS is verified for a
// remote host and skipped only for a loopback self-signed node. Hard idle+total timeout; bounded body so a hostile or
// broken peer cannot exhaust memory. Never throws — resolves { ok, status, json | error }.
function getJson(nodeUrl, token, endpoint) {
	return new Promise((resolve) => {
		let u; try { u = new URL(endpoint, nodeUrl.replace(/\/*$/, '/')); } catch (e) { return resolve({ ok: false, error: 'bad url' }); }
		const isHttps = u.protocol === 'https:';
		const mod = isHttps ? https : http;
		const loopback = Common.isLoopbackHost(u.hostname);
		const opts = { method: 'GET', headers: token ? { Authorization: 'Bearer ' + token } : {}, timeout: POLL_TIMEOUT_MS };
		if (isHttps) opts.rejectUnauthorized = !loopback; // verify a real remote; allow a loopback self-signed node
		let settled = false;
		const done = (v) => { if (!settled) { settled = true; resolve(v); } };
		let req;
		try { req = mod.request(u, opts, (res) => {
			let body = '', bytes = 0;
			res.on('data', (d) => { bytes += d.length; if (bytes > 256 * 1024) { try { req.destroy(); } catch (_) {} return done({ ok: false, error: 'response too large' }); } body += d; });
			res.on('end', () => { let json = null; try { json = JSON.parse(body); } catch (_) {} done({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: json }); });
		}); } catch (e) { return done({ ok: false, error: e && e.message || 'request failed' }); }
		req.on('error', (e) => done({ ok: false, error: e && e.message || 'unreachable' }));
		req.on('timeout', () => { try { req.destroy(); } catch (_) {} done({ ok: false, error: 'timed out' }); });
		req.end();
	});
}

// A single authenticated POST to a node endpoint — used to trigger a SAFE action on a node from the hub (lock its
// vaults, refresh its self-check). Same auth/TLS rules as the GET poller: bearer token + the CSRF header the node's
// /api guard requires, TLS verified for a remote host. Never throws — resolves { ok, status, json | error }.
function postAction(nodeUrl, token, endpoint, body) {
	return new Promise((resolve) => {
		let u; try { u = new URL(endpoint, nodeUrl.replace(/\/*$/, '/')); } catch (e) { return resolve({ ok: false, error: 'bad url' }); }
		const isHttps = u.protocol === 'https:', mod = isHttps ? https : http, loopback = Common.isLoopbackHost(u.hostname);
		const payload = JSON.stringify(body || {});
		const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-Vdisk': '1' };
		if (token) headers.Authorization = 'Bearer ' + token;
		const opts = { method: 'POST', headers: headers, timeout: POLL_TIMEOUT_MS };
		if (isHttps) opts.rejectUnauthorized = !loopback;
		let settled = false; const done = (v) => { if (!settled) { settled = true; resolve(v); } };
		let req;
		try { req = mod.request(u, opts, (res) => { let body2 = '', bytes = 0; res.on('data', (d) => { bytes += d.length; if (bytes <= 256 * 1024) body2 += d; }); res.on('end', () => { let json = null; try { json = JSON.parse(body2); } catch (_) {} done({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: json }); }); }); }
		catch (e) { return done({ ok: false, error: e && e.message || 'request failed' }); }
		req.on('error', (e) => done({ ok: false, error: e && e.message || 'unreachable' }));
		req.on('timeout', () => { try { req.destroy(); } catch (_) {} done({ ok: false, error: 'timed out' }); });
		req.write(payload); req.end();
	});
}

// The SAFE actions the hub may trigger on a node, mapped to the node's existing /api endpoint. Deliberately limited to
// non-destructive operations: locking a node (unmount everything) and refreshing its self-check. No backup/delete/etc.
const FLEET_ACTIONS = { 'lock-all': 'lock-all', 'refresh': 'selfcheck' };
async function nodeAction(id, action) {
	const node = (await load()).find((n) => n.id === id);
	if (!node) throw Object.assign(new Error('Unknown node.'), { code: 'NO_NODE' });
	const endpoint = FLEET_ACTIONS[action];
	if (!endpoint) throw Object.assign(new Error('That action is not allowed on a node.'), { code: 'BAD_ACTION' });
	const r = await postAction(node.url, node.token, '/api/' + endpoint, {});
	if (!r.ok) throw Object.assign(new Error('The node did not accept the action: ' + (r.error || ('HTTP ' + (r.status || '?'))) + '.'), { code: 'ACTION_FAILED' });
	await pollNode(node).catch(() => {}); // reflect the new state right away
	return { ok: true, action: action };
}

// Poll one node's /health and fold it into a status. Reachable + healthy => online; reachable + a self-check error =>
// degraded; a failed request => unreachable. The stored health summary is counts/status only (never findings' text).
async function pollNode(node) {
	const r = await getJson(node.url, node.token, 'health');
	const now = Date.now();
	if (!r.ok || !r.json) { const prev = cache.get(node.id) || {}; cache.set(node.id, { status: 'unreachable', lastSeen: prev.lastSeen || null, health: prev.health || null, error: r.error || ('HTTP ' + (r.status || '?')), at: now }); return cache.get(node.id); }
	const h = r.json;
	const summary = { status: h.status || 'ok', checks: h.checks || 0, warnings: h.warnings || 0, errors: h.errors || 0, version: h.version || null };
	const status = summary.status === 'error' ? 'degraded' : 'online';
	cache.set(node.id, { status: status, lastSeen: now, health: summary, error: null, at: now });
	return cache.get(node.id);
}
async function pollAll() {
	const list = await load();
	if (!list.length) return [];
	return Common.mapLimit(list, POLL_CONCURRENCY, (n) => pollNode(n).catch(() => null));
}

// A verify-before-save enroll: reach the node's /health once with the token; only persist if it answers. Returns the
// node id and its first health summary so the UI can show it immediately.
async function verifyAndAdd({ label, url, token }) {
	url = normalizeUrl(url);
	const r = await getJson(url, token, 'health');
	if (!r.ok) throw Object.assign(new Error('Could not reach that node: ' + (r.error || ('HTTP ' + (r.status || '?'))) + '. Check the address and the token.'), { code: 'UNREACHABLE' });
	const added = await addNode({ label, url, token });
	const list = await load(); const node = list.find((n) => n.id === added.id);
	if (node) await pollNode(node);
	return added;
}

// A node's effective status, folding in staleness: a node whose last successful poll is older than STALE_AFTER_MS is
// reported unreachable even if its most recent poll object still says otherwise. One place, used by snapshot and the
// transition detector, so the two can never disagree.
function effectiveStatus(c) {
	let status = (c && c.status) || 'unknown';
	if (c && c.lastSeen && (Date.now() - c.lastSeen) > STALE_AFTER_MS) status = 'unreachable';
	return status;
}

// The cached fleet snapshot for the web state — read from memory, so it never does network I/O on a page poll.
function snapshot() {
	const list = nodes || [];
	return list.map((n) => {
		const c = cache.get(n.id) || {};
		return { id: n.id, label: n.label, url: n.url, status: effectiveStatus(c), lastSeen: c.lastSeen || null, health: c.health || null, error: c.error || null };
	});
}

// Register a callback fired after a poll when a node's status changes for REAL (sustained across SUSTAIN_POLLS, so a
// single blip never alerts). The webserver sets this to push a notification; Fleet itself stays free of the notify
// dependency. A null hook (the default) simply means no alerting.
function setAlertHook(fn) { alertHook = (typeof fn === 'function') ? fn : null; }

// Walk the current statuses against the per-node hysteresis machine and return the transitions that just became
// durable, e.g. [{ id, label, from: 'online', to: 'unreachable' }]. A node's FIRST observation only sets a baseline
// (enrolling a node never fires an alert). Prunes machine entries for removed nodes. Pure over the in-memory state.
function detectTransitions() {
	const out = [], list = nodes || [];
	for (let i = 0; i < list.length; i++) {
		const n = list[i], cur = effectiveStatus(cache.get(n.id) || {});
		let m = alertMachine.get(n.id);
		if (!m) { alertMachine.set(n.id, { current: cur, pending: null, count: 0 }); continue; }
		if (cur === m.current) { m.pending = null; m.count = 0; continue; }
		if (cur === m.pending) m.count++; else { m.pending = cur; m.count = 1; }
		if (m.count >= SUSTAIN_POLLS) { out.push({ id: n.id, label: n.label, from: m.current, to: cur }); m.current = cur; m.pending = null; m.count = 0; }
	}
	for (const id of Array.from(alertMachine.keys())) if (!list.find((n) => n.id === id)) alertMachine.delete(id);
	return out;
}

// Start the background poll loop (idempotent, unref'd so it never holds the process open). Loads the registry, then
// refreshes on an interval. Failures are swallowed — a poll error simply marks that node unreachable.
// One poll cycle: refresh every node, then fire the alert hook for any status change that just became durable. Errors
// are swallowed so a bad poll or a throwing hook can never break the loop.
function tick() {
	return pollAll().then(() => {
		const tr = detectTransitions();
		if (tr.length && alertHook) { try { alertHook(tr); } catch (_) {} }
	}).catch(() => {});
}
function start() {
	if (timer) return;
	load().then(() => tick()).catch(() => {});
	timer = setInterval(() => { tick(); }, POLL_INTERVAL_MS);
	if (timer.unref) timer.unref();
}
function stop() { if (timer) { clearInterval(timer); timer = null; } }

module.exports = {
	listNodes, addNode, removeNode, verifyAndAdd, pollNode, pollAll, snapshot, start, stop,
	setAlertHook, detectTransitions, effectiveStatus, tick, nodeAction, FLEET_ACTIONS,
	POLL_INTERVAL_MS, STALE_AFTER_MS, SUSTAIN_POLLS, _reset: () => { nodes = null; cache.clear(); alertMachine.clear(); alertHook = null; },
};
