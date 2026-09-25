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

let nodes = null;      // [{ id, label, url, token, addedAt }] — lazy-loaded registry
const cache = new Map(); // id -> { status, lastSeen, health, error, at } — last poll result, in memory only
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

// The cached fleet snapshot for the web state — read from memory, so it never does network I/O on a page poll. A node
// with a lastSeen older than STALE_AFTER_MS is reported unreachable even if its last poll happened to succeed.
function snapshot() {
	const list = nodes || [];
	const now = Date.now();
	return list.map((n) => {
		const c = cache.get(n.id) || {};
		let status = c.status || 'unknown';
		if (c.lastSeen && (now - c.lastSeen) > STALE_AFTER_MS) status = 'unreachable';
		return { id: n.id, label: n.label, url: n.url, status: status, lastSeen: c.lastSeen || null, health: c.health || null, error: c.error || null };
	});
}

// Start the background poll loop (idempotent, unref'd so it never holds the process open). Loads the registry, then
// refreshes on an interval. Failures are swallowed — a poll error simply marks that node unreachable.
function start() {
	if (timer) return;
	load().then(() => pollAll()).catch(() => {});
	timer = setInterval(() => { pollAll().catch(() => {}); }, POLL_INTERVAL_MS);
	if (timer.unref) timer.unref();
}
function stop() { if (timer) { clearInterval(timer); timer = null; } }

module.exports = {
	listNodes, addNode, removeNode, verifyAndAdd, pollNode, pollAll, snapshot, start, stop,
	POLL_INTERVAL_MS, STALE_AFTER_MS, _reset: () => { nodes = null; cache.clear(); },
};
