'use strict';
// Shared devices/connectivity model — the pure logic behind the "Devices & connections" view: which connections to
// list, how to read a reachability probe's result, a bounded-concurrency runner for probing many at once without a
// flood, and a recent-activity feed assembled from data already on the state poll. It lives here (not in the browser
// bundle) so all of this is unit-tested in Node with no browser and no network, deterministically and cross-platform.
// No bundler: the page loads it with a <script> tag BEFORE app.js, and it also exports for require() in tests. ES5
// (var, function expressions — no arrow functions, no optional chaining) so it runs on the oldest supported browser.
(function (root) {
	function arr(v) { return Array.isArray(v) ? v : []; }
	function hostOf(url) { try { var m = String(url || '').match(/^[a-z]+:\/\/([^/]+)/i); return m ? m[1] : String(url || ''); } catch (e) { return String(url || ''); } }

	// The flat list of connections to show, grouped by kind. Only peers, cloud remotes, and SFTP/backup destinations are
	// TESTABLE (they have an on-demand reachability probe); a served vault is shown as live status from the poll. No
	// secret is read — passwords never reach the state, and a served vault exposes only its URL, never its contents.
	function deviceList(state) {
		var out = [];
		arr(state.peers).forEach(function (p) {
			out.push({ kind: 'peer', id: p.id, label: p.label || hostOf(p.url) || 'Device', sub: hostOf(p.url), testable: true, removable: true });
		});
		arr(state.cloudRemotes).forEach(function (c) {
			out.push({ kind: 'cloud', id: c.id, label: c.label || c.type || 'Cloud', sub: c.type || 'cloud storage', testable: true, removable: false });
		});
		arr(state.sftpDests).forEach(function (s) {
			out.push({ kind: 'sftp', id: s.id, label: s.label || s.host, sub: (s.user ? s.user + '@' : '') + s.host + (s.port && s.port !== 22 ? ':' + s.port : ''), testable: true, removable: false });
		});
		arr(state.vaults).forEach(function (v) {
			if (v && v.serving && v.serving.serving) out.push({ kind: 'serve', id: v.path, label: v.name || 'Vault', sub: v.serving.url || 'being served', testable: false, removable: false, live: true });
		});
		return out;
	}

	// Normalize a probe response into a plain reachability verdict. The three endpoints differ: the peer and SFTP tests
	// report failure text under `error`, while the cloud test reports under `detail` for BOTH success and failure (and
	// treats a missing target folder as reachable). A thrown request (network/abort) is reported as an inconclusive
	// failure, never as reachable.
	function reachabilityFrom(kind, res) {
		if (!res || typeof res !== 'object') return { reachable: false, note: 'Could not test' };
		var okFlag = !!res.ok;
		if (kind === 'cloud') return { reachable: okFlag, note: String(res.detail || (okFlag ? 'Reachable' : 'Unreachable')) };
		if (kind === 'peer') return { reachable: okFlag, note: okFlag ? ('Reachable' + (res.via ? ' · ' + res.via : '')) : String(res.error || 'Unreachable') };
		// sftp (and any other testable kind)
		return { reachable: okFlag, note: okFlag ? 'Reachable' : String(res.error || 'Unreachable') };
	}

	// Run `fn` over `items` with at most `limit` in flight at once — a bounded-concurrency map so probing many
	// connections never opens an unbounded burst of requests (which would hammer the engine and the event loop). Never
	// rejects: a failing `fn` settles that slot with { error } so one bad probe cannot abort the sweep. Results preserve
	// input order. Returns a Promise of the results array.
	function mapLimit(items, limit, fn) {
		items = arr(items);
		var n = items.length, lim = Math.max(1, Math.min(limit | 0 || 1, n || 1));
		var results = new Array(n), next = 0, done = 0;
		return new Promise(function (resolve) {
			if (!n) { resolve([]); return; }
			function start() {
				while (next < n && (next - done) < lim) {
					(function (i) {
						next++;
						Promise.resolve().then(function () { return fn(items[i], i); }).then(
							function (r) { results[i] = r; },
							function (e) { results[i] = { error: e && e.message ? e.message : String(e) }; }
						).then(function () { done++; if (done === n) resolve(results); else start(); });
					})(next);
				}
			}
			start();
		});
	}

	// A recent-activity feed assembled ONLY from what the state poll already carries — the latest backup run per vault,
	// the latest mirror sync, and the last self-check sweep — so it needs no new persistence and no extra requests. Each
	// item is { atMs, text, level }; the caller formats the time (relative) and colors by level. Newest first, capped.
	function recentActivity(state, cap) {
		var items = [];
		var sc = state.selfCheck || {};
		if (sc.at) { var t = Date.parse(sc.at); if (t) items.push({ atMs: t, text: 'System check ran', level: 'info' }); }
		arr(state.vaults).forEach(function (v) {
			if (!v) return;
			var name = v.name || 'a vault';
			var b = v.backupSchedule || {};
			if (b.lastRunAt) { var bt = Date.parse(b.lastRunAt); if (bt) { var bad = typeof b.lastResult === 'string' && b.lastResult.indexOf('error') === 0; items.push({ atMs: bt, text: 'Backup of ' + name + (bad ? ' failed' : ' ran'), level: bad ? 'error' : 'good' }); } }
			var m = v.mirror || {};
			if (m.configured && m.lastSyncAt) { var mt = Date.parse(m.lastSyncAt); if (mt) items.push({ atMs: mt, text: 'Mirror of ' + name + ' synced', level: (m.lastConflicts ? 'warn' : 'good') }); }
		});
		items.sort(function (a, b) { return b.atMs - a.atMs; });
		return items.slice(0, cap || 8);
	}

	root.VaultDevices = { deviceList: deviceList, reachabilityFrom: reachabilityFrom, mapLimit: mapLimit, recentActivity: recentActivity };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultDevices;
