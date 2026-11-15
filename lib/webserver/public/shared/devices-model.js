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

	// User-facing text comes from this catalog through the shared i18n helper (one {var} template per string), never
	// built with "+". Server-supplied strings (a probe's own detail/error message, an address) are shown as given.
	var I18n = (typeof require === 'function') ? require('./i18n') : (root.VaultI18n || null);
	var STRINGS = {
		en: {
			deviceFallback: 'Device', cloudFallback: 'Cloud', cloudStorage: 'cloud storage', vaultFallback: 'Vault', beingServed: 'being served',
			couldNotTest: 'Could not test', reachable: 'Reachable', unreachable: 'Unreachable', reachableVia: 'Reachable · {via}',
			systemCheckRan: 'System check ran', aVault: 'a vault',
			kindPeer: 'Paired device', kindCloud: 'Cloud storage', kindSftp: 'Backup destination', kindServe: 'Serving',
			backupRan: 'Backup of {name} ran', backupFailed: 'Backup of {name} failed', mirrorSynced: 'Mirror of {name} synced'
		}
	};
	function T(lang, key, vars) { return I18n ? I18n.t(STRINGS, lang, key, vars) : key; }

	// The flat list of connections to show, grouped by kind. Only peers, cloud remotes, and SFTP/backup destinations are
	// TESTABLE (they have an on-demand reachability probe); a served vault is shown as live status from the poll. No
	// secret is read — passwords never reach the state, and a served vault exposes only its URL, never its contents.
	function deviceList(state, lang) {
		lang = lang || 'en';
		var out = [];
		arr(state.peers).forEach(function (p) {
			out.push({ kind: 'peer', id: p.id, label: p.label || hostOf(p.url) || T(lang, 'deviceFallback'), sub: hostOf(p.url), testable: true, removable: true });
		});
		arr(state.cloudRemotes).forEach(function (c) {
			out.push({ kind: 'cloud', id: c.id, label: c.label || c.type || T(lang, 'cloudFallback'), sub: c.type || T(lang, 'cloudStorage'), testable: true, removable: false });
		});
		arr(state.sftpDests).forEach(function (s) {
			out.push({ kind: 'sftp', id: s.id, label: s.label || s.host, sub: (s.user ? s.user + '@' : '') + s.host + (s.port && s.port !== 22 ? ':' + s.port : ''), testable: true, removable: false });
		});
		arr(state.vaults).forEach(function (v) {
			if (v && v.serving && v.serving.serving) out.push({ kind: 'serve', id: v.path, label: v.name || T(lang, 'vaultFallback'), sub: v.serving.url || T(lang, 'beingServed'), testable: false, removable: false, live: true });
		});
		return out;
	}

	// Normalize a probe response into a plain reachability verdict. The three endpoints differ: the peer and SFTP tests
	// report failure text under `error`, while the cloud test reports under `detail` for BOTH success and failure (and
	// treats a missing target folder as reachable). A thrown request (network/abort) is reported as an inconclusive
	// failure, never as reachable.
	function reachabilityFrom(kind, res, lang) {
		lang = lang || 'en';
		if (!res || typeof res !== 'object') return { reachable: false, note: T(lang, 'couldNotTest') };
		var okFlag = !!res.ok;
		if (kind === 'cloud') return { reachable: okFlag, note: String(res.detail || (okFlag ? T(lang, 'reachable') : T(lang, 'unreachable'))) };
		if (kind === 'peer') return { reachable: okFlag, note: okFlag ? (res.via ? T(lang, 'reachableVia', { via: res.via }) : T(lang, 'reachable')) : String(res.error || T(lang, 'unreachable')) };
		// sftp (and any other testable kind)
		return { reachable: okFlag, note: okFlag ? T(lang, 'reachable') : String(res.error || T(lang, 'unreachable')) };
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
	function recentActivity(state, cap, lang) {
		lang = lang || 'en';
		var items = [];
		var sc = state.selfCheck || {};
		if (sc.at) { var t = Date.parse(sc.at); if (t) items.push({ atMs: t, text: T(lang, 'systemCheckRan'), level: 'info' }); }
		arr(state.vaults).forEach(function (v) {
			if (!v) return;
			var name = v.name || T(lang, 'aVault');
			var b = v.backupSchedule || {};
			if (b.lastRunAt) { var bt = Date.parse(b.lastRunAt); if (bt) { var bad = typeof b.lastResult === 'string' && b.lastResult.indexOf('error') === 0; items.push({ atMs: bt, text: T(lang, bad ? 'backupFailed' : 'backupRan', { name: name }), level: bad ? 'error' : 'good' }); } }
			var m = v.mirror || {};
			if (m.configured && m.lastSyncAt) { var mt = Date.parse(m.lastSyncAt); if (mt) items.push({ atMs: mt, text: T(lang, 'mirrorSynced', { name: name }), level: (m.lastConflicts ? 'warn' : 'good') }); }
		});
		items.sort(function (a, b) { return b.atMs - a.atMs; });
		return items.slice(0, cap || 8);
	}

	// The display label for a connection kind — one source, so the rendered row and any future surface agree and a
	// locale translates it in the catalog. An unknown kind falls back to the kind string itself (never a crash).
	function deviceKindLabel(kind, lang) {
		var key = { peer: 'kindPeer', cloud: 'kindCloud', sftp: 'kindSftp', serve: 'kindServe' }[kind];
		return key ? T(lang, key) : String(kind == null ? '' : kind);
	}

	root.VaultDevices = { deviceList: deviceList, reachabilityFrom: reachabilityFrom, mapLimit: mapLimit, recentActivity: recentActivity, deviceKindLabel: deviceKindLabel, STRINGS: STRINGS };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultDevices;
