'use strict';
// Shared dashboard model — the single, pure function that turns a /api/state snapshot into the dashboard's tiles.
// It lives here (not in the browser bundle) so the exact same logic is unit-tested in Node with no browser: the tests
// feed it synthetic states and assert each tile's level and text, which is deterministic and cross-platform. There is
// no bundler (the app serves static files), so this attaches one small global that the page loads with a <script> tag
// BEFORE its app code, and also exports for require() in tests. Written in ES5 (var, function expressions — no arrow
// functions, no optional chaining) so it runs on the oldest browser the clients support.
//
// computeDashboard(state, fmtBytes) -> [ { id, title, level, value, detail, action } ]
//   level is one of 'good' | 'warn' | 'error' | 'info' | 'neutral' — the renderer maps it to a color token, never the
//   other way round, so severity is decided in one place. `value` is the headline; `detail` is an optional second line.
//   `action` is an optional key naming where the tile takes you when clicked (the renderer maps the key to a jump into
//   the matching setup/management area, so the dashboard is a launchpad, not just a readout); a tile with no action is
//   a plain status card. fmtBytes is the client's byte formatter, passed in so the gauge text matches the rest of the
//   UI exactly; a small built-in is used when it is absent (the tests call without one). The function reads ONLY fields
//   that are safe to show, and in particular never reads a size or file count for a locked (not-mounted) vault — a
//   locked vault must never disclose its contents, and the state carries no such field, so the tile counts status only.
(function (root) {
	function defaultBytes(n) {
		n = Number(n); if (!isFinite(n) || n < 0) return '';
		if (n < 1024) return n + ' B';
		var units = ['KB', 'MB', 'GB', 'TB', 'PB'], i = -1;
		do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
		return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
	}
	function arr(v) { return Array.isArray(v) ? v : []; }

	function healthTile(state) {
		// The environment banner already surfaces engine/driver readiness (and there is a dedicated engine tile), so drop
		// those two findings here to avoid showing the same problem twice. Everything else — including the event-loop and
		// heap-headroom checks and the overdue/failed-backup findings — rolls up into this one health verdict.
		var sc = state.selfCheck || {};
		var findings = arr(sc.findings).filter(function (f) { return f && f.check !== 'engine' && f.check !== 'driver'; });
		var errors = findings.filter(function (f) { return f.level === 'error'; }).length;
		if (!findings.length) return { id: 'health', title: 'System health', level: 'good', value: 'All systems normal', detail: '', action: 'notifications' };
		var level = errors ? 'error' : 'warn';
		var n = findings.length;
		return {
			id: 'health', title: 'System health', level: level,
			value: n + (n === 1 ? ' item to review' : ' items to review'),
			detail: String((findings[0] && findings[0].message) || ''),
			action: 'notifications'
		};
	}

	function vaultsTile(state) {
		var vaults = arr(state.vaults);
		var total = vaults.length;
		var unlocked = 0, attention = 0;
		for (var i = 0; i < vaults.length; i++) {
			var v = vaults[i] || {};
			if (v.mounted) unlocked++;
			// health is null when locked; only a mounted-but-wedged drive needs attention. No size/count is read here.
			if (v.mounted && (v.health === 'unresponsive' || v.health === 'dead')) attention++;
		}
		if (!total) return { id: 'vaults', title: 'Vaults', level: 'neutral', value: 'No vaults yet', detail: '', action: 'vaults' };
		var level = attention ? 'error' : 'good';
		return {
			id: 'vaults', title: 'Vaults', level: level,
			value: unlocked + ' unlocked · ' + total + (total === 1 ? ' vault' : ' vaults'),
			detail: attention ? (attention + (attention === 1 ? ' vault is not responding' : ' vaults are not responding')) : (total - unlocked) + ' locked',
			action: 'vaults'
		};
	}

	function backupsTile(state) {
		// Which schedules are overdue is worked out authoritatively by the server's schedule_health self-check, so it is
		// not re-derived here (it surfaces in the health tile). This tile counts what is scheduled and what last failed.
		var vaults = arr(state.vaults);
		var scheduled = 0, failed = 0, newest = 0;
		for (var i = 0; i < vaults.length; i++) {
			var s = (vaults[i] || {}).backupSchedule || {};
			if (!s.mode || s.mode === 'off') continue;
			scheduled++;
			if (typeof s.lastResult === 'string' && s.lastResult.indexOf('error') === 0) failed++;
			var t = s.lastRunAt ? Date.parse(s.lastRunAt) : 0;
			if (t && t > newest) newest = t;
		}
		// Backups, mirroring, and serving are all set up per vault on the vault cards, so every one of those tiles takes
		// you to the vault list — the one place to configure and manage them, whether or not any are set up yet.
		if (!scheduled) return { id: 'backups', title: 'Backups', level: 'neutral', value: 'None scheduled', detail: 'Set up a backup on any vault', action: 'vaults' };
		var level = failed ? 'error' : 'good';
		return {
			id: 'backups', title: 'Backups', level: level,
			value: scheduled + (scheduled === 1 ? ' schedule' : ' schedules'),
			detail: failed ? (failed + ' failed recently') : (newest ? 'Last run ' + new Date(newest).toLocaleString() : 'Scheduled'),
			action: 'vaults'
		};
	}

	function connectivityTile(state) {
		// Only CONFIGURED counts are shown — live reachability is not on the poll (it is an on-demand test), so this tile
		// never claims a peer or remote is "connected" from stale data. It also shows how many vaults are actively served.
		var peers = arr(state.peers).length;
		var remotes = arr(state.cloudRemotes).length + arr(state.sftpDests).length;
		var serving = 0;
		var vaults = arr(state.vaults);
		for (var i = 0; i < vaults.length; i++) { var sv = (vaults[i] || {}).serving; if (sv && sv.serving) serving++; }
		if (!peers && !remotes && !serving) return { id: 'connectivity', title: 'Connectivity', level: 'neutral', value: 'Nothing configured', detail: 'Serve or mirror from any vault', action: 'vaults' };
		var parts = [];
		if (peers) parts.push(peers + (peers === 1 ? ' device' : ' devices'));
		if (remotes) parts.push(remotes + (remotes === 1 ? ' remote' : ' remotes'));
		return {
			id: 'connectivity', title: 'Connectivity', level: 'info',
			value: parts.length ? parts.join(' · ') : 'Configured',
			detail: serving ? (serving + (serving === 1 ? ' vault is being served' : ' vaults are being served')) : '',
			action: 'vaults'
		};
	}

	function engineTile(state) {
		var d = state.doctor || {}, engine = d.engine || {}, driver = d.driver || {};
		if (engine.ok && driver.ok) return { id: 'engine', title: 'Engine & driver', level: 'good', value: 'Ready', detail: '' };
		if (!engine.ok && engine.downloading) return { id: 'engine', title: 'Engine & driver', level: 'info', value: 'Setting up…', detail: 'Downloading the storage engine on first run.' };
		if (!engine.ok) return { id: 'engine', title: 'Engine & driver', level: 'error', value: 'Engine not ready', detail: 'The storage engine is unavailable.', action: 'engine' };
		// engine ok, driver not — mounting as a drive needs the driver; the in-app viewer still works without it.
		return { id: 'engine', title: 'Engine & driver', level: 'warn', value: 'Driver needs attention', detail: String(driver.warn || driver.detail || 'The mount driver is not fully ready.'), action: 'engine' };
	}

	function updateTile(state) {
		var u = (state.settings && state.settings.updateStatus) || null;
		if (!u || !u.current) return null; // no check has run yet — omit the tile rather than show an empty one
		if (u.updateAvailable) return { id: 'update', title: 'Version', level: 'info', value: 'Update available', detail: 'You have ' + String(u.current) + (u.latest ? '; ' + String(u.latest) + ' is out.' : '.'), action: 'update' };
		return { id: 'update', title: 'Version', level: 'good', value: 'Up to date', detail: String(u.current) };
	}

	function diskTile(state, fmtBytes) {
		var vols = arr(state.disk);
		if (!vols.length) return null; // the periodic disk check has not reported yet — omit rather than guess
		// Show the tightest volume (least free), since that is the one that will bite first when copying a large file in.
		var tight = null;
		for (var i = 0; i < vols.length; i++) { var v = vols[i]; if (!v || typeof v.pctFree !== 'number') continue; if (!tight || v.pctFree < tight.pctFree) tight = v; }
		if (!tight) return null;
		var freeGiB = tight.freeBytes / 1073741824;
		var level = (tight.pctFree < 5 || freeGiB < 2) ? 'error' : ((tight.pctFree < 10 || freeGiB < 5) ? 'warn' : 'good');
		return {
			id: 'disk', title: 'Disk space', level: level,
			value: Math.round(tight.pctFree) + '% free',
			detail: fmtBytes(tight.freeBytes) + ' free of ' + fmtBytes(tight.totalBytes)
		};
	}

	function computeDashboard(state, fmtBytes) {
		state = state || {};
		var fmt = (typeof fmtBytes === 'function') ? fmtBytes : defaultBytes;
		var tiles = [
			healthTile(state),
			vaultsTile(state),
			diskTile(state, fmt),
			backupsTile(state),
			connectivityTile(state),
			engineTile(state),
			updateTile(state)
		];
		// Drop the tiles that opted out (returned null): update before any check, disk before the first sweep.
		return tiles.filter(function (t) { return !!t; });
	}

	root.VaultDashboard = { computeDashboard: computeDashboard };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultDashboard;
