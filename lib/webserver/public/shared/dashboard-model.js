'use strict';
// Shared dashboard model — the single, pure function that turns a /api/state snapshot into the dashboard's tiles.
// It lives here (not in the browser bundle) so the exact same logic is unit-tested in Node with no browser: the tests
// feed it synthetic states and assert each tile's level and text, which is deterministic and cross-platform. There is
// no bundler (the app serves static files), so this attaches one small global that the page loads with a <script> tag
// BEFORE its app code, and also exports for require() in tests. Written in ES5 (var, function expressions — no arrow
// functions, no optional chaining) so it runs on the oldest browser the clients support.
//
// Every user-facing string comes from the STRINGS catalog below via the shared i18n helper (one {var} template per
// string, plural forms chosen by the locale's rule) — the model never builds a sentence with "+" or hardcodes an
// English plural, so it is translation-ready and a locale is just another key in the catalog.
//
// computeDashboard(state, fmtBytes, lang) -> [ { id, title, level, value, detail, action } ]
//   level is one of 'good' | 'warn' | 'error' | 'info' | 'neutral' — the renderer maps it to a color token, never the
//   other way round, so severity is decided in one place. `value` is the headline; `detail` is an optional second line.
//   `action` is an optional key naming where the tile takes you when clicked (the renderer maps the key to a jump into
//   the matching setup/management area, so the dashboard is a launchpad, not just a readout); a tile with no action is
//   a plain status card. fmtBytes is the client's byte formatter, passed in so the gauge text matches the rest of the
//   UI exactly; a small built-in is used when it is absent (the tests call without one). `lang` defaults to 'en'. The
//   function reads ONLY fields that are safe to show, and in particular never reads a size or file count for a locked
//   (not-mounted) vault — a locked vault must never disclose its contents, and the state carries no such field.
(function (root) {
	var I18n = (typeof require === 'function') ? require('./i18n') : (root.VaultI18n || null);

	var STRINGS = {
		en: {
			t_health: 'System health', t_vaults: 'Vaults', t_backups: 'Backups', t_connectivity: 'Connectivity',
			t_engine: 'Engine & driver', t_version: 'Version', t_disk: 'Disk space', t_perf: 'Performance',
			allNormal: 'All systems normal', pillWarn: 'Needs a look', pillError: 'Attention needed',
			reviewItems_one: '{n} item to review', reviewItems_other: '{n} items to review',
			noVaults: 'No vaults yet',
			vaultsValue_one: '{unlocked} unlocked · {n} vault', vaultsValue_other: '{unlocked} unlocked · {n} vaults',
			notResponding_one: '{n} vault is not responding', notResponding_other: '{n} vaults are not responding',
			lockedCount: '{n} locked',
			noneScheduled: 'None scheduled', setUpBackup: 'Set up a backup on any vault',
			schedules_one: '{n} schedule', schedules_other: '{n} schedules',
			failedRecently: '{n} failed recently', lastRun: 'Last run {when}', scheduled: 'Scheduled',
			nothingConfigured: 'Nothing configured', serveOrMirror: 'Serve or mirror from any vault',
			devices_one: '{n} device', devices_other: '{n} devices',
			remotes_one: '{n} remote', remotes_other: '{n} remotes',
			configured: 'Configured',
			served_one: '{n} vault is being served', served_other: '{n} vaults are being served',
			ready: 'Ready', settingUp: 'Setting up…', settingUpDetail: 'Downloading the storage engine on first run.',
			engineNotReady: 'Engine not ready', engineUnavailable: 'The storage engine is unavailable.',
			driverAttention: 'Driver needs attention', driverNotReady: 'The mount driver is not fully ready.',
			updateAvailable: 'Update available',
			youHave: 'You have {current}.', youHaveOut: 'You have {current}; {latest} is out.',
			upToDate: 'Up to date',
			pctFree: '{pct}% free', diskDetail: '{free} free of {total}', diskDetailLabel: '{free} free of {total} · {label}',
			pctMemory: '{pct}% memory', responseDelay: 'Response delay {ms} ms'
		}
	};
	function T(lang, key, vars) { return I18n ? I18n.t(STRINGS, lang, key, vars) : key; }

	function defaultBytes(n) {
		n = Number(n); if (!isFinite(n) || n < 0) return '';
		if (n < 1024) return n + ' B';
		var units = ['KB', 'MB', 'GB', 'TB', 'PB'], i = -1;
		do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
		return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
	}
	function arr(v) { return Array.isArray(v) ? v : []; }

	function healthTile(state, lang) {
		// The environment banner already surfaces engine/driver readiness (and there is a dedicated engine tile), so drop
		// those two findings here to avoid showing the same problem twice. Everything else — including the event-loop and
		// heap-headroom checks and the overdue/failed-backup findings — rolls up into this one health verdict.
		var sc = state.selfCheck || {};
		var findings = arr(sc.findings).filter(function (f) { return f && f.check !== 'engine' && f.check !== 'driver'; });
		var errors = findings.filter(function (f) { return f.level === 'error'; }).length;
		if (!findings.length) return { id: 'health', title: T(lang, 't_health'), level: 'good', value: T(lang, 'allNormal'), detail: '', action: 'notifications' };
		return {
			id: 'health', title: T(lang, 't_health'), level: errors ? 'error' : 'warn',
			value: T(lang, 'reviewItems', { n: findings.length }),
			detail: String((findings[0] && findings[0].message) || ''),
			action: 'notifications'
		};
	}

	function vaultsTile(state, lang) {
		var vaults = arr(state.vaults);
		var total = vaults.length;
		var unlocked = 0, attention = 0;
		for (var i = 0; i < vaults.length; i++) {
			var v = vaults[i] || {};
			if (v.mounted) unlocked++;
			// health is null when locked; only a mounted-but-wedged drive needs attention. No size/count is read here.
			if (v.mounted && (v.health === 'unresponsive' || v.health === 'dead')) attention++;
		}
		if (!total) return { id: 'vaults', title: T(lang, 't_vaults'), level: 'neutral', value: T(lang, 'noVaults'), detail: '', action: 'vaults' };
		return {
			id: 'vaults', title: T(lang, 't_vaults'), level: attention ? 'error' : 'good',
			value: T(lang, 'vaultsValue', { unlocked: unlocked, n: total }),
			detail: attention ? T(lang, 'notResponding', { n: attention }) : T(lang, 'lockedCount', { n: (total - unlocked) }),
			action: 'vaults'
		};
	}

	function backupsTile(state, lang) {
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
		if (!scheduled) return { id: 'backups', title: T(lang, 't_backups'), level: 'neutral', value: T(lang, 'noneScheduled'), detail: T(lang, 'setUpBackup'), action: 'vaults' };
		return {
			id: 'backups', title: T(lang, 't_backups'), level: failed ? 'error' : 'good',
			value: T(lang, 'schedules', { n: scheduled }),
			detail: failed ? T(lang, 'failedRecently', { n: failed }) : (newest ? T(lang, 'lastRun', { when: new Date(newest).toLocaleString() }) : T(lang, 'scheduled')),
			action: 'vaults'
		};
	}

	function connectivityTile(state, lang) {
		// Only CONFIGURED counts are shown — live reachability is not on the poll (it is an on-demand test), so this tile
		// never claims a peer or remote is "connected" from stale data. It also shows how many vaults are actively served.
		var peers = arr(state.peers).length;
		var remotes = arr(state.cloudRemotes).length + arr(state.sftpDests).length;
		var serving = 0;
		var vaults = arr(state.vaults);
		for (var i = 0; i < vaults.length; i++) { var sv = (vaults[i] || {}).serving; if (sv && sv.serving) serving++; }
		if (!peers && !remotes && !serving) return { id: 'connectivity', title: T(lang, 't_connectivity'), level: 'neutral', value: T(lang, 'nothingConfigured'), detail: T(lang, 'serveOrMirror'), action: 'devices' };
		var parts = [];
		if (peers) parts.push(T(lang, 'devices', { n: peers }));
		if (remotes) parts.push(T(lang, 'remotes', { n: remotes }));
		return {
			id: 'connectivity', title: T(lang, 't_connectivity'), level: 'info',
			value: parts.length ? parts.join(' · ') : T(lang, 'configured'),
			detail: serving ? T(lang, 'served', { n: serving }) : '',
			action: 'devices'
		};
	}

	function engineTile(state, lang) {
		var d = state.doctor || {}, engine = d.engine || {}, driver = d.driver || {};
		if (engine.ok && driver.ok) return { id: 'engine', title: T(lang, 't_engine'), level: 'good', value: T(lang, 'ready'), detail: '' };
		if (!engine.ok && engine.downloading) return { id: 'engine', title: T(lang, 't_engine'), level: 'info', value: T(lang, 'settingUp'), detail: T(lang, 'settingUpDetail') };
		if (!engine.ok) return { id: 'engine', title: T(lang, 't_engine'), level: 'error', value: T(lang, 'engineNotReady'), detail: T(lang, 'engineUnavailable'), action: 'engine' };
		// engine ok, driver not — mounting as a drive needs the driver; the in-app viewer still works without it.
		return { id: 'engine', title: T(lang, 't_engine'), level: 'warn', value: T(lang, 'driverAttention'), detail: String(driver.warn || driver.detail || T(lang, 'driverNotReady')), action: 'engine' };
	}

	function updateTile(state, lang) {
		var u = (state.settings && state.settings.updateStatus) || null;
		if (!u || !u.current) return null; // no check has run yet — omit the tile rather than show an empty one
		if (u.updateAvailable) return { id: 'update', title: T(lang, 't_version'), level: 'info', value: T(lang, 'updateAvailable'), detail: u.latest ? T(lang, 'youHaveOut', { current: String(u.current), latest: String(u.latest) }) : T(lang, 'youHave', { current: String(u.current) }), action: 'update' };
		return { id: 'update', title: T(lang, 't_version'), level: 'good', value: T(lang, 'upToDate'), detail: String(u.current) };
	}

	function diskTile(state, fmtBytes, lang) {
		var vols = arr(state.disk);
		if (!vols.length) return null; // the periodic disk check has not reported yet — omit rather than guess
		// Show the tightest volume (least free), since that is the one that will bite first when copying a large file in.
		var tight = null;
		for (var i = 0; i < vols.length; i++) { var v = vols[i]; if (!v || typeof v.pctFree !== 'number') continue; if (!tight || v.pctFree < tight.pctFree) tight = v; }
		if (!tight) return null;
		var freeGiB = tight.freeBytes / 1073741824;
		var level = (tight.pctFree < 5 || freeGiB < 2) ? 'error' : ((tight.pctFree < 10 || freeGiB < 5) ? 'warn' : 'good');
		var free = fmtBytes(tight.freeBytes), tot = fmtBytes(tight.totalBytes);
		return {
			id: 'disk', title: T(lang, 't_disk'), level: level,
			value: T(lang, 'pctFree', { pct: Math.round(tight.pctFree) }),
			// Name WHICH disk this reading is about: the gauge shows the tightest volume, so a near-full external drive
			// would otherwise be misread as the system disk when they differ. The label is server-supplied and privacy-safe.
			detail: tight.label ? T(lang, 'diskDetailLabel', { free: free, total: tot, label: tight.label }) : T(lang, 'diskDetail', { free: free, total: tot })
		};
	}

	function perfTile(state, lang) {
		// A live trend of event-loop lag and heap use, from the in-memory sample ring. Omitted until there is at least
		// one sample. `spark` carries the two series so the renderer can draw sparklines; the model stays pure and the
		// severity is decided here (warn when the newest sample crosses the same thresholds the self-check probes use).
		var perf = arr(state.perf);
		if (!perf.length) return null;
		var last = perf[perf.length - 1] || {};
		var heapPct = Math.round(last.heapPct || 0);
		var lag = Math.round(last.loopLagMs || 0);
		var level = (heapPct >= 90 || lag >= 1000) ? 'warn' : 'good';
		return {
			id: 'perf', title: T(lang, 't_perf'), level: level,
			value: T(lang, 'pctMemory', { pct: heapPct }),
			detail: T(lang, 'responseDelay', { ms: lag }),
			spark: { heap: perf.map(function (p) { return Number(p.heapPct) || 0; }), lag: perf.map(function (p) { return Number(p.loopLagMs) || 0; }) }
		};
	}

	function computeDashboard(state, fmtBytes, lang) {
		state = state || {};
		lang = lang || 'en';
		var fmt = (typeof fmtBytes === 'function') ? fmtBytes : defaultBytes;
		var tiles = [
			healthTile(state, lang),
			vaultsTile(state, lang),
			diskTile(state, fmt, lang),
			perfTile(state, lang),
			backupsTile(state, lang),
			connectivityTile(state, lang),
			engineTile(state, lang),
			updateTile(state, lang)
		];
		// Drop the tiles that opted out (returned null): update before any check, disk before the first sweep.
		return tiles.filter(function (t) { return !!t; });
	}

	// The single overall verdict for the header status pill: 'error' if anything is wrong, 'warn' if anything wants a
	// look, otherwise 'ok'. Informational tiles (an available update, configured connectivity) do not count as trouble.
	function overall(tiles) {
		var worst = 'ok';
		for (var i = 0; i < tiles.length; i++) {
			var l = tiles[i] && tiles[i].level;
			if (l === 'error') return 'error';
			if (l === 'warn') worst = 'warn';
		}
		return worst;
	}

	// The header status pill's text for an overall() verdict — one place, so the pill and the health tile never drift
	// apart and a locale only has to translate the catalog. 'ok' reuses the tile's own "all normal" string.
	function statusPillText(level, lang) {
		if (level === 'error') return T(lang, 'pillError');
		if (level === 'warn') return T(lang, 'pillWarn');
		return T(lang, 'allNormal');
	}

	root.VaultDashboard = { computeDashboard: computeDashboard, overall: overall, statusPillText: statusPillText, STRINGS: STRINGS };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultDashboard;
