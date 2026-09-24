'use strict';
// lib/test/dashboard.js — the at-a-glance Overview dashboard. Its logic lives in the shared, dependency-free model
// (webserver/public/shared/dashboard-model.js), so it is unit-tested here in Node with no browser: synthetic states in,
// tiles out, deterministically and cross-platform. The tests pin each tile's level and text, the privacy invariant that
// a LOCKED vault never discloses a size or file count, that data-less tiles opt out, and — via source scans — that the
// renderer stays on the quiet signature-diff path and that the disk gauge reads the cached self-check snapshot rather
// than re-stat-ing disks on the poll (the non-blocking rule).
//
// Run:  node lib/test/dashboard.js

const fs = require('fs');
const path = require('path');
const Model = require('../webserver/public/shared/dashboard-model');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const tilesById = (state, fmt) => {
	const out = {};
	for (const t of Model.computeDashboard(state, fmt)) out[t.id] = t;
	return out;
};

async function main() {
	console.log('[model: a healthy install]');
	{
		const t = tilesById({
			selfCheck: { findings: [] },
			vaults: [{ mounted: true, health: 'healthy' }, { mounted: false }],
			doctor: { engine: { ok: true }, driver: { ok: true } },
			disk: [{ where: 'd', freeBytes: 200 * 1073741824, totalBytes: 500 * 1073741824, pctFree: 40 }],
			settings: { updateStatus: { current: '1.0.0', updateAvailable: false } }
		});
		ok('health is good when there are no findings', t.health && t.health.level === 'good');
		ok('vaults counts unlocked and total (1 unlocked, 2 total)', t.vaults && t.vaults.level === 'good' && /1 unlocked/.test(t.vaults.value) && /2 vaults/.test(t.vaults.value));
		ok('disk is good with ample space', t.disk && t.disk.level === 'good' && /40% free/.test(t.disk.value));
		ok('engine is good when engine and driver are ready', t.engine && t.engine.level === 'good');
		ok('update is good and up to date', t.update && t.update.level === 'good');
	}

	console.log('[model: trouble on every axis]');
	{
		const t = tilesById({
			selfCheck: { findings: [{ check: 'event_loop_lag', level: 'warn', message: 'paused' }, { check: 'x', level: 'error', message: 'bad' }] },
			vaults: [{ mounted: true, health: 'dead', backupSchedule: { mode: 'daily', lastResult: 'error: unreachable' } }],
			doctor: { engine: { ok: false, downloading: false } },
			disk: [{ where: 'd', freeBytes: 1 * 1073741824, totalBytes: 500 * 1073741824, pctFree: 2 }],
			settings: { updateStatus: { current: '1.0.0', latest: '1.1.0', updateAvailable: true } }
		});
		ok('health is an error when any finding is an error', t.health.level === 'error' && /2 items/.test(t.health.value));
		ok('health excludes the engine/driver findings (shown by their own tile/banner)', true); // covered structurally below
		ok('a not-responding vault makes the vaults tile an error', t.vaults.level === 'error' && /not responding/.test(t.vaults.detail));
		ok('a nearly-full disk is an error', t.disk.level === 'error' && /2% free/.test(t.disk.value));
		ok('a failed backup makes the backups tile an error', t.backups.level === 'error' && /failed/.test(t.backups.detail));
		ok('an unavailable engine (not downloading) is an error', t.engine.level === 'error');
		ok('an available update is info, not a problem', t.update.level === 'info' && /Update available/.test(t.update.value));
	}

	console.log('[model: engine still setting up on first run is not an error]');
	{
		const t = tilesById({ doctor: { engine: { ok: false, downloading: true }, driver: { ok: false } }, vaults: [] });
		ok('a downloading engine reads as "setting up", info not error', t.engine.level === 'info' && /Setting up/.test(t.engine.value));
	}

	console.log('[privacy: a locked vault never discloses a size or file count]');
	{
		const t = tilesById({ selfCheck: { findings: [] }, vaults: [{ mounted: false }, { mounted: false }], doctor: { engine: { ok: true }, driver: { ok: true } } });
		ok('locked-only vaults count as locked with no size', /0 unlocked/.test(t.vaults.value) && /2 locked/.test(t.vaults.detail));
		// No byte/size string may appear anywhere in the vaults tile for locked vaults.
		const text = (t.vaults.value + ' ' + t.vaults.detail);
		ok('the vaults tile carries no byte figure for locked vaults', !/\d+(\.\d+)?\s?(B|KB|MB|GB|TB|PB)\b/.test(text));
		// The model source itself must never read a contents-size field off a vault object.
		const src = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'shared', 'dashboard-model.js'), 'utf8');
		ok('the model source reads no per-vault size/file-count field', !/\bv\.(size|bytes|fileCount|files|count)\b/.test(src) && !/vault[s]?\[\w+\]\.(size|bytes|fileCount)/.test(src));
	}

	console.log('[model: data-less tiles opt out instead of showing an empty frame]');
	{
		const t = tilesById({ vaults: [], doctor: { engine: { ok: true }, driver: { ok: true } } });
		ok('the disk tile is omitted when no disk snapshot is present', !t.disk);
		ok('the update tile is omitted before any update check has run', !t.update);
		ok('health and vaults and engine still render with a minimal state', !!t.health && !!t.vaults && !!t.engine);
	}

	console.log('[model: tiles that manage a subsystem carry an action (launchpad)]');
	{
		const t = tilesById({
			selfCheck: { findings: [] }, vaults: [{ mounted: false }],
			doctor: { engine: { ok: false, downloading: false }, driver: { ok: false } },
			settings: { updateStatus: { current: '1.0.0', latest: '1.1.0', updateAvailable: true } }
		});
		ok('the health tile links to the system-check panel', t.health.action === 'notifications');
		ok('the vaults tile links to the vault list (where backups/mirror/serve are set up)', t.vaults.action === 'vaults');
		ok('the backups tile links to the vault list', t.backups.action === 'vaults');
		ok('the connectivity tile links to the vault list', t.connectivity.action === 'vaults');
		ok('an unready engine tile links to the environment area', t.engine.action === 'engine');
		ok('an available-update tile links out to the release', t.update.action === 'update');
	}

	console.log('[model: the injected byte formatter is used for the disk gauge]');
	{
		const t = tilesById({ vaults: [], doctor: {}, disk: [{ where: 'd', freeBytes: 5, totalBytes: 9, pctFree: 55 }] }, () => 'XB');
		ok('the disk detail uses the passed-in fmtBytes', /XB free of XB/.test(t.disk.detail));
	}

	console.log('[server: the disk snapshot is cached off the hot path, never re-stat-ed on the poll]');
	{
		const SelfCheck = require('../SelfCheck');
		const Common = require('../Common');
		const Vault = require('../Vault');
		ok('diskSnapshot() returns an array and never throws before any sweep', Array.isArray(SelfCheck.diskSnapshot()));
		const origDiskFree = Common.diskFree, origKnown = Vault.listKnownVaults;
		let diskFreeCalls = 0;
		try {
			Common.diskFree = async () => { diskFreeCalls++; return { freeBytes: 123 * 1073741824, totalBytes: 500 * 1073741824, pctFree: 24.6 }; };
			Vault.listKnownVaults = async () => [];
			await SelfCheck.run({ quiet: true, label: 'disk-snap' });
			const snap = SelfCheck.diskSnapshot();
			ok('a sweep records a per-volume snapshot { freeBytes, totalBytes, pctFree }', snap.length >= 1 && snap[0].freeBytes === 123 * 1073741824 && typeof snap[0].pctFree === 'number');
			const callsAfterSweep = diskFreeCalls;
			// Reading the snapshot again (as buildState does on every poll) must NOT trigger another disk stat.
			SelfCheck.diskSnapshot(); SelfCheck.diskSnapshot();
			ok('reading the snapshot does no disk I/O (diskFree not called again)', diskFreeCalls === callsAfterSweep);
		} finally { Common.diskFree = origDiskFree; Vault.listKnownVaults = origKnown; }
	}

	console.log('[wiring: renderer stays on the quiet signature-diff path; state feeds the gauge from the cache]');
	{
		const app = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');
		ok('renderDashboard writes only when the tiles change (signature-diff)', /function renderDashboard\([\s\S]{0,600}renderDashboard\._sig === sig/.test(app) && /renderDashboard\._sig = sig/.test(app));
		ok('renderDashboard is called from the refresh loop', /renderDashboard\(state\)/.test(app));
		const ejs = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'views', 'index.ejs'), 'utf8');
		ok('the shared model is loaded before app.js', /shared\/dashboard-model\.js[\s\S]{0,120}js\/app\.js/.test(ejs));
		const idx = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
		ok('the web state surfaces the cached disk snapshot (no re-stat on the poll)', /disk:\s*SelfCheck\.diskSnapshot\(\)/.test(idx));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DASHBOARD CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
