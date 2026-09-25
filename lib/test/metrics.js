'use strict';
// lib/test/metrics.js — the monitoring surface: the Prometheus /metrics text, the /health verdict, and the
// `vdisk healthcheck` CLI. The formatting and the verdict live in lib/Metrics.js (pure, no I/O), so they are unit-tested
// directly; the endpoint and CLI wiring, the privacy rule (no vault identity in metrics), the remote-token gate, and the
// self-check alerting are pinned by source scans. Deterministic, cross-platform, no browser and no engine.
//
// Run:  node lib/test/metrics.js

const fs = require('fs');
const path = require('path');
const M = require('../Metrics');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

function main() {
	console.log('[healthVerdict: one shared verdict + exit code]');
	{
		ok('no findings is ok / exit 0', (() => { const v = M.healthVerdict([]); return v.status === 'ok' && v.code === 0; })());
		ok('a warning is warn / exit 1', (() => { const v = M.healthVerdict([{ level: 'warn' }]); return v.status === 'warn' && v.code === 1 && v.warn === 1; })());
		ok('an error is error / exit 2 (error beats warn)', (() => { const v = M.healthVerdict([{ level: 'warn' }, { level: 'error' }]); return v.status === 'error' && v.code === 2 && v.error === 1 && v.warn === 1; })());
		ok('a garbage/missing list is ok, never throws', (() => { const v = M.healthVerdict(null); return v.status === 'ok' && v.code === 0; })());
	}

	console.log('[renderMetrics: valid Prometheus text]');
	{
		const snap = {
			version: '1.1.0', uptimeSeconds: 123, rssBytes: 5e7, heapUsedBytes: 2e7, heapLimitBytes: 2e9,
			vaults: { total: 3, mounted: 2, unresponsive: 1 }, selfcheck: { warn: 1, error: 0, status: 'warn' },
			disk: { freeBytes: 42e9, freeRatio: 0.084 }, serving: 1, peers: 2, remotes: 1, backups: { scheduled: 1, failed: 0 },
			processes: { engine: 2, service: 1 },
		};
		const out = M.renderMetrics(snap);
		ok('every metric has a HELP and a TYPE line', (() => {
			const names = Array.from(out.matchAll(/^# TYPE (\S+) /gm)).map(m => m[1]);
			return names.length >= 15 && names.every(n => out.indexOf('# HELP ' + n + ' ') >= 0);
		})());
		ok('reports vault counts', /vaultonaut_vaults_total 3/.test(out) && /vaultonaut_vaults_mounted 2/.test(out) && /vaultonaut_vaults_unresponsive 1/.test(out));
		ok('reports self-check findings by level and an overall status', /vaultonaut_selfcheck_findings\{level="warn"\} 1/.test(out) && /vaultonaut_selfcheck_status 1/.test(out));
		ok('reports the disk gauge as bytes and a ratio', /vaultonaut_disk_free_bytes 42000000000/.test(out) && /vaultonaut_disk_free_ratio 0\.084/.test(out));
		ok('carries the version as a build_info label', /vaultonaut_build_info\{version="1\.1\.0"\} 1/.test(out));
		ok('reports tracked processes by kind label', /vaultonaut_processes\{kind="engine"\} 2/.test(out));
		ok('a missing field renders as 0, not NaN or undefined', (() => { const o = M.renderMetrics({}); return /vaultonaut_vaults_total 0/.test(o) && !/NaN|undefined/.test(o); })());
		// PRIVACY: the output must never contain a filesystem path or a decrypted-looking name. Feed a snapshot that does
		// NOT include identities (as the collector guarantees) and assert the rendered text has no path separators in values.
		ok('metrics text carries no vault path or name', !/\/(Users|home|vault|Vaults)\//i.test(out) && !/name="[^"]*[\/\\]/.test(out));
		// Label values are escaped so a stray quote/backslash/newline cannot break the format.
		ok('label values are escaped', /vaultonaut_build_info\{version="a\\"b"\}/.test(M.renderMetrics({ version: 'a"b' })));
	}

	console.log('[wiring: endpoints, gate, CLI, alerting, docs]');
	{
		const idx = read('webserver/index.js');
		ok('the /metrics route is registered and gated', /app\.get\('\/metrics'[\s\S]{0,120}monitorAllowed\(req, res\)/.test(idx));
		ok('the /health route is registered and gated', /app\.get\('\/health'[\s\S]{0,120}monitorAllowed\(req, res\)/.test(idx));
		ok('a loopback caller is allowed but a remote caller must present a valid API token', /function monitorAllowed[\s\S]{0,400}isLoopbackAddr\(peer\)[\s\S]{0,400}verifyApiToken\(bearer/.test(idx));
		ok('the metrics collector reads cached sources, not a per-scrape disk stat', /function collectMetrics[\s\S]{0,400}Watchdog\.snapshot\(\)[\s\S]{0,600}SelfCheck\.diskSnapshot\(\)/.test(idx));
		ok('/health uses the HTTP status code (503 on error)', /status\(v\.status === 'error' \? 503 : 200\)/.test(idx));
		ok('the periodic self-check alerts on a worsening', /SelfCheck\.run\(\{ label: 'periodic' \}\)\.then\(maybeAlertSelfCheck\)/.test(idx) && /function maybeAlertSelfCheck/.test(idx));

		const cmds = read('Commands.js');
		ok('the healthcheck CLI is defined and dispatched with 0/1/2 exit codes', /async function cmdHealthcheck\([\s\S]{0,900}process\.exitCode = v\.code/.test(cmds) && /case 'healthcheck': case 'health': await cmdHealthcheck\(\)/.test(cmds));

		const notify = read('Notify.js');
		ok('the system-check notification event exists (so the toggle is real)', /'system-check':\s*\{[^}]*defaultOn/.test(notify));

		const help = fs.readFileSync(path.join(__dirname, '..', 'templates', 'help.txt'), 'utf8');
		ok('help.txt documents the healthcheck command', /vdisk healthcheck/.test(help));
		const readme = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'README.md'), 'utf8');
		ok('the README documents healthcheck, /metrics, and /health', /vdisk healthcheck/.test(readme) && /GET `?\/metrics`?|`\/metrics`|\/metrics/.test(readme) && /\/health/.test(readme));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL METRICS CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
