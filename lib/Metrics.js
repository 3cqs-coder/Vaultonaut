'use strict';
// lib/Metrics.js — the pure formatting/verdict core behind the monitoring endpoints, kept dependency-free and free of
// any I/O so it is unit-tested directly. Two jobs:
//   • renderMetrics(snap) turns a plain snapshot object into the standard text-based metrics exposition format that
//     common monitoring collectors scrape over HTTP. The caller gathers the snapshot from cached, non-blocking
//     sources; this only formats it.
//   • healthVerdict(findings) reduces the self-check findings to one status/exit-code, shared by the /health endpoint,
//     the `vdisk healthcheck` CLI, and the self-check alerting, so all three agree on what "healthy" means.
//
// PRIVACY: metrics carry only counts, ratios, and status — never a vault name, path, size, or contents. A monitoring
// stack learns the shape of the install's health, never what is in it. The caller is responsible for passing only such
// aggregate values; this module never reads a vault.

// One metric family: name, HELP text, TYPE (gauge/counter), and either a bare value or labelled sub-values.
function line(name, help, value, labels) {
	const out = ['# HELP ' + name + ' ' + help, '# TYPE ' + name + ' gauge'];
	if (Array.isArray(labels)) {
		for (const l of labels) out.push(name + '{' + l.labels + '} ' + num(l.value));
	} else {
		out.push(name + ' ' + num(value));
	}
	return out.join('\n');
}
function num(v) { v = Number(v); return Number.isFinite(v) ? String(v) : '0'; }
// Escape a label value per the metrics text format (backslash, double-quote, newline).
function esc(s) { return String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n'); }

// The severity of a set of self-check findings, as one verdict shared by every monitoring surface. Findings only ever
// carry 'warn' or 'error'. Status maps to an exit code (0 ok, 1 warn, 2 error) for the CLI and to a status string for
// JSON/metrics. Never throws; a missing/garbage list reads as OK (no findings).
function healthVerdict(findings) {
	const list = Array.isArray(findings) ? findings : [];
	let warn = 0, error = 0;
	for (const f of list) { if (f && f.level === 'error') error++; else if (f && f.level === 'warn') warn++; }
	const status = error ? 'error' : (warn ? 'warn' : 'ok');
	return { status: status, code: error ? 2 : (warn ? 1 : 0), warn: warn, error: error, total: list.length };
}

// Render a metrics snapshot to the exposition text. Every field is optional; a missing one is reported as 0 (or omitted
// for build_info's label). The snapshot shape (all counts/ratios/bytes, no identities):
//   { version, up, uptimeSeconds, rssBytes, heapUsedBytes, heapLimitBytes,
//     vaults:{total,mounted,unresponsive}, selfcheck:{warn,error,status}, disk:{freeBytes,freeRatio},
//     serving, peers, remotes, backups:{scheduled,failed}, processes:{ '<kind>': n, ... } }
function renderMetrics(snap) {
	snap = snap || {};
	const v = snap.vaults || {}, sc = snap.selfcheck || {}, disk = snap.disk || {}, b = snap.backups || {};
	const statusCode = sc.status === 'error' ? 2 : (sc.status === 'warn' ? 1 : 0);
	const blocks = [];
	blocks.push(line('vaultonaut_up', 'Whether the Vaultonaut service is up (always 1 when scraped).', snap.up == null ? 1 : snap.up));
	blocks.push(line('vaultonaut_build_info', 'Build information; the value is always 1.', null, [{ labels: 'version="' + esc(snap.version || '') + '"', value: 1 }]));
	blocks.push(line('vaultonaut_process_uptime_seconds', 'Seconds since the service process started.', snap.uptimeSeconds));
	blocks.push(line('vaultonaut_process_resident_memory_bytes', 'Resident set size of the service process in bytes.', snap.rssBytes));
	blocks.push(line('vaultonaut_heap_used_bytes', 'V8 heap used by the service process in bytes.', snap.heapUsedBytes));
	blocks.push(line('vaultonaut_heap_limit_bytes', 'V8 heap size limit of the service process in bytes.', snap.heapLimitBytes));
	blocks.push(line('vaultonaut_vaults_total', 'Number of vaults known to this install.', v.total));
	blocks.push(line('vaultonaut_vaults_mounted', 'Number of vaults currently unlocked (mounted).', v.mounted));
	blocks.push(line('vaultonaut_vaults_unresponsive', 'Number of mounted vaults whose drive is not responding.', v.unresponsive));
	blocks.push(line('vaultonaut_selfcheck_findings', 'Open self-check findings by severity.', null, [
		{ labels: 'level="warn"', value: sc.warn || 0 },
		{ labels: 'level="error"', value: sc.error || 0 },
	]));
	blocks.push(line('vaultonaut_selfcheck_status', 'Overall self-check status: 0 ok, 1 warning, 2 error.', statusCode));
	blocks.push(line('vaultonaut_disk_free_bytes', 'Free space on the tightest vault volume, in bytes.', disk.freeBytes));
	blocks.push(line('vaultonaut_disk_free_ratio', 'Free space on the tightest vault volume, as a 0..1 ratio.', disk.freeRatio));
	blocks.push(line('vaultonaut_serving_vaults', 'Number of vaults currently being served to other devices.', snap.serving));
	blocks.push(line('vaultonaut_peers_configured', 'Number of configured peer devices.', snap.peers));
	blocks.push(line('vaultonaut_remotes_configured', 'Number of configured cloud and backup destinations.', snap.remotes));
	blocks.push(line('vaultonaut_backups_scheduled', 'Number of vaults with a backup schedule.', b.scheduled));
	blocks.push(line('vaultonaut_backups_failed', 'Number of scheduled backups whose last run failed.', b.failed));
	if (snap.processes && typeof snap.processes === 'object') {
		const rows = Object.keys(snap.processes).map((k) => ({ labels: 'kind="' + esc(k) + '"', value: snap.processes[k] }));
		if (rows.length) blocks.push(line('vaultonaut_processes', 'Tracked child processes by kind.', null, rows));
	}
	return blocks.join('\n') + '\n';
}

module.exports = { renderMetrics, healthVerdict };
