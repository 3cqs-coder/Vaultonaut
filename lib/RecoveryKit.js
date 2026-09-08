'use strict';
// lib/RecoveryKit.js — renders a one-page, printable Recovery Kit for a vault. All wording lives in
// the template data file (templates/recovery-kit.html); this module only fills in the values, safely.
// It is deliberately tiny and dependency-free so both the CLI and the web UI can produce the same kit.
//
//   render({ appName, cli, vaultName, vaultPath, identity, fingerprint, seq, recoveryKey, generatedAt })
//     -> a complete, self-contained HTML string
//
// A kit with a recoveryKey shows the spare key; without one it shows how to add it. The template
// carries both variants between HTML-comment markers, and we strip whichever is not used — so no
// page markup is ever built in code.

const fs = require('fs');
const path = require('path');

const TEMPLATE_PATH = path.join(__dirname, 'templates', 'recovery-kit.html');

// HTML-escape every substituted value. The values here are low-risk (a vault name, a folder path,
// short base32 codes), but a vault name is user-controlled, so escaping keeps the printable page
// safe to open in a browser regardless of what a folder was named.
function esc(s) {
	return String(s == null ? '' : s)
		.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Remove a `<!--NAME:START-->…<!--NAME:END-->` region from the template (used to drop the branch we
// are not rendering). Global + dotAll so it spans lines and clears every occurrence.
function stripBlock(html, name) {
	const re = new RegExp('<!--' + name + ':START-->[\\s\\S]*?<!--' + name + ':END-->', 'g');
	return html.replace(re, '');
}

function render(data = {}) {
	const d = data || {};
	const hasKey = !!d.recoveryKey;
	let html = fs.readFileSync(TEMPLATE_PATH, 'utf8');
	// Keep exactly one of the two recovery-key variants: drop the unused block entirely, then remove the
	// kept block's own START/END marker comments so no template scaffolding shows in the finished page.
	html = stripBlock(html, hasKey ? 'NOKEY' : 'KEY');
	html = html.replace(/<!--(?:KEY|NOKEY):(?:START|END)-->/g, '');
	const values = {
		APP_NAME: d.appName || 'Vault',
		CLI: d.cli || 'vdisk',
		VAULT_NAME: d.vaultName || '',
		VAULT_PATH: d.vaultPath || '',
		IDENTITY: d.identity || '—',
		FINGERPRINT: d.fingerprint || 'not yet recorded',
		SEQ: (d.seq == null ? '—' : d.seq),
		RECOVERY_KEY: d.recoveryKey || '',
		GENERATED_AT: d.generatedAt || new Date().toLocaleString(),
	};
	return html.replace(/\{\{(\w+)\}\}/g, (m, key) => (key in values ? esc(values[key]) : m));
}

module.exports = { render };
