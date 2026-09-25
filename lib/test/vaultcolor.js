'use strict';
// lib/test/vaultcolor.js — the per-vault color tag (a trust / sensitivity signal). A non-secret, path-keyed preference
// exactly like a favorite: only a name from the fixed palette is stored, an unknown value clears the tag, and the key
// is carried with the vault on rename/travel. Source scans pin the route, the state field, and the UI wiring. No engine.
//
// Run:  node lib/test/vaultcolor.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');

async function main() {
	console.log('[storage: a color is a validated, path-keyed, clearable tag]');
	{
		const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-color-'));
		const origDataDir = Common.dataDir;
		Common.setDataDir(dir);
		const Vault = require('../Vault');
		const vpath = path.join(dir, 'MyVault');
		try {
			ok('the palette lists the fixed color names', Array.isArray(Vault.VAULT_COLORS) && Vault.VAULT_COLORS.indexOf('red') >= 0 && Vault.VAULT_COLORS.length === 6);
			const set = await Vault.setVaultColor(vpath, 'red');
			ok('setting a valid color returns it', set.color === 'red');
			const s1 = await Vault.getSettings();
			ok('the color is stored under vaultColors, keyed by the resolved path', s1.vaultColors && Object.values(s1.vaultColors)[0] === 'red');
			const bad = await Vault.setVaultColor(vpath, 'chartreuse');
			ok('an unknown color clears the tag (never stored raw)', bad.color === null);
			const s2 = await Vault.getSettings();
			ok('an unknown color leaves nothing behind', !s2.vaultColors || Object.keys(s2.vaultColors).length === 0);
			await Vault.setVaultColor(vpath, 'blue');
			const cleared = await Vault.setVaultColor(vpath, '');
			ok('an empty color clears an existing tag', cleared.color === null);
		} finally { Common.dataDir = origDataDir; await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }
	}

	console.log('[wiring: path-keyed carry, route, state field, and the UI]');
	{
		const vaultjs = read('Vault.js');
		ok('vaultColors is a path-keyed setting (carried on rename/travel)', /VAULT_PATH_KEYED = \[[^\]]*'vaultColors'/.test(vaultjs));
		const idx = read('webserver/index.js');
		ok('the vault-color route is registered', /app\.post\('\/api\/vault-color'[\s\S]{0,120}Vault\.setVaultColor/.test(idx));
		ok('the per-vault state carries the color', /color:\s*\(settings\.vaultColors \|\| \{\}\)\[abs\]/.test(idx));
		const app = read('webserver/public/js/app.js');
		ok('the card renders the color rail and a picker', /data-color="\$\{esc\(v\.color\)\}"/.test(app) && /function colorPicker\(/.test(app));
		ok('a swatch click sets the color and never stores "none" as a value', /act === 'set-color'[\s\S]{0,300}color: c \}\)/.test(app) && /=== 'none' \? '' :/.test(app));
		const css = read('webserver/public/css/app.css');
		ok('the color palette is defined as theme tokens (not raw values in rule bodies)', /--tag-red:/.test(css) && /\.card\[data-color="red"\]::before \{ background: var\(--tag-red\)/.test(css));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-COLOR CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
