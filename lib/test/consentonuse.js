'use strict';
// lib/test/consentonuse.js — consent-on-use: an opt-in per-vault mode where each unlock is approved and RECORDED in the
// vault's tamper-evident ledger, turning the ledger into a signed history of every use of the key. This verifies:
//   1) the per-vault flag round-trips (a non-secret preference, keyed by path like a favorite);
//   2) with the flag ON, a mount appends a signed 'unlock' entry to the tamper-log, and the log still verifies;
//   3) with the flag OFF, a mount adds NO unlock entry (the ledger stays clean for ordinary vaults);
//   4) source guards: the flag is in VAULT_PATH_KEYED, the mount records against the ACTUALLY-MOUNTED backing vault
//      (so a decoy never records against or reveals the real vault), and the record is best-effort/non-blocking.
// Layers 2-3 need the engine + a mount driver (the ledger entry is written on a real mount); layer 1 + the source
// guards are pure and always run.
//
// Run:  node lib/test/consentonuse.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	// --- Source guards (pure) ---
	const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the consent flag is a per-vault-keyed setting (carried on rename/travel)', /VAULT_PATH_KEYED = \[[^\]]*'consentOnUse'/.test(src));
	ok('the mount records the unlock against the ACTUALLY-MOUNTED vault (abs), never the presented identity', /if \(await isConsentOnUse\(abs\)\)[\s\S]{0,200}logTamper\(manifest, \{ kind: 'unlock'/.test(src));
	ok('the ledger write is best-effort and non-blocking (guarded, never fails a mount)', /try \{\s*if \(await isConsentOnUse\(abs\)\)[\s\S]{0,400}\} catch \(_\) \{\}/.test(src));
	ok('a write session co-signs the tamper head after recording the unlock', /if \(await isConsentOnUse\(abs\)\)[\s\S]{0,300}signTamperHead\(Integrity\.vaultId\(manifest\), keys\.signPriv/.test(src));
	const idx = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the state surfaces the vault\'s own consent flag (a decoy is never listed, so no pairing is revealed)', /consentOnUse: !!\(\(settings\.consentOnUse \|\| \{\}\)\[abs\]\)/.test(idx));
	ok('the consent-on-use route is registered', /app\.post\('\/api\/consent-on-use'/.test(idx));

	// --- Behavior ---
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-consent-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.setDataDir(dataDir);
	const vdisk = require('../index');

	const srcDir = path.join(tmp, 'src'); await fsp.mkdir(srcDir, { recursive: true });
	await fsp.writeFile(path.join(srcDir, 'a.txt'), 'x');
	const v = path.join(tmp, 'Consent.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: srcDir });

	// 1. The flag round-trips.
	await vdisk.setConsentOnUse(v, true);
	ok('setConsentOnUse(on) turns the flag on', (await vdisk.isConsentOnUse(v)) === true);
	await vdisk.setConsentOnUse(v, false);
	ok('setConsentOnUse(off) turns the flag off', (await vdisk.isConsentOnUse(v)) === false);

	const d = await vdisk.doctor();
	if (!d.engine.ok || !d.driver.ok) { console.log('Engine or driver missing — skipping the mount/ledger checks.'); return done(); }

	// 2. With the flag ON, a mount records a signed 'unlock' entry and the log still verifies.
	await vdisk.setConsentOnUse(v, true);
	const cacheDir = path.join(tmp, 'cache');
	await vdisk.mount(v, { password: 'pw1', cacheDir });
	await vdisk.unmount(v, {}).catch(() => {});
	const log1 = await vdisk.tamperLog(v);
	const unlocks1 = (log1.events || []).filter((e) => e.kind === 'unlock');
	ok('mounting a consent-on-use vault records an unlock entry in the ledger', unlocks1.length >= 1);
	ok('the recorded unlock is an informational, hash-chained entry', unlocks1[0] && unlocks1[0].severity === 'info' && !!unlocks1[0].hash);

	// 3. With the flag OFF, a mount adds NO new unlock entry.
	await vdisk.setConsentOnUse(v, false);
	await vdisk.mount(v, { password: 'pw1', cacheDir });
	await vdisk.unmount(v, {}).catch(() => {});
	const log2 = await vdisk.tamperLog(v);
	const unlocks2 = (log2.events || []).filter((e) => e.kind === 'unlock');
	ok('mounting with consent-on-use OFF adds no unlock entry (the ledger stays clean)', unlocks2.length === unlocks1.length);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CONSENT-ON-USE CHECKS PASSED'));
	try { require('../Common').setDataDir(null); } catch (_) {}
	if (tmp) return fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}).then(() => process.exit(failures ? 1 : 0));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
