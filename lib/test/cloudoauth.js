'use strict';
// lib/test/cloudoauth.js — the OAuth cloud-vault MECHANICS that can be verified without a live provider:
// the crypt config emits base32768 only when asked; the engine's token harvest (config dump) round-trips a
// refresh token; the browser-OAuth capture parses a real consent URL out of the engine; and the token store
// keeps the token as an encrypted secret (never plaintext in settings). The live browser consent and a real
// Drive/OneDrive/Dropbox mount are NOT exercised here — those need a real account.
//
// Run:  node lib/test/cloudoauth.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-oauth-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Rclone = require('../Rclone');

	// crypt config: base32768 emitted only when set; the default (base32) stays implicit for compatibility.
	const withEnc = Rclone.cryptRemoteSection('vault', { cipherDir: 'backend:x', passwordObscured: 'p', filenameEncoding: 'base32768' });
	const noEnc = Rclone.cryptRemoteSection('vault', { cipherDir: 'backend:x', passwordObscured: 'p' });
	const b32 = Rclone.cryptRemoteSection('vault', { cipherDir: 'backend:x', passwordObscured: 'p', filenameEncoding: 'base32' });
	ok('the crypt config emits base32768 when asked', /filename_encoding = base32768/.test(withEnc));
	ok('the crypt config leaves the default (base32) implicit', !/filename_encoding/.test(noEnc) && !/filename_encoding/.test(b32));

	// Backend classification.
	ok('OAuth backends are recognized (drive/onedrive/dropbox), key backends are not', vdisk.isOAuthBackend('drive') && vdisk.isOAuthBackend('onedrive') && vdisk.isOAuthBackend('dropbox') && !vdisk.isOAuthBackend('s3') && !vdisk.isOAuthBackend('b2'));
	// Filename encoding by backend: UTF-16 backends get base32768, others the default.
	ok('UTF-16 backends select base32768, others the default', vdisk.cloudFilenameEncoding('onedrive') === 'base32768' && vdisk.cloudFilenameEncoding('dropbox') === 'base32768' && vdisk.cloudFilenameEncoding('drive') === undefined && vdisk.cloudFilenameEncoding('s3') === undefined);

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping engine-dependent checks.'); return done(); }
	const bin = d.engine.rclone;

	// Token harvest: write a config with a rotated token, read it back via the engine.
	const cfg = path.join(tmp, 'r.conf');
	await fsp.writeFile(cfg, '[gdrive]\ntype = drive\ntoken = {"access_token":"a","token_type":"Bearer","refresh_token":"ROT123","expiry":"2026-01-23T10:19:51Z"}\n\n[vault]\ntype = crypt\nremote = gdrive:v\n');
	const tok = await Rclone.harvestToken(bin, cfg, 'gdrive');
	ok('the engine harvests a (rotated) token back from a config', tok && JSON.parse(tok).refresh_token === 'ROT123');
	ok('the harvest falls back to the first OAuth section when the name is unknown', (await Rclone.harvestToken(bin, cfg, 'nope')) && JSON.parse(await Rclone.harvestToken(bin, cfg, 'nope')).refresh_token === 'ROT123');

	// Browser-OAuth capture: the engine spins up its loopback consent server and we parse the URL out.
	let url = null;
	try { await Rclone.authorize(bin, 'drive', { timeoutMs: 4000, onUrl: u => { url = u; } }); } catch (_) {}
	ok('the browser-OAuth capture parses the provider consent URL', /^http:\/\/127\.0\.0\.1:\d+\/auth\?/.test(url || ''));

	// cloudAuthorize refuses a non-OAuth backend (those use an API key).
	let refused = false; try { await vdisk.cloudAuthorize('s3', {}); } catch (_) { refused = true; }
	ok('cloudAuthorize refuses a key-based backend', refused);

	// The token store: saveCloudOAuth keeps the token as an ENCRYPTED secret — never plaintext in settings.
	await vdisk.saveCloudOAuth({ id: 'gd1', label: 'My Drive', type: 'drive', token: '{"refresh_token":"SECRETTOKEN"}', opts: { scope: 'drive' } });
	const listed = await vdisk.listCloudRemotes();
	const rec = listed.find(r => r.id === 'gd1');
	ok('the OAuth remote is stored (type + metadata + secrets present)', rec && rec.type === 'drive' && rec.opts.scope === 'drive' && rec.hasSecrets);
	const settingsRaw = await fsp.readFile(path.join(dataDir, 'settings.json'), 'utf8');
	ok('the token never appears in plaintext in the app settings', !settingsRaw.includes('SECRETTOKEN'));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLOUD-OAUTH CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
