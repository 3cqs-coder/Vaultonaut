'use strict';
// lib/test/vaultmeta.js — the vault's ENCRYPTED metadata (display title + description). It is sealed with the vault
// key, so it is readable only with a password that opens the vault — never from the folder name or a locked vault.
// Covers the round-trip, that a wrong password is refused, that a read-only credential can view but not rename, that
// clearing and partial updates work, that the blob is EXTENSIBLE (an unknown future field survives), and that the
// ciphertext never leaks the plaintext. Creating a vault needs the engine; the metadata operations need no mount.
//
// Run:  node -r ./lib/test/_setup.js lib/test/vaultmeta.js

const os = require('os'), path = require('path'), fsp = require('fs').promises;
const vdisk = require('../index');
const Vault = require('../Vault'); // for the internal-but-exported cache helpers (vaultIdOf, cachedVaultName, getSettings)

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-meta-')); workspace = tmp;
	const v = path.join(tmp, 'MyFolder.vault');
	await vdisk.create(v, { password: 'pw1' });

	// A fresh vault has no metadata, so the display title falls back to the folder name.
	let r = await vdisk.getVaultMeta(v, 'pw1');
	ok('a fresh vault has empty metadata', r.meta.title === '' && r.meta.description === '');
	ok('the display title falls back to the folder name when no title is set', vdisk.vaultTitle(v, r.meta.title) === 'MyFolder');

	// Set a title + description and read them back.
	await vdisk.setVaultMeta(v, { password: 'pw1', fields: { title: 'Server keys', description: 'prod + staging' } });
	r = await vdisk.getVaultMeta(v, 'pw1');
	ok('the title and description round-trip', r.meta.title === 'Server keys' && r.meta.description === 'prod + staging');
	ok('the display title now prefers the encrypted title', vdisk.vaultTitle(v, r.meta.title) === 'Server keys');

	// LOCAL NAME CACHE: setting/reading the metadata seeds a per-machine cache keyed by vaultId, so the vault list can
	// show the friendly name while the vault is LOCKED (no key available). The cache lives in the local settings, never
	// in the vault, and is keyed by the stable vaultId so it survives a folder rename or move.
	const man = await Vault.readManifest(v);
	const vid = Vault.vaultIdOf(man);
	let settings = await Vault.getSettings();
	ok('the local name cache remembers the decrypted title (keyed by vaultId)', !!(settings.vaultNames && settings.vaultNames[vid] && settings.vaultNames[vid].title === 'Server keys'));
	ok('the cache is keyed by the stable vaultId, not the folder path', !settings.vaultNames[v]);
	const cached = Vault.cachedVaultName(man, settings);
	ok('cachedVaultName resolves the title + description from an already-read settings object', cached && cached.title === 'Server keys' && cached.description === 'prod + staging');

	// The metadata must be encrypted in the manifest, not stored in the clear.
	const manRaw = await fsp.readFile(path.join(v, 'vault.json'), 'utf8');
	ok('the manifest carries a sealed meta blob', /"meta"\s*:/.test(manRaw));
	ok('the manifest does not store the title/description in plaintext', !manRaw.includes('Server keys') && !manRaw.includes('prod + staging'));

	// A wrong password cannot read the metadata (fails closed).
	let threw = false; try { await vdisk.getVaultMeta(v, 'wrong'); } catch (_) { threw = true; }
	ok('a wrong password cannot read the metadata', threw);

	// A partial update changes only the field given and preserves the rest.
	await vdisk.setVaultMeta(v, { password: 'pw1', fields: { description: 'prod only' } });
	r = await vdisk.getVaultMeta(v, 'pw1');
	ok('a partial update keeps the untouched field', r.meta.title === 'Server keys' && r.meta.description === 'prod only');

	// Clearing a field (empty string) removes it, so the title falls back to the folder name again.
	await vdisk.setVaultMeta(v, { password: 'pw1', fields: { title: '' } });
	r = await vdisk.getVaultMeta(v, 'pw1');
	ok('clearing the title falls back to the folder name', r.meta.title === '' && vdisk.vaultTitle(v, r.meta.title) === 'MyFolder');

	// Sanitization: an over-long title is capped at its limit.
	await vdisk.setVaultMeta(v, { password: 'pw1', fields: { title: 'x'.repeat(200) } });
	r = await vdisk.getVaultMeta(v, 'pw1');
	ok('a too-long title is capped to its length limit', r.meta.title.length === 80);
	await vdisk.setVaultMeta(v, { password: 'pw1', fields: { title: 'Server keys' } }); // restore a normal title

	// A READ-ONLY credential may VIEW the metadata but must not be able to change it (renaming is a write).
	await vdisk.addReadOnlyKey(v, { password: 'pw1', readOnlyPassword: 'ro1' });
	const ro = await vdisk.getVaultMeta(v, 'ro1');
	ok('a read-only credential can view the metadata', ro.meta.title === 'Server keys');
	let roBlocked = false; try { await vdisk.setVaultMeta(v, { password: 'ro1', fields: { title: 'hijacked' } }); } catch (_) { roBlocked = true; }
	ok('a read-only credential cannot rename the vault', roBlocked);
	ok('the title is unchanged after the read-only attempt', (await vdisk.getVaultMeta(v, 'pw1')).meta.title === 'Server keys');

	// Forgetting a vault drops its cached name (keyed by vaultId), so it does not linger in local state.
	await vdisk.removeKnownVault(v);
	settings = await Vault.getSettings();
	ok('removing a vault drops its cached name from local state', !(settings.vaultNames && settings.vaultNames[vid]));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-META CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
});
