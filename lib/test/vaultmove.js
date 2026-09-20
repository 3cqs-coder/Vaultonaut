'use strict';
// lib/test/vaultmove.js — a vault's per-path settings (mirror, backup, schedules, favorites, serve credentials) must
// FOLLOW it when its folder is moved or renamed on disk OUTSIDE the app. An opaque vault's folder is named by its own
// id, so a move keeps that id; re-adding the vault at its new path recognizes it as the same vault, carries its
// settings across, and drops the stale entry. This is what keeps sync and backups working no matter where a vault lives.
//
// Run:  node -r ./lib/test/_setup.js lib/test/vaultmove.js

const os = require('os'), path = require('path'), fsp = require('fs').promises, fs = require('fs');
const vdisk = require('../index');
const Vault = require('../Vault');
const Common = require('../Common'); // samePath, and renameWithRetry (Windows EPERM/EBUSY-tolerant) for the move simulation

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const exists = async (p) => { try { await fsp.access(p); return true; } catch (_) { return false; } };
const knownHas = (list, p) => list.some(x => Common.samePath(x, p));

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-move-')); workspace = tmp;
	// Create an OPAQUE vault (folder named by its id) at location A; it registers as a known vault.
	const created = await vdisk.create(path.join(tmp, 'Work.vault'), { password: 'pw1', opaque: true });
	const A = created.vault;
	const base = path.basename(A);
	ok('an opaque vault was created (the folder is its id)', /^[0-9a-f]{32}\.vault$/.test(base));

	// Give it a path-keyed setting: mark it a favorite (favorites is one of the path-keyed stores).
	await Vault.setFavorite(A, true);
	let s = await Vault.getSettings();
	ok('the vault has a path-keyed setting at its original path', !!(s.favorites && s.favorites[A]));

	// MOVE the folder to a new location B — a plain filesystem move, as if done in Finder/Explorer outside the app.
	const B = path.join(tmp, 'moved', base);
	await fsp.mkdir(path.dirname(B), { recursive: true });
	await Common.renameWithRetry(A, B); // tolerant of a slow Windows runner still holding the just-written vault.json
	ok('the vault folder was moved on disk', !(await exists(A)) && (await exists(B)));

	// Re-add the vault at its new location. The app should recognize the same vault by its opaque folder id.
	await Vault.addKnownVault(B);
	s = await Vault.getSettings();
	ok('the path-keyed setting followed the vault to its new path', !!(s.favorites && s.favorites[B]));
	ok('the stale setting at the old path is gone', !(s.favorites && s.favorites[A]));
	let known = await Vault.listKnownVaults();
	ok('the new path is a known vault', knownHas(known, B));
	ok('the stale old entry was dropped', !knownHas(known, A));

	// A genuine SECOND COPY (the old folder still exists) must NOT be treated as a move — both keep their own settings.
	const C = path.join(tmp, 'copy', base);
	await fsp.mkdir(path.dirname(C), { recursive: true });
	await fsp.cp(B, C, { recursive: true });
	await Vault.setFavorite(B, true); // ensure B has the favorite
	await Vault.addKnownVault(C);
	s = await Vault.getSettings();
	ok('adding a second copy does not steal the original\'s settings (both exist -> not a move)', !!(s.favorites && s.favorites[B]));
	known = await Vault.listKnownVaults();
	ok('both the original and the copy are known (a copy is not a move)', knownHas(known, B) && knownHas(known, C));

	// ANONYMIZE: convert an EXISTING named vault to an opaque one in place — rename the folder to the vaultId, keep the
	// old name as the encrypted title, and carry its settings over. The vault must be unmounted (it is here).
	const named = await vdisk.create(path.join(tmp, 'Secret Docs.vault'), { password: 'pw2' }); // opaque:false -> a real folder name
	const N = named.vault;
	ok('a named vault has a real folder name on disk', /Secret Docs\.vault$/.test(N));
	await Vault.setFavorite(N, true);
	const an = await vdisk.anonymizeVault(N, { password: 'pw2' });
	ok('anonymize renames the folder to the opaque vaultId', /^[0-9a-f]{32}\.vault$/.test(path.basename(an.vault)) && !/Secret Docs/.test(an.vault));
	ok('the old named folder is gone and the opaque one exists', !(await exists(N)) && (await exists(an.vault)));
	ok('the old folder name is kept as the encrypted title', (await vdisk.getVaultMeta(an.vault, 'pw2')).meta.title === 'Secret Docs');
	const sa = await Vault.getSettings();
	ok('path-keyed settings followed the anonymized vault', !!(sa.favorites && sa.favorites[an.vault]) && !(sa.favorites && sa.favorites[N]));
	ok('the anonymized vault still opens with its password', !!(await vdisk.getVaultMeta(an.vault, 'pw2')));
	const known2 = await Vault.listKnownVaults();
	ok('the known-vault list points at the new opaque path', knownHas(known2, an.vault) && !knownHas(known2, N));
	ok('anonymizing an already-opaque vault is a no-op', (await vdisk.anonymizeVault(an.vault, { password: 'pw2' })).alreadyOpaque === true);
	// A read-only credential must not be able to anonymize a still-NAMED vault (the no-op short-circuit above never runs).
	const named2 = await vdisk.create(path.join(tmp, 'ReadOnly Test.vault'), { password: 'pw3' });
	await vdisk.addReadOnlyKey(named2.vault, { password: 'pw3', readOnlyPassword: 'ro3' });
	let roBlocked = false; try { await vdisk.anonymizeVault(named2.vault, { password: 'ro3' }); } catch (_) { roBlocked = true; }
	ok('a read-only credential cannot anonymize a vault', roBlocked && /ReadOnly Test\.vault$/.test(named2.vault));

	// ROLLBACK: if the post-rename bookkeeping fails, anonymize must fully restore the vault — folder name, settings,
	// and registration — never leave it stranded at a path that no longer exists. Force the new-path registration to
	// fail and confirm everything is put back.
	const rb = await vdisk.create(path.join(tmp, 'Rollback Test.vault'), { password: 'pw4' });
	await Vault.setFavorite(rb.vault, true);
	const rbVid = Vault.vaultIdOf(await Vault.readManifest(rb.vault));
	const rbNew = path.join(path.dirname(rb.vault), rbVid + '.vault');
	const State = require('../State');
	const realAdd = State.addVault;
	let seen = 0;
	State.addVault = async (p) => { if (seen++ === 0 && /^[0-9a-f]{32}\.vault$/.test(path.basename(String(p)))) throw new Error('injected state write failure'); return realAdd(p); };
	let anonFailed = false;
	try { await vdisk.anonymizeVault(rb.vault, { password: 'pw4' }); } catch (_) { anonFailed = true; } finally { State.addVault = realAdd; }
	ok('anonymize surfaces a bookkeeping failure instead of swallowing it', anonFailed);
	ok('the folder name is restored after a failed anonymize (not stranded at the opaque path)', (await exists(rb.vault)) && !(await exists(rbNew)));
	const srb = await Vault.getSettings();
	ok('the path-keyed setting is restored to the original path after a failed anonymize', !!(srb.favorites && srb.favorites[rb.vault]) && !(srb.favorites && srb.favorites[rbNew]));
	ok('the vault is still registered at its original path after a failed anonymize', knownHas(await Vault.listKnownVaults(), rb.vault));
	ok('the restored vault still opens with its password', !!(await vdisk.getVaultMeta(rb.vault, 'pw4')));

	// AUTO-CONVERT ON UNLOCK: with the setting on (the production default), unlocking a still-NAMED vault renames its
	// folder to the opaque format, keeping the name encrypted. The conversion runs before the mount itself, so it
	// happens whether or not a mount driver is available here; any mount is unmounted for cleanup.
	delete process.env.VAULTONAUT_NO_AUTO_ANONYMIZE;
	try {
		const auto = await vdisk.create(path.join(tmp, 'AutoConvert.vault'), { password: 'pw5' });
		const autoOld = auto.vault;
		const autoVid = Vault.vaultIdOf(await Vault.readManifest(autoOld));
		const autoNew = path.join(path.dirname(autoOld), autoVid + '.vault');
		try { const mr = await vdisk.mount(autoOld, { password: 'pw5' }); if (mr && mr.mountpoint) { try { await vdisk.unmount(mr.mountpoint); } catch (_) {} } } catch (_) {}
		ok('unlocking a still-named vault auto-converts it to an opaque folder', !(await exists(autoOld)) && (await exists(autoNew)));
		ok('the auto-converted vault keeps its name as the encrypted title', (await vdisk.getVaultMeta(autoNew, 'pw5')).meta.title === 'AutoConvert');
		// With the setting OFF, unlocking a named vault must NOT convert it.
		await Vault.setSettings({ autoAnonymize: false });
		const keep = await vdisk.create(path.join(tmp, 'KeepNamed.vault'), { password: 'pw6' });
		try { const mr2 = await vdisk.mount(keep.vault, { password: 'pw6' }); if (mr2 && mr2.mountpoint) { try { await vdisk.unmount(mr2.mountpoint); } catch (_) {} } } catch (_) {}
		ok('with auto-conversion off, a named vault keeps its folder name', await exists(keep.vault));
		await Vault.setSettings({ autoAnonymize: true });
	} finally { process.env.VAULTONAUT_NO_AUTO_ANONYMIZE = '1'; }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-MOVE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
});
