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
const Common = require('../Common');

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
	await fsp.rename(A, B);
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

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-MOVE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
});
