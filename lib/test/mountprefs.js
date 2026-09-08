'use strict';
// lib/test/mountprefs.js — a vault's remembered mount-mode preference (its "favorite") is applied on
// a later plain mount, so a vault set as a working disk once (the mode that copies large files
// reliably) stays one without re-choosing — while an explicit choice still overrides it. Needs the
// bundled engine and a mount driver; skips the mount checks gracefully when no driver is installed.
//
// Run:  node lib/test/mountprefs.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mountprefs-')); workspace = tmp;
	const v = path.join(tmp, 'Pref.vault');
	await vdisk.create(v, { password: 'pw' });

	// recordMountPrefs persists whether or not a driver is present — check the persistence directly.
	await vdisk.recordMountPrefs(v, { workingDisk: true });
	const prefs = ((await vdisk.getSettings()).mountPrefs || {})[path.resolve(v)] || {};
	ok('the working-disk preference is remembered for the vault', prefs.workingDisk === true);

	if (!d.driver.ok) { console.log('No mount driver — skipping the applied-on-mount checks.'); }
	else {
		// Use an explicit on-disk cache dir so the cache-mode assertions hold even on a machine with no RAM disk
		// (e.g. Windows without ImDisk), where a RAM-backed 'full'/'writes' mount would otherwise fall back to
		// streaming ('off'). This still exercises the preference-application logic — only WHERE the cache lives
		// changes, not the mode the preference selects.
		const cacheDir = path.join(tmp, 'cache');
		let r = await vdisk.mount(v, { password: 'pw', cacheDir });       // plain mount, no cache-mode flags
		ok('a plain mount applies the remembered working-disk preference (full)', r.cacheMode === 'full');
		await vdisk.unmount(v, {});

		r = await vdisk.mount(v, { password: 'pw', streaming: true });    // explicit choice
		ok('an explicit cache-mode choice overrides the remembered preference', r.cacheMode === 'off');
		await vdisk.unmount(v, {});

		await vdisk.recordMountPrefs(v, {});                              // clear the preference
		r = await vdisk.mount(v, { password: 'pw', cacheDir });
		ok('with no preference a plain mount uses the default (writes)', r.cacheMode === 'writes');
		await vdisk.unmount(v, {});

		// The FUSE-T SMB-backend preference (macOS only) is remembered and applied on a plain mount.
		if (process.platform === 'darwin') {
			await vdisk.recordMountPrefs(v, { fuseBackend: 'smb' });
			r = await vdisk.mount(v, { password: 'pw' });
			ok('a remembered SMB-backend preference is applied on a plain mount', r.fuseBackend === 'smb');
			await vdisk.unmount(v, {});
		}
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOUNT-PREFS CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-mountprefs-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
