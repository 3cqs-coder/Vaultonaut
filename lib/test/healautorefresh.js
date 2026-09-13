'use strict';
// lib/test/healautorefresh.js — self-heal must ACTUALLY keep its recovery data current as a user changes a protected
// vault. This drives the real flow end to end through a live mount: create a vault, mount it and write files, protect
// it at 15% (the exact "add healing immediately on a new vault" case), then mount again to ADD files and REMOVE files,
// and after each unmount run the same refresh the service runs on unmount (Vault.refreshRecoveryIfStale). It asserts
// the refresh actually rebuilds (not a silent skip), emits progress (the data the "updating" pill is built from), and
// that the recovery index tracks the new file set — so a future change can never silently stop self-heal from updating.
// Needs the bundled engine AND a mount driver; skips cleanly without one (mirrors deepbaseline.js).
//
// Run:  node lib/test/healautorefresh.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

let workspace = null, mounted = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	if (!d.driver || !d.driver.ok) { console.log('No mount driver — skipping the self-heal auto-refresh cycle.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-healauto-')); workspace = tmp;
	const cacheDir = path.join(tmp, 'cache');
	const v = path.join(tmp, 'AutoHeal.vault');

	// Create an empty vault, mount it, and write a few files through the crypt engine.
	await vdisk.create(v, { password: 'pw' });
	let m = await vdisk.mount(v, { password: 'pw', cacheDir }); mounted = v;
	await sleep(800);
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(m.mountpoint, 'f' + i + '.bin'), Buffer.alloc(200000, i));
	await sleep(400); await vdisk.unmount(v, {}); mounted = null; await sleep(500);

	// Protect at 15% (high) IMMEDIATELY on the new vault — the user's exact scenario.
	const p = await vdisk.protect(v, { tier: 'high' });
	ok('protect on a new vault builds signed recovery data', !p.skipped && p.dataBlocks > 0 && p.signed === true);
	const blocks0 = (await vdisk.recoveryStatus(v)).dataBlocks;
	ok('recovery status reports it protected right after protect', (await vdisk.recoveryStatus(v)).protected === true);

	// ADD files through a mount, then run the post-unmount refresh the service runs.
	m = await vdisk.mount(v, { password: 'pw', cacheDir }); mounted = v;
	await sleep(800);
	for (let i = 5; i < 9; i++) await fsp.writeFile(path.join(m.mountpoint, 'add' + i + '.bin'), Buffer.alloc(300000, i));
	await sleep(400); await vdisk.unmount(v, {}); mounted = null; await sleep(500);
	let ticks = 0;
	let r = await vdisk.refreshRecoveryIfStale(v, { onProgress: (x) => { if (x) ticks++; } });
	ok('self-heal REBUILDS after files are ADDED (not a silent skip)', r.refreshed === true && r.signed === true);
	ok('the ADD rebuild emits progress (the "updating" pill has data to show)', ticks > 0);
	const blocksAdd = (await vdisk.recoveryStatus(v)).dataBlocks;
	ok('the recovery index grew to cover the added files', blocksAdd > blocks0);

	// A SECOND unmount with NO change must be a no-op (self-clearing — no needless rebuild, no false churn).
	r = await vdisk.refreshRecoveryIfStale(v, { onProgress: () => {} });
	ok('an unchanged vault does NOT rebuild (up to date, self-clearing)', r.refreshed === false);

	// REMOVE files through a mount, then refresh.
	m = await vdisk.mount(v, { password: 'pw', cacheDir }); mounted = v;
	await sleep(800);
	await fsp.rm(path.join(m.mountpoint, 'add5.bin'), { force: true });
	await fsp.rm(path.join(m.mountpoint, 'add6.bin'), { force: true });
	await sleep(400); await vdisk.unmount(v, {}); mounted = null; await sleep(500);
	ticks = 0;
	r = await vdisk.refreshRecoveryIfStale(v, { onProgress: (x) => { if (x) ticks++; } });
	ok('self-heal REBUILDS after files are REMOVED', r.refreshed === true && r.signed === true);
	ok('the REMOVE rebuild emits progress', ticks > 0);
	const blocksRem = (await vdisk.recoveryStatus(v)).dataBlocks;
	ok('the recovery index shrank to match the smaller file set', blocksRem < blocksAdd);

	// The recovery data must verify clean against the current contents after all that.
	const vr = await vdisk.verifyRecovery(v, {});
	ok('recovery verifies clean against the current vault after add + remove', vr.protected === true && vr.clean === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SELF-HEAL AUTO-REFRESH CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { if (mounted) await vdisk.unmount(mounted, { force: true }).catch(() => {}); } catch (_) {}
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-healauto-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
