'use strict';
// lib/test/unmountfollowup.js — the post-unmount follow-up (self-heal recovery refresh AND mirror sync) is gated on the
// unmount result's `redirected` flag: the webserver runs it only when `!r.redirected`, because a DECOY unmount must not
// touch the real vault. A regression once set `redirected` from the always-present `backing` field instead of a real
// decoy signal, so EVERY normal vault's unmount reported redirected=true and its self-heal never refreshed after a
// change — a protected vault silently going stale, which is severe (its recovery data no longer covers new files).
// This pins the invariant both ways: a NORMAL vault's unmount must report redirected=false so the follow-up runs (and
// self-heal actually rebuilds), and a DECOY redirect must report redirected=true so the real vault is left untouched.
// Needs the bundled engine AND a mount driver; skips cleanly without one.
//
// Run:  node lib/test/unmountfollowup.js

const os = require('os');
const fs = require('fs');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

let workspace = null, mountedReal = null, mountedDecoyReal = null;
async function main() {
	// SOURCE GUARD (runs everywhere, even without a mount driver, so CI catches a regression the mount cycle below
	// would miss when skipped): the unmount result must derive `redirected` from the real decoy flag, NEVER from the
	// always-present `backing` field — the exact confusion that made every normal vault skip its self-heal follow-up.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the mount session records the decoy flag from opts._presentAs', /decoy:\s*!!opts\._presentAs/.test(vaultSrc));
	ok('the unmount result derives redirected from sk.decoy', /redirected:\s*!!\(sk && sk\.decoy\)/.test(vaultSrc));
	ok('the unmount result does NOT derive redirected from the always-set sk.backing', !/redirected:\s*!!\(sk && sk\.backing\)/.test(vaultSrc));

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	if (!d.driver || !d.driver.ok) { console.log('No mount driver — skipping the unmount-follow-up cycle.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-unmountfu-')); workspace = tmp;
	const cacheDir = path.join(tmp, 'cache');

	// --- NORMAL vault: unmount must NOT be flagged redirected, so the self-heal follow-up runs and actually rebuilds ---
	const v = path.join(tmp, 'Real.vault');
	await vdisk.create(v, { password: 'pw' });
	let m = await vdisk.mount(v, { password: 'pw', cacheDir }); mountedReal = v;
	ok('a normal mount is not reported as a decoy redirect', m.redirected === false || m.redirected === undefined);
	await sleep(800);
	for (let i = 0; i < 4; i++) await fsp.writeFile(path.join(m.mountpoint, 'f' + i + '.bin'), Buffer.alloc(200000, i));
	await sleep(400);
	await vdisk.unmount(v, {}); mountedReal = null; await sleep(500);
	await vdisk.protect(v, { tier: 'high' });
	const before = (await vdisk.recoveryStatus(v)).dataBlocks;

	// Add files, unmount, and CHECK THE UNMOUNT RESULT — the exact flag the webserver gates the follow-up on.
	m = await vdisk.mount(v, { password: 'pw', cacheDir }); mountedReal = v;
	await sleep(800);
	for (let i = 4; i < 8; i++) await fsp.writeFile(path.join(m.mountpoint, 'g' + i + '.bin'), Buffer.alloc(250000, i));
	await sleep(400);
	const ur = await vdisk.unmount(v, {}); mountedReal = null; await sleep(500);
	ok('a normal unmount reports redirected=false (so the self-heal follow-up is scheduled)', ur.redirected === false);
	ok('a normal unmount reports forced=false', ur.forced === false);
	// Now the follow-up the webserver would run must actually rebuild the recovery data.
	const r = await vdisk.refreshRecoveryIfStale(v, { onProgress: () => {} });
	ok('self-heal rebuilds after a normal unmount (the follow-up would run and update)', r.refreshed === true);
	ok('the recovery index grew to cover the added files', (await vdisk.recoveryStatus(v)).dataBlocks > before);

	// --- DECOY redirect: mounting the real vault with the DECOY password must report redirected=true both ways, so the
	//     webserver skips the real-vault follow-up (touching it would leak that a decoy exists). ---
	const real2 = path.join(tmp, 'Real2.vault'); await vdisk.create(real2, { password: 'realpw' });
	const decoy = path.join(tmp, 'Decoy.vault'); await vdisk.create(decoy, { password: 'decoypw' });
	await vdisk.decoySet({ realVault: real2, decoyVault: decoy, decoyPassword: 'decoypw', managerPassword: 'mgr' });
	const md = await vdisk.mount(real2, { password: 'decoypw', cacheDir }); mountedDecoyReal = real2; // the decoy password redirects to the decoy
	ok('mounting with the decoy password reports a redirect', md.redirected === true);
	await sleep(600);
	const dr = await vdisk.unmount(real2, {}); mountedDecoyReal = null; await sleep(400);
	ok('a decoy unmount reports redirected=true (real-vault follow-up correctly skipped)', dr.redirected === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UNMOUNT-FOLLOW-UP CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { if (mountedReal) await vdisk.unmount(mountedReal, { force: true }).catch(() => {}); } catch (_) {}
	try { if (mountedDecoyReal) await vdisk.unmount(mountedDecoyReal, { force: true }).catch(() => {}); } catch (_) {}
	try { await vdisk.decoyRemove({ realVault: path.join(workspace || '', 'Real2.vault'), managerPassword: 'mgr' }).catch(() => {}); } catch (_) {}
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-unmountfu-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
