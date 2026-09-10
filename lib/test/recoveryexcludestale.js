'use strict';
// lib/test/recoveryexcludestale.js — regression guard for the recurring false "Repaired 1 data block" after a key
// rotation. The tool's own metadata blobs (.vaultsnapshot / .vaultcheck / .vaultsession) are excluded from the
// self-heal parity by their ENCRYPTED names, cached per vault. A key rotation re-encrypts every filename, so a cache
// from before the rotation matches nothing afterward. When that stale cache was trusted, .vaultsnapshot stopped
// being excluded, got covered by the parity, and was "repaired" (the re-signed baseline reverted) on every
// mount/unmount cycle — while the tamper check (which works on decrypted names) stayed clean. The fix validates the
// cache against the live store and recomputes it when it no longer matches, so a rotated vault self-heals cleanly.
//
// Run:  node -r ./lib/test/_setup.js lib/test/recoveryexcludestale.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-exclstale-')); workspace = tmp;

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(50 * 1024));
	const v = path.join(tmp, 'Rotated.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Establish the exclude cache + a baseline, then protect (self-heal recovery data).
	await vdisk.checkOnMount(v, 'pw');
	await vdisk.protect(v, {});

	// Sanity: before any rotation, a mount/unmount cycle leaves self-heal clean (the exclude is correct).
	await vdisk.checkOnMount(v, 'pw'); await vdisk.snapshot(v, { password: 'pw' });
	let pre = await vdisk.heal(v, {});
	ok('before rotation, a mount/unmount cycle heals cleanly (baseline is excluded)', pre.repairedData === 0 && pre.repairedFiles.length === 0);

	// Rotate the keys — this re-encrypts every filename in the store, so the cached (pre-rotation) encrypted exclude
	// names now match nothing. Rotation drops the old recovery data (it described the old keys).
	await vdisk.rotate(v, { password: 'pw' });

	// The protect path must REFUSE to build recovery data from a stale exclude (it would cover the metadata blobs),
	// directing the user to mount once so the exclude recomputes — exactly like a missing cache.
	let refused = null;
	try { await vdisk.protect(v, {}); } catch (e) { refused = e; }
	ok('after rotation, protect with a stale exclude is refused as not-ready (never builds from a stale list)', !!refused && refused.code === 'EXCLUDE_NOT_READY');

	// Mount once: this recomputes the exclude against the rotated store.
	await vdisk.checkOnMount(v, 'pw');
	// Now re-protect ("Update protection") succeeds and covers the CURRENT store with the CURRENT exclude.
	await vdisk.protect(v, {});

	// The real test: repeated mount/unmount cycles on the rotated vault must NOT report or "repair" any damage.
	let stillClean = true;
	for (let cycle = 0; cycle < 3; cycle++) {
		await vdisk.checkOnMount(v, 'pw');           // mount rewrites .vaultcheck / .vaultsession
		await vdisk.snapshot(v, { password: 'pw' }); // unmount re-signs .vaultsnapshot
		const rep = await vdisk.verifyRecovery(v, {});
		const h = await vdisk.heal(v, {});
		if (!(rep.clean && rep.damagedData === 0 && h.repairedData === 0 && h.repairedFiles.length === 0)) stillClean = false;
	}
	ok('after rotation + remount + update, repeated mount/unmount cycles self-heal cleanly (no phantom repair, no revert)', stillClean);

	// And the user's real files still decrypt (the fix did not touch real data).
	let opens = true; try { await vdisk.list(v, { password: 'pw' }); } catch (_) { opens = false; }
	ok('the rotated vault still opens and lists its files', opens);

	// AUTO-FIX (needs a real mount for a trusted session): a vault whose recovery data was built with a STALE
	// exclusion (covering the tool's own metadata blob) must repair itself the first time it is opened and closed —
	// no manual "Update protection" — and must NOT rebuild again on later cycles (self-clearing, no loop).
	const Recovery = require('../Recovery');
	if ((await vdisk.doctor()).driver.ok) {
		const v2 = path.join(tmp, 'AutoFix.vault');
		await vdisk.importFolder(v2, { password: 'pw', sourceDir: src });
		await vdisk.checkOnMount(v2, 'pw');
		// Simulate a pre-fix index: built with an EMPTY exclusion, so it covers .vaultsnapshot.
		await Recovery.protect(v2, { tier: 'medium', cipherDir: path.join(v2, 'data'), exclude: [] });
		ok('the simulated pre-fix index covers the metadata blob (empty exclusion)', (await Recovery.readIndexMeta(v2)).exclude.length === 0);
		const cacheDir = path.join(tmp, 'cache2');
		try {
			await vdisk.mount(v2, { password: 'pw', cacheDir });   // "open" — recomputes the exclusion, marks a trusted session
			await vdisk.unmount(v2, {});
			const r = await vdisk.refreshRecoveryIfStale(v2, {});  // "close" — the app's auto-refresh
			ok('opening and closing the vault auto-rebuilds the recovery data (no manual Update protection)', r.refreshed === true);
			ok('the rebuilt index now excludes the metadata blobs', (await Recovery.readIndexMeta(v2)).exclude.length > 0);
			await vdisk.checkOnMount(v2, 'pw'); await vdisk.snapshot(v2, { password: 'pw' });
			ok('after the auto-fix, self-heal is clean', (await vdisk.verifyRecovery(v2, {})).clean === true);
			// Loop-proof: a second open/close must NOT rebuild again.
			await vdisk.mount(v2, { password: 'pw', cacheDir }); await vdisk.unmount(v2, {});
			const r2 = await vdisk.refreshRecoveryIfStale(v2, {});
			ok('a second open/close does NOT rebuild again (self-clearing, no loop)', r2.refreshed === false);
		} finally { await vdisk.unmount(v2, {}).catch(() => {}); }
		await vdisk.removeKnownVault(v2).catch(() => {});
	} else { console.log('  skip  (no mount driver — auto-fix-on-open/close needs a real mount for a trusted session)'); }

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-EXCLUDE-STALE CHECKS PASSED'));
	if (workspace) { try { fs.rmSync(workspace, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); if (workspace) { try { fs.rmSync(workspace, { recursive: true, force: true }); } catch (_) {} } process.exit(1); });
