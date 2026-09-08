'use strict';
// lib/test/decoy.js — per-vault decoy (duress) protection. A protected vault is paired with a separate decoy
// vault; opening the protected vault with the decoy vault's password resolves to the decoy instead. This test
// covers the crypto/registry invariants directly (no engine needed) and, when the engine is present, the
// end-to-end pairing with real vaults (the decoy password is verified against the decoy vault at pair time).
//
// Run:  node lib/test/decoy.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-decoy-'));
	const Common = require('../Common');
	Common.dataDir = () => tmp; // redirect the registry into a throwaway dir — never touch real state
	const Decoy = require('../Decoy');

	ok('no decoy registry by default', Decoy.hasRegistry() === false);
	// Deniability: listing with NO registry must look exactly like a wrong password (null, never []), so the
	// endpoint cannot be used as an oracle for whether a decoy pairing exists.
	ok('listing with no registry is indistinguishable from a wrong password (null, not [])', (await Decoy.listMappings('anything')) === null);

	// --- Crypto / registry invariants (no engine) ---
	const V1 = '/real/Personal.vault', D1 = '/decoy/Recipes.vault';
	const V2 = '/real/Work.vault', D2 = '/decoy/Music.vault';
	await Decoy.setDecoy({ realVault: V1, decoyVault: D1, decoyPassword: 'decoy-pw-1', managerPassword: 'manager-pw' });
	ok('a registry is created on first pairing', Decoy.hasRegistry() === true);

	const reg = JSON.parse(await fsp.readFile(Decoy.registryPath(), 'utf8'));
	ok('the registry has the fixed slot count (decoy count is hidden)', reg.slots.length === Decoy.SLOT_COUNT);
	ok('every slot is the same size (filler indistinguishable from real)', new Set(reg.slots.map(s => s.length)).size === 1);

	ok('the decoy password resolves to the decoy vault', (await Decoy.resolveDecoy(V1, 'decoy-pw-1')) === path.resolve(D1));
	ok('a wrong password resolves to nothing', (await Decoy.resolveDecoy(V1, 'nope')) === null);
	ok('the decoy password does not redirect a DIFFERENT vault', (await Decoy.resolveDecoy(V2, 'decoy-pw-1')) === null);
	ok('the manager password does not itself resolve a decoy', (await Decoy.resolveDecoy(V1, 'manager-pw')) === null);

	// A second pairing, same manager. Both resolve, and the slot count stays fixed (the number of decoys is
	// still invisible).
	await Decoy.setDecoy({ realVault: V2, decoyVault: D2, decoyPassword: 'decoy-pw-2', managerPassword: 'manager-pw' });
	ok('a second pairing resolves', (await Decoy.resolveDecoy(V2, 'decoy-pw-2')) === path.resolve(D2));
	ok('the first pairing still resolves after adding a second', (await Decoy.resolveDecoy(V1, 'decoy-pw-1')) === path.resolve(D1));
	ok('the slot count is unchanged after a second pairing', JSON.parse(await fsp.readFile(Decoy.registryPath(), 'utf8')).slots.length === Decoy.SLOT_COUNT);

	// The wrong manager password cannot manage.
	let wrongMgrRefused = false;
	try { await Decoy.setDecoy({ realVault: '/real/x.vault', decoyVault: '/decoy/y.vault', decoyPassword: 'p', managerPassword: 'WRONG' }); } catch (_) { wrongMgrRefused = true; }
	ok('a wrong manager password is refused', wrongMgrRefused);

	// The hidden management view (manager password) lists the pairings; a wrong manager password returns null.
	const mappings = await Decoy.listMappings('manager-pw');
	ok('the manager lists both pairings', mappings && mappings.length === 2 && mappings.some(m => m.realVault === path.resolve(V1) && m.decoyVault === path.resolve(D1)));
	ok('a wrong manager password lists nothing', (await Decoy.listMappings('WRONG')) === null);

	// Removing a pairing drops only that one; removing the last clears the registry entirely.
	await Decoy.removeDecoy({ realVault: V1, managerPassword: 'manager-pw' });
	ok('a removed pairing no longer resolves', (await Decoy.resolveDecoy(V1, 'decoy-pw-1')) === null);
	ok('the other pairing survives a removal', (await Decoy.resolveDecoy(V2, 'decoy-pw-2')) === path.resolve(D2));
	await Decoy.removeDecoy({ realVault: V2, managerPassword: 'manager-pw' });
	ok('removing the last pairing clears the registry', Decoy.hasRegistry() === false);

	// CONCURRENCY: several pairings submitted at once (a double-submit, or two tabs) must ALL survive. Each is a
	// read-modify-write of the whole registry, so without serialization the later writes would clobber the earlier
	// ones and a vault the user believes is duress-protected would silently be left unprotected.
	const many = Array.from({ length: 6 }, (_, i) => ({ real: '/real/C' + i + '.vault', decoy: '/decoy/C' + i + '.vault', pw: 'decoy-c-' + i }));
	await Promise.all(many.map(m => Decoy.setDecoy({ realVault: m.real, decoyVault: m.decoy, decoyPassword: m.pw, managerPassword: 'manager-pw' })));
	let allConcurrentSurvived = true;
	for (const m of many) if ((await Decoy.resolveDecoy(m.real, m.pw)) !== path.resolve(m.decoy)) allConcurrentSurvived = false;
	ok('every concurrently-added pairing survives (none silently dropped)', allConcurrentSurvived);
	const concurrentList = await Decoy.listMappings('manager-pw');
	ok('the manager view lists all concurrently-added pairings', concurrentList && concurrentList.length === many.length);
	await Decoy.removeRegistry(); // clean slate for the corrupt-registry section below

	// A corrupt primary registry recovers resolution from the one-generation backup. Done last, in isolation,
	// because a modify-after-corruption rebuilds from the (one-generation) backup by design.
	await Decoy.setDecoy({ realVault: V1, decoyVault: D1, decoyPassword: 'decoy-pw-1', managerPassword: 'manager-pw' });
	await Decoy.setDecoy({ realVault: V2, decoyVault: D2, decoyPassword: 'decoy-pw-2', managerPassword: 'manager-pw' }); // makes a good .bak holding [V1]
	await fsp.writeFile(Decoy.registryPath(), 'not valid json{', 'utf8');
	ok('a corrupt registry recovers resolution from the .bak backup', (await Decoy.resolveDecoy(V1, 'decoy-pw-1')) === path.resolve(D1));
	await Decoy.removeRegistry(); // clear the unit-test registry before the end-to-end section starts fresh

	// --- End-to-end pairing with real vaults (needs the engine; no mount driver required) ---
	const vdisk = require('../index');
	Common.statePath = () => path.join(tmp, 'state.json'); // isolate the known-vaults list too
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('  skip  end-to-end pairing (engine missing)'); return done(); }

	const realDir = path.join(tmp, 'Secret.vault'), decoyDir = path.join(tmp, 'Boring.vault');
	await vdisk.create(realDir, { password: 'real-password' });
	await vdisk.create(decoyDir, { password: 'boring-password' });

	// Pairing verifies the decoy password against the DECOY vault (so a mistyped pairing is caught now).
	let badDecoyPw = false;
	try { await vdisk.decoySet({ realVault: realDir, decoyVault: decoyDir, decoyPassword: 'not-the-decoy-password', managerPassword: 'mgr' }); } catch (_) { badDecoyPw = true; }
	ok('pairing rejects a password that does not open the decoy vault', badDecoyPw);

	// A decoy password that ALSO opens the REAL vault is refused — the mount only redirects to the decoy after the
	// real vault fails to unlock, so such a password would reveal the real vault under duress and never trigger it.
	const sameDir = path.join(tmp, 'Same.vault');
	await vdisk.create(sameDir, { password: 'real-password' });
	let sameRefused = false;
	try { await vdisk.decoySet({ realVault: realDir, decoyVault: sameDir, decoyPassword: 'real-password', managerPassword: 'mgr' }); } catch (_) { sameRefused = true; }
	ok('pairing rejects a decoy password that also opens the real vault', sameRefused);

	await vdisk.decoySet({ realVault: realDir, decoyVault: decoyDir, decoyPassword: 'boring-password', managerPassword: 'mgr' });
	ok('a real pairing is created', vdisk.decoyProtected() === true);
	// The mount path resolves the decoy: opening the real vault with the decoy vault's password maps to the
	// decoy vault (the mount then opens THAT with the same password, which is the decoy vault's own password).
	ok('opening the real vault with the decoy password resolves to the decoy', (await Decoy.resolveDecoy(realDir, 'boring-password')) === path.resolve(decoyDir));
	ok('the real vault password does not resolve a decoy (the trigger is the decoy password)', (await Decoy.resolveDecoy(realDir, 'real-password')) === null);
	// The mount path tries the real password FIRST and only consults resolveDecoy when that fails, so the real
	// password still opens the real vault. Confirm the real password genuinely opens the real vault (list opens
	// it and throws on a wrong password; no snapshot needed).
	let realOpens = true; try { await vdisk.list(realDir, { password: 'real-password' }); } catch (_) { realOpens = false; }
	ok('the real password opens the real vault (no decoy)', realOpens);

	// End-to-end mount redirect (needs a mount driver; skipped otherwise): opening the REAL vault with the
	// decoy password actually mounts the DECOY vault instead. This also proves the redirect does not deadlock
	// (it re-enters the mount path below the serial lock, never through it).
	const drv = await require('../Driver').detect().catch(() => ({ ok: false }));
	if (drv && drv.ok) {
		const mp = path.join(tmp, 'mnt');
		let m = null;
		try {
			m = await vdisk.mount(realDir, { password: 'boring-password', mountpoint: mp });
			// The mount succeeds with the DECOY's password (which does not open the real vault), so the decoy is
			// what actually mounted — yet it is PRESENTED as the real vault, so nothing (state, status, this return
			// value) reveals the pairing.
			ok('opening the real vault with the decoy password mounts the decoy but presents the real vault', m && Common.samePath(m.vault, realDir));
			const st = (await vdisk.status().catch(() => [])) || [];
			const rec = st.find(x => x.mountpoint && Common.samePath(x.mountpoint, mp));
			ok('the mount state records the real vault, not the decoy (no pairing tell)', rec && Common.samePath(rec.vault, realDir) && !Common.samePath(rec.vault, decoyDir));
			// CONTENT ISOLATION: write a sentinel THROUGH this decoy-redirected mount. A label check alone can't
			// catch a regression that actually opened the REAL vault — the write must land in the DECOY's store.
			await fsp.writeFile(path.join(mp, 'decoy-sentinel.txt'), 'i am the decoy');
		} catch (e) { console.log('  skip  live mount redirect (' + (e && e.message || e) + ')'); }
		finally { if (m && m.mountpoint) await vdisk.unmount(m.mountpoint).catch(() => {}); }
		// After the decoy mount/unmount, the REAL vault must be untouched (teardown finalized the decoy, not it).
		let realStillOpens = true; try { await vdisk.list(realDir, { password: 'real-password' }); } catch (_) { realStillOpens = false; }
		ok('the real vault is untouched after a decoy mount and unmount', realStillOpens);
		// The sentinel written through the decoy-redirected mount is in the DECOY vault, and the REAL vault never
		// saw it — the decoy password serves decoy CONTENT, never the real vault's, which is the whole point.
		const decoyList = await vdisk.list(decoyDir, { password: 'boring-password' }).catch(() => []);
		ok('a file written via the decoy password is in the DECOY vault', decoyList.some(f => /decoy-sentinel\.txt/.test(f)));
		const realList = await vdisk.list(realDir, { password: 'real-password' }).catch(() => []);
		ok('the REAL vault never received the decoy write (content isolation holds)', !realList.some(f => /decoy-sentinel\.txt/.test(f)));

		// A decoy MOVED since pairing must not throw a distinctive error under duress: the mount falls through to
		// the normal wrong-password path, so a stale pairing looks exactly like a mistyped password.
		const movedTo = path.join(tmp, 'Moved.vault');
		await fsp.rename(decoyDir, movedTo);
		let staleFellThrough = false, mp2 = null;
		try { const r = await vdisk.mount(realDir, { password: 'boring-password', mountpoint: path.join(tmp, 'mnt2') }); mp2 = r && r.mountpoint; } catch (_) { staleFellThrough = true; }
		finally { if (mp2) await vdisk.unmount(mp2).catch(() => {}); }
		ok('a moved decoy falls through to a normal wrong-password error, not a distinctive failure', staleFellThrough);
		let realOk2 = true; try { await vdisk.list(realDir, { password: 'real-password' }); } catch (_) { realOk2 = false; }
		ok('the real vault is untouched after a stale-decoy unlock attempt', realOk2);
		await fsp.rename(movedTo, decoyDir);
	} else { console.log('  skip  live mount redirect (no mount driver)'); }

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DECOY CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
