'use strict';
// lib/test/vaultsize.js — Vault.vaultSize reports how much data a vault holds. It is deliberately deniability-safe:
// it REFUSES for an unmounted vault (so the UI never broadcasts an unmounted folder's footprint, which would reveal
// a large real vault hidden behind a small decoy). For a MOUNTED local vault with no decoy feature in use, it sizes
// the on-disk ciphertext store (reliable on every platform, unlike a mount walk whose fs.stat can fail on WinFsp);
// when a decoy is in use, or for a cloud vault, it sizes the mounted contents so a decoy unlock reports the decoy's
// size. Either way it EXCLUDES the self-healing recovery data, which lives outside the store. This pins the refusal
// (no mount driver needed) and, when a driver is present, the size measurement and the recovery exclusion.
//
// Run:  node lib/test/vaultsize.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdvsize-'));
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'd'); Common.statePath = () => path.join(tmp, 'd', 'state.json');
	const Vault = require('../Vault');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.bin'), Buffer.alloc(120000));
	await fsp.writeFile(path.join(src, 'b.bin'), Buffer.alloc(30000));
	const v = path.join(tmp, 'V.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Deniability: an UNMOUNTED vault must refuse to report a size — never broadcast the on-disk footprint.
	let refused = false;
	try { await Vault.vaultSize(v); } catch (e) { refused = /mount the vault first/i.test(e.message); }
	ok('vaultSize refuses for an unmounted vault (deniability)', refused);

	// The mounted measurement + healing exclusion need a mount driver.
	const drv = await require('../Driver').detect().catch(() => ({ ok: false }));
	if (!(drv && drv.ok)) { console.log('  skip  mounted size checks (no mount driver)'); return done(); }
	let m = null;
	try { m = await vdisk.mount(v, { password: 'pw', mountpoint: path.join(tmp, 'mnt') }); } catch (e) { console.log('  skip  mounted size (mount failed: ' + (e && e.message || e) + ')'); return done(); }
	try {
		const CONTENT = 150000; // a.bin + b.bin
		const r = await Vault.vaultSize(v);
		ok('a mounted (non-decoy, local) vault reports its on-disk size, about the files it holds', r.bytes >= CONTENT && r.bytes < CONTENT + 15000);
		// Add high-tier recovery data (~15% parity ≈ 22 KB), which lives in .recovery/ OUTSIDE the mounted store. The
		// reported size must stay in the content band — if the parity leaked in it would jump by ~22 KB, well past it.
		// (A tight before/after equality is avoided because the OS may add a few KB of its own mount metadata between
		// the two mounts; the band still cleanly separates "parity excluded" from "parity counted".)
		await vdisk.unmount(m.mountpoint); m = null;
		await vdisk.protect(v, { tier: 'high' });
		m = await vdisk.mount(v, { password: 'pw', mountpoint: path.join(tmp, 'mnt') });
		const r2 = await Vault.vaultSize(v);
		ok('the self-healing recovery data is excluded from the size', r2.bytes >= CONTENT && r2.bytes < CONTENT + 15000);
	} finally { if (m && m.mountpoint) await vdisk.unmount(m.mountpoint).catch(() => {}); }

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-SIZE CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
