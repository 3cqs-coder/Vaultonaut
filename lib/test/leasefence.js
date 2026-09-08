'use strict';
// lib/test/leasefence.js — the cross-process persist FENCE. A vault change reads the manifest under an advisory
// lease, does its work, then writes. If that lease is judged stale and STOLEN by another process mid-operation (a
// reclaimed birth window, a wall-clock jump, a long event-loop stall past the lease TTL), the write must ABORT
// cleanly rather than clobber the change the new holder made. This simulates the theft — rewriting the on-disk
// lock with a different nonce while an update is in flight — and confirms the write is refused (LEASE_LOST) and
// the manifest is left exactly as it was.
//
// Run:  node lib/test/leasefence.js  (needs the engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-lease-')); workspace = tmp;
	const Common = require('../Common');
	Common.dataDir = () => tmp;                       // locks live under dataDir/locks — keep them in the throwaway dir
	Common.statePath = () => path.join(tmp, 'state.json');
	const vdisk = require('../index');
	const Vault = require('../Vault');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping the lease-fence checks.'); return done(); }

	const v = path.join(tmp, 'Lease.vault');
	await vdisk.create(v, { password: 'lease-test-passphrase' });

	// A normal partial update (no theft) commits and persists.
	await Vault.updateManifestFields(v, (m) => { m.snapshot = { marker: 'first' }; });
	ok('a normal update persists', (await Vault.readManifest(v)).snapshot && (await Vault.readManifest(v)).snapshot.marker === 'first');

	// Now steal the lease mid-update: inside apply (after the manifest was read, before it is written) rewrite the
	// vault's lock file with a DIFFERENT nonce and a fresh timestamp, as another process reclaiming a "stale" lease
	// would. The persist fence must then refuse the write.
	let stole = false;
	const theft = async (m) => {
		m.snapshot = { marker: 'must-not-persist' }; // the change we expect to be dropped
		const locksDir = path.join(Common.dataDir(), 'locks');
		const files = await fsp.readdir(locksDir).catch(() => []);
		const lock = files.find(f => f.endsWith('.lock'));
		if (lock) {
			const p = path.join(locksDir, lock);
			const rec = JSON.parse(await fsp.readFile(p, 'utf8'));
			rec.nonce = 'stolen-by-another-process'; rec.at = Date.now(); // fresh, so it does not read as stale
			await fsp.writeFile(p, JSON.stringify(rec));
			stole = true;
		}
	};
	let code = null;
	try { await Vault.updateManifestFields(v, theft); } catch (e) { code = e.code; }
	ok('the test actually stole the lease mid-update', stole);
	ok('the write is refused with LEASE_LOST', code === 'LEASE_LOST');
	ok('the stolen-lease change did NOT persist (no clobber)', (await Vault.readManifest(v)).snapshot.marker === 'first');

	// After the aborted write the vault is still fully usable.
	ok('the vault still opens after the aborted write', Array.isArray(await vdisk.list(v, { password: 'lease-test-passphrase' }).catch(() => null)));
	// The fictional other process releases its (stolen) lock; a fresh update then commits normally.
	{ const locksDir = path.join(Common.dataDir(), 'locks'); for (const f of await fsp.readdir(locksDir).catch(() => [])) if (f.endsWith('.lock')) await fsp.rm(path.join(locksDir, f), { force: true }); }
	await Vault.updateManifestFields(v, (m) => { m.snapshot = { marker: 'second' }; });
	ok('a later update commits normally', (await Vault.readManifest(v)).snapshot.marker === 'second');

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LEASE-FENCE CHECKS PASSED'));
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} } process.exit(1); });
