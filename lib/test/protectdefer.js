'use strict';
// lib/test/protectdefer.js — a manual "update protection" (Vault.protect) must NOT silently strip a SIGNED recovery
// index. A password-less rebuild cannot re-sign the index, so if the vault's recovery data is currently signed, a
// rebuild would leave it unsigned at a higher version — which verify/heal then flag as a DOWNGRADE and refuse to
// auto-repair (the same trace an attacker leaves by stripping a signature). That would turn a routine action into a
// scary, repair-blocking state, exactly the kind of false alarm a benign user action must never raise. So a manual
// protect with no unlocked session in hand DEFERS on a signed vault (leaving the signed index in place and telling
// the user to open it once), and still does a normal cold, unsigned protect on a never-signed vault.
//
// Run:  node lib/test/protectdefer.js  (needs the bundled engine and a mount driver — one mount captures the signer)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	if (!d.driver.ok) { console.log('No mount driver — skipping (a mount is needed to capture the write-authority signer).'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-protdefer-')); workspace = tmp;

	// A never-signed vault: a cold, password-less protect must still work (unsigned), never defer.
	{
		const src = path.join(tmp, 'srcA'); await fsp.mkdir(src);
		for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(40 * 1024));
		const v = path.join(tmp, 'Cold.vault');
		await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
		const r = await vdisk.protect(v, { tier: 'low' });
		ok('a never-signed vault gets a normal cold protect (not deferred)', !r.deferred && r.dataBlocks > 0);
		await vdisk.removeKnownVault(v).catch(() => {});
	}

	// A signed vault: sign it via a real read-write session (the mount captures the signer that a same-process
	// protect then uses), then a later manual protect with no session in hand must DEFER rather than strip the signature.
	{
		const src = path.join(tmp, 'srcB'); await fsp.mkdir(src);
		for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(40 * 1024));
		const v = path.join(tmp, 'Signed.vault');
		await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
		await vdisk.mount(v, { password: 'pw' }); await vdisk.unmount(v, {}); // a read-write session: captures the signer in this process
		const signed = await vdisk.protect(v, { tier: 'low' }); // uses the just-captured signer -> a SIGNED index (floor > 0)
		ok('a protect with a recent read-write session signs the index', signed.signed === true && !signed.deferred);
		const auth = (await Recovery.verify(v, { pubkey: null, vaultId: null }));
		ok('the vault now has a signed recovery index', !!(auth && auth.authenticity && auth.authenticity.signed));
		// No unlocked session remains in hand (the signer was single-use and is consumed), so a manual re-protect must
		// DEFER rather than rebuild unsigned and create a downgrade.
		const again = await vdisk.protect(v, { tier: 'low' });
		ok('a manual protect on a signed vault with no unlocked session DEFERS (does not strip the signature)', again.deferred === true && again.reason === 'signed-needs-unlock');
		const still = (await Recovery.verify(v, { pubkey: null, vaultId: null }));
		ok('the signed index is left intact after the deferral (no downgrade created)', !!(still && still.authenticity && still.authenticity.signed));
		await vdisk.removeKnownVault(v).catch(() => {});
	}

	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PROTECT-DEFER CHECKS PASSED'));
	return cleanup().then(() => process.exit(failures ? 1 : 0));
}
async function cleanup() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
