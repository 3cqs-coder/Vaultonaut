'use strict';
// lib/test/decoystale.js — a decoy pairing can silently go stale: the duress redirect is keyed to the decoy
// vault at a fixed path, with the decoy password's derived key snapshotted at pairing. If the decoy vault later
// moves, is replaced, or has its password changed, the recorded decoy password no longer triggers the redirect —
// and, for a duress feature, a user must not believe they are protected when they are not. The manager-password
// management view now flags such a pairing (and ONLY there, so nothing leaks to a decoy-password-only adversary).
// This proves a fresh pairing reads clean, a decoy password change is flagged, and a missing decoy is flagged.
//
// Run:  node lib/test/decoystale.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-decoystale-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const real = path.join(tmp, 'Real.vault'); await vdisk.create(real, { password: 'realpw' });
	const decoy = path.join(tmp, 'Decoy.vault'); await vdisk.create(decoy, { password: 'decoypw' });
	await vdisk.decoySet({ realVault: real, decoyVault: decoy, decoyPassword: 'decoypw', managerPassword: 'mgr' });

	let list = await vdisk.decoyList('mgr');
	ok('a fresh pairing reads as ok with no warning', list.length === 1 && list[0].status === 'ok' && !list[0].warning);
	ok('a wrong manager password still returns null (no oracle)', (await vdisk.decoyList('wrong-manager')) === null);

	// Change the decoy vault's password — this rewrites its unlock slot, so the pairing may no longer trigger.
	await vdisk.changePassword(decoy, { oldPassword: 'decoypw', newPassword: 'decoypw2' });
	list = await vdisk.decoyList('mgr');
	ok('a decoy-vault password change is flagged as stale', list[0].status === 'decoy-keys-changed' && /keys have changed/i.test(list[0].warning || ''));

	// Remove the decoy vault entirely — the decoy can no longer open.
	await fsp.rm(decoy, { recursive: true, force: true });
	list = await vdisk.decoyList('mgr');
	ok('a missing decoy vault is flagged', list[0].status === 'decoy-missing' && /missing or has moved/i.test(list[0].warning || ''));

	// A pairing whose PROTECTED vault is gone is flagged too (the redirect would never trigger).
	await fsp.rm(real, { recursive: true, force: true });
	list = await vdisk.decoyList('mgr');
	ok('a missing protected vault is flagged', list[0].status === 'real-missing');

	return done();
}

async function done() {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-decoystale-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DECOY-STALE CHECKS PASSED'));
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
