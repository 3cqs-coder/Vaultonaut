'use strict';
// lib/test/slotrollbackcheck.js — the boot self-check must also flag a rolled-back KEY-SLOT set, not just a
// rolled-back roster or access list. Restoring an older, still-validly-signed manifest could re-list a removed
// extra password, keyfile, or read-only key; the manifest seal alone cannot stop it (the old manifest was
// legitimately signed). crypt.slotEpoch is anchored locally on each write, and listKeys.rolledBack (surfaced by
// the 'roster_rollback' self-check) fires when the on-disk epoch is older than the anchor. This proves the check
// is silent on a clean vault, fires (naming the vault) after a slot rollback, and clears after a fresh write.
//
// Run:  node lib/test/slotrollbackcheck.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const SelfCheck = require('../SelfCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function slotFindings() { const r = await SelfCheck.run({ quiet: true, label: 'test' }); return r.filter(f => f.check === 'roster_rollback' && /key slots/i.test(f.message)); }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-slotroll-')); workspace = tmp;
	// Isolate the known-vaults list and the rollback-anchor ledger in the workspace.
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(256));
	const v = path.join(tmp, 'Slot.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw' });

	// Add a second key, then capture that manifest (a validly-signed OLDER slot epoch) before removing the key.
	await vdisk.addKey(v, { password: 'pw', newPassword: 'pw2', label: 'extra' });
	const mfPath = path.join(v, 'vault.json');
	const manifestWithExtra = await fsp.readFile(mfPath, 'utf8'); // slot epoch N, includes the pw2 slot
	const keys = await vdisk.listKeys(v);
	const extraId = keys.slots.find(s => s.label === 'extra').id;
	await vdisk.removeKey(v, { password: 'pw', slotId: extraId }); // slot epoch N+1, pw2 slot gone

	ok('a clean, current vault raises no key-slot rollback warning', (await slotFindings()).length === 0);
	ok('listKeys does not report a rollback on the current vault', (await vdisk.listKeys(v)).rolledBack === false);

	// Roll back: restore the older manifest in place. Its signature is genuine, but the local slot-epoch anchor is
	// now higher, so it reads as rolled back — and the removed key has reappeared.
	await fsp.writeFile(mfPath, manifestWithExtra);
	const flagged = await slotFindings();
	ok('the boot self-check flags the rolled-back key slots', flagged.length === 1);
	ok('the warning names the affected vault', flagged.length === 1 && flagged[0].message.includes(v));
	ok('the reappeared removed key is detectable (rolledBack on listKeys)', (await vdisk.listKeys(v)).rolledBack === true);

	// A fresh legitimate slot change advances the epoch to (at least) the anchor → the warning clears.
	await vdisk.addKey(v, { password: 'pw', newPassword: 'pw3', label: 'fresh' });
	ok('a fresh legitimate key change clears the rollback warning', (await slotFindings()).length === 0);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SLOT-ROLLBACK-CHECK CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
