'use strict';
// lib/test/rosterrollbackcheck.js — the boot self-check that surfaces a rolled-back access list (or membership
// roster). A rollback (an older, still-validly-signed roster restored in place) would make a revoked read link or
// a removed member reappear; it was previously noticed only when the user happened to open the access panel. The
// 'roster_rollback' self-check now flags it at boot. This proves the check stays silent on a clean vault and fires
// (with the vault named) once the roster is rolled back — and clears again after a fresh legitimate write.
//
// Run:  node lib/test/rosterrollbackcheck.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const SelfCheck = require('../SelfCheck');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function rosterFindings() { const r = await SelfCheck.run({ quiet: true, label: 'test' }); return r.filter(f => f.check === 'roster_rollback'); }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-rollchk-')); workspace = tmp;
	// Isolate the known-vaults list and the rollback-anchor ledger in the workspace, so the check reads a known
	// anchor and never touches the real user data dir. (Same technique the shares test uses.)
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(256));
	const v = path.join(tmp, 'Roll.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw' }); // publishes the key the roster is signed against

	const { sid } = await vdisk.makeReadCap(v, { password: 'pw', label: 'Alice' });
	const rosterPath = path.join(v, 'shares.json');
	const rosterBeforeRevoke = await fsp.readFile(rosterPath, 'utf8'); // a validly-signed OLD version
	await vdisk.revokeShare(v, { password: 'pw', sid });

	ok('a clean, current vault raises no rollback warning', (await rosterFindings()).length === 0);

	// Roll back: restore the older (pre-revoke) roster in place. Its signature is genuine, but the local epoch
	// anchor is now higher, so it reads as rolled back.
	await fsp.writeFile(rosterPath, rosterBeforeRevoke);
	const flagged = await rosterFindings();
	ok('the boot self-check flags the rolled-back access list', flagged.length === 1 && /access list/i.test(flagged[0].message));
	ok('the warning names the affected vault', flagged.length === 1 && flagged[0].message.includes(v));

	// A fresh legitimate write advances the epoch above the anchor → the warning clears.
	await vdisk.revokeShare(v, { password: 'pw', sid });
	ok('a fresh legitimate write clears the rollback warning', (await rosterFindings()).length === 0);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ROSTER-ROLLBACK-CHECK CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
