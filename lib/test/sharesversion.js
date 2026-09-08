'use strict';
// lib/test/sharesversion.js — the share roster's format VERSION is bound into its signature, and a claimed
// "newer version" is only honored (refused as a downgrade) when its signature verifies. Previously the version
// was unsigned and refused unconditionally, so anyone who could write the file could set version:999 to block
// every future revoke/prune — a filesystem-write denial-of-modification against revocation. This proves a forged
// version is (a) detected as tampering and (b) no longer blocks the owner from revoking.
//
// Run:  node lib/test/sharesversion.js   (needs the engine; no mount driver)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-shver-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(256));
	const v = path.join(tmp, 'V.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw' });

	const { sid } = await vdisk.makeReadCap(v, { password: 'pw', label: 'Alice' });
	ok('a freshly minted roster verifies', (await vdisk.listShares(v)).sigOk === true);

	// Forge the format version on disk (the signature stays over the real version).
	const rosterPath = path.join(v, 'shares.json');
	const store = JSON.parse(await fsp.readFile(rosterPath, 'utf8'));
	store.version = 999;
	await fsp.writeFile(rosterPath, JSON.stringify(store));

	ok('a forged roster version is detected as tampering (signature no longer verifies)', (await vdisk.listShares(v)).sigOk === false);

	// The forged version must NOT block the owner from revoking — the old code threw "newer version" here.
	let revokeThrew = false;
	try { await vdisk.revokeShare(v, { password: 'pw', sid }); } catch (_) { revokeThrew = true; }
	ok('revocation still works despite the forged version (denial-of-modification closed)', !revokeThrew);

	const after = await vdisk.listShares(v);
	ok('after the owner rewrite the roster verifies again and the share is revoked', after.sigOk === true && after.shares[0] && after.shares[0].revoked === true);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SHARES-VERSION CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
