'use strict';
// lib/test/decoyepoch.js — the decoy registry's cross-process conflict guard. Within one process a serial queue
// orders registry writes, but two DIFFERENT processes (a CLI change while the service runs one) are not ordered;
// without protection the later write, built from a stale read taken before a slow key derivation, would silently
// drop the other process's mapping — leaving a vault the user believes is duress-protected unprotected. A monotonic
// `epoch` in the record guards it: each write records epoch+1 and both mutators refuse to overwrite if the on-disk
// epoch moved since they read it. This proves the epoch is maintained across changes (so no mapping is lost across
// sequential edits) and that the refusal check is wired before every rebuild.
//
// Run:  node lib/test/decoyepoch.js   (no engine, no network — exercises lib/Decoy directly)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-decoyepoch-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	const Decoy = require('../Decoy');

	const epochOf = () => { try { return Number(JSON.parse(fs.readFileSync(Decoy.registryPath(), 'utf8')).epoch) || 0; } catch (_) { return null; } };
	const mgr = 'manager-pass';
	const paths = (n) => ({ realVault: path.join(tmp, 'real' + n), decoyVault: path.join(tmp, 'decoy' + n) });

	// First pairing creates the registry at epoch 1.
	await Decoy.setDecoy({ ...paths(1), decoyPassword: 'decoy-pw-1', managerPassword: mgr });
	ok('the first pairing writes epoch 1', epochOf() === 1);

	// A second pairing bumps to epoch 2 and both mappings survive (no lost update in the read-modify-write).
	await Decoy.setDecoy({ ...paths(2), decoyPassword: 'decoy-pw-2', managerPassword: mgr });
	ok('a second pairing writes epoch 2', epochOf() === 2);
	ok('both pairings are present (neither read-modify-write dropped the other)', (await Decoy.listMappings(mgr)).length === 2);

	// Removing one bumps the epoch again and leaves the other intact.
	await Decoy.removeDecoy({ realVault: paths(1).realVault, managerPassword: mgr });
	ok('removing a pairing bumps to epoch 3', epochOf() === 3);
	ok('the other pairing remains', (await Decoy.listMappings(mgr)).length === 1);

	// The refusal check must run before EACH rebuild (static guard so the cross-process protection cannot be
	// silently dropped in a future edit).
	const src = fs.readFileSync(path.join(__dirname, '..', 'Decoy.js'), 'utf8');
	const setDecoyBody = src.slice(src.indexOf('async function setDecoy'), src.indexOf('async function removeDecoy'));
	const removeDecoyBody = src.slice(src.indexOf('async function removeDecoy'), src.indexOf('async function listMappings'));
	ok('setDecoy re-checks the epoch before rebuilding', /assertUnchanged\(baseEpoch\)[\s\S]*rebuild\(/.test(setDecoyBody));
	ok('removeDecoy re-checks the epoch before rebuilding/removing', /assertUnchanged\(m\.epoch\)/.test(removeDecoyBody));

	return done();
}

function done() {
	try { if (tmp) fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DECOY-EPOCH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
