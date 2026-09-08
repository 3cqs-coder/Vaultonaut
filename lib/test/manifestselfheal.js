'use strict';
// lib/test/manifestselfheal.js — the manifest is the ONLY copy of the salt and the wrapped master key, so a torn
// primary (a crash mid-write, a bad hand-edit) must never brick a vault. persistManifest keeps a second copy at
// .vault.bak; opening the vault must transparently heal a missing or corrupt primary from that backup, and rewrite
// the primary so it is whole again. This proves that recovery end to end.
//
// Run:  node lib/test/manifestselfheal.js  (needs the engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const vdisk = require('../index');

const PASS = 'a-manifest-heal-passphrase';
let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const opens = async (dir) => { try { return Array.isArray(await vdisk.list(dir, { password: PASS })); } catch (_) { return false; } };
const isValidManifest = (p) => { try { const j = JSON.parse(fs.readFileSync(p, 'utf8')); return !!(j && j.crypt && j.crypt.salt); } catch (_) { return false; } };

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping the manifest self-heal checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mheal-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'appdata'); Common.statePath = () => path.join(tmp, 'appdata', 'state.json'); // isolate state/ledger from the real data dir (engine stays pinned by the test preload)
	const v = path.join(tmp, 'Heal.vault');
	await vdisk.create(v, { password: PASS });
	const primary = path.join(v, 'vault.json'), backup = path.join(v, '.vault.bak');
	ok('a fresh vault has both the manifest and its backup', fs.existsSync(primary) && fs.existsSync(backup));
	const original = await fsp.readFile(backup, 'utf8'); // the good manifest content, kept for comparison

	// --- a CORRUPT primary heals from the backup ---
	await fsp.writeFile(primary, '{ this is not valid json', 'utf8');
	ok('the vault still opens with a corrupt primary manifest', await opens(v));
	ok('the primary manifest is rewritten to a valid manifest', isValidManifest(primary));

	// --- a MISSING primary heals from the backup ---
	await fsp.rm(primary, { force: true });
	ok('the vault still opens with the primary manifest missing', await opens(v));
	ok('the primary manifest is recreated', fs.existsSync(primary) && isValidManifest(primary));

	// --- a MISSING backup is re-created from the primary (so redundancy is restored) ---
	await fsp.rm(backup, { force: true });
	ok('the vault still opens with the backup missing', await opens(v));
	ok('the backup manifest is recreated', fs.existsSync(backup) && isValidManifest(backup));

	// The healed vault must still unlock with the ORIGINAL password (the salt/KDF params were preserved, not reset).
	ok('the original password still opens the healed vault', await opens(v));
	ok('the recovered manifest holds the same salt as the original', (() => { try { return JSON.parse(fs.readFileSync(primary, 'utf8')).crypt.salt === JSON.parse(original).crypt.salt; } catch (_) { return false; } })());

	// A vault with BOTH copies unreadable is a real loss, not a silent success: opening it must fail clearly.
	await fsp.writeFile(primary, 'garbage', 'utf8');
	await fsp.writeFile(backup, 'garbage', 'utf8');
	ok('a vault with both manifest copies corrupt fails to open (no false success)', !(await opens(v)));

	// A manifest body that is VALID JSON but not an object — the literal `null` is the trap — must give the same
	// friendly "damaged manifest" error, not a raw "Cannot read properties of null" TypeError leaking to the user.
	await fsp.writeFile(primary, 'null', 'utf8');
	await fsp.writeFile(backup, 'null', 'utf8');
	let nullErr = null; try { await require('../Vault').readManifest(v); } catch (e) { nullErr = e; }
	ok('a null manifest fails with a clear message, not an internal TypeError', !!nullErr && /not readable|damaged|incompatible version/i.test(nullErr.message) && !/Cannot read propert/i.test(nullErr.message));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MANIFEST-SELF-HEAL CHECKS PASSED'));
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} } process.exit(1); });
