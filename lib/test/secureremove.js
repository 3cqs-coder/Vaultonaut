'use strict';
// lib/test/secureremove.js — crypto-erase / secure-remove. A vault's keys are destroyed so the copy can never be
// opened again; the optional pre-erase pack preserves a portable, still-openable copy. Verifies both, and that a
// panic erase (no safety copy) also renders the vault unopenable and gone. Needs the bundled engine (no mount
// driver).
//
// Run:  node lib/test/secureremove.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function gone(p) { return !(await fsp.stat(p).then(() => true, () => false)); }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-secrm-'));
	const Common = require('../Common');
	Common.dataDir = () => path.join(tmp, 'data'); Common.statePath = () => path.join(tmp, 'data', 'state.json');
	await fsp.mkdir(Common.dataDir(), { recursive: true });
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('  skip  (engine missing)'); return done(tmp); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'secret.txt'), 'top secret payload');

	// --- the password gate: a permanent erase needs the vault's own read-write password, not just its (visible) name ---
	// Knowing a vault's name is no secret — it is shown in the list — so erasing must prove the caller can actually open
	// the vault. A wrong password, an empty one, or a read-only password must all be refused before anything is touched,
	// and the vault must stay fully openable after each refusal (no data loss).
	const vg = path.join(tmp, 'Gated.vault');
	await vdisk.importFolder(vg, { password: 'right-pw', sourceDir: src });
	await vdisk.addReadOnlyKey(vg, { password: 'right-pw', readOnlyPassword: 'read-only-pw' });
	ok('erase is refused with NO password', await vdisk.secureRemove(vg, {}).then(() => false, (e) => /password is incorrect/i.test(e.message)));
	ok('erase is refused with a WRONG password', await vdisk.secureRemove(vg, { password: 'wrong-pw' }).then(() => false, (e) => /password is incorrect/i.test(e.message)));
	ok('erase is refused with a READ-ONLY password', await vdisk.secureRemove(vg, { password: 'read-only-pw' }).then(() => false, (e) => /read-only password cannot/i.test(e.message)));
	ok('the vault is still fully openable after the refusals (no data loss)', await vdisk.list(vg, { password: 'right-pw' }).then(a => Array.isArray(a) && a.some(f => /secret\.txt/.test(f)), () => false));
	ok('erase SUCCEEDS with the correct read-write password', await vdisk.secureRemove(vg, { password: 'right-pw' }).then((r) => r && r.leftover === false, () => false));
	ok('the correctly-erased vault folder is gone', await gone(vg));

	// --- with a safety pack: the live copy is erased, the packed copy still opens ---
	const v1 = path.join(tmp, 'Keepme.vault');
	await vdisk.importFolder(v1, { password: 'pw1', sourceDir: src });
	ok('the vault opens before erasing', Array.isArray(await vdisk.list(v1, { password: 'pw1' })));
	const keep = path.join(tmp, 'saved' + (require('../Brand').packExt || '.vdisk'));
	const res = await vdisk.secureRemove(v1, { password: 'pw1', keepPath: keep });
	ok('a portable copy was saved first', res.kept && fs.existsSync(keep));
	ok('the live vault folder is gone', await gone(v1));
	ok('the erased vault can no longer be opened (its keys are destroyed)', await vdisk.list(v1, { password: 'pw1' }).then(() => false, () => true));
	// the saved pack still restores and opens with the same password
	const restored = path.join(tmp, 'restored');
	const un = await vdisk.unpack(keep, restored);
	const files = await vdisk.list(un.vault, { password: 'pw1' }).catch(() => null);
	ok('the saved copy restores and opens with the password', Array.isArray(files) && files.some(f => /secret\.txt/.test(f)));

	// --- panic erase: no safety copy, and the vault is gone + unopenable ---
	const v2 = path.join(tmp, 'Panic.vault');
	await vdisk.importFolder(v2, { password: 'pw2', sourceDir: src });
	const res2 = await vdisk.secureRemove(v2, { password: 'pw2' }); // no keepPath = panic-style (no safety copy)
	ok('a panic erase keeps no copy', !res2.kept);
	ok('the panic-erased vault folder is gone', await gone(v2));
	ok('the panic-erased vault can no longer be opened', await vdisk.list(v2, { password: 'pw2' }).then(() => false, () => true));

	// --- a clean erase reports no leftover husk, and prunes an emergency arming for that vault ---
	// Emergency (dead-man) access is armed under a key derived from the vault's identity, not its path, so it is not
	// among the path-keyed settings that list-removal scrubs. secure-remove must drop it explicitly, or a later
	// release would hand a trusted contact a grant for a vault that no longer exists.
	const contact = require('../Emergency').generateContactKeypair();
	await vdisk.emergencyEnroll({ contactPubKey: contact.publicKey, contactLabel: 'Test contact' });
	const v4 = path.join(tmp, 'Armed.vault');
	await vdisk.importFolder(v4, { password: 'pw4', sourceDir: src });
	await vdisk.emergencyArm(v4, { password: 'pw4' });
	ok('the vault is armed for emergency access before erasing', (await vdisk.emergencyStatus()).armed.some(a => a.name === 'Armed'));
	const res4 = await vdisk.secureRemove(v4, { password: 'pw4' });
	ok('a clean erase reports no leftover key file', res4.leftover === false);
	ok('secure-remove prunes the emergency arming for the erased vault', !(await vdisk.emergencyStatus()).armed.some(a => a.name === 'Armed'));

	// --- refuses an in-vault --keep path, and leaves the vault intact (regression guard) ---
	// The safety copy must never land inside the vault being erased, or the erase destroys it too. The containment
	// check must resolve BOTH the keep path and the vault path the same way: a vault under a symlinked path (macOS
	// os.tmpdir() sits under /var -> /private/var) once slipped the guard because only the keep path was resolved,
	// so an in-vault copy was written and erased with the vault. The vault must survive the refusal fully openable.
	const v3 = path.join(tmp, 'Guard.vault');
	await vdisk.importFolder(v3, { password: 'pw3', sourceDir: src });
	const insideKeep = path.join(v3, 'inside' + (require('../Brand').packExt || '.vdisk'));
	ok('secure-remove refuses a --keep path inside the vault', await vdisk.secureRemove(v3, { password: 'pw3', keepPath: insideKeep }).then(() => false, (e) => /OUTSIDE the vault/.test(e.message)));
	ok('the vault is left fully intact after that refusal (no data loss)', await vdisk.list(v3, { password: 'pw3' }).then(a => Array.isArray(a) && a.some(f => /secret\.txt/.test(f)), () => false));
	await vdisk.secureRemove(v3, { password: 'pw3' }).catch(() => {}); // tidy up the guard vault

	// --- refuses a non-vault path (never erases the wrong folder) ---
	ok('secure-remove refuses a folder that is not a vault', await vdisk.secureRemove(src, {}).then(() => false, () => true));

	// --- staged rotation residue is shredded too, not just the canonical manifest ---
	// An interrupted rotation leaves vault.json.new / .vault.bak.new (each holds a fresh-key-wrapped master) and an
	// atomic write can leave vault.json.<pid>.<hex>.tmp. secure-remove must overwrite EVERY manifest-family file, so
	// no recoverable wrapped-key copy survives on media where an unlinked file can be undeleted.
	const v5 = path.join(tmp, 'Staged.vault');
	await vdisk.importFolder(v5, { password: 'pw5', sourceDir: src });
	await fsp.writeFile(path.join(v5, 'vault.json.new'), JSON.stringify({ crypt: { keySlots: [{ wrappedKey: 'staged-key' }] } }));
	await fsp.writeFile(path.join(v5, '.vault.bak.new'), 'staged-backup');
	await fsp.writeFile(path.join(v5, 'vault.json.12345.abcdef.tmp'), 'atomic-write-residue');
	const res5 = await vdisk.secureRemove(v5, { password: 'pw5' });
	ok('secure-remove completes with staged rotation residue present', res5 && res5.leftover === false);
	ok('the staged rotation residue is gone after erase', await gone(path.join(v5, 'vault.json.new')) && await gone(path.join(v5, '.vault.bak.new')) && await gone(v5));
	// Source guard: the shred selection must cover manifest-family residue by prefix, not just the fixed pair, so a
	// future edit cannot narrow it back and leave a staged wrapped-key copy merely unlinked.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	const secBody = vaultSrc.slice(vaultSrc.indexOf('async function secureRemove('), vaultSrc.indexOf('async function secureRemove(') + 5500);
	ok('secure-remove shreds manifest-family residue by name prefix', /startsWith\(MANIFEST \+ '\.'\)/.test(secBody) && /startsWith\(MANIFEST_BAK \+ '\.'\)/.test(secBody));

	return done(tmp);
}

async function done(tmp) {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SECURE-REMOVE CHECKS PASSED'));
	try { await fsp.rm(tmp, { recursive: true, force: true }); } catch (_) {}
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); process.exit(1); });
