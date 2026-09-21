'use strict';
// lib/test/goldenvault.js — backward-compatibility guard. A FROZEN vault manifest in the released format-5 layout
// (the format the shipped 1.0.0 client created) must keep opening on the current build. Every other lifecycle test
// creates its fixture with the CURRENT code and reads it back, so a change that alters BOTH the writer and the reader
// together — a re-encoded key slot, a reordered field, a changed KDF default — passes every round-trip test while
// silently breaking vaults written by 1.0.0. This test reads a committed format-5 manifest the current code did NOT
// write, and proves the current build still accepts its format and unwraps its key slot. The fixture protects a
// throwaway vault; its password is published here on purpose.
//
// If this ever fails, the current build can no longer open a 1.0.0 vault — a backward-compatibility break that must
// be fixed with a real migration, never worked around by editing the frozen fixture or the expected value.
//
// Run:  node lib/test/goldenvault.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const Kdf = require('../Kdf');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const FIXTURE = path.join(__dirname, 'fixtures', 'golden-v5.vault.json');
const PASSWORD = 'pw-golden';
// The exact credential the format-5 slot must still unwrap to. Frozen — a change to this value means the unwrap
// output moved, which is the regression this guard exists to catch.
const EXPECTED_MASTER = '{"v":1,"cap":"rw","key":"OPCJnIgyXiCSKktCRe77jj0tJtenqRNSNwVWyonlmgI="}';

async function main() {
	const manifest = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
	ok('the frozen fixture is a format-5 manifest (the 1.0.0-era layout)', manifest.format === 5);
	ok('the fixture carries a single password key slot in the format-5 shape', Array.isArray(manifest.crypt.keySlots) && manifest.crypt.keySlots.length === 1 && manifest.crypt.keySlots[0].kind === 'password' && !('owner' in manifest.crypt.keySlots[0]));

	// 1. The current manifest reader ACCEPTS a format-5 vault (never refuses it on the format gate). Place the frozen
	//    bytes in a temp dir as vault.json and read them through the real reader.
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-golden-'));
	try {
		fs.mkdirSync(path.join(tmp, 'Golden.vault'));
		fs.writeFileSync(path.join(tmp, 'Golden.vault', 'vault.json'), JSON.stringify(manifest));
		const read = await vdisk.readManifest(path.join(tmp, 'Golden.vault'));
		ok('the current build reads a format-5 manifest without refusing it', !!read && read.format === 5);
		const listed = await vdisk.listKeys(path.join(tmp, 'Golden.vault'), { password: PASSWORD });
		ok('the current build lists the format-5 vault\'s key slots', Array.isArray(listed.slots) && listed.slots.length === 1 && listed.slots[0].kind === 'password');
	} finally { fs.rmSync(tmp, { recursive: true, force: true }); }

	// 2. The format-5 password slot still UNWRAPS with the current KDF + unwrap code — the actual "the vault still
	//    opens" guarantee. Derive the wrapping key from the slot's own stored KDF params and the frozen password, then
	//    unwrap the master credential and compare it to the frozen expected value.
	const slot = manifest.crypt.keySlots[0];
	const key = await Kdf.deriveKey(PASSWORD, slot.kdf);
	const master = Kdf.unwrapSecret(slot.wrappedKey, key);
	ok('the format-5 key slot unwraps to the exact expected master credential', master === EXPECTED_MASTER);

	// 3. A wrong password fails to unwrap (fail closed), so the check above is meaningful.
	let wrongFailed = false;
	try { Kdf.unwrapSecret(slot.wrappedKey, await Kdf.deriveKey('WRONG', slot.kdf)); } catch (_) { wrongFailed = true; }
	ok('a wrong password does not unwrap the format-5 slot (fail closed)', wrongFailed);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL GOLDEN-VAULT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
