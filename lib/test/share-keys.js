'use strict';
// lib/test/share-keys.js — sharing a vault with only SELECTED keys. When a vault is packed for sharing, the
// packer can choose which key slots travel with the copy. A password whose slot is left out must NOT open the
// shared copy — so the owner can hand a group a vault that opens only with the group password, while their own
// password is powerless on that copy. This verifies the packed manifest carries exactly the chosen slots, the
// chosen key opens it, the excluded key does not, and the underlying data is intact. Needs the engine only.
//
// Run:  node lib/test/share-keys.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-sharekeys-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4096));
	const v = path.join(tmp, 'Share.vault'); await vdisk.importFolder(v, { password: 'OWNER-pw', sourceDir: src });

	const g = await vdisk.addReadOnlyKey(v, { password: 'OWNER-pw', readOnlyPassword: 'GROUP-pw', label: 'Group share (read-only)' });
	ok('adding a group key returns its slot id', !!g.slotId);
	ok('the vault now has two key slots', (await vdisk.listKeys(v)).slots.length === 2);

	// Pack with ONLY the group slot.
	const outFolder = path.join(tmp, 'out'); await fsp.mkdir(outFolder);
	const packed = await vdisk.pack(v, null, { destFolder: outFolder, keepSlots: [g.slotId] });
	const dest = path.join(tmp, 'recipient'); await fsp.mkdir(dest);
	const un = await vdisk.unpack(packed.file, dest);
	const sharedSlots = (await vdisk.listKeys(un.vault)).slots;
	ok('the shared copy carries exactly one slot', sharedSlots.length === 1);
	ok('the shared copy keeps the chosen (group) slot only', sharedSlots.length === 1 && sharedSlots[0].id === g.slotId);

	const groupOpens = await vdisk.verify(un.vault, { password: 'GROUP-pw', quick: true }).then(() => true).catch(() => false);
	ok('the GROUP password opens the shared copy', groupOpens);
	let ownerOpens = false; try { await vdisk.verify(un.vault, { password: 'OWNER-pw', quick: true }); ownerOpens = true; } catch (_) {}
	ok('the OWNER password does NOT open the shared copy', ownerOpens === false);

	// The original vault is untouched — still opens with both.
	ok('the original vault still opens with the owner password', await vdisk.verify(v, { password: 'OWNER-pw', quick: true }).then(() => true).catch(() => false));

	// A full pack (no keepSlots) still carries every key.
	const full = await vdisk.pack(v, null, { destFolder: outFolder, overwrite: true });
	const dest2 = path.join(tmp, 'full'); await fsp.mkdir(dest2);
	const un2 = await vdisk.unpack(full.file, dest2);
	ok('a normal pack (no selection) still carries all keys', (await vdisk.listKeys(un2.vault)).slots.length === 2);

	// Refuse a selection that keeps no real slot (would make the copy unopenable).
	let refused = false; try { await vdisk.pack(v, null, { destFolder: outFolder, overwrite: true, keepSlots: ['does-not-exist'] }); } catch (_) { refused = true; }
	ok('a selection matching no key is refused', refused);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SHARE-KEY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-sharekeys-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
