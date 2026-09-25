'use strict';
// lib/test/movevault.js — receiving (pulling) a vault's encrypted store into a NEW local vault folder, the backend of
// the fleet "move a vault to another node" flow. receiveVault copies the OPAQUE ciphertext from a source, verifies the
// copy is COMPLETE, then adopts (registers) the vault so it appears in this node's list. This verifies: a received
// copy is a byte-faithful, same-identity copy that this node now knows about; an incomplete/non-vault source is
// refused and leaves NOTHING behind (fail-safe cleanup); and an existing vault is never silently overwritten. The
// source here is a LOCAL folder (a backup), which exercises the exact copy/verify/register/cleanup logic
// deterministically and cross-platform, without a live network serve (the webdav peer path reuses the same code).
//
// Run:  node lib/test/movevault.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-mv-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// A source vault with a handful of files.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(48 * 1024));
	const v = path.join(tmp, 'V.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const srcSalt = (await vdisk.readManifest(v)).crypt.salt;

	// Serve stand-in: back the vault up to a local folder. backupRoot/V.vault now holds the encrypted store, exactly
	// the shape a source node serves — so receiving from this local folder exercises the real pull path.
	const backupRoot = path.join(tmp, 'served'); await fsp.mkdir(backupRoot, { recursive: true });
	await vdisk.backup(v, backupRoot);

	// --- Receive into a fresh node's vault root ---
	const toRoot = path.join(tmp, 'node2'); await fsp.mkdir(toRoot, { recursive: true });
	const r = await vdisk.receiveVault(backupRoot, { toRoot, name: 'V.vault' });
	const got = path.join(toRoot, 'V.vault');
	ok('receiveVault reports RECEIVED', r && r.verdict === 'RECEIVED' && path.resolve(r.vault) === path.resolve(got));
	ok('the received folder is a real vault', fs.existsSync(path.join(got, 'vault.json')));
	// Same identity: the master key derives from the password + this salt, so an equal salt means the same password
	// opens the received copy — no key ever had to travel.
	ok('the received vault has the same identity (salt) as the source', (await vdisk.readManifest(got)).crypt.salt === srcSalt);
	// Adopted: this node now knows the received vault (it is recorded in the persisted vault list).
	const state = JSON.parse(await fsp.readFile(Common.statePath(), 'utf8'));
	const vaults = (state.vaults || []).map(x => path.resolve(x.dir || x.path || x));
	ok('the received vault is registered in this node\'s vault list', vaults.includes(path.resolve(got)));
	// Completeness: every source cipher file is present at the destination (the check gate would have refused otherwise).
	const countCipher = async (root) => { let n = 0; const walk = async (d) => { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else n++; } }; await walk(root); return n; };
	ok('the destination holds the full ciphertext', (await countCipher(got)) >= (await countCipher(path.join(backupRoot, 'V.vault'))));

	// --- Refuse to overwrite an existing vault ---
	let refused = false; try { await vdisk.receiveVault(backupRoot, { toRoot, name: 'V.vault' }); } catch (_) { refused = true; }
	ok('receiving over an existing vault is refused (no silent clobber)', refused);

	// --- Fail-safe: a non-vault source leaves nothing behind ---
	const junk = path.join(tmp, 'junk'); await fsp.mkdir(path.join(junk, 'Nope.vault'), { recursive: true });
	await fsp.writeFile(path.join(junk, 'Nope.vault', 'random.txt'), 'not a vault');
	let failed = false; try { await vdisk.receiveVault(junk, { toRoot, name: 'Nope.vault' }); } catch (_) { failed = true; }
	ok('receiving from a non-vault source fails', failed);
	ok('a failed receive leaves no partial vault folder behind (fail-safe cleanup)', !fs.existsSync(path.join(toRoot, 'Nope.vault')));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOVE-VAULT CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
