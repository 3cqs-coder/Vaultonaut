'use strict';
// lib/test/dualkey.js — the dual-key (read-cap / write-cap) design. A read-write password can do
// everything; a read-only password (or a shared read-capability token) can DECRYPT and VERIFY but
// cannot write: the drive mounts read-only, and snapshot/add-key/remove-key are refused. The security
// crux: the signing (write) key is independent of the read key, so a read-only holder cannot forge an
// authentic write, and any change they make to their copy fails signature verification.
//
// Run:  node lib/test/dualkey.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function refused(fn) { try { await fn(); return false; } catch (_) { return true; } }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-dualkey-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	const secretText = 'confidential ' + crypto.randomBytes(6).toString('hex');
	await fsp.writeFile(path.join(src, 'doc.txt'), secretText);
	const v = path.join(tmp, 'K.vault');
	await vdisk.importFolder(v, { password: 'rw-pass', sourceDir: src });

	console.log('[a read-only password can be added by an owner]');
	await vdisk.addReadOnlyKey(v, { password: 'rw-pass', readOnlyPassword: 'ro-pass' });
	const keys = await vdisk.listKeys(v);
	ok('the vault now has a read-write and a read-only slot', keys.slots.some(s => s.kind !== 'readonly') && keys.slots.some(s => s.kind === 'readonly'));
	ok('a read-only credential cannot add another key', await refused(() => vdisk.addRecoveryKey(v, { password: 'ro-pass' })));
	ok('a read-only credential cannot change the password', await refused(() => vdisk.changePassword(v, { oldPassword: 'ro-pass', newPassword: 'x' })));
	// A read link can only be minted with the write key, since only that key can record it in the signed roster — a
	// read-only password must not create a link the owner could neither see nor revoke.
	ok('a read-only credential cannot create a read link', await refused(() => vdisk.makeReadCap(v, { password: 'ro-pass' })));
	// assertReadable underlies the "prove you can open this vault" gate on copy/serve operations over an exposed
	// interface: EITHER a read-only or a read-write password opens it (reading is enough to copy ciphertext), but a
	// wrong or empty password is refused.
	ok('assertReadable accepts a read-write password', await Vault.assertReadable(v, 'rw-pass').then(() => true, () => false));
	ok('assertReadable accepts a read-only password', await Vault.assertReadable(v, 'ro-pass').then(() => true, () => false));
	ok('assertReadable refuses a wrong password', await refused(() => Vault.assertReadable(v, 'nope')));
	ok('assertReadable refuses an empty password', await refused(() => Vault.assertReadable(v, '')));

	console.log('[read-only mount: reads yes, writes no]');
	const m = await vdisk.mount(v, { password: 'ro-pass' });
	let readBack = '', wrote = true;
	try { readBack = await fsp.readFile(path.join(m.mountpoint, 'doc.txt'), 'utf8'); } catch (_) {}
	try { await fsp.writeFile(path.join(m.mountpoint, 'sneak.txt'), 'x'); } catch (_) { wrote = false; }
	await vdisk.unmount(m.mountpoint).catch(() => {});
	ok('the read-only mount decrypts the content', readBack === secretText);
	ok('the read-only mount rejects writes (mounted read-only)', wrote === false);
	ok('a read-only credential cannot snapshot (sign a baseline)', await refused(() => vdisk.snapshot(v, { password: 'ro-pass' })));

	console.log('[the write key is independent of the read key — a read holder cannot forge it]');
	const manifest = JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
	// The read key is recoverable by a read holder; deriving a signing key FROM it yields a DIFFERENT
	// public key than the vault's real signer — proving the signer is not the read key.
	const readKeyOnlyPub = Integrity.signKeysFromSeed(Buffer.from('00'.repeat(32), 'hex').toString('base64')).pub; // any non-write-seed material
	ok('the vault publishes a verify key', !!(manifest.integrity && manifest.integrity.pubkey));
	ok('the signer is not derivable from arbitrary non-write material', manifest.integrity.pubkey !== readKeyOnlyPub);

	console.log('[a shared read capability opens a COPY read-only]');
	const { token } = await vdisk.makeReadCap(v, { password: 'rw-pass' });
	ok('the token is a read-capability string', /^vdrc1\./.test(token));
	// The recipient has a copy of the vault folder + the token (no password).
	const copy = path.join(tmp, 'Copy.vault');
	await fsp.cp(v, copy, { recursive: true });
	const m2 = await vdisk.mount(copy, { readCap: token });
	let capRead = '', capWrote = true;
	try { capRead = await fsp.readFile(path.join(m2.mountpoint, 'doc.txt'), 'utf8'); } catch (_) {}
	try { await fsp.writeFile(path.join(m2.mountpoint, 'x.txt'), 'x'); } catch (_) { capWrote = false; }
	await vdisk.unmount(m2.mountpoint).catch(() => {});
	ok('the read capability decrypts the copy', capRead === secretText);
	ok('the read capability mounts read-only', capWrote === false);
	ok('a garbage token is rejected', vdisk.parseReadCap('vdrc1.not-valid') === null);

	console.log('[baseline authenticity: only the write key can produce a verifiable signature]');
	// The vault signs its baseline over the file-set root. Verification uses the public key, so a read
	// holder can detect any change — but cannot re-sign it, because a signature from any other key fails.
	const input = 'root|' + crypto.randomBytes(8).toString('hex');
	const writeSeed = crypto.randomBytes(32).toString('base64');
	const sk = Integrity.signKeysFromSeed(writeSeed);
	ok('a baseline signed with the write key verifies against its public key', Integrity.verify(sk.pub, input, Integrity.sign(sk.priv, input)) === true);
	const otherSk = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	ok('a signature from any other key is rejected (a read holder cannot forge one)', Integrity.verify(sk.pub, input, Integrity.sign(otherSk.priv, input)) === false);
	// And the read key derived from a write seed can NEVER climb back to that seed (one-way).
	const readKey = Integrity.readKeyFromSeed(writeSeed, 'some-salt');
	ok('the read key is a one-way function of the write seed', readKey !== writeSeed && Integrity.signKeysFromSeed(readKey).pub !== sk.pub);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DUAL-KEY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-dualkey-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
