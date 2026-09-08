'use strict';
// lib/test/sharebundle.js — the portable, offline recipient share bundle (Vault.shareSeal / shareOpen). A sender
// seals a read capability to a recipient's PUBLIC key with the post-quantum hybrid seal; only the recipient's
// private key opens it, recovering a read cap that mounts a copy read-only. This verifies the seal round-trips to
// a valid read cap FOR THIS VAULT, that the metadata is right, that an optional expiry propagates, and that a
// wrong key, a tampered bundle, and a non-share file all fail closed. The read-cap mount path itself is covered by
// dualkey.js; here the focus is the seal/unseal layer. Needs the engine to make a vault; no mount driver required.
//
// Run:  node lib/test/sharebundle.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const E = require('../Emergency');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-sharebundle-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'secret.txt'), crypto.randomBytes(2048));
	const v = path.join(tmp, 'Share.vault'); await vdisk.importFolder(v, { password: 'OWNER-pw', sourceDir: src });
	const manifest = JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));

	// Recipient makes a keypair and (in real life) sends the sender only the public key.
	const rcpt = vdisk.emergencyKeypair();
	ok('the recipient gets a public and a private key', !!rcpt.publicKey && !!rcpt.privateKey);

	// Sender seals a read cap to the recipient's public key.
	const { bundle, pq } = await vdisk.shareSeal(v, { password: 'OWNER-pw', recipientPub: rcpt.publicKey });
	ok('the bundle is marked as a share', bundle && bundle.kind === 'share');
	ok('the bundle names the vault', bundle.vault === 'Share');
	ok('the bundle records the vault identity', !!bundle.identity);
	ok('the bundle carries a sealed blob', typeof bundle.sealed === 'string' && bundle.sealed.length > 0);
	ok('the bundle reports whether it is post-quantum', bundle.pq === E.isPostQuantum() && bundle.pq === pq);
	ok('the sealed blob is NOT a bare read cap (it is encrypted to the recipient)', !/^vdrc1\./.test(bundle.sealed));

	// Recipient opens it with their private key, recovering a valid read cap FOR THIS VAULT.
	const opened = vdisk.shareOpen(bundle, rcpt.privateKey);
	ok('opening recovers a read-capability token', /^vdrc1\./.test(opened.token));
	const cap = vdisk.parseReadCap(opened.token);
	ok('the recovered token parses as a read cap', cap !== null);
	ok('the recovered cap is for THIS vault (published key matches)', cap && cap.pub === manifest.integrity.pubkey);
	ok('opening reports the vault name and identity', opened.vault === 'Share' && !!opened.identity);

	// Opening from the JSON string form (as read off disk) works too.
	const openedFromJson = vdisk.shareOpen(JSON.stringify(bundle), rcpt.privateKey);
	ok('a bundle read as JSON text opens the same', openedFromJson.token === opened.token);

	// An optional expiry propagates into the read cap.
	const withExp = await vdisk.shareSeal(v, { password: 'OWNER-pw', recipientPub: rcpt.publicKey, expiryDays: 7 });
	const expCap = vdisk.parseReadCap(vdisk.shareOpen(withExp.bundle, rcpt.privateKey).token);
	ok('an expiry set at seal time rides along in the cap', expCap && Number(expCap.exp) > Date.now());

	// Fail-closed cases.
	const other = vdisk.emergencyKeypair();
	let wrongThrew = false; try { vdisk.shareOpen(bundle, other.privateKey); } catch (_) { wrongThrew = true; }
	ok('a different private key cannot open the bundle', wrongThrew);

	const tampered = JSON.parse(JSON.stringify(bundle));
	const raw = Buffer.from(tampered.sealed, 'base64'); raw[raw.length - 1] ^= 0xff; tampered.sealed = raw.toString('base64');
	let tamperThrew = false; try { vdisk.shareOpen(tampered, rcpt.privateKey); } catch (_) { tamperThrew = true; }
	ok('a tampered bundle fails closed', tamperThrew);

	let notShareThrew = false; try { vdisk.shareOpen({ kind: 'nope' }, rcpt.privateKey); } catch (_) { notShareThrew = true; }
	ok('a non-share object is rejected', notShareThrew);

	let badJsonThrew = false; try { vdisk.shareOpen('this is not json', rcpt.privateKey); } catch (_) { badJsonThrew = true; }
	ok('an unreadable file is rejected', badJsonThrew);

	// A seal with no recipient key is refused (nothing to seal to).
	let noPubThrew = false; try { await vdisk.shareSeal(v, { password: 'OWNER-pw', recipientPub: '' }); } catch (_) { noPubThrew = true; }
	ok('sealing with no recipient key is refused', noPubThrew);

	// The original vault is untouched — still opens with the owner password.
	ok('the original vault still opens with the owner password', await vdisk.verify(v, { password: 'OWNER-pw', quick: true }).then(() => true).catch(() => false));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SHARE-BUNDLE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-sharebundle-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
