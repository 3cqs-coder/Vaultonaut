'use strict';
// lib/test/recoverysign.js — the recovery index's AUTHENTICITY signature. A read-only holder has the read key
// but not the write-authority signing key, so it cannot forge a recovery index that verifies against the vault's
// published public key. This checks that: an unsigned index reads as weaker-trust; a valid signature verifies; a
// signature checked against the WRONG key, or bound to a DIFFERENT vault id, is a tamper signal (forgery /
// cross-vault transplant); a stale signature after an unsigned rebuild reads as unsigned (not tampering); sign-
// in-place makes a current index verifiable without a rebuild; heal REFUSES a present-but-invalid signature
// rather than repairing from a possibly-forged index; and each rebuild bumps the monotonic version.
//
// Run:  node lib/test/recoverysign.js  (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');
const Integrity = require('../Integrity');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping the recovery-sign checks.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recsign-')); workspace = tmp;
	// Keep the rollback ledger (where the recovery-signed version is anchored) inside the workspace, so the
	// downgrade check below reads a known anchor and the real user ledger is never touched.
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(40 * 1024));
	const v = path.join(tmp, 'Sign.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Synthetic write-authority keypair + vault id (the machinery is independent of a specific vault's key).
	const kp = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	const wrong = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	const vaultId = crypto.randomBytes(16).toString('hex');

	await Recovery.protect(v, { tier: 'low' }); // unsigned build
	let a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('an unsigned index reads as weaker-trust (signed:false)', !!a && a.signed === false);

	const p = await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId }); // signed build
	ok('a signed protect reports signed + a version', p.signed === true && Number.isInteger(p.signedVersion));
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('a valid signature verifies against the published key', !!a && a.verified === true);
	a = (await Recovery.verify(v, { pubkey: wrong.pub, vaultId })).authenticity;
	ok('a signature checked against the WRONG key is a tamper signal', !!a && a.tampered === true);
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId: 'a-different-vault' })).authenticity;
	ok('a signature bound to a DIFFERENT vault id does not verify (no transplant)', !!a && a.tampered === true);

	await Recovery.protect(v, { tier: 'low' }); // unsigned rebuild → clears the old sidecar
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('an unsigned rebuild clears the old signature (signed:false, not tampered)', !!a && a.signed === false && !a.tampered);

	await Recovery.signIndex(v, { signPriv: kp.priv, vaultId }); // sign the current index in place (no rebuild)
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('sign-in-place makes an existing index verify', !!a && a.verified === true);

	// REGRESSION: bit-rot in ONE signature replica must not deny repair — an intact replica still verifies.
	const sig0 = path.join(v, '.recovery', 'index.sig.json');
	const s0 = JSON.parse(await fsp.readFile(sig0, 'utf8')); s0.sig = s0.sig.slice(0, -6) + 'AAAAAA'; await fsp.writeFile(sig0, JSON.stringify(s0));
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('bit-rot in one signature replica still verifies via an intact replica', !!a && a.verified === true && !a.tampered);

	let refused = false;
	try { await Recovery.heal(v, { pubkey: wrong.pub, vaultId }); } catch (e) { refused = !!(e.authenticity && e.authenticity.tampered); }
	ok('heal REFUSES a present-but-invalid signature (possible forgery)', refused);
	const h = await Recovery.heal(v, { pubkey: kp.pub, vaultId });
	ok('heal proceeds when the signature verifies', !!h && h.protected === true);

	const before = (await Recovery.readIndex(v)).version;
	await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId });
	ok('each rebuild bumps the monotonic index version', (await Recovery.readIndex(v)).version > before);

	const sigReplicas = ['index.sig.json', 'index.sig.bak.json', 'index.sig.bak2.json'].map(n => path.join(v, '.recovery', n));
	async function rewriteSigs(mut) { for (const p of sigReplicas) { try { const s = JSON.parse(await fsp.readFile(p, 'utf8')); mut(s); await fsp.writeFile(p, JSON.stringify(s)); } catch (_) {} } }

	// An unknown signature scheme (a newer build's sidecar) reads as UNSIGNED, not tampered — so an older build
	// never refuses to repair a healthy vault after a future algorithm change.
	await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId });
	await rewriteSigs(s => { s.alg = 'ed448-future'; });
	a = (await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity;
	ok('an unknown signature scheme reads as unsigned, not tampered', !!a && a.signed === false && !a.tampered);

	// The "repair anyway" override lets heal proceed even when the signature does not verify (so a rare
	// multi-fault can never leave a vault permanently unrepairable), while the default still refuses.
	await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId });
	await rewriteSigs(s => { s.sig = s.sig.slice(0, -6) + 'AAAAAA'; });
	ok('an all-replica bad signature reads as tampered', (((await Recovery.verify(v, { pubkey: kp.pub, vaultId })).authenticity) || {}).tampered === true);
	let denied = false; try { await Recovery.heal(v, { pubkey: kp.pub, vaultId }); } catch (e) { denied = e.code === 'AUTH_REFUSED'; }
	ok('heal refuses a tampered signature by default', denied);
	const hf = await Recovery.heal(v, { pubkey: kp.pub, vaultId, allowUnverified: true });
	ok('heal proceeds with the allowUnverified override', !!hf && hf.protected === true);

	// A signature-strip DOWNGRADE: the local ledger recorded that this vault's recovery data was signed, but the
	// index now arrives unsigned — how an attacker would force the weaker no-password repair. Refused by default,
	// with allowUnverified as the escape. (A never-signed vault has no anchor, so a legitimate cold protect is fine.)
	const dgId = crypto.randomBytes(16).toString('hex');
	await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId: dgId });          // sign, then anchor it locally
	await Integrity.noteRecoverySigned(dgId, (await Recovery.readIndex(v)).version);        // as the Vault layer does after signing
	await Recovery.protect(v, { tier: 'low' });                                             // unsigned rebuild = the stripped signature
	let dgRefused = false; try { await Recovery.heal(v, { pubkey: kp.pub, vaultId: dgId }); } catch (e) { dgRefused = e.code === 'AUTH_REFUSED' && !!e.downgrade; }
	ok('heal refuses a signature-strip downgrade by default', dgRefused);
	const hdg = await Recovery.heal(v, { pubkey: kp.pub, vaultId: dgId, allowUnverified: true });
	ok('heal proceeds past a downgrade with the allowUnverified override', !!hdg && hdg.protected === true);

	// OLDER-BUT-SIGNED replay: the current index is genuinely signed and verifies, but this computer has already
	// seen a NEWER signed version. Restoring the older signed index (to roll recovery data back to a pre-repair or
	// pre-revocation state) must be refused too — the anchor, not just "is it signed", is what catches it.
	const rpId = crypto.randomBytes(16).toString('hex');
	await Recovery.protect(v, { tier: 'low', signPriv: kp.priv, vaultId: rpId });            // current index: validly signed at version V
	const vNow = (await Recovery.readIndex(v)).version;
	await Integrity.noteRecoverySigned(rpId, vNow + 5);                                       // this machine has since seen version V+5 signed
	let replayRefused = false; try { await Recovery.heal(v, { pubkey: kp.pub, vaultId: rpId }); } catch (e) { replayRefused = e.code === 'AUTH_REFUSED' && !!e.downgrade; }
	ok('heal refuses an older-but-validly-signed index below the anchored version', replayRefused);

	await vdisk.removeKnownVault(v).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-SIGN CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-recsign-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
