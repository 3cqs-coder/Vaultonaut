'use strict';
// lib/test/shares.js — revocable sharing (Part A): a read link carries a share id and an optional
// expiry, and is recorded in a write-key-signed roster so the owner can see who has access and revoke a
// share. Expiry and revocation are policy the recipient's tool enforces (not cryptography); truly cutting
// off a leaked read key needs a re-encryption, which is a separate operation. Needs the engine only.
//
// Run:  node lib/test/shares.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-shares-')); workspace = tmp;
	// Keep the rollback ledger (where the roster epoch is anchored) inside the workspace, so the rollback check
	// below reads a known anchor and the real user ledger is never touched.
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(512));
	const v = path.join(tmp, 'Share.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw1' }); // publishes the key the roster is signed/verified against

	const { token, sid, exp } = await vdisk.makeReadCap(v, { password: 'pw1', label: 'Alice', expiryDays: 7 });
	ok('a read link has a share id', !!sid);
	ok('a read link has a future expiry', !!(exp && exp > Date.now()));
	const cap = Vault.parseReadCap(token);
	ok('the token carries the expiry the recipient enforces', cap && cap.exp === exp);

	const l1 = await vdisk.listShares(v);
	ok('the share appears in the roster', l1.shares.length === 1 && l1.shares[0].sid === sid && l1.shares[0].label === 'Alice');
	ok('the roster signature verifies', l1.sigOk === true);
	ok('the share is active (not revoked or expired)', !l1.shares[0].revoked && !l1.shares[0].expired);

	// Keep a copy of the pre-revocation roster: a validly-signed OLD version an attacker could restore in place.
	const rosterPath = path.join(v, 'shares.json');
	const rosterBeforeRevoke = await fsp.readFile(rosterPath, 'utf8');

	await vdisk.revokeShare(v, { password: 'pw1', sid });
	const l2 = await vdisk.listShares(v);
	ok('the share shows revoked after revoke', l2.shares[0].revoked === true);
	ok('the roster still verifies after a revoke (re-signed)', l2.sigOk === true);

	// ROLLBACK: restore the older, still-validly-signed roster (from before the revoke) in place. Its signature
	// is genuine, so a signature check alone would accept it and the revoked share would read as active again. The
	// local epoch anchor must catch it: the roster is flagged as rolled back and not trusted.
	await fsp.writeFile(rosterPath, rosterBeforeRevoke);
	const lRb = await vdisk.listShares(v);
	ok('a rolled-back (older, still-signed) roster is detected', lRb.rolledBack === true);
	ok('a rolled-back roster is not trusted (sigOk false) even though its signature is genuine', lRb.sigOk === false);
	// A fresh legitimate write recovers: it advances the epoch back above the anchor and re-signs.
	await vdisk.revokeShare(v, { password: 'pw1', sid });
	const lRec = await vdisk.listShares(v);
	ok('a new legitimate write clears the rollback flag and re-establishes trust', lRec.rolledBack === false && lRec.sigOk === true);

	let refusedRo = false;
	try { const ro = await vdisk.makeReadCap(v, { password: 'pw1' }); await vdisk.revokeShare(v, { password: ro.token, sid }); } catch (_) { refusedRo = true; }
	ok('a read link cannot be used to revoke (needs a write password)', refusedRo);

	// A past-expiry share is marked expired; and adding a share WITHOUT re-signing breaks the roster signature.
	const sp = path.join(v, 'shares.json');
	const store = JSON.parse(await fsp.readFile(sp, 'utf8'));
	store.shares.push({ sid: 'past0001', label: 'Old', perm: 'read', createdAt: new Date().toISOString(), exp: Date.now() - 1000, revoked: false });
	await fsp.writeFile(sp, JSON.stringify(store));
	const l3 = await vdisk.listShares(v);
	ok('a past-expiry share is marked expired', !!(l3.shares.find(s => s.sid === 'past0001') || {}).expired);
	ok('an altered roster fails signature verification', l3.sigOk === false);

	// pruneShares removes the DEAD entries (revoked or expired), re-signs what remains, and keeps active shares.
	const deadBefore = l3.shares.filter(s => s.revoked || s.expired).length;
	const activeBefore = l3.shares.filter(s => !s.revoked && !s.expired).length;
	const pr = await vdisk.pruneShares(v, { password: 'pw1' });
	ok('pruneShares removes exactly the revoked/expired entries', pr.removed === deadBefore && deadBefore > 0);
	const l4 = await vdisk.listShares(v);
	ok('after prune, no revoked or expired entries remain and the roster re-verifies', l4.shares.every(s => !s.revoked && !s.expired) && l4.shares.length === activeBefore && l4.sigOk === true);
	let roPrune = false;
	try { const ro = await vdisk.makeReadCap(v, { password: 'pw1' }); await vdisk.pruneShares(v, { password: ro.token }); } catch (_) { roPrune = true; }
	ok('a read-only credential cannot prune the access list', roPrune);

	// Auto-prune on write: an expired entry is dropped automatically the next time the roster is legitimately
	// written and re-signed — no manual cleanup needed. A revoked entry is NOT auto-removed (kept visible).
	const sp2 = path.join(v, 'shares.json');
	const st2 = JSON.parse(await fsp.readFile(sp2, 'utf8'));
	st2.shares.push({ sid: 'exp00002', label: 'Temp', perm: 'read', createdAt: new Date().toISOString(), exp: Date.now() - 1000, revoked: false });
	await fsp.writeFile(sp2, JSON.stringify(st2));
	await vdisk.makeReadCap(v, { password: 'pw1', label: 'Fresh' }); // any legitimate roster write re-signs and self-cleans
	const lAuto = await vdisk.listShares(v);
	ok('an expired entry is auto-pruned on the next roster write', !lAuto.shares.find(s => s.sid === 'exp00002') && lAuto.sigOk === true);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SHARE CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
