'use strict';
// lib/test/tamperbaselineanchor.js — tamper detection is anchored on CONTENT against the local monotonic
// ledger, not on two bookkeeping records being in step. The in-vault snapshot record and the ledger can
// legitimately fall out of step (a snapshot write cut short when the service is killed, a lock-all then a
// couple of mount/unmount cycles), and that used to raise a scary false alarm — "the snapshot has been
// altered" or "the vault was rolled back" — for a vault nobody touched. This pins the intended behavior:
//
//   • a fresh baseline audits clean and mounts trusted;
//   • when the ledger is AHEAD of the in-vault record but the vault's CURRENT contents still hash to the
//     last trusted root, that is benign bookkeeping — the audit is clean (staleBaseline), no tamper, and
//     the next on-mount check SELF-HEALS the record so it never re-alarms;
//   • a genuine rollback (the ledger is ahead AND the contents no longer match the trusted root) is still
//     flagged as a rollback and is NEVER cleared by the content anchor;
//   • a foreign/undecryptable file dropped into the store is still flagged as tampering;
//   • a removed baseline record is still flagged.
//
// Uses checkOnMount to exercise the on-mount path without needing a mount driver, so it runs everywhere.
//
// Run:  node lib/test/tamperbaselineanchor.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Integrity = require('../Integrity');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const tampers = (a) => (a && a.tamper) || [];
const joined = (a) => tampers(a).join(' | ');

const ledgerPath = () => path.join(Common.dataDir(), 'integrity.json');
async function readLedger() { return JSON.parse(await fsp.readFile(ledgerPath(), 'utf8')); }
async function writeLedger(l) { await fsp.writeFile(ledgerPath(), JSON.stringify(l)); }

let ws = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-anchor-')); ws = tmp;
	// Keep this test's rollback ledger (and vault registry) in its OWN throwaway dir, not the shared .test-data, so
	// state other suites accumulate there across repeated runs can never perturb it. The engine binary stays shared
	// because the preload set binDir explicitly (independent of dataDir), so this does not trigger a re-download.
	Common.setDataDir(tmp);
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4096));
	await fsp.writeFile(path.join(src, 'b.txt'), crypto.randomBytes(2048));
	const v = path.join(tmp, 'Anchor.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw1' }); // deep baseline; advances the ledger to seq/root

	const vid = Integrity.vaultId(await vdisk.readManifest(v));

	// 1) A fresh baseline is clean on both the audit and the on-mount path.
	ok('a fresh snapshot audits clean', tampers(await vdisk.audit(v, { password: 'pw1' })).length === 0);
	ok('a fresh snapshot mounts trusted', (await vdisk.checkOnMount(v, 'pw1')).trusted === true);

	// 1b) MANIFEST FINGERPRINT — forge vs. lag. The manifest's snapshot fingerprint is a password-less cache. A
	//     FORGED fingerprint (its fields edited to fake the vault's version or content) must be caught; an authentic
	//     fingerprint that merely LAGS the record (left behind by an interrupted write) must NOT be mistaken for it.
	const mfPath = path.join(vdisk.resolveVaultDir(v), 'vault.json');
	const readMan = async () => JSON.parse(await fsp.readFile(mfPath, 'utf8'));
	const writeMan = async (m) => Common.writeJsonAtomic(mfPath, m);
	{
		// A lagging-but-authentic fingerprint: snapshot A, keep its fingerprint, snapshot B, then restore A's
		// fingerprint into the manifest. The in-vault record is B; the manifest fingerprint is the authentic A.
		const manA = await readMan(); const fpA = manA.snapshot; // authentic fingerprint of baseline A
		await vdisk.snapshot(v, { password: 'pw1' });            // baseline B (record + ledger advance)
		const manB = await readMan(); manB.snapshot = fpA; await writeMan(manB); // fingerprint now lags the record
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('an authentic fingerprint that lags the record is NOT tampering', tampers(a).length === 0);
		await vdisk.snapshot(v, { password: 'pw1' }); // resync fingerprint and record
	}
	{
		// A forged fingerprint: alter a field (root) without the key, so its own HMAC no longer matches.
		const m = await readMan(); m.snapshot.root = crypto.createHash('sha256').update('forged-root').digest('hex'); await writeMan(m);
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a forged fingerprint (altered field) is detected as tampering', tampers(a).length > 0);
		await vdisk.snapshot(v, { password: 'pw1' }); // restore a valid fingerprint for the sections below
	}

	// 2) BENIGN DESYNC — the ledger is ahead of the in-vault record, but the contents are unchanged. This is
	//    exactly the interrupted-write case the user hit. Bump ONLY the ledger's seq, keeping its trusted root
	//    (the real content root), so the record now looks "older than this device recorded" while nothing changed.
	{
		const l = await readLedger();
		const trustedRoot = l[vid].root;
		l[vid] = { ...l[vid], seq: l[vid].seq + 5 }; // ledger moved on; the in-vault record stayed behind
		await writeLedger(l);
		ok('the ledger is now ahead of the in-vault record (setup)', (await readLedger())[vid].root === trustedRoot);

		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a stale in-vault record with UNCHANGED contents is NOT tampering', tampers(a).length === 0);
		ok('the audit reports it as clean', a.clean === true);
		ok('the audit marks the baseline as merely stale (not tampered)', a.staleBaseline === true);
	}

	// 3) SELF-HEAL on mount — the on-mount check re-establishes the in-vault baseline so the desync clears for good.
	{
		const r = await vdisk.checkOnMount(v, 'pw1');
		ok('the on-mount check trusts a stale-but-unchanged vault', r.trusted === true);
		ok('the on-mount check raises no warning for it', r.warn == null);
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('after self-heal the audit is clean with no lingering staleness', a.clean === true && a.staleBaseline !== true);
	}

	// 4) GENUINE ROLLBACK — the ledger is ahead AND the contents no longer match the trusted root. The content
	//    anchor must NOT clear this: it is a real finding.
	{
		const l = await readLedger();
		const fakeRoot = crypto.createHash('sha256').update('a-different-newer-baseline').digest('hex');
		l[vid] = { ...l[vid], seq: l[vid].seq + 5, root: fakeRoot }; // a newer baseline this device saw, whose content differs from now
		await writeLedger(l);

		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a real rollback is still flagged', tampers(a).length > 0);
		ok('the rollback is named as a rollback (plain language)', /rolled back|older version|possible rollback/i.test(joined(a)));
		ok('a real rollback is NOT cleared by the content anchor', a.staleBaseline !== true && a.clean === false);

		// Re-baselining is how a user accepts the current state and clears the alarm.
		await vdisk.snapshot(v, { password: 'pw1' });
		ok('re-baselining clears the rollback alarm', tampers(await vdisk.audit(v, { password: 'pw1' })).length === 0);
	}

	// 5) FOREIGN FILE — an undecryptable file dropped into the encrypted store is tampering, regardless of the ledger.
	{
		const foreign = path.join(v, 'data', 'not-a-vault-file.bin');
		await fsp.writeFile(foreign, crypto.randomBytes(1024)); // a plain name the crypt view cannot decode
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a foreign file in the store is flagged as tampering', tampers(a).length > 0 && (a.foreign || []).length > 0);
		await fsp.rm(foreign, { force: true });
		await vdisk.snapshot(v, { password: 'pw1' }); // back to a clean baseline
		ok('removing the foreign file and re-baselining clears it', tampers(await vdisk.audit(v, { password: 'pw1' })).length === 0);
	}

	// 6) SEAL INTEGRITY. A seal is the strict, never-auto-refreshed tripwire; it must never be silently downgraded to
	//    unsealed, and a legitimate unseal must not raise a false seal-downgrade alarm.
	await vdisk.snapshot(v, { password: 'pw1' }); // clean unsealed baseline to start from
	{
		// 7a) A legitimate seal audits clean; a legitimate unseal afterward audits clean too (no seal-downgrade
		//     false alarm from the ledger's sealed anchor, which the unseal advances forward to unsealed).
		await vdisk.seal(v, { password: 'pw1' });
		ok('a freshly sealed vault audits clean', tampers(await vdisk.audit(v, { password: 'pw1' })).length === 0);
		await vdisk.unseal(v, { password: 'pw1' });
		ok('a legitimate unseal does NOT raise a seal-downgrade alarm', tampers(await vdisk.audit(v, { password: 'pw1' })).length === 0);
	}
	{
		// 7b) SEAL DOWNGRADE by restoring an older, authentic UNSEALED record while the contents are unchanged (the
		//     realistic attack: someone with store write access swaps in a genuine pre-seal snapshot blob). Copy the
		//     unsealed store, seal, then restore the store — the in-vault record is now the old unsealed one while the
		//     manifest fingerprint and ledger still record the seal. This must be flagged, never cleared or self-healed.
		const dataDir = path.join(vdisk.resolveVaultDir(v), 'data');
		const backup = path.join(ws, 'store-unsealed');
		await vdisk.snapshot(v, { password: 'pw1' });                 // authentic UNSEALED record in the store
		await fsp.rm(backup, { recursive: true, force: true });
		await fsp.cp(dataDir, backup, { recursive: true });           // capture the unsealed store
		await vdisk.seal(v, { password: 'pw1' });                     // now sealed (record + fingerprint + ledger)
		await fsp.rm(dataDir, { recursive: true, force: true });
		await fsp.cp(backup, dataDir, { recursive: true });           // restore the OLD unsealed record (contents unchanged)
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('restoring an older unsealed record over a seal is flagged (not cleared by the content anchor)', tampers(a).length > 0 && a.clean === false);
		ok('the seal downgrade is not treated as a benign stale baseline', a.staleBaseline !== true);
		const m = await vdisk.checkOnMount(v, 'pw1');
		ok('the on-mount check refuses to trust a seal downgrade', m.trusted === false && m.warn && (m.warn.tamper || []).length > 0);
		await vdisk.seal(v, { password: 'pw1' }); // re-establish a clean sealed baseline
	}
	{
		// 7c) Guard unit: even if the record-level checks were bypassed (e.g. a legacy fingerprint that predates the
		//     self-verifying shape), the shared classifier must never CLEAR a rollback/diff that would downgrade a seal.
		//     Drive it directly: an unsealed record with unchanged contents, but the ledger's trusted anchor says sealed.
		await vdisk.unseal(v, { password: 'pw1' });                   // record now unsealed, ledger unsealed
		const l = await readLedger(); l[vid] = { ...l[vid], sealed: true }; await writeLedger(l); // ledger last-trusted = sealed
        const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a ledger sealed-anchor vs an unsealed record is flagged as a seal downgrade', tampers(a).length > 0 && /seal/i.test(joined(a)));
		await vdisk.snapshot(v, { password: 'pw1' }); // advance ledger to unsealed, clearing the synthetic anchor
	}
	{
		// 6d) SEAL ANCHOR in the ledger. Sealing must record sealed:true in the local (attacker-inaccessible) ledger,
		// a vault sealed by an OLDER build (whose ledger entry predates the field) must BACKFILL the anchor on a normal
		// mount, and a legitimate unseal must advance it to unsealed.
		await vdisk.seal(v, { password: 'pw1' });
		let l = await readLedger();
		ok('sealing records the sealed anchor in the ledger', !!(l[vid] && l[vid].sealed === true));
		delete l[vid].sealed; await writeLedger(l);                 // emulate a legacy (pre-field) ledger entry
		await vdisk.checkOnMount(v, 'pw1');                          // a normal mount observes the authentic sealed record
		l = await readLedger();
		ok('a normal mount backfills the sealed anchor for a legacy sealed vault', !!(l[vid] && l[vid].sealed === true));
		await vdisk.unseal(v, { password: 'pw1' });
		l = await readLedger();
		ok('a legitimate unseal advances the ledger anchor to unsealed', !!(l[vid] && l[vid].sealed === false));
	}
	{
		// 6e) A vault the device recorded as SEALED whose in-vault record is ABSENT is a stripped seal, not an
		// un-snapshotted vault — caught on BOTH the audit and the on-mount path via the authenticated ledger anchor,
		// even when the manifest's own (editable) sealed flag is gone.
		const src2 = path.join(ws, 'src2'); await fsp.mkdir(src2, { recursive: true }); await fsp.writeFile(path.join(src2, 'x.txt'), crypto.randomBytes(1024));
		const v2 = path.join(ws, 'SealAnchor.vault');
		await vdisk.importFolder(v2, { password: 'pw1', sourceDir: src2 }); // no baseline yet → no in-vault record
		const vid2 = Integrity.vaultId(await vdisk.readManifest(v2));
		const l = await readLedger(); l[vid2] = { seq: 1, root: crypto.createHash('sha256').update('x').digest('hex'), sealed: true }; await writeLedger(l);
		const a = await vdisk.audit(v2, { password: 'pw1' });
		ok('audit flags a missing record when the device recorded the vault sealed', tampers(a).some(t => /sealed baseline record is missing/i.test(t)));
		const m = await vdisk.checkOnMount(v2, 'pw1');
		ok('the on-mount check flags a missing sealed record too', m.trusted === false && !!(m.warn && (m.warn.tamper || []).some(t => /missing/i.test(t))));
		await vdisk.removeKnownVault(v2).catch(() => {});
	}

	// 7) CORRUPTED / REMOVED RECORD (destructive — runs last). Corrupting the in-vault snapshot record so it cannot be
	//    read back must still be reported, never silently healed. This leaves the store's metadata blobs damaged, so
	//    no further snapshot is taken after it.
	{
		const blobs = [];
		async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else blobs.push(p); } }
		await walk(path.join(v, 'data'));
		// The snapshot record is one of the smaller blobs; corrupt the smallest few so the record read fails closed.
		// (A byte flip in an authenticated-encryption blob fails to decrypt: the reader sees no readable record.)
		const small = (await Promise.all(blobs.map(async p => ({ p, s: (await fsp.stat(p)).size })))).sort((a, b) => a.s - b.s).slice(0, 3);
		for (const { p } of small) { const buf = await fsp.readFile(p); if (buf.length) { buf[0] ^= 0xff; await fsp.writeFile(p, buf); } }
		const a = await vdisk.audit(v, { password: 'pw1' });
		ok('a corrupted/removed baseline record is reported (not silently cleared)', tampers(a).length > 0 || (a.errors || []).length > 0);
	}

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	if (ws) await fsp.rm(ws, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TAMPER-BASELINE-ANCHOR CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (ws) await fsp.rm(ws, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
