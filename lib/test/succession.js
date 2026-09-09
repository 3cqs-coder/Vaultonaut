'use strict';
// lib/test/succession.js — identity-substitution detection in the tamper audit. The manifest seal is signed
// by the key the manifest itself publishes, so a holder of the READ key who swaps the published verify key
// (re-signing the baseline and re-sealing with their own key) leaves a manifest that still verifies against
// ITSELF. The rollback ledger closes this: it records the committed identity, so an audit requires a valid,
// signed succession whenever the current identity differs from the last one this machine recorded. This test
// proves the three behaviors that matter: a legitimate rotation is never flagged (even when the ledger lags
// behind it), a substitution with no valid succession IS flagged, and a pre-existing ledger without a
// recorded identity never false-alarms. Needs the engine (rotation runs unmounted).
//
// Run:  node lib/test/succession.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanup() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-succ-')); workspace = tmp;
	// Isolate the rollback ledger and known-vaults state in the throwaway workspace, so the test never touches
	// the real ones. binDir() is ROOT-based, so the engine still resolves after this redirect.
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const Vault = require('../Vault');
	const Integrity = require('../Integrity');

	const ledgerFile = path.join(dataDir, 'integrity.json');
	const readLedger = async () => JSON.parse(await fsp.readFile(ledgerFile, 'utf8'));
	const writeLedger = async (l) => fsp.writeFile(ledgerFile, JSON.stringify(l, null, 2));

	// A small vault with a signed baseline (records the identity in the ledger).
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(2000));
	const v = path.join(tmp, 'Succ.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw1' });

	const before = await Vault.readManifest(v);
	const vid = Integrity.vaultId(before);
	const identityA = Integrity.identity(Integrity.pubkeyOf(before));

	let led = await readLedger();
	ok('the ledger recorded the vault identity at snapshot', led[vid] && led[vid].identity === identityA);
	ok('a fresh vault audits clean', (await vdisk.audit(v, { password: 'pw1' })).clean === true);

	// --- A legitimate rotation is never flagged ---
	const r = await vdisk.rotate(v, { password: 'pw1', reason: 'test' });
	const identityB = r.newIdentity;
	ok('the rotation changed the identity', identityB && identityB !== identityA);
	ok('a legitimately rotated vault audits clean', (await vdisk.audit(v, { password: 'pw1' })).clean === true);

	// The store-level `version` on the succession log is NOT signed (each block is individually signed over its own
	// fields). So an UNSIGNED version bump must not be trusted to short-circuit verification — otherwise a forged bump
	// could silently convert a genuinely broken chain into a benign empty one. Confirm a bumped store version leaves
	// the real, per-block-signed chain intact and verifying (it is neither masked nor emptied).
	{
		const sp = path.join(v, 'succession.json');
		const okBefore = await vdisk.verifySuccession(v);
		ok('the rotated succession chain verifies', okBefore.ok === true && okBefore.chain.length >= 1);
		const st = JSON.parse(await fsp.readFile(sp, 'utf8'));
		const orig = JSON.stringify(st);
		await fsp.writeFile(sp, JSON.stringify({ ...st, version: (Number(st.version) || 1) + 1 }));
		const bumped = await vdisk.verifySuccession(v);
		ok('an unsigned store-version bump does NOT empty or mask the per-block-signed chain', bumped.ok === true && bumped.chain.length === okBefore.chain.length && !bumped.unknownFormat);
		await fsp.writeFile(sp, orig); // restore
		ok('the restored succession chain verifies again', (await vdisk.verifySuccession(v)).ok === true);
	}

	// Even if this machine's ledger still holds the OLD identity (it lagged the rotation), the signed
	// succession A->B connects them, so the audit must stay clean — no false alarm.
	led = await readLedger(); led[vid].identity = identityA; await writeLedger(led);
	ok('a ledger lagging a legit rotation does not false-alarm', (await vdisk.audit(v, { password: 'pw1' })).clean === true);

	// --- A substitution with no valid succession IS flagged, and a routine mount/snapshot cannot launder it ---
	// Simulate an attacker who changed the identity to B but cannot present a valid succession from the
	// recorded identity A: remove the succession record. Put the ledger in the last known-good state (identity
	// A, one version behind the substituted vault), then run the UNAUTHORIZED observe a routine mount/snapshot
	// performs — it must NOT overwrite the known-good identity, or the audit's check would be silently disarmed.
	await fsp.rm(path.join(v, 'succession.json'), { force: true });
	const manifestB = await Vault.readManifest(v);
	const seqV = manifestB.snapshot.seq, rootV = manifestB.snapshot.root;
	led = await readLedger(); led[vid] = { seq: seqV - 1, root: rootV, at: new Date().toISOString(), identity: identityA }; await writeLedger(led);
	await Integrity.observe(vid, seqV, rootV, rootV, identityB, false); // the mount/snapshot path (unauthorized)
	led = await readLedger();
	ok('a routine mount/snapshot cannot launder a substituted identity into the ledger', led[vid].identity === identityA);
	const sub = await vdisk.audit(v, { password: 'pw1' });
	ok('an identity change without a valid succession is flagged as tampering',
		sub.clean === false && sub.tamper.some(t => /identity changed without a valid, signed succession/i.test(t)));

	// The on-mount check must catch the SAME substitution, not only the deep audit — a read-only-password mounter
	// who never runs an audit is otherwise exposed. It shares the audit's identity/succession logic.
	const subMount = await vdisk.checkOnMount(v, 'pw1');
	ok('the on-mount check also flags an identity substitution (not only audit)',
		subMount.warn && Array.isArray(subMount.warn.tamper) && subMount.warn.tamper.some(t => /identity changed without a valid, signed succession/i.test(t)));

	// --- A pre-existing ledger with no recorded identity never false-alarms ---
	// Restore the succession, then drop the identity field (a vault first seen before this feature existed).
	// The audit cannot enforce without a recorded identity, so it must not flag — the first-sighting fallback.
	// (Recompute the succession by rotating again would add a chain link; instead just restore state cleanly:
	// set the ledger identity to the current B and clear it to emulate a legacy entry.)
	led = await readLedger(); delete led[vid].identity; await writeLedger(led);
	// Rewrite a valid succession is not needed here — with no recorded identity the check is skipped entirely.
	const legacy = await vdisk.audit(v, { password: 'pw1' });
	ok('a legacy ledger entry without a recorded identity does not false-alarm',
		!legacy.tamper.some(t => /identity changed without a valid, signed succession/i.test(t)));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SUCCESSION CHECKS PASSED'));
	await cleanup();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
