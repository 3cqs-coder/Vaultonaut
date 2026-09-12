'use strict';
// lib/test/rotate.js — key rotation + full re-encryption (#7 part B). The vault's write seed and identity
// are rotated and every file is re-encrypted under the new key (verified byte-for-byte by rclone before
// anything live is touched). Checks the data-safety and correctness invariants: contents survive
// identically, the rotating password still opens the re-keyed vault, the identity changes with a verifiable
// signed succession, old read links die, the roster is cleared, and an interrupted (pre-commit) rotation
// rolls back leaving the vault untouched. Needs the engine (no mount driver — rotation runs unmounted).
//
// Run:  node lib/test/rotate.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function exists(p) { try { await fsp.stat(p); return true; } catch (_) { return false; } }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-rotate-')); workspace = tmp;
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'appdata'); Common.statePath = () => path.join(tmp, 'appdata', 'state.json'); // isolate the ledger/tamper-log/state from the real data dir (engine stays pinned by the test preload)
	const src = path.join(tmp, 'src'); await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(3000));
	await fsp.writeFile(path.join(src, 'sub', 'b.bin'), crypto.randomBytes(50000));
	const v = path.join(tmp, 'Rot.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.addKey(v, { password: 'pw1', newPassword: 'pw2', label: 'extra' }); // a second credential rotation must invalidate
	await vdisk.snapshot(v, { password: 'pw1' });
	ok('the extra password opens the vault before rotation', await Vault.assertReadable(v, 'pw2').then(() => true, () => false));

	const oldFp = await vdisk.fingerprint(v);
	const oldIdentity = oldFp.identity;
	const lb = await vdisk.list(v, { password: 'pw1' }); const norm = a => (Array.isArray(a) ? a : (a.entries || a.files || [])).map(f => f.path || f.name || f.Path || String(f)).sort(); const listBefore = norm(lb);
	const oldCap = await vdisk.makeReadCap(v, { password: 'pw1' });      // a read link that must die on rotation
	await vdisk.makeReadCap(v, { password: 'pw1', label: 'roster entry' }); // something in the roster
	// Build self-heal recovery data over the CURRENT ciphertext (via the Recovery module directly, which needs no
	// mounted-metadata precondition). It describes the old keys, so the rotation MUST clear it — otherwise a later
	// "Check & repair" would report the whole vault damaged and a scheduled auto-heal could reconstruct old-key
	// blocks over the new store, corrupting it.
	const Recovery = require('../Recovery');
	await Recovery.protect(v, { cipherDir: path.join(v, 'data'), tier: 'low', exclude: [] });
	ok('recovery data exists before rotation', (await Recovery.hasRecovery(v)) === true);

	// --- The rotation ---
	// A CLEAN rotation must complete on its own straight-line path, NOT by throwing and being silently finished by
	// resumeRekey (which logs "completed after an interruption" and skips the pre-commit lease fence). A bug like a
	// stale variable reference in rotate() would be masked that way, so capture the warnings and assert none reports
	// an interruption. This guards a class that neither `node --check` nor the outcome assertions below can catch.
	const warned = [];
	const origWarn = console.warn;
	console.warn = (...a) => { warned.push(a.join(' ')); origWarn(...a); };
	let r;
	try { r = await vdisk.rotate(v, { password: 'pw1', reason: 'test-revocation' }); }
	finally { console.warn = origWarn; }
		// Finding 2: a rotation resets every access method except the main password (and team members), but only recovery
		// was reported before, so an invalidated Touch ID or keyfile was a silent surprise. The extra password added at
		// setup must now be reported so the UI can tell the user to set it up again.
		ok("the rotation reports the extra password it invalidated (so the user is told to re-add it)", Array.isArray(r.droppedAccessMethods) && r.droppedAccessMethods.some(x => /extra password/.test(x)));
	ok('a clean rotation completes without hitting the interruption-recovery path', !warned.some(l => /interrupt/i.test(l)));
	ok('rotation reports a new identity', !!(r.newIdentity && r.newIdentity !== oldIdentity));

	const Integrity = require('../Integrity');
	const after = await Vault.readManifest(v);
	ok('the vault identity changed', Integrity.identity(Integrity.pubkeyOf(after)) === r.newIdentity && r.newIdentity !== oldIdentity);
	ok('the rotating password still opens the re-keyed vault', !(await vdisk.audit(v, { password: 'pw1' })).errors.length);
	ok('a rotation invalidates every OTHER credential (the extra password no longer opens)', !(await Vault.assertReadable(v, 'pw2').then(() => true, () => false)));
	ok('the re-keyed vault audits clean (baseline verifies under the new key)', !(await vdisk.audit(v, { password: 'pw1' })).tamper.length);
	ok('the stale self-heal recovery data was cleared by the rotation', (await require('../Recovery').hasRecovery(v)) === false);

	// Contents survived identically (rclone verified byte-for-byte; also confirm the file set is unchanged).
	if (listBefore) {
		const listAfter = norm(await vdisk.list(v, { password: 'pw1' }));
		ok('the file set is unchanged after re-encryption', JSON.stringify(listAfter) === JSON.stringify(listBefore));
	}

	// The OLD read link is now for a stale identity and is rejected against the re-keyed vault.
	const cap = Vault.parseReadCap(oldCap.token);
	ok('the old read link no longer matches the vault (dead)', cap && cap.pub && after.integrity && cap.pub !== after.integrity.pubkey);

	// The identity succession verifies (old key vouched, new key co-signed).
	const succ = await vdisk.verifySuccession(v);
	ok('the identity succession chain verifies', succ.ok === true && succ.current === r.newIdentity && succ.chain[0].oldIdentity === oldIdentity);

	// The share roster was cleared (all old links invalidated) and re-signed under the new key.
	const shares = await vdisk.listShares(v);
	ok('the share roster is cleared and valid after rotation', shares.shares.length === 0 && shares.sigOk === true);

	// A NEW read link works and is bound to the new identity.
	const newCap = await vdisk.makeReadCap(v, { password: 'pw1' });
	ok('a new read link is bound to the new identity', Vault.parseReadCap(newCap.token).pub === after.integrity.pubkey);

	// No rotation debris left behind.
	const debris = await Promise.all([ 'data.new.tmp', 'data.old.tmp', 'vault.json.new', '.vault.bak.new', '.rekey-journal.json' ].map(f => exists(path.join(v, f))));
	ok('no rotation temp files or journal remain', debris.every(x => !x));

	// --- Interrupted (pre-commit) rotation rolls back, vault untouched ---
	await fsp.mkdir(path.join(v, 'data.new.tmp'), { recursive: true });
	await fsp.writeFile(path.join(v, 'data.new.tmp', 'junk'), 'x');
	await fsp.writeFile(path.join(v, '.rekey-journal.json'), JSON.stringify({ phase: 'COPY', at: new Date().toISOString() }));
	const res = await vdisk.resumeRekey(v);
	ok('a pre-commit interruption is rolled back', res.resumed === true && res.completed === false);
	ok('the vault still opens normally after rollback', !(await vdisk.audit(v, { password: 'pw1' })).errors.length);
	ok('the staged temp copy was discarded on rollback', !(await exists(path.join(v, 'data.new.tmp'))) && !(await exists(path.join(v, '.rekey-journal.json'))));

	// --- Interrupted COMMIT with a FRESH heartbeat must be COMPLETED, not skipped (data-safety regression) ---
	// A crash during the commit leaves a journal whose heartbeat is only seconds old. An unforced recovery
	// (the sweep) must still finish the commit — never defer it as "actively progressing" — or a re-rotate's
	// prep cleanup could delete the only surviving copies. Build the scariest sub-state: data/ already moved
	// aside, the new store staged, and a COMMIT journal stamped now.
	{
		const dataDir = path.join(v, 'data');
		await fsp.cp(dataDir, path.join(v, 'data.new.tmp'), { recursive: true });
		await fsp.rename(dataDir, path.join(v, 'data.old.tmp')); // data/ now missing — the unrecoverable window if mis-handled
		await fsp.copyFile(path.join(v, 'vault.json'), path.join(v, 'vault.json.new'));
		await fsp.copyFile(path.join(v, 'vault.json'), path.join(v, '.vault.bak.new'));
		// The journal carries the identities and the hadRecovery flag the completion path needs. A crash-recovered
		// rotation must run the SAME post-commit notifications as a normal one (recovery nudge, off-site warning,
		// tamper-history entry, emergency-arming drop) — it previously skipped them, leaving the vault looking fully
		// rotated while silently dropping recovery with no reminder. Proven below by the tamper-history entry it writes.
		const rotatedBefore = ((await Vault.tamperLog(v)).events || []).filter(e => e.kind === 'identity-rotated').length;
		await fsp.writeFile(path.join(v, '.rekey-journal.json'), JSON.stringify({ phase: 'COMMIT', hadRecovery: true, oldIdentity: 'ROT-OLD', newIdentity: 'ROT-NEW', reason: 'resume-notify-test', heartbeatAt: new Date().toISOString(), at: new Date().toISOString() }));
		const rr = await vdisk.resumeRekey(v); // UNFORCED, exactly as the recovery sweep calls it
		ok('a fresh-heartbeat committed rotation is completed, not skipped', rr.resumed === true && rr.completed === true);
		ok('the data store is restored after the completed commit', (await exists(path.join(v, 'data'))) && !(await exists(path.join(v, 'data.new.tmp'))) && !(await exists(path.join(v, 'data.old.tmp'))));
		ok('a resumed committed rotation runs the post-commit notifications (records the identity change in the tamper history)', ((await Vault.tamperLog(v)).events || []).filter(e => e.kind === 'identity-rotated').length === rotatedBefore + 1);
		ok('the vault still opens after the completed commit', !(await vdisk.audit(v, { password: 'pw1' })).errors.length);
	}

	// --- A resumed COMMIT installs the REAL new generation (not a copy of the current manifest) ---
	// The synthetic case above proves data is restored; this proves the resumed commit actually SWITCHES the vault
	// to the new key material a crash left staged — so the new identity is live, links bound to the old identity die,
	// and the vault audits clean. It reconstructs a faithful mid-commit state from an ACTUAL rotation: perform the
	// rotation for real (so genuine new-gen ciphertext + manifest exist), stage those as the *.new / data.new.tmp
	// copies, and put the OLD generation back as the live store — exactly the on-disk state a crash at the commit
	// point leaves — then resume and confirm the NEW generation is installed.
	{
		const genOldDir = path.join(tmp, 'gen-old');
		await fsp.cp(path.join(v, 'data'), genOldDir, { recursive: true });                 // OLD (pre-rotation) ciphertext
		const oldManifest = await fsp.readFile(path.join(v, 'vault.json'));
		const oldSucc = await fsp.readFile(path.join(v, 'succession.json')).catch(() => null);
		const oldShares = await fsp.readFile(path.join(v, 'shares.json')).catch(() => null);
		const idOld = (await vdisk.fingerprint(v)).identity;
		const capOldGen = await vdisk.makeReadCap(v, { password: 'pw1' });                    // a link bound to the OLD identity

		const rReal = await vdisk.rotate(v, { password: 'pw1', reason: 'stage-new-gen' });    // real rotation -> NEW gen is now live
		const newId = rReal.newIdentity;
		// The live files are the NEW gen — stage them as the crash-time copies, then restore the OLD gen as live.
		await fsp.cp(path.join(v, 'data'), path.join(v, 'data.new.tmp'), { recursive: true });
		await fsp.copyFile(path.join(v, 'vault.json'), path.join(v, 'vault.json.new'));
		await fsp.copyFile(path.join(v, 'vault.json'), path.join(v, '.vault.bak.new'));
		if (await exists(path.join(v, 'succession.json'))) await fsp.copyFile(path.join(v, 'succession.json'), path.join(v, 'succession.json.new'));
		if (await exists(path.join(v, 'shares.json'))) await fsp.copyFile(path.join(v, 'shares.json'), path.join(v, 'shares.json.new'));
		await fsp.rm(path.join(v, 'data'), { recursive: true, force: true });
		await fsp.cp(genOldDir, path.join(v, 'data'), { recursive: true });
		await fsp.writeFile(path.join(v, 'vault.json'), oldManifest);
		if (oldSucc) await fsp.writeFile(path.join(v, 'succession.json'), oldSucc);
		if (oldShares) await fsp.writeFile(path.join(v, 'shares.json'), oldShares);
		await fsp.writeFile(path.join(v, '.rekey-journal.json'), JSON.stringify({ phase: 'COMMIT', heartbeatAt: new Date().toISOString(), at: new Date().toISOString() }));
		ok('the reconstructed pre-commit state is the OLD generation', (await vdisk.fingerprint(v)).identity === idOld);

		const rr = await vdisk.resumeRekey(v, { force: true });
		ok('the resumed commit completes', rr.resumed === true && rr.completed === true);
		ok('the resumed commit installs the NEW identity', (await vdisk.fingerprint(v)).identity === newId && newId !== idOld);
		const au = await vdisk.audit(v, { password: 'pw1' });
		ok('the resumed vault opens and audits clean under the rotating password', !au.errors.length && !au.tamper.length);
		ok('a link bound to the pre-rotation identity is dead after the resumed commit', Vault.parseReadCap(capOldGen.token).pub !== (await Vault.readManifest(v)).integrity.pubkey);
		ok('no rotation debris remains after the resumed commit', (await Promise.all(['data.new.tmp', 'data.old.tmp', 'vault.json.new', '.vault.bak.new', 'succession.json.new', 'shares.json.new', '.rekey-journal.json'].map(f => exists(path.join(v, f))))).every(x => !x));
	}

	// --- A rotation that FAILS mid-re-encryption rejects with the real error and leaves the vault intact ---
	// Regression for a stale-variable-reference class of bug: the heartbeat timer and its write queue are created
	// inside the rotation's try but referenced again from its catch and finally (a catch is a separate lexical scope
	// from its try). If either were declared with block scope INSIDE the try, the catch's own cleanup would throw a
	// ReferenceError that MASKED the true failure and skipped the roll-back — leaving staged debris and a half-rotated
	// vault. Force the re-encryption copy to fail and assert the rejection carries the engine's message (never a
	// ReferenceError), the identity is unchanged, and the vault still opens with no debris left behind.
	{
		const vFail = path.join(tmp, 'RotFail.vault');
		await vdisk.importFolder(vFail, { password: 'pw1', sourceDir: src });
		await vdisk.snapshot(vFail, { password: 'pw1' }); // a baseline so the post-rollback audit is a real "still clean" check, not a "no snapshot yet" notice
		const idBefore = (await vdisk.fingerprint(vFail)).identity;
		const Rclone = require('../Rclone');
		const origRun = Rclone.run; // stub ONLY the old->new re-encryption copy; every other engine call runs for real
		Rclone.run = async (b, args, opts) => (Array.isArray(args) && args[0] === 'copy' && args.includes('old:') && args.includes('new:'))
			? { status: 1, stdout: '', stderr: 'INJECTED re-encryption failure (rotation-failure regression)' }
			: origRun(b, args, opts);
		let threw = null;
		try { await vdisk.rotate(vFail, { password: 'pw1', reason: 'inject-fail' }); }
		catch (e) { threw = e; }
		finally { Rclone.run = origRun; }
		ok('a failed rotation rejects with the real engine error, not a ReferenceError masking it', !!threw && !(threw instanceof ReferenceError) && /re-encryption did not complete/i.test(threw.message || ''));
		ok('a failed rotation leaves the identity unchanged', (await vdisk.fingerprint(vFail)).identity === idBefore);
		ok('a failed rotation leaves the vault openable and clean', !(await vdisk.audit(vFail, { password: 'pw1' })).errors.length);
		ok('a failed rotation leaves no rotation debris', (await Promise.all(['data.new.tmp', 'data.old.tmp', 'vault.json.new', '.vault.bak.new', '.rekey-journal.json'].map(f => exists(path.join(vFail, f))))).every(x => !x));
		await vdisk.removeKnownVault(vFail).catch(() => {});
	}

	// A read-only credential cannot rotate.
	let roRefused = false;
	try { await vdisk.rotate(v, { password: oldCap.token }); } catch (_) { roRefused = true; }
	ok('rotation refuses an invalid/read-only credential', roRefused);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ROTATION CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
