'use strict';
// lib/test/mirror.js — end-to-end tests for Tier 1 "Mirror": two-way, zero-knowledge sync of a
// vault's encrypted folder to a second place. Covers priming (with the anti-clobber guards),
// two-way propagation, conflict preservation, the never-auto-prime rule, and teardown — all against
// a local destination folder, which needs only the bundled engine (no network).
//
// Run:  node lib/test/mirror.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const has = (p) => fs.existsSync(p);

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mirror-'));
	workspace = tmp;

	// A small vault with some content.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.bin'), crypto.randomBytes(400 * 1024));
	const v = path.join(tmp, 'Mirror.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const dataDir = path.join(v, 'data');

	console.log('[setup + prime]');
	const dest = path.join(tmp, 'dest');
	await vdisk.setMirrorDest(v, dest);
	let st = await vdisk.mirrorStatus(v);
	ok('a mirror is configured but not yet primed', st.configured === true && st.primed === false);
	ok('an unprimed mirror is not auto-synced (never auto-primes)', (await vdisk.syncMirrorIfConfigured(v)).reason === 'not-primed');

	const r1 = await vdisk.syncMirror(v, { prime: true });
	const mirrorVault = path.join(dest, 'Mirror.vault');
	ok('priming creates a full vault copy at the destination', r1.primed === true && has(path.join(mirrorVault, 'vault.json')) && has(path.join(mirrorVault, 'data')));
	ok('the destination copy is only ciphertext (a data/ folder, no plaintext source name)', has(path.join(mirrorVault, 'data')) && !has(path.join(mirrorVault, 'a.bin')));
	st = await vdisk.mirrorStatus(v);
	ok('status reports primed with a last-sync time', st.primed === true && !!st.lastSyncAt);

	console.log('[two-way propagation]');
	// A change made on the DESTINATION side comes back to the vault.
	await fsp.writeFile(path.join(mirrorVault, 'data', 'from-dest.bin'), crypto.randomBytes(2048));
	await vdisk.syncMirrorIfConfigured(v);
	ok('a change at the destination propagates back to the vault', has(path.join(dataDir, 'from-dest.bin')));
	// A change made on the VAULT side goes out to the destination.
	await fsp.writeFile(path.join(dataDir, 'from-vault.bin'), crypto.randomBytes(2048));
	await vdisk.syncMirror(v);
	ok('a change at the vault propagates out to the destination', has(path.join(mirrorVault, 'data', 'from-vault.bin')));
	ok('the vault still decrypts after clean round-trips', (await vdisk.verify(v, { password: 'pw', deep: true })).integrity === 'ok');

	console.log('[conflict is preserved, not clobbered]');
	// The same file changed on both sides between runs -> both versions kept, and surfaced.
	await fsp.writeFile(path.join(dataDir, 'from-dest.bin'), Buffer.from('vault-side'));
	await fsp.writeFile(path.join(mirrorVault, 'data', 'from-dest.bin'), Buffer.from('dest-side-different'));
	const rc = await vdisk.syncMirror(v);
	ok('a two-sided change is reported as a conflict', rc.conflicts === true);
	const names = fs.readdirSync(path.join(dataDir)).filter(n => n.includes('from-dest'));
	ok('both versions of the conflicted file are kept', names.length >= 2);
	const artifacts = await vdisk.scanSyncArtifacts(v).catch(() => []);
	ok('the sync-artifact check surfaces the conflict for the user', Array.isArray(artifacts) && artifacts.length >= 1);

	console.log('[safety: a vanished destination sentinel aborts, never deletes the local vault]');
	// Simulate an unmounted/emptied destination drive (or a hostile peer that wiped its copy) by removing the
	// access sentinel (vault.json) from the destination. A steady-state sync must ABORT rather than read the
	// absence as a deletion and propagate it back — which would remove the LOCAL vault's manifest and make the
	// vault unusable. This isolates the --check-access guard from the engine's percentage-based delete cap.
	const beforeFiles = fs.readdirSync(dataDir).length;
	await fsp.rm(path.join(mirrorVault, 'vault.json'), { force: true });
	let aborted = false;
	try { await vdisk.syncMirror(v); } catch (_) { aborted = true; }
	ok('a sync with a vanished destination sentinel fails closed (does not silently sync)', aborted);
	ok('the local vault manifest is untouched after the aborted sync', has(path.join(v, 'vault.json')));
	ok('no local vault file was deleted by the aborted sync', has(path.join(dataDir, 'from-vault.bin')) && fs.readdirSync(dataDir).length >= beforeFiles);
	await fsp.copyFile(path.join(v, 'vault.json'), path.join(mirrorVault, 'vault.json')); // restore the destination sentinel

	console.log('[re-prime is authoritative: a destination-only file is not merged back into the vault]');
	{
		// After a key rotation every ciphertext filename changes, so on a re-prime the destination holds files that
		// no longer exist locally. A prime must make the destination match THIS vault authoritatively and must NOT
		// copy those destination-only files back into the local vault — otherwise stale, undecryptable old-key
		// ciphertext would be merged into it. rclone's `bisync --resync` builds a superset (copies path2-only files
		// back), so the prime first does a one-way authoritative sync; this pins that behavior.
		const rsrc = path.join(tmp, 'rsrc'); await fsp.mkdir(rsrc, { recursive: true });
		await fsp.writeFile(path.join(rsrc, 'keep.bin'), crypto.randomBytes(64 * 1024));
		const rv = path.join(tmp, 'Reprime.vault');
		await vdisk.importFolder(rv, { password: 'pw', sourceDir: rsrc });
		const rdest = path.join(tmp, 'rdest');
		await vdisk.setMirrorDest(rv, rdest);
		await vdisk.syncMirror(rv, { prime: true });
		const rmv = path.join(rdest, 'Reprime.vault');
		// Plant a destination-only file (stands in for stale old-key ciphertext left at the destination after a
		// rotation), then RE-prime.
		await fsp.writeFile(path.join(rmv, 'data', 'stale-oldkey.bin'), Buffer.from('STALE OLD-KEY CIPHERTEXT'));
		await vdisk.syncMirror(rv, { prime: true });
		const findUnder = (dir, name) => { let hit = false; const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (e.name === name) hit = true; } }; try { walk(dir); } catch (_) {} return hit; };
		ok('a re-prime does not copy a destination-only file back into the local vault', !has(path.join(rv, 'data', 'stale-oldkey.bin')));
		ok('the destination-only file is archived at the destination, not lost', findUnder(path.join(rmv, '.versions'), 'stale-oldkey.bin'));
		ok('the local vault still decrypts after the authoritative re-prime', (await vdisk.verify(rv, { password: 'pw', deep: true })).integrity === 'ok');
		await vdisk.removeMirror(rv).catch(() => {});
		await vdisk.removeKnownVault(rv).catch(() => {});
	}

	console.log('[guards + teardown]');
	// Priming over a DIFFERENT vault must be refused (never overwrite an unrelated vault).
	const other = path.join(tmp, 'Other.vault');
	await vdisk.importFolder(other, { password: 'pw', sourceDir: src });
	const badDest = path.join(tmp, 'baddest');
	await fsp.mkdir(path.join(badDest, 'Mirror.vault'), { recursive: true });
	await fsp.cp(other, path.join(badDest, 'Mirror.vault'), { recursive: true });
	await vdisk.setMirrorDest(v, badDest); // re-point; clears the old baseline
	let refused = false;
	try { await vdisk.syncMirror(v, { prime: true }); } catch (e) { refused = /DIFFERENT vault|already/.test(e.message); }
	ok('priming over a different vault at the destination is refused', refused);

	await vdisk.setMirrorDest(v, dest); // back to the good destination
	await vdisk.removeMirror(v);
	ok('removing the mirror forgets the destination', (await vdisk.mirrorStatus(v)).configured === false);
	ok('removing the mirror leaves the destination copy in place (never deletes data)', has(path.join(mirrorVault, 'vault.json')));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MIRROR CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if ((kv.path || kv).includes('vdisk-mirror-')) await vdisk.removeKnownVault(kv.path || kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
