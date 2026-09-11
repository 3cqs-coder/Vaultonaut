'use strict';
// lib/test/recovery.js — end-to-end tests for optional per-vault self-healing: build recovery data,
// corrupt the raw ciphertext, confirm verify detects it, heal repairs it, and the vault still
// decrypts+authenticates afterwards. Also covers the unrecoverable case (more damage than the
// parity budget) and multi-stripe interleaving (a contiguous burst spread across stripes).
//
// Run:  node lib/test/recovery.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');
const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function cipherBlobs(vaultDir) {
	const out = [];
	async function walk(dir) { for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) await walk(p); else out.push(p); } }
	await walk(path.join(vaultDir, 'data'));
	return out;
}
async function flipByte(file, pos) { const b = await fsp.readFile(file); b[pos % b.length] ^= 0xff; await fsp.writeFile(file, b); }

async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recovery-'));
	workspace = tmp;

	// --- happy path: protect -> corrupt -> verify -> heal -> still decrypts ---
	console.log('[protect / verify / heal]');
	// ~25 data blocks so the per-stripe parity budget (m ≈ round(k * 15%) ≈ 4 at 'high') comfortably
	// exceeds the 3 blocks we corrupt below.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(1200 * 1024));
	for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(50 * 1024));
	const v = path.join(tmp, 'Heal.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const before = (await vdisk.list(v, { password: 'pw' })).filter(f => !f.endsWith('/')).sort();

	const prot = await Recovery.protect(v, { tier: 'high' });
	ok('protect builds recovery data (' + prot.dataBlocks + ' blocks, budget m=' + (await Recovery.readIndex(v)).rs.m + ')', prot.dataBlocks > 20 && prot.parityBlocks >= 3);
	ok('the recovery index is present and self-verifies', await Recovery.hasRecovery(v));
	ok('verify is clean right after protect', (await Recovery.verify(v)).clean);

	// The cached status reader (used by the frequent UI poll) reports the right tier, is stable across
	// repeat calls, and refreshes when the index is rewritten at a new tier (stat-keyed invalidation).
	const s1 = await Recovery.readIndexMeta(v), s2 = await Recovery.readIndexMeta(v);
	ok('status reader reports protected at the tier it was built with', s1.protected === true && s1.tier === 'high');
	ok('status reader is stable across repeat calls', s2.tier === 'high' && s2.dataBlocks === s1.dataBlocks);
	await Recovery.protect(v, { tier: 'low' });
	ok('status reader refreshes after the index is rewritten at a new tier', (await Recovery.readIndexMeta(v)).tier === 'low');
	await Recovery.protect(v, { tier: 'high' }); // restore for the rest of the suite

	const blobs = (await cipherBlobs(v)).filter(p => !p.includes('.recovery'));
	await flipByte(blobs[0], 3); await flipByte(blobs[1], 50); await flipByte(blobs[2], 9);
	const vrep = await Recovery.verify(v);
	ok('verify detects the corruption', !vrep.clean && vrep.damagedData >= 3);
	ok('verify reports it is fully recoverable', vrep.fullyRecoverable);

	const h = await Recovery.heal(v);
	ok('heal repairs the damaged blocks', h.repairedData >= 3);
	ok('verify is clean after heal', (await Recovery.verify(v)).clean);
	const after = (await vdisk.list(v, { password: 'pw' })).filter(f => !f.endsWith('/')).sort();
	ok('the vault still lists every file after heal', JSON.stringify(before) === JSON.stringify(after));
	ok('deep verify: all files decrypt and authenticate after heal', (await vdisk.verify(v, { password: 'pw', deep: true })).integrity === 'ok');

	// --- unprotect requires the vault's read-write password (removing self-heal is a standing-security change) ---
	console.log('[unprotect needs the read-write password]');
	const upv = path.join(tmp, 'Unprot.vault');
	await vdisk.importFolder(upv, { password: 'pw', sourceDir: src });
	await Recovery.protect(upv, { tier: 'low' });
	await vdisk.addReadOnlyKey(upv, { password: 'pw', readOnlyPassword: 'ro-pw' });
	ok('unprotect is refused with a wrong password', await vdisk.unprotect(upv, { password: 'nope' }).then(() => false, (e) => /password is incorrect/i.test(e.message)));
	ok('unprotect is refused with a read-only password', await vdisk.unprotect(upv, { password: 'ro-pw' }).then(() => false, (e) => /read-only password cannot/i.test(e.message)));
	ok('the recovery data survives the refused attempts', await Recovery.hasRecovery(upv));
	ok('unprotect succeeds with the correct read-write password', await vdisk.unprotect(upv, { password: 'pw' }).then((r) => r && r.ok === true, () => false));
	ok('the recovery data is gone after a correct unprotect', !(await Recovery.hasRecovery(upv)));
	try { await vdisk.removeKnownVault(upv); } catch (_) {}

	// --- exclude guard: never build parity that covers an unexcluded tamper baseline ---
	console.log('[exclude guard]');
	// A vault with a tamper baseline but no computed metadata-exclude (it was never mounted, so the one-time
	// name lookup never ran) must REFUSE to protect — otherwise a later heal could revert the baseline blobs.
	const gv = path.join(tmp, 'Guard.vault');
	await vdisk.importFolder(gv, { password: 'pw', sourceDir: src });
	await vdisk.snapshot(gv, { password: 'pw' }); // creates manifest.snapshot; recoveryExclude stays empty
	let guardErr = null;
	try { await vdisk.protect(gv, { tier: 'low' }); } catch (e) { guardErr = e; }
	ok('protect refuses when a baseline exists but the exclude is not ready', !!guardErr && guardErr.code === 'EXCLUDE_NOT_READY');
	ok('the refused vault was left unprotected', !(await Recovery.hasRecovery(gv)));
	try { await vdisk.removeKnownVault(gv); } catch (_) {}

	// --- unrecoverable: damage beyond the parity budget of a stripe is reported, not silently wrong ---
	console.log('[unrecoverable damage]');
	const v2 = path.join(tmp, 'Small.vault');
	await vdisk.create(v2, { password: 'pw' });
	// give it a little content via a tiny import so there is data to protect
	const src2 = path.join(tmp, 'src2'); await fsp.mkdir(src2, { recursive: true });
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(src2, 'g' + i + '.bin'), crypto.randomBytes(70 * 1024));
	const v3 = path.join(tmp, 'Low.vault');
	await vdisk.importFolder(v3, { password: 'pw', sourceDir: src2 });
	await Recovery.protect(v3, { tier: 'low' }); // low tier -> smallest budget (m may be 1 for a single stripe)
	const idx = await Recovery.readIndex(v3);
	const m = idx.rs.m;
	// Corrupt m+1 DISTINCT blocks that land in the SAME stripe. With a single stripe (few blocks),
	// every block is in stripe 0, so corrupting m+1 blocks exceeds the budget.
	const blobs3 = (await cipherBlobs(v3)).filter(p => !p.includes('.recovery'));
	let flipped = 0;
	for (const b of blobs3) { if (flipped > m) break; await flipByte(b, 1); flipped++; }
	const uv = await Recovery.verify(v3);
	ok('verify flags an over-budget stripe as unrecoverable', idx.stripes > 1 ? true : uv.unrecoverableStripes >= 1);
	const uh = await Recovery.heal(v3);
	ok('heal reports the unrecoverable stripe rather than corrupting data', idx.stripes > 1 ? true : uh.unrecoverableStripes >= 1);

	// --- multi-stripe interleaving: a contiguous burst spread across stripes is recoverable ---
	console.log('[multi-stripe interleaving]');
	const bigSrc = path.join(tmp, 'bigsrc'); await fsp.mkdir(bigSrc, { recursive: true });
	// > K_MAX (128) blocks so there are multiple stripes: ~140 blocks = ~9 MB
	await fsp.writeFile(path.join(bigSrc, 'huge.bin'), crypto.randomBytes(140 * 64 * 1024));
	const v4 = path.join(tmp, 'Big.vault');
	await vdisk.importFolder(v4, { password: 'pw', sourceDir: bigSrc });
	const p4 = await Recovery.protect(v4, { tier: 'medium' });
	ok('a large vault produces multiple stripes', p4.stripes > 1);
	// Corrupt a CONTIGUOUS run of blocks in the largest blob (the single ~9 MB encrypted file).
	// Interleaving assigns consecutive blocks to different stripes, so a burst of up to (stripes)
	// consecutive blocks lands one-per-stripe and stays within each stripe's budget.
	const blobs4 = (await cipherBlobs(v4)).filter(p => !p.includes('.recovery'));
	const stats = await Promise.all(blobs4.map(async p => ({ p, size: (await fsp.stat(p)).size })));
	const target = stats.sort((a, b) => b.size - a.size)[0].p; // the biggest blob
	const buf = await fsp.readFile(target);
	for (let blk = 0; blk < p4.stripes && (blk + 1) * 65536 <= buf.length; blk++) buf[blk * 65536 + 7] ^= 0xff; // one byte in each of the first S blocks
	await fsp.writeFile(target, buf);
	const bv = await Recovery.verify(v4);
	ok('an interleaved burst is detected and fully recoverable', bv.damagedData >= 1 && bv.fullyRecoverable);
	await Recovery.heal(v4);
	ok('verify is clean after healing the burst', (await Recovery.verify(v4)).clean);
	ok('the large vault still decrypts after heal', (await vdisk.verify(v4, { password: 'pw', deep: true })).integrity === 'ok');
	void v2;

	// --- progress reporting (worker-driven) + automatic staleness refresh ---
	console.log('[progress + automatic refresh after changes]');
	const psrc = path.join(tmp, 'psrc'); await fsp.mkdir(psrc, { recursive: true });
	await fsp.writeFile(path.join(psrc, 'p.bin'), crypto.randomBytes(600 * 1024));
	const vp = path.join(tmp, 'Prog.vault');
	await vdisk.importFolder(vp, { password: 'pw', sourceDir: psrc });
	const pcts = [];
	await Recovery.protect(vp, { tier: 'medium', onProgress: p => pcts.push(p.percent) });
	ok('protect streams progress ending at 100%', pcts.length > 1 && pcts[pcts.length - 1] === 100);
	ok('progress is within range and non-decreasing', pcts.every((x, i) => x >= 0 && x <= 100 && (i === 0 || x >= pcts[i - 1])));
	ok('a freshly protected vault is not stale', (await Recovery.isStale(vp)) === false);

	// A pure modification-time change must NOT count as stale: the vault's tamper baseline rewrites a
	// metadata file on every unmount, so keying off mtime would re-encode the whole vault every time.
	const blob = (await cipherBlobs(vp))[0];
	const future = new Date(Date.now() + 5000);
	await fsp.utimes(blob, future, future);
	ok('a pure modification-time change is NOT treated as stale', (await Recovery.isStale(vp)) === false);

	// A change to EXISTING protected content with NO trusted session (i.e. a change made AT REST) must be
	// treated as potential damage: the auto-refresh DEFERS instead of baking it into the parity, so the vault
	// stays repairable. (A legitimate edit through a trusted mount session still refreshes — that path is
	// exercised end-to-end by the mount-based suites.)
	const origSize = (await fsp.stat(blob)).size;
	await fsp.appendFile(blob, Buffer.alloc(100));
	ok('a resized vault is detected as stale', (await Recovery.isStale(vp)) === true);
	const rr = await vdisk.refreshRecoveryIfStale(vp);
	ok('auto-refresh DEFERS an at-rest change (never bakes damage into the parity)', rr.refreshed === false && (rr.reason === 'damage-detected' || rr.reason === 'files-missing'));
	await fsp.truncate(blob, origSize); // restore the blob so the vault is byte-for-byte intact again
	ok('the restored vault verifies clean and is up to date', (await vdisk.verifyRecovery(vp)).clean === true && (await Recovery.isStale(vp)) === false);
	const rr2 = await vdisk.refreshRecoveryIfStale(vp);
	ok('refreshRecoveryIfStale is a no-op when up to date', rr2.refreshed === false && rr2.reason === 'up-to-date');

	// --- OS metadata sidecars (.DS_Store) must NOT make a read-only session look stale ---
	// macOS writes a .DS_Store into every folder you browse; recovery excludes them by their (deterministic)
	// encrypted basename, so navigating/playing media does not needlessly rebuild the parity on every unmount.
	console.log('[OS sidecars are excluded from staleness]');
	const jsrc = path.join(tmp, 'jsrc');
	await fsp.mkdir(path.join(jsrc, 'A'), { recursive: true });
	await fsp.mkdir(path.join(jsrc, 'B'), { recursive: true });
	await fsp.writeFile(path.join(jsrc, 'A', '.DS_Store'), Buffer.from('dsA'));
	await fsp.writeFile(path.join(jsrc, 'B', '.DS_Store'), Buffer.from('dsB'));
	await fsp.writeFile(path.join(jsrc, 'A', 'real.bin'), crypto.randomBytes(40 * 1024));
	const jv = path.join(tmp, 'Junk.vault');
	await vdisk.importFolder(jv, { password: 'pw', sourceDir: jsrc });
	const jblobs = await cipherBlobs(jv);
	const jcounts = {}; for (const p of jblobs) { const b = path.basename(p); jcounts[b] = (jcounts[b] || 0) + 1; }
	const dsName = Object.keys(jcounts).find(b => jcounts[b] > 1); // .DS_Store shares one encrypted basename across A and B
	ok('the two .DS_Store files share one deterministic encrypted basename', !!dsName);
	await Recovery.protect(jv, { tier: 'low', exclude: dsName ? [dsName] : [] });
	for (const p of jblobs) if (path.basename(p) === dsName) await fsp.appendFile(p, Buffer.alloc(50)); // macOS re-touches .DS_Store
	ok('changing OS sidecars does NOT make the vault stale (no needless rebuild)', (await Recovery.isStale(jv)) === false);
	let jReal = null; for (const p of jblobs) { if (path.basename(p) === dsName) continue; if ((await fsp.stat(p)).size > 1000) { jReal = p; break; } }
	if (jReal) await fsp.appendFile(jReal, Buffer.alloc(100));
	ok('a change to a REAL file is still detected as stale', (await Recovery.isStale(jv)) === true);
	try { await vdisk.removeKnownVault(jv); } catch (_) {}

	// --- DATA SAFETY: the auto-refresh must NEVER bake a deletion into the recovery data ---
	// Reproduces the real-world flow that broke: a protected file is moved OUT of the vault, then the unmount
	// "updating…" step (refreshRecoveryIfStale) runs. It MUST refuse to re-protect over the loss, so that the
	// recovery data still describes the missing file and "Check & repair" (verify + heal) can restore it.
	// Before the fix, the auto-refresh rebuilt the parity over the deletion and heal then found "nothing to do".
	console.log('[auto-refresh never discards a healable deletion]');
	const dsrc = path.join(tmp, 'dsrc'); await fsp.mkdir(dsrc, { recursive: true });
	for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(dsrc, 'd' + i + '.bin'), crypto.randomBytes(60 * 1024));
	const dv = path.join(tmp, 'DelSafe.vault');
	await vdisk.importFolder(dv, { password: 'pw', sourceDir: dsrc });
	await Recovery.protect(dv, { tier: 'high' });
	const dvContent = JSON.stringify((await vdisk.list(dv, { password: 'pw' })).filter(f => !f.endsWith('/')).sort());
	await fsp.rm((await cipherBlobs(dv))[0], { force: true }); // move a file out of the vault (delete an encrypted blob)
	const dref = await vdisk.refreshRecoveryIfStale(dv); // the unmount auto-refresh
	ok('auto-refresh REFUSES to rebuild when a protected file is missing', dref.refreshed === false && dref.reason === 'files-missing' && dref.missing >= 1);
	ok('verify still detects the loss after the deferred refresh', (await vdisk.verifyRecovery(dv)).clean === false);
	const dheal = await vdisk.heal(dv);
	ok('heal restores the moved-out file (did NOT report clean)', dheal && dheal.healed > 0);
	ok('the vault decrypts to its ORIGINAL file list after heal', JSON.stringify((await vdisk.list(dv, { password: 'pw' })).filter(f => !f.endsWith('/')).sort()) === dvContent);
	ok('verify is clean again after heal', (await vdisk.verifyRecovery(dv)).clean === true);
	try { await vdisk.removeKnownVault(dv); } catch (_) {}

	// --- security: reject a crafted index whose file path escapes the vault ---
	console.log('[path-traversal guard]');
	// The recovery index travels inside a shareable vault and is only self-hashed (unkeyed), so a hostile
	// index must never be able to steer heal's writes outside the vault. Craft a VALID-hash index with a
	// traversal path and confirm verify/heal REFUSE and nothing lands outside the vault.
	const tv = path.join(tmp, 'Traversal.vault');
	await vdisk.importFolder(tv, { password: 'pw', sourceDir: src });
	await Recovery.protect(tv, { tier: 'low' });
	const escapeTarget = path.join(tmp, 'ESCAPED'); // '../../ESCAPED' from <tv>/data resolves here
	const tvRec = Recovery.recoveryDir(tv);
	for (const name of await fsp.readdir(tvRec)) {
		if (!/^index/.test(name)) continue;
		const p = path.join(tvRec, name);
		const idx = JSON.parse(await fsp.readFile(p, 'utf8'));
		if (idx.files && idx.files[0]) idx.files[0].path = '../../ESCAPED'; // escape data/ then the vault folder
		delete idx.indexHash;
		idx.indexHash = crypto.createHash('sha256').update(JSON.stringify(idx)).digest('hex'); // keep the self-hash valid
		await fsp.writeFile(p, JSON.stringify(idx));
	}
	let tvVerify = false, tvHeal = false;
	try { await Recovery.verify(tv); } catch (e) { tvVerify = /unsafe file path/.test(e.message); }
	try { await Recovery.heal(tv); } catch (e) { tvHeal = /unsafe file path/.test(e.message); }
	ok('verify refuses an index with a path-traversal entry', tvVerify);
	ok('heal refuses an index with a path-traversal entry', tvHeal);
	ok('nothing was written outside the vault', (await fsp.access(escapeTarget).then(() => true, () => false)) === false);
	try { await vdisk.removeKnownVault(tv); } catch (_) {}

	// --- security: reject a crafted index whose file resolves OUT via a planted symlink ---
	console.log('[symlink-escape guard]');
	// readIndex blocks '..'/absolute path STRINGS, but a hostile vault can plant a symlink inside data/ plus a
	// '..'-free relative path that follows it OUT of the vault at write time. Confirm the realpath containment
	// refuses before any block is read or written. The symlink target must exist for realpath to resolve it.
	const sv = path.join(tmp, 'Symlink.vault');
	await vdisk.importFolder(sv, { password: 'pw', sourceDir: src });
	await Recovery.protect(sv, { tier: 'low' });
	const svOutside = path.join(tmp, 'OUTSIDE');
	await fsp.mkdir(svOutside, { recursive: true });
	// Creating a symlink needs elevation (or Developer Mode) on Windows, so skip these checks where it is not
	// permitted rather than failing the suite — the containment guard they exercise is exercised on macOS/Linux.
	let symlinked = false;
	try { await fsp.symlink(svOutside, path.join(sv, 'data', 'out')); symlinked = true; } // data/out -> <tmp>/OUTSIDE
	catch (e) { console.log('  info   cannot create a symlink here (' + (e.code || e.message) + ') — skipping the symlink-escape checks (needs elevation on Windows).'); }
	if (symlinked) {
		const svRec = Recovery.recoveryDir(sv);
		for (const name of await fsp.readdir(svRec)) {
			if (!/^index/.test(name)) continue;
			const p = path.join(svRec, name);
			const idx = JSON.parse(await fsp.readFile(p, 'utf8'));
			if (idx.files && idx.files[0]) idx.files[0].path = 'out/secret'; // no '..', but follows the symlink OUT
			delete idx.indexHash;
			idx.indexHash = crypto.createHash('sha256').update(JSON.stringify(idx)).digest('hex'); // keep the self-hash valid
			await fsp.writeFile(p, JSON.stringify(idx));
		}
		let svVerify = false, svHeal = false;
		try { await Recovery.verify(sv); } catch (e) { svVerify = /resolves outside the vault/.test(e.message); }
		try { await Recovery.heal(sv); } catch (e) { svHeal = /resolves outside the vault/.test(e.message); }
		ok('verify refuses an index whose path follows a symlink out of the vault', svVerify);
		ok('heal refuses an index whose path follows a symlink out of the vault', svHeal);
		ok('nothing was written through the symlink', (await fsp.access(path.join(svOutside, 'secret')).then(() => true, () => false)) === false);
	}
	try { await vdisk.removeKnownVault(sv); } catch (_) {}

	// --- security: reject a crafted index with an inconsistent RS geometry (crafted DoS shape) ---
	console.log('[index-shape guard]');
	// The whole erasure-coding geometry is DETERMINED by the data-block count and redundancy, so an absurd
	// stripe/parity count no longer matches the canonical shape and must be refused before it drives a huge
	// allocation or an effectively-infinite loop in verify/heal.
	const shv = path.join(tmp, 'Shape.vault');
	await vdisk.importFolder(shv, { password: 'pw', sourceDir: src });
	await Recovery.protect(shv, { tier: 'low' });
	const shvRec = Recovery.recoveryDir(shv);
	for (const name of await fsp.readdir(shvRec)) {
		if (!/^index/.test(name)) continue;
		const p = path.join(shvRec, name);
		const idx = JSON.parse(await fsp.readFile(p, 'utf8'));
		idx.stripes = 2000000000; // an absurd stripe count that no longer matches the canonical shape
		delete idx.indexHash;
		idx.indexHash = crypto.createHash('sha256').update(JSON.stringify(idx)).digest('hex');
		await fsp.writeFile(p, JSON.stringify(idx));
	}
	let shvVerify = false;
	try { await Recovery.verify(shv); } catch (e) { shvVerify = /invalid or inconsistent structure/.test(e.message); }
	ok('verify refuses an index whose erasure-coding geometry is inconsistent', shvVerify);
	try { await vdisk.removeKnownVault(shv); } catch (_) {}

	// A crafted per-block length must also be refused: heal writes exactly `len` bytes of a rebuilt block, so a
	// len larger than one block (or non-integer) could steer a wrong-length write.
	const blv = path.join(tmp, 'BlockLen.vault');
	await vdisk.importFolder(blv, { password: 'pw', sourceDir: src });
	await Recovery.protect(blv, { tier: 'low' });
	const blvRec = Recovery.recoveryDir(blv);
	for (const name of await fsp.readdir(blvRec)) {
		if (!/^index/.test(name)) continue;
		const p = path.join(blvRec, name);
		const idx = JSON.parse(await fsp.readFile(p, 'utf8'));
		if (idx.files && idx.files[0] && idx.files[0].blocks && idx.files[0].blocks[0]) idx.files[0].blocks[0].len = 1 << 30; // 1 GiB, far larger than a 64 KiB block
		delete idx.indexHash;
		idx.indexHash = crypto.createHash('sha256').update(JSON.stringify(idx)).digest('hex');
		await fsp.writeFile(p, JSON.stringify(idx));
	}
	let blvVerify = false;
	try { await Recovery.verify(blv); } catch (e) { blvVerify = /invalid or inconsistent structure/.test(e.message); }
	ok('verify refuses an index with an out-of-range per-block length', blvVerify);
	try { await vdisk.removeKnownVault(blv); } catch (_) {}

	// --- security: KDF params travel in an untrusted manifest — reject out-of-range values ---
	console.log('[kdf param bounds]');
	// A crafted memKiB/iterations would OOM or CPU-hang the victim the instant they type a password. Bound
	// them to a sane superset of the tool's own levels; a valid in-range set must still derive normally.
	const goodSalt = crypto.randomBytes(16).toString('base64');
	const good = { algo: 'argon2id', v: 1, memKiB: 65536, iterations: 3, parallelism: 4, hashLen: 32, salt: goodSalt };
	const badParams = [
		{ ...good, memKiB: 1 << 30 },            // memory cost far past the cap (OOM)
		{ ...good, iterations: 1000 },           // iteration count far past the cap (CPU hang)
		{ ...good, hashLen: 4 },                 // hash length too short
		{ ...good, salt: 'x'.repeat(5000) }      // salt string absurdly long
	];
	let kdfBad = 0;
	for (const bp of badParams) { try { await Kdf.deriveSecret('pw', bp); } catch (_) { kdfBad++; } }
	ok('deriveSecret refuses every out-of-range KDF parameter set', kdfBad === badParams.length);
	let kdfOk = false;
	try { await Kdf.deriveSecret('pw', good); kdfOk = true; } catch (_) {}
	ok('deriveSecret still accepts valid in-range KDF parameters', kdfOk);

	// --- fail closed on a recovery format written by a newer version ---
	console.log('[newer recovery format is refused, not misread]');
	// Bump every index replica to a future schema version (re-signing each so the self-hash still
	// matches), then confirm the acting paths refuse rather than guess at an unknown layout.
	const recDir = Recovery.recoveryDir(v);
	let bumped = 0;
	for (const name of await fsp.readdir(recDir)) {
		if (!/^index/.test(name)) continue;
		const p = path.join(recDir, name);
		const idx = JSON.parse(await fsp.readFile(p, 'utf8'));
		idx.schemaVersion = 999; delete idx.indexHash;
		const h = crypto.createHash('sha256').update(JSON.stringify(idx)).digest('hex');
		idx.indexHash = h; await fsp.writeFile(p, JSON.stringify(idx));
		bumped++;
	}
	ok('there are index replicas to age forward', bumped > 0);
	let refused = false;
	try { await Recovery.verify(v); } catch (e) { refused = /newer version/.test(e.message); }
	ok('verify refuses a newer recovery format instead of misreading it', refused);
	let healRefused = false;
	try { await Recovery.heal(v); } catch (e) { healRefused = /newer version/.test(e.message); }
	ok('heal refuses a newer recovery format instead of guessing', healRefused);
	const probe = await vdisk.recoveryStatus(v);
	ok('a status probe still reports the recovery data as present (unreadable)', probe.protected === true && probe.unreadable === true);

	// --- smallest practical vault (a single stripe) ---
	// The happy path above uses a mid-size vault (~25 data blocks). This covers the OTHER end: the smallest vault the
	// architecture produces — one tiny file, whose whole ciphertext is a couple of <=64 KiB blocks in a single stripe
	// (S=1). That degenerate single-stripe geometry is exercised nowhere else. Corrupt exactly ONE of its blocks (one
	// loss, within the m>=1 parity budget), and confirm verify detects it, heal rebuilds it, and the vault still
	// decrypts. (The absolute D=1 mirror geometry, which importFolder cannot produce, is pinned in recoverygeometry.js.)
	console.log('[smallest vault (single stripe)]');
	const sbSrc = path.join(tmp, 'sbsrc'); await fsp.mkdir(sbSrc, { recursive: true });
	await fsp.writeFile(path.join(sbSrc, 'only.txt'), crypto.randomBytes(16 * 1024)); // one small file -> a tiny single-stripe vault
	const sbv = path.join(tmp, 'Single.vault');
	await vdisk.importFolder(sbv, { password: 'pw', sourceDir: sbSrc });
	const sbProt = await Recovery.protect(sbv, { tier: 'low' });
	// A vault of at most K_MAX (128) data blocks is a single stripe by construction (S = ceil(D/128) = 1), so a small
	// block count IS the single-stripe geometry; the index persists only {k, m} (S is re-derived), so assert via D.
	ok('the smallest vault protects into a single stripe with parity', sbProt.dataBlocks >= 1 && sbProt.dataBlocks <= 128 && sbProt.parityBlocks >= 1);
	ok('smallest-vault verify is clean right after protect', (await Recovery.verify(sbv)).clean);
	const sbBlobs = (await cipherBlobs(sbv)).filter(p => !p.includes('.recovery'));
	ok('the smallest vault has at least one ciphertext blob to corrupt', sbBlobs.length >= 1);
	await flipByte(sbBlobs[0], 40); // corrupt ONE data block's content (past the 32-byte crypt header) — one loss, within budget
	const sbVer = await Recovery.verify(sbv);
	ok('smallest-vault verify detects the corruption and reports it recoverable', !sbVer.clean && sbVer.damagedData >= 1 && sbVer.fullyRecoverable);
	const sbHeal = await Recovery.heal(sbv);
	ok('smallest-vault heal repairs the damaged block', sbHeal.repairedData >= 1);
	ok('smallest-vault verify is clean after heal', (await Recovery.verify(sbv)).clean);
	ok('the smallest vault still decrypts and authenticates after heal', (await vdisk.verify(sbv, { password: 'pw', deep: true })).integrity === 'ok');
	try { await vdisk.removeKnownVault(sbv); } catch (_) {}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

let workspace = null;
async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if (kv.includes('vdisk-recovery-')) await vdisk.removeKnownVault(kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
