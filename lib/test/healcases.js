'use strict';
// lib/test/healcases.js — the full matrix of situations self-healing must recover from. Recovery works
// over the encrypted ciphertext blobs, and once a block fails its CRC the cause does not matter: bit-rot,
// truncation, deletion, and a vanished directory all become "erasures" that Reed–Solomon rebuilds from
// parity. Each case below drives one of those failures through a real vault and confirms the blob comes
// back byte-for-byte AND with its original metadata (mtime/mode/owner) restored from the index snapshot.
//
// Run:  node lib/test/healcases.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function walk(dir) { const out = []; for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) out.push(...await walk(p)); else { const st = await fsp.stat(p); out.push({ path: p, size: st.size, mode: st.mode }); } } return out; }
async function sha(p) { return crypto.createHash('sha256').update(await fsp.readFile(p)).digest('hex'); }
function smallest(files) { return files.slice().sort((a, b) => a.size - b.size)[0]; }

const STAMP = new Date('2019-03-04T09:15:00Z'); // a distinctive "original" time to prove metadata is restored

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-healcases-')); workspace = tmp;

	// A multi-file vault, with a nested folder, so parity spans many stripes and losing one blob stays
	// well within the redundancy budget. (A single-file vault cannot survive losing its only file — that
	// is 100% loss, which no parity scheme recovers; real recovery is about localized damage.)
	const src = path.join(tmp, 'src');
	await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	for (let i = 0; i < 12; i++) await fsp.writeFile(path.join(src, 'file' + i + '.bin'), crypto.randomBytes(128 * 1024));
	await fsp.writeFile(path.join(src, 'sub', 'nested.bin'), crypto.randomBytes(96 * 1024));
	const v = path.join(tmp, 'HealCases.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const dataDir = path.join(v, 'data');

	// Stamp every ciphertext blob with the distinctive original time, then protect at high redundancy so
	// the index records that time (and each blob's mode) as the metadata a repair must restore.
	for (const f of await walk(dataDir)) await fsp.utimes(f.path, STAMP, STAMP);
	await vdisk.protect(v, { tier: 'high' });

	async function healOk(label) { const r = await vdisk.heal(v); ok(label + ': heal did not report unrecoverable stripes', r.unrecoverableStripes === 0); return r; }
	function stampedBack(p) { return fsp.stat(p).then(st => Math.abs(st.mtime.getTime() - STAMP.getTime()) < 2000); }

	console.log('[1] silent bit-rot — a block changes in place, same size and (untouched) mtime');
	{
		const blobs = await walk(dataDir); const t = blobs[0].path; const want = await sha(t);
		const b = await fsp.readFile(t); b[Math.floor(b.length / 2)] ^= 0xff; await fsp.writeFile(t, b);
		await healOk('bit-rot');
		ok('bit-rot: content restored byte-for-byte', await sha(t) === want);
		ok('bit-rot: original modification time restored', await stampedBack(t));
	}

	console.log('[2] whole-file deletion — the blob is gone and must be recreated from parity');
	{
		const blobs = await walk(dataDir); const victim = smallest(blobs); const want = await sha(victim.path); const mode = victim.mode;
		await fsp.rm(victim.path);
		await healOk('deletion');
		ok('deletion: the blob was recreated', await fsp.stat(victim.path).then(() => true, () => false));
		ok('deletion: recreated content matches byte-for-byte', await sha(victim.path) === want);
		ok('deletion: recreated file has its original modification time (not "now")', await stampedBack(victim.path));
		if (process.platform !== 'win32') ok('deletion: recreated file has its original permissions', (await fsp.stat(victim.path)).mode === mode);
	}

	console.log('[3] vanished directory — a nested blob AND its parent folder are removed');
	{
		const nestedDir = (await fsp.readdir(dataDir, { withFileTypes: true })).find(e => e.isDirectory());
		const dirAbs = path.join(dataDir, nestedDir.name);
		const before = await walk(dirAbs); const want = new Map(); for (const f of before) want.set(path.relative(dataDir, f.path), await sha(f.path));
		await fsp.rm(dirAbs, { recursive: true, force: true });
		await healOk('dir-loss');
		let allBack = true; for (const [rel, h] of want) { const p = path.join(dataDir, rel); if (!(await fsp.stat(p).then(() => true, () => false)) || await sha(p) !== h) allBack = false; }
		ok('dir-loss: the directory and its blobs were recreated with matching content', allBack);
	}

	console.log('[4a] truncation — a shorter blob is PRESERVED by default (it could be a user trim) and rebuilt only with force');
	{
		const blobs = await walk(dataDir); const t = blobs[1].path; const want = await sha(t); const origSize = blobs[1].size;
		await fsp.truncate(t, Math.floor(origSize / 2)); // lop off the tail
		// DATA SAFETY: a blob shorter than the index could be corruption OR a user who trimmed the file with the
		// recovery refresh deferred (an untrusted/forced-teardown session). Heal cannot tell them apart by size, so
		// by default it must NOT rebuild the removed tail from stale parity and silently resurrect deleted data — it
		// preserves and reports it, exactly as it does for a grown blob. Rebuilding is opt-in via force.
		const rDefault = await vdisk.heal(v);
		ok('truncate (default): the shortened blob was NOT rebuilt — a possible user trim is preserved', (await fsp.stat(t)).size === Math.floor(origSize / 2));
		ok('truncate (default): the change is reported so the user can update protection', rDefault.changedSkipped >= 1);
		// FORCE: the explicit override rebuilds it from parity, for when the user is certain the truncation is damage.
		const rForce = await vdisk.heal(v, { force: true });
		ok('truncate (force): the blob was rebuilt to its full size', (await fsp.stat(t)).size === origSize);
		ok('truncate (force): content restored byte-for-byte', await sha(t) === want);
		ok('truncate (force): original modification time restored', await stampedBack(t));
	}

	console.log('[4b] appended data — a grown blob is preserved by default (may be an edit heal cannot verify), truncated only with force');
	{
		const blobs = await walk(dataDir); const t = blobs[2].path; const want = await sha(t); const origSize = blobs[2].size;
		await fsp.appendFile(t, crypto.randomBytes(20 * 1024));
		const preVer = await Recovery.verify(v);
		ok('grow: verify flags the over-long blob (block CRCs alone would miss it)', preVer.clean === false && preVer.oversizeFiles >= 1);
		// DEFAULT: heal has no key to tell appended ciphertext from garbage, so it PRESERVES a grown blob and reports
		// it as changed rather than risk truncating away the user's appended data.
		const rDefault = await vdisk.heal(v);
		ok('grow (default): the grown blob was NOT truncated — appended bytes are preserved', (await fsp.stat(t)).size === origSize + 20 * 1024);
		ok('grow (default): no size repair was performed', (rDefault.repairedSize || 0) === 0);
		ok('grow (default): the change is reported so the user can update protection', rDefault.changedSkipped >= 1);
		// FORCE: the explicit override truncates it back, for when the user is certain the growth is corruption.
		const rForce = await vdisk.heal(v, { force: true });
		ok('grow (force): heal reported a size repair', rForce.repairedSize >= 1);
		ok('grow (force): the blob was truncated back to its recorded size', (await fsp.stat(t)).size === origSize);
		ok('grow (force): content unchanged byte-for-byte', await sha(t) === want);
		ok('grow (force): original modification time restored', await stampedBack(t));
	}

	console.log('[4c] an in-place EDIT (changed block + longer file) is preserved by default, reverted only with force');
	{
		const bb = (await walk(dataDir)).filter(f => f.size >= 50 * 1024); const t = bb[3].path; const orig = await fsp.readFile(t); const origSize = orig.length;
		const edited = Buffer.concat([crypto.randomBytes(origSize), crypto.randomBytes(8 * 1024)]); // the user rewrites the file: different content AND longer
		await fsp.writeFile(t, edited);
		const rDefault = await vdisk.heal(v);
		ok('edit (default): the edited blob was left exactly as written — never reverted to the stale parity', Buffer.compare(await fsp.readFile(t), edited) === 0);
		ok('edit (default): the edit is reported as a change, not silently repaired', rDefault.changedSkipped >= 1);
		await vdisk.heal(v, { force: true }); // the explicit override restores it from parity (and cleans up for the cases below)
		ok('edit (force): the blob was restored to its protected content and length', Buffer.compare(await fsp.readFile(t), orig) === 0);
	}

	console.log('[5] parity loss — the parity file itself is deleted and rebuilt from intact data');
	{
		await fsp.rm(path.join(Recovery.recoveryDir(v), 'parity.bin'));
		const heal = await vdisk.heal(v);
		ok('parity-loss: heal rebuilt parity blocks', heal.repairedParity >= 1 && heal.unrecoverableStripes === 0);
		ok('parity-loss: parity.bin was recreated', await fsp.stat(path.join(Recovery.recoveryDir(v), 'parity.bin')).then(() => true, () => false));
		const ver = await Recovery.verify(v);
		ok('parity-loss: block-level verify is clean afterward', ver.clean === true);
	}

	console.log('[6] a clean vault heals to a no-op');
	{ const r = await vdisk.heal(v); ok('clean: nothing repaired, nothing unrecoverable', r.healed === 0 && r.unrecoverableStripes === 0); }

	// User-data blobs only (skip the tiny metadata blobs) so a case targets a real file.
	const bigBlobs = async () => (await walk(dataDir)).filter(f => f.size >= 50 * 1024);

	console.log('[7] a heal restores only the files it repaired, never an undamaged file’s metadata');
	{
		// Legitimately re-timestamp a HEALTHY file, then damage a DIFFERENT file and heal. The repair must
		// fix the damaged file and re-stamp it to the snapshot, WITHOUT reverting the healthy file’s newer
		// mod-time — the staleness check ignores mtime by design, so the index’s stored time is intentionally
		// stale for an edited file, and clobbering it would be a surprising, wrong mutation.
		const blobs = await bigBlobs();
		const healthy = blobs[0].path, victim = blobs[1].path;
		const newTime = new Date('2030-01-01T00:00:00Z'); await fsp.utimes(healthy, newTime, newTime);
		const dmg = await fsp.readFile(victim); dmg[10] ^= 0xff; await fsp.writeFile(victim, dmg);
		await vdisk.heal(v);
		ok('scoped: the damaged file was repaired and re-stamped to the snapshot', await stampedBack(victim));
		ok('scoped: the untouched healthy file kept its newer mod-time', Math.abs((await fsp.stat(healthy)).mtime.getTime() - newTime.getTime()) < 2000);
	}

	console.log('[8] a write-protected blob is reported, not thrown, and heals once writable');
	if (typeof process.getuid === 'function' && process.getuid() === 0) {
		console.log('  (skipped — running as root bypasses file permissions)');
	} else {
		const t = (await bigBlobs())[1].path;
		const b = await fsp.readFile(t); b[10] ^= 0xff; await fsp.writeFile(t, b); // damage a block
		await fsp.chmod(t, 0o444);                                                 // make the repair write fail
		let threw = false, r = null;
		try { r = await vdisk.heal(v); } catch (_) { threw = true; }
		try { await fsp.chmod(t, 0o644); } catch (_) {}                            // ensure writable for cleanup
		ok('write-error: heal did not throw on an unwritable blob', threw === false);
		ok('write-error: the unwritable repair was counted, not swallowed', r && r.writeErrors >= 1);
		const r2 = await vdisk.heal(v);
		ok('write-error: a follow-up heal repairs it once writable', r2.writeErrors === 0 && (await Recovery.verify(v)).clean === true);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HEAL-CASE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-healcases-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
