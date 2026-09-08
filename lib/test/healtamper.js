'use strict';
// lib/test/healtamper.js — a self-heal must not break the tamper baseline. The tamper snapshot is
// itself an encrypted blob in the vault, and it is rewritten every time the baseline refreshes; if the
// recovery parity covered it, a heal would find it "changed" and revert it to a stale version, which
// then fails the tamper check with "the snapshot record does not match". The fix leaves the tool's own
// changing metadata blobs out of the recovery parity. This verifies: the excluded names are cached on
// mount, a heal after a baseline change does NOT touch them (tamper stays clean), and a heal still
// repairs real corruption of a user file. Needs the bundled engine and a mount driver.
//
// Run:  node lib/test/healtamper.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function blobSizes(dir) {
	const out = [];
	async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else { const st = await fsp.stat(p); out.push({ path: p, size: st.size }); } } }
	await walk(dir);
	return out;
}
async function biggestBlob(dir) { return (await blobSizes(dir)).sort((a, b) => b.size - a.size)[0].path; }
// The smallest USER-DATA blob: skip the tool's own small metadata blobs (snapshot/session/canary, all a
// few KB) by size so a deletion test targets a real file, and pick a small one so it stays within budget.
async function smallUserBlob(dir) { const u = (await blobSizes(dir)).filter(f => f.size >= 30 * 1024).sort((a, b) => a.size - b.size); return u.length ? u[0].path : null; }

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	if (!d.driver.ok) { console.log('No mount driver — skipping (this test needs a mount to cache the excluded names).'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-healtamper-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.bin'), crypto.randomBytes(300 * 1024));
	await fsp.writeFile(path.join(src, 'b.bin'), crypto.randomBytes(300 * 1024));
	// Several more small files so parity has headroom: recovering a fully DELETED file is only possible
	// when the lost fraction stays within the redundancy budget (a vault of two files cannot survive losing
	// one — that is 50% loss). These give the deletion case below enough surviving data to rebuild from.
	for (let i = 0; i < 10; i++) await fsp.writeFile(path.join(src, 'c' + i + '.bin'), crypto.randomBytes(48 * 1024));
	const v = path.join(tmp, 'HealTamper.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Mount once so the tool computes and caches the excluded metadata blob names. The cache is a per-machine
	// sidecar under the app data dir (keyed by the vault path), NOT the signed manifest, so a mount never rewrites
	// the manifest and cannot clobber a concurrent key change.
	await vdisk.mount(v, { password: 'pw' }); await vdisk.unmount(v, {});
	const Common = require('../Common');
	const exclHash = crypto.createHash('sha256').update(path.resolve(v)).digest('hex').slice(0, 16);
	let cachedNames = [];
	try { cachedNames = JSON.parse(await fsp.readFile(path.join(Common.dataDir(), 'recovery-exclude', exclHash + '.json'), 'utf8')).names; } catch (_) {}
	ok('the changing metadata blob names are cached on mount (in the sidecar, not the manifest)', Array.isArray(cachedNames) && cachedNames.length >= 2);
	ok('the mount did not write the metadata cache into the signed manifest', !(await vdisk.readManifest(v)).recoveryExclude);

	await vdisk.snapshot(v, { password: 'pw' });      // baseline
	await vdisk.protect(v, { tier: 'high' });          // recovery parity (excludes the metadata)
	ok('the vault audits clean after snapshot + protect', (await vdisk.audit(v, { password: 'pw' })).clean === true);

	await vdisk.snapshot(v, { password: 'pw' });       // rewrite the baseline snapshot blob
	const h = await vdisk.heal(v);                     // a heal must not revert it
	ok('a heal after a baseline change does not touch the metadata (0 repaired)', (h.repairedFiles ? h.repairedFiles.length : 0) === 0);
	const a = await vdisk.audit(v, { password: 'pw' });
	ok('the tamper check is still clean after the heal (baseline intact)', a.clean === true && a.tamper.length === 0);

	// Recovery must still repair a genuine corruption of a user file — and the tamper baseline must remain
	// clean afterward, because the repair restores the blob to its exact original bytes.
	const blob = await biggestBlob(path.join(v, 'data'));
	const buf = await fsp.readFile(blob); buf[Math.floor(buf.length / 2)] ^= 0xff; await fsp.writeFile(blob, buf);
	const h2 = await vdisk.heal(v);
	ok('a heal still repairs real corruption of a user file', Array.isArray(h2.repairedFiles) && h2.repairedFiles.length >= 1);
	const a2 = await vdisk.audit(v, { password: 'pw' });
	ok('the tamper check is clean after repairing corruption', a2.clean === true && a2.tamper.length === 0);

	// The reported real-world scenario: DELETE a user file from the vault, then heal. Recovery recreates
	// the blob from parity byte-for-byte (and restores its original metadata), so the vault matches its
	// baseline again and the tamper check stays clean — no false "a file was removed/added".
	const victim = await smallUserBlob(path.join(v, 'data'));
	await fsp.rm(victim);
	const h3 = await vdisk.heal(v);
	ok('a heal recreates a deleted user file', Array.isArray(h3.repairedFiles) && h3.repairedFiles.length >= 1);
	ok('recreating the deleted file did not exceed the redundancy budget', h3.unrecoverableStripes === 0);
	const a3 = await vdisk.audit(v, { password: 'pw' });
	ok('the tamper check is clean after a deleted file is healed back', a3.clean === true && a3.tamper.length === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HEAL-TAMPER CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-healtamper-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
