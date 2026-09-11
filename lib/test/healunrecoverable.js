'use strict';
// lib/test/healunrecoverable.js — self-heal must be HONEST about what it did, and a successful heal must leave the
// tamper check clean. Reed-Solomon recovery data only rebuilds a loss up to its redundancy budget, so:
//   Case 1 (loss within budget): heal fully rebuilds the file, reports nothing unrecoverable, and a deep audit is
//           CLEAN afterward — "if the heal fixes it, the tamper check no longer reports it".
//   Case 2 (loss beyond budget, e.g. a whole large file deleted): heal CANNOT rebuild it, so it must report the file
//           as unrecoverable (never count a still-broken file as repaired), and the audit must not read as clean.
// Needs the bundled engine and a mount driver: one mount+unmount computes the protected-metadata exclusion list that
// `protect` requires once a tamper baseline exists (the heal/audit themselves then run on the unmounted store).
//
// Run:  node lib/test/healunrecoverable.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function userBlobs(cipherDir) {
	const out = [];
	async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else { const size = (await fsp.stat(p)).size; if (size >= 30 * 1024) out.push({ p, size }); } } } // >=30KB skips the tool's own small metadata blobs
	await walk(cipherDir);
	return out;
}

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	if (!d.driver.ok) { console.log('No mount driver — skipping (one mount is needed to compute the protected-metadata list before protect).'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-healunrec-')); workspace = tmp;

	// ── Case 1: a small loss WITHIN the recovery budget heals fully and the audit is clean afterward. ──
	{
		const src = path.join(tmp, 'src1'); await fsp.mkdir(src);
		for (let i = 0; i < 14; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(48 * 1024)); // many similar files: any one is a small fraction
		const v = path.join(tmp, 'Recoverable.vault');
		await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
		await vdisk.mount(v, { password: 'pw' }); await vdisk.unmount(v, {}); // one mount computes the protected-metadata exclusion list protect needs
		await vdisk.snapshot(v, { password: 'pw', deep: true }); // the baseline the audit compares against
		await vdisk.protect(v, { tier: 'high' });                 // 15% budget; one of 14 files is ~7%, well within it
		const cipherDir = path.join(v, 'data');
		const one = (await userBlobs(cipherDir)).sort((a, b) => a.size - b.size)[0];
		await fsp.rm(one.p); // delete one file's ciphertext outright (a whole-file loss, but a small fraction)
		const h = await vdisk.heal(v);
		ok('case 1: heal reports nothing unrecoverable for a loss within budget', h.unrecoverable === 0 && (h.unrecoverableFiles || []).length === 0);
		ok('case 1: heal actually rebuilt data', h.repairedData > 0);
		const rep = await vdisk.audit(v, { password: 'pw', deep: true });
		ok('case 1: the deep audit is CLEAN after a successful heal (no damaged/removed)', rep.clean === true && (rep.damaged || []).length === 0 && rep.removed.length === 0);
		await vdisk.removeKnownVault(v).catch(() => {});
	}

	// ── Case 2: a loss BEYOND the budget (a large file that is most of the vault) cannot be rebuilt — report it. ──
	{
		const src = path.join(tmp, 'src2'); await fsp.mkdir(src);
		await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(320 * 1024)); // dominates the vault
		await fsp.writeFile(path.join(src, 'tiny1.bin'), crypto.randomBytes(8 * 1024));
		await fsp.writeFile(path.join(src, 'tiny2.bin'), crypto.randomBytes(8 * 1024));
		const v = path.join(tmp, 'Unrecoverable.vault');
		await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
		await vdisk.mount(v, { password: 'pw' }); await vdisk.unmount(v, {}); // one mount computes the protected-metadata exclusion list protect needs
		await vdisk.snapshot(v, { password: 'pw', deep: true });
		await vdisk.protect(v, { tier: 'medium' });
		const cipherDir = path.join(v, 'data');
		const big = (await userBlobs(cipherDir)).sort((a, b) => b.size - a.size)[0];
		await fsp.rm(big.p); // delete the dominant file — far more than the 10% budget can rebuild
		const h = await vdisk.heal(v);
		ok('case 2: heal reports the file it could NOT fully recover', h.unrecoverable >= 1 && (h.unrecoverableFiles || []).length >= 1);
		const rep = await vdisk.audit(v, { password: 'pw', deep: true });
		ok('case 2: the audit does not read as clean (the loss is still there)', rep.clean === false);
		ok('case 2: the audit surfaces the loss (removed or damaged), not a mysterious abort', (rep.removed.length + (rep.damaged || []).length) >= 1 && !rep.errors.some(e => /could not scan/i.test(e)));
		await vdisk.removeKnownVault(v).catch(() => {});
	}

	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HEAL-UNRECOVERABLE CHECKS PASSED'));
	return cleanup().then(() => process.exit(failures ? 1 : 0));
}
async function cleanup() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
