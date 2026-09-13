'use strict';
// lib/test/recoveryadaptive.js — self-heal must work at ANY vault size, not just up to a fixed byte ceiling. The parity
// engine keeps the block COUNT bounded (that bounds the index size and the encode memory) by scaling the block SIZE up
// for a large vault (Recovery.chooseBlockSize). This test forces that adaptive path on a SMALL vault by lowering the
// block-count ceiling (maxDataBlocks), then proves the whole cycle — protect, detect corruption, heal, and decrypt —
// works byte-for-byte at a larger, non-default block size. It also proves the honest, non-destructive decline when a
// vault is genuinely beyond what parity can cover (past maxDataBlocks even at the largest block).
//
// Run:  node lib/test/recoveryadaptive.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function flipByte(file, pos) { const b = await fsp.readFile(file); b[pos % b.length] ^= 0xff; await fsp.writeFile(file, b); }
async function firstBlob(dataDir) { // the largest ciphertext blob under data/, so a flipped byte lands in real content
	const out = [];
	async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else if (e.isFile()) out.push(p); } }
	await walk(dataDir);
	let best = null, bestSize = -1;
	for (const p of out) { const s = (await fsp.stat(p)).size; if (s > bestSize) { bestSize = s; best = p; } }
	return best;
}

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recadapt-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	// ~1.4 MB of data: a big file plus several small ones, so the block count is well above a low ceiling at 64 KiB.
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(1200 * 1024));
	for (let i = 0; i < 6; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(50 * 1024));
	const v = path.join(tmp, 'Adapt.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// --- adaptive path: a low block-count ceiling forces a LARGER block size than the 64 KiB default ---
	// At 64 KiB this vault is ~25 blocks; capping the count at 10 forces chooseBlockSize to step the block size up.
	const prot = await Recovery.protect(v, { tier: 'high', maxDataBlocks: 10 });
	ok('protect succeeds under a low block-count ceiling (adaptive)', prot && !prot.skipped && prot.dataBlocks >= 1);
	ok('the block count was kept within the ceiling', prot.dataBlocks <= 10);
	const idx = await Recovery.readIndex(v);
	ok('the index recorded a LARGER-than-default block size', idx.blockSize > Recovery.BLOCK_SIZE && (idx.blockSize & (idx.blockSize - 1)) === 0);
	ok('verify is clean right after an adaptive protect', (await Recovery.verify(v)).clean);

	// Corrupt a real ciphertext blob and confirm the adaptive-size engine detects and repairs it byte-for-byte.
	const blob = await firstBlob(path.join(v, 'data'));
	ok('found a ciphertext blob to corrupt', !!blob);
	const before = JSON.stringify(await vdisk.list(v, { password: 'pw' }));
	for (let i = 0; i < 3; i++) await flipByte(blob, 1000 + i * 4096); // damage a few blocks in the largest blob
	const vrep = await Recovery.verify(v);
	ok('adaptive verify detects the corruption', vrep.clean === false && vrep.damagedData >= 1);
	const h = await Recovery.heal(v);
	ok('adaptive heal repairs the damaged blocks', h.repairedData >= 1);
	ok('adaptive verify is clean after heal', (await Recovery.verify(v)).clean);
	ok('the vault still lists every file after an adaptive heal', JSON.stringify(await vdisk.list(v, { password: 'pw' })) === before);
	ok('deep verify: every file decrypts and authenticates after an adaptive heal', (await vdisk.verify(v, { password: 'pw', deep: true })).integrity === 'ok');

	// --- honest decline: a vault beyond maxDataBlocks even at the LARGEST block declines and keeps existing data ---
	// First, re-protecting THIS vault under an impossibly low ceiling declines and leaves the good data untouched.
	const decl = await Recovery.protect(v, { tier: 'high', maxDataBlocks: 1 });
	ok('protect declines honestly past the coverage limit (keep-last-good)', decl && decl.skipped === true && (decl.reason === 'too-large' || decl.reason === 'too-many-files'));
	ok('the previous adaptive recovery data survives the decline', await Recovery.hasRecovery(v));
	ok('verify is still clean after a declined re-protect (existing data untouched)', (await Recovery.verify(v)).clean);

	// The specific block-count decline (reason 'too-large'): a SINGLE file larger than maxDataBlocks * MAX_BLOCK_SIZE
	// cannot fit even at the largest block, so protect declines by block count (not file count). One 1.2 MB file with a
	// 1-block ceiling forces this: file count 1 passes the file cap, but ceil(1.2 MB / 1 MiB) = 2 blocks overflows it.
	const src2 = path.join(tmp, 'src2'); await fsp.mkdir(src2);
	await fsp.writeFile(path.join(src2, 'one.bin'), crypto.randomBytes(Math.floor(2.2 * 1024 * 1024))); // ~3 blocks at the 1 MiB cap
	const v2 = path.join(tmp, 'TooBig.vault');
	await vdisk.importFolder(v2, { password: 'pw', sourceDir: src2 });
	const decl2 = await Recovery.protect(v2, { tier: 'high', maxDataBlocks: 2 }); // file count 1 <= 2, but block count 3 > 2
	ok('a single oversize file declines by block count (reason too-large)', decl2 && decl2.skipped === true && decl2.reason === 'too-large');
	ok('nothing was protected on the declined oversize vault', !(await Recovery.hasRecovery(v2)));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-ADAPTIVE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-recadapt-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
