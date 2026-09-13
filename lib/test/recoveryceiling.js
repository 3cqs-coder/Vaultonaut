'use strict';
// lib/test/recoveryceiling.js — the parity self-heal must stay bounded for a very large vault WITHOUT capping the
// vault size it can protect. The recovery index holds one CRC record per block, so the index size and encode memory
// grow with the block COUNT, not the byte size. So the block SIZE adapts: a vault that would exceed the block-count
// ceiling (MAX_DATA_BLOCKS) at the default 64 KiB block is protected with a LARGER block instead, keeping the count
// bounded while covering far more data (up to MAX_DATA_BLOCKS * MAX_BLOCK_SIZE — multiple terabytes). Only past that
// does protect DECLINE, and a decline must leave any EXISTING recovery data untouched (keep-last-good). This test
// drives the real protect path with a deliberately tiny ceiling (threaded through as maxDataBlocks) so both the
// adaptation and the honest decline are deterministic without a multi-terabyte vault.
//
// Run:  node lib/test/recoveryceiling.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-recoveryceiling-'));
	workspace = tmp;

	// A vault holding ONE large file — many blocks, few files — so the BLOCK-count ceiling can be exercised
	// independently of the file-count ceiling below. 5 MiB is ~80 data blocks.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(5 * 1024 * 1024));
	const v = path.join(tmp, 'Ceiling.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Protect normally (the default ceiling is far above this vault) and capture the resulting index identity.
	const prot = await Recovery.protect(v, { tier: 'low' });
	ok('a normal protect under the ceiling builds recovery data', !prot.skipped && prot.dataBlocks > 1);
	const idxBefore = await Recovery.readIndex(v);
	ok('the recovery index is present and self-verifies after the normal protect', !!(idxBefore && idxBefore.indexHash));
	ok('verify is clean right after the normal protect', (await Recovery.verify(v)).clean);

	// BLOCK-count ADAPTATION: a ceiling of 40 blocks sits above the vault's handful of cipher files (so the file-count
	// ceiling does not trip) but below its ~80 blocks at 64 KiB — so instead of declining, protect steps the block size
	// up until the count fits. The vault stays fully protected, at a larger block size, with the count within the ceiling.
	const adapted = await Recovery.protect(v, { tier: 'low', maxDataBlocks: 40 });
	ok('protect ADAPTS (does not decline) when the vault would exceed the block ceiling at the default size', adapted && !adapted.skipped);
	ok('adaptation keeps the block count within the ceiling', adapted.dataBlocks <= 40);
	const idxAdapted = await Recovery.readIndex(v);
	ok('adaptation used a larger-than-default block size', idxAdapted.blockSize > Recovery.BLOCK_SIZE && idxAdapted.blockSize <= Recovery.MAX_BLOCK_SIZE);
	ok('verify is clean after the adaptive protect', (await Recovery.verify(v)).clean);

	// Genuine DECLINE: only past MAX_DATA_BLOCKS * MAX_BLOCK_SIZE — i.e. a single file too big to fit even at the largest
	// block. A ~2.2 MiB file with a 2-block ceiling forces this (file count 1 <= 2, but 3 blocks at the 1 MiB cap > 2).
	// A decline must leave any EXISTING recovery data byte-for-byte untouched (keep-last-good).
	const idxBeforeDecline = await Recovery.readIndex(v);
	// Exercise the decline against the existing vault by asking for a ceiling its block count cannot meet even at
	// MAX_BLOCK_SIZE. Its ~5 MiB of data needs >= 5 blocks at the 1 MiB cap, so a 4-block ceiling declines by block
	// count (file count is well under 4) while leaving the good index in place.
	const declined = await Recovery.protect(v, { tier: 'low', maxDataBlocks: 4 });
	ok('protect declines past the coverage limit (block count cannot fit even at the largest block)', declined && declined.skipped === true && declined.reason === 'too-large');
	ok('the decline reports the counts and a plain-language message', declined.dataBlocks > declined.maxDataBlocks && typeof declined.message === 'string' && /beyond the size|too large/i.test(declined.message));

	// Keep-last-good: the existing recovery data must be byte-for-byte untouched (same version and self-hash), and
	// the vault must still verify clean — a decline must never strip or rewrite protection an earlier version earned.
	const idxAfter = await Recovery.readIndex(v);
	ok('the existing recovery index is untouched after the decline (same version)', idxAfter && idxAfter.version === idxBeforeDecline.version);
	ok('the existing recovery index is untouched after the decline (same self-hash)', idxAfter && idxAfter.indexHash === idxBeforeDecline.indexHash);
	ok('recovery is still present after the decline', await Recovery.hasRecovery(v));
	ok('verify is still clean after the decline', (await Recovery.verify(v)).clean);

	// A decline must NOT strip an existing signature. The exported protect returns on skip BEFORE its sign/remove
	// branch, so a pre-existing signature sidecar survives a decline untouched. Drop a sentinel at the primary sidecar
	// path, decline, and confirm it is still there (removeIndexSig would have deleted it).
	const sigSentinel = path.join(Recovery.recoveryDir(v), 'index.sig.json');
	await fsp.writeFile(sigSentinel, '{"sentinel":true}');
	await Recovery.protect(v, { tier: 'low', maxDataBlocks: 4 }); // declines (see above)
	ok('a decline leaves an existing signature sidecar untouched (never strips the signature)', await fsp.readFile(sigSentinel, 'utf8').then((s) => s === '{"sentinel":true}', () => false));
	await fsp.rm(sigSentinel, { force: true });

	// A vault with MORE FILES than the ceiling also declines gracefully — the working set is bounded by file COUNT,
	// not only by block count, so millions of tiny/empty files can never grow the file list until the worker OOMs.
	const src2 = path.join(tmp, 'src2'); await fsp.mkdir(src2, { recursive: true });
	await fsp.writeFile(path.join(src2, 'a.txt'), 'one');
	await fsp.writeFile(path.join(src2, 'b.txt'), 'two');
	const v2 = path.join(tmp, 'Files.vault');
	await vdisk.importFolder(v2, { password: 'pw', sourceDir: src2 });
	const tooMany = await Recovery.protect(v2, { tier: 'low', maxDataBlocks: 1 }); // 2 files > 1-file ceiling
	ok('protect declines a vault with more files than the ceiling', tooMany && tooMany.skipped === true && tooMany.reason === 'too-many-files');
	ok('the too-many-files decline carries a plain-language message', typeof tooMany.message === 'string' && /too many files/i.test(tooMany.message));

	// The default ceiling is a real, sane bound (not accidentally zero/undefined) and comfortably larger than this vault.
	ok('a normal protect still succeeds after the decline (ceiling did not become sticky)', !(await Recovery.protect(v, { tier: 'low' })).skipped);

	// Drift guard: pin the block-count ceiling and the adaptive block-size cap, and confirm their PRODUCT — the actual
	// self-heal coverage with adaptive sizing — lands in the multi-terabyte range. If either constant were lowered, the
	// coverage would silently shrink; this keeps the code and the docs honest about how large a vault self-heal covers.
	ok('MAX_DATA_BLOCKS is pinned to its documented value', Recovery.MAX_DATA_BLOCKS === 4_000_000);
	ok('MAX_BLOCK_SIZE is pinned to its documented value', Recovery.MAX_BLOCK_SIZE === 1024 * 1024);
	const coverageBytes = Recovery.MAX_BLOCK_SIZE * Recovery.MAX_DATA_BLOCKS;
	ok('adaptive self-heal coverage is in the multi-terabyte range', coverageBytes >= 3 * 1024 ** 4 && coverageBytes <= 8 * 1024 ** 4);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-CEILING CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if (kv.includes('vdisk-recoveryceiling-')) await vdisk.removeKnownVault(kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
