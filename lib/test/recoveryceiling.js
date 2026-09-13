'use strict';
// lib/test/recoveryceiling.js — the parity self-heal must stay bounded for a very large vault. The recovery index
// holds one CRC record per 64 KiB block, so both the index's size and the memory the encode builds grow with the
// vault's data. Above a block-count ceiling (MAX_DATA_BLOCKS) protect must DECLINE — rather than hold gigabytes of
// working memory or write an index larger than readIndex will load back — and it must leave any EXISTING recovery
// data untouched (keep-last-good), the same discipline the content-search indexer uses. This test drives the real
// protect path with a deliberately tiny ceiling (threaded through as maxDataBlocks) so it is deterministic without
// a multi-hundred-GB vault, and confirms the decline is honest and non-destructive.
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

	// BLOCK-count decline: a ceiling of 40 blocks sits above the vault's handful of cipher files (so the file-count
	// ceiling does not trip) but well below its ~80 blocks, so protect declines on block count specifically.
	const declined = await Recovery.protect(v, { tier: 'low', maxDataBlocks: 40 });
	ok('protect declines when the vault exceeds the block ceiling', declined && declined.skipped === true);
	ok('the decline reports the too-large reason and the counts', declined.reason === 'too-large' && declined.dataBlocks > declined.maxDataBlocks && declined.maxDataBlocks === 40);
	ok('the decline carries a plain-language message', typeof declined.message === 'string' && /too large/i.test(declined.message));

	// Keep-last-good: the existing recovery data must be byte-for-byte untouched (same version and self-hash), and
	// the vault must still verify clean — a decline must never strip or rewrite protection an earlier version earned.
	const idxAfter = await Recovery.readIndex(v);
	ok('the existing recovery index is untouched after the decline (same version)', idxAfter && idxAfter.version === idxBefore.version);
	ok('the existing recovery index is untouched after the decline (same self-hash)', idxAfter && idxAfter.indexHash === idxBefore.indexHash);
	ok('recovery is still present after the decline', await Recovery.hasRecovery(v));
	ok('verify is still clean after the decline', (await Recovery.verify(v)).clean);

	// A decline must NOT strip an existing signature. The exported protect returns on skip BEFORE its sign/remove
	// branch, so a pre-existing signature sidecar survives a decline untouched. Drop a sentinel at the primary sidecar
	// path, decline, and confirm it is still there (removeIndexSig would have deleted it).
	const sigSentinel = path.join(Recovery.recoveryDir(v), 'index.sig.json');
	await fsp.writeFile(sigSentinel, '{"sentinel":true}');
	await Recovery.protect(v, { tier: 'low', maxDataBlocks: 1 }); // declines
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

	// Drift guard: pin the default ceiling to its DOCUMENTED size. The README self-heal section promises "vaults up to
	// a few hundred gigabytes"; if MAX_DATA_BLOCKS were lowered, that claim (and the code comment) would silently become
	// false. Assert the exact value and that BLOCK_SIZE * MAX_DATA_BLOCKS lands in the documented ~200-300 GB band.
	ok('MAX_DATA_BLOCKS is pinned to its documented value', Recovery.MAX_DATA_BLOCKS === 4_000_000);
	const ceilingBytes = Recovery.BLOCK_SIZE * Recovery.MAX_DATA_BLOCKS;
	ok('the self-heal size ceiling is in the documented few-hundred-GB band', ceilingBytes >= 200 * 1024 ** 3 && ceilingBytes <= 300 * 1024 ** 3);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-CEILING CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if (kv.includes('vdisk-recoveryceiling-')) await vdisk.removeKnownVault(kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
