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

	// A small vault with several data blocks (~300 KiB → well over one 64 KiB block).
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(300 * 1024));
	const v = path.join(tmp, 'Ceiling.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Protect normally (the default ceiling is far above this vault) and capture the resulting index identity.
	const prot = await Recovery.protect(v, { tier: 'low' });
	ok('a normal protect under the ceiling builds recovery data', !prot.skipped && prot.dataBlocks > 1);
	const idxBefore = await Recovery.readIndex(v);
	ok('the recovery index is present and self-verifies after the normal protect', !!(idxBefore && idxBefore.indexHash));
	ok('verify is clean right after the normal protect', (await Recovery.verify(v)).clean);

	// Now protect again with a ceiling of 1 block. The vault has more than one block, so protect must DECLINE.
	const declined = await Recovery.protect(v, { tier: 'low', maxDataBlocks: 1 });
	ok('protect declines when the vault exceeds the block ceiling', declined && declined.skipped === true);
	ok('the decline reports the too-large reason and the counts', declined.reason === 'too-large' && declined.dataBlocks > 1 && declined.maxDataBlocks === 1);
	ok('the decline carries a plain-language message', typeof declined.message === 'string' && /too large/i.test(declined.message));

	// Keep-last-good: the existing recovery data must be byte-for-byte untouched (same version and self-hash), and
	// the vault must still verify clean — a decline must never strip or rewrite protection an earlier version earned.
	const idxAfter = await Recovery.readIndex(v);
	ok('the existing recovery index is untouched after the decline (same version)', idxAfter && idxAfter.version === idxBefore.version);
	ok('the existing recovery index is untouched after the decline (same self-hash)', idxAfter && idxAfter.indexHash === idxBefore.indexHash);
	ok('recovery is still present after the decline', await Recovery.hasRecovery(v));
	ok('verify is still clean after the decline', (await Recovery.verify(v)).clean);

	// The default ceiling is a real, sane bound (not accidentally zero/undefined) and comfortably larger than this vault.
	// (Sourced indirectly: a normal protect above succeeded, proving the default admits a small vault.)
	ok('a normal protect still succeeds after the decline (ceiling did not become sticky)', !(await Recovery.protect(v, { tier: 'low' })).skipped);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-CEILING CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if (kv.includes('vdisk-recoveryceiling-')) await vdisk.removeKnownVault(kv); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
