'use strict';
// lib/test/sidecarreaders.js — the vault's list-shaped sidecars (the share roster, the succession log, the
// attestation chain) are read through one shared, corrupt-tolerant reader. Their contract is that an unreadable,
// corrupt, or over-large sidecar yields the default EMPTY shape rather than throwing — an unlocked best-effort read
// must never turn a damaged sidecar into a failed operation (the write paths, under the vault lock, are what move a
// bad file aside). This pins that contract so the shared reader can never regress into throwing. Uses the public
// listShares path over a real vault; needs the bundled engine only to create the vault.
//
// Run:  node lib/test/sidecarreaders.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-sidecar-')); workspace = tmp;
	const v = path.join(tmp, 'Side.vault');
	await vdisk.create(v, { password: 'pw' });
	const sharesFile = path.join(v, 'shares.json');

	// A brand-new vault has no roster yet: the reader returns the default empty shape, not an error.
	const fresh = await vdisk.listShares(v);
	ok('a vault with no roster reads as an empty share list (no throw)', fresh && Array.isArray(fresh.shares) && fresh.shares.length === 0);

	// A corrupt roster (invalid JSON) must also read as the default empty shape, never throw.
	await fsp.writeFile(sharesFile, '{ this is not valid json ][', 'utf8');
	let corruptThrew = false, corrupt = null;
	try { corrupt = await vdisk.listShares(v); } catch (_) { corruptThrew = true; }
	ok('a corrupt roster reads as an empty share list, not an error', !corruptThrew && corrupt && Array.isArray(corrupt.shares) && corrupt.shares.length === 0);

	// A truncated / half-written roster (valid-looking prefix) must be tolerated the same way.
	await fsp.writeFile(sharesFile, '{"version":1,"shares":[{"sid":"x"', 'utf8');
	let truncThrew = false, trunc = null;
	try { trunc = await vdisk.listShares(v); } catch (_) { truncThrew = true; }
	ok('a truncated roster reads as an empty share list, not an error', !truncThrew && trunc && Array.isArray(trunc.shares) && trunc.shares.length === 0);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SIDECAR-READER CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); }).finally(async () => {
	// Vault.create auto-registers the vault in the known-vaults list, so deregister the throwaway one (and remove the
	// temp folder) to avoid leaving a phantom entry that later tests or the UI would see.
	try { await vdisk.removeKnownVault(path.join(workspace, 'Side.vault')); } catch (_) {}
	if (workspace) { try { await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {} }
});
