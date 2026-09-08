'use strict';
// lib/test/deepbaseline.js — a deep (content-hash) baseline must SURVIVE an unmount cycle. The clean-
// unmount auto-refresh used to rewrite the baseline size-only, erasing the per-file content hashes that
// are the only thing catching a same-size content substitution. The fix preserves the baseline's depth,
// so a vault the user deep-snapshotted keeps accurate content hashes across mount/unmount. Needs the
// engine; the mount cycle needs a driver and is skipped without one. Cleanup unmounts via the product.
//
// Run:  node lib/test/deepbaseline.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-deepbase-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4096));
	const v = path.join(tmp, 'Deep.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// A deep snapshot records per-file content hashes.
	await vdisk.snapshot(v, { password: 'pw1', deep: true });
	ok('a deep snapshot marks the baseline deep', (await Vault.readManifest(v)).snapshot.deep === true);

	if (!d.driver.ok) { console.log('No mount driver — skipping the unmount-cycle check.'); await vdisk.removeKnownVault(v).catch(() => {}); return done(); }

	// A mount/unmount cycle triggers the clean-unmount auto-refresh. The baseline must STAY deep.
	const cacheDir = path.join(tmp, 'cache');
	await vdisk.mount(v, { password: 'pw1', cacheDir });
	await vdisk.unmount(v, {});
	// Give the fire-and-forget finish a moment to settle, then re-read.
	await new Promise(r => setTimeout(r, 500));
	const after = await Vault.readManifest(v);
	ok('the baseline is STILL deep after an unmount cycle (evidence not erased)', after.snapshot.deep === true);
	ok('the baseline still has a recorded root', !!after.snapshot.root);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DEEP-BASELINE CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
