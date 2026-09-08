'use strict';
// lib/test/pollmanifest.js — readManifestForPoll is the stat-keyed manifest read the dashboard poll uses so it does
// not re-read and re-parse every vault's manifest every few seconds. The risk of any cache is staleness, so this
// pins the two properties that make it safe: it returns the SAME parsed manifest object while the file is unchanged
// (a cache hit, not a re-read), and it returns a FRESH, correct manifest after the file actually changes (a real
// password change rewrites it), so the poll never shows stale vault state. Needs the bundled engine.
//
// Run:  node lib/test/pollmanifest.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-pollm-'));
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'd'); Common.statePath = () => path.join(tmp, 'd', 'state.json');
	const Vault = require('../Vault');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true }); await fsp.writeFile(path.join(src, 'a.txt'), 'x');
	const v = path.join(tmp, 'V.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// A poll read matches the authoritative read, and a repeat while the file is unchanged returns the SAME object.
	const authoritative = await Vault.readManifest(v);
	const p1 = await Vault.readManifestForPoll(v);
	ok('the poll read matches the authoritative manifest', p1 && p1.format === authoritative.format && !!p1.crypt);
	const p2 = await Vault.readManifestForPoll(v);
	ok('an unchanged manifest is served from cache (same object, no re-read)', p2 === p1);

	// After the manifest actually changes, the poll read must return a FRESH, correct manifest — not the stale cache.
	await new Promise(r => setTimeout(r, 1100)); // clear any coarse mtime granularity so the change is detectable
	await vdisk.changePassword(v, { oldPassword: 'pw', newPassword: 'pw2' }); // rewrites the manifest
	const p3 = await Vault.readManifestForPoll(v);
	ok('a changed manifest invalidates the cache (fresh object)', p3 !== p1);
	ok('the fresh manifest is still valid', !!p3 && !!p3.crypt && typeof p3.format === 'number');
	ok('the vault opens with the new password (caching did not corrupt the manifest)', await vdisk.list(v, { password: 'pw2' }).then(() => true, () => false));

	// A missing primary manifest must not serve a stale cached copy — it falls back to the authoritative read.
	await fsp.rm(path.join(v, 'vault.json'), { force: true });
	const p4 = await Vault.readManifestForPoll(v); // readManifest self-heals from the backup
	ok('a missing primary still yields a valid manifest via the authoritative fallback', !!p4 && !!p4.crypt);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL POLL-MANIFEST CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
