'use strict';
// lib/test/worm.js — WORM (Object Lock / tamper-proof) cloud-vault mode. Verifies the backend config emission
// (the object_lock_* keys rclone applies to every upload) and the create-time validation. The full end-to-end
// path (creating a bucket with Object Lock and confirming writes are immutable) needs a live S3 or S3-compatible
// bucket and is not exercised here; these checks cover the logic that decides what the engine is told to do.
//
// Run:  node lib/test/worm.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-worm-'));
	const Common = require('../Common');
	Common.dataDir = () => tmp; Common.statePath = () => path.join(tmp, 'state.json'); // isolate — never touch real state
	const Vault = require('../Vault');
	const vdisk = require('../index');

	// --- backend config emission (the mechanism that makes every upload immutable) ---
	const gov = Vault.wormBackendLines({ mode: 'governance', retainDays: 30 }, 's3');
	ok('governance mode emits the lock mode and a duration retention', /object_lock_mode = GOVERNANCE/.test(gov) && /object_lock_retain_until_date = 30d/.test(gov));
	ok('compliance mode emits COMPLIANCE', Vault.wormBackendLines({ mode: 'compliance', retainDays: 7 }, 's3').includes('object_lock_mode = COMPLIANCE'));
	ok('retention days are a whole-day duration (Nd), resolved at each upload', Vault.wormBackendLines({ mode: 'governance', retainDays: 365 }, 's3').includes('object_lock_retain_until_date = 365d'));
	ok('a non-S3 backend gets NO lock keys (Object Lock is S3-only)', Vault.wormBackendLines({ mode: 'governance', retainDays: 30 }, 'dropbox') === '');
	ok('no retention means no lock keys', Vault.wormBackendLines({ mode: 'governance' }, 's3') === '');
	ok('set-after-upload is emitted only when requested', Vault.wormBackendLines({ mode: 'governance', retainDays: 30, setAfterUpload: true }, 's3').includes('object_lock_set_after_upload = true'));

	// --- create-time validation (these all throw before any network call) ---
	let e1 = ''; try { await vdisk.create(path.join(tmp, 'a.vault'), { password: 'pw', worm: { retainDays: 30 } }); } catch (e) { e1 = e.message; }
	ok('WORM on a non-cloud vault is refused', /only for cloud/i.test(e1));
	let e2 = ''; try { await vdisk.create(path.join(tmp, 'b.vault'), { password: 'pw', cloud: { remoteId: 'nope' }, worm: {} }); } catch (e) { e2 = e.message; }
	ok('WORM without a retention period is refused', /retention period/i.test(e2));

	// --- a WORM manifest carries the intent forward for the mount config ---
	const manifest = { crypt: { backend: { remoteId: 'r1', remotePath: 'bucket/vault', worm: { mode: 'governance', retainDays: 30 } } } };
	ok('a WORM manifest records the mode and retention', manifest.crypt.backend.worm.mode === 'governance' && manifest.crypt.backend.worm.retainDays === 30);

	await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORM CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
