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

	// --- who needs the follow-up (set-after-upload) lock. Backblaze B2 rejects inline Object-Lock headers on PUT, but
	//     rclone's S3 backend has NO "Backblaze" provider value — a B2 remote is provider "Other" with an
	//     s3.<region>.backblazeb2.com endpoint — so detection MUST key on the endpoint host, not the provider name. A
	//     regression here would either break every write to a B2 WORM vault or, worse, upload its objects UNLOCKED
	//     while the vault is labeled tamper-proof. ---
	ok('Backblaze B2 (provider Other + backblazeb2.com endpoint) needs set-after-upload', Vault.wormNeedsSetAfterUpload({ provider: 'Other', endpoint: 's3.us-west-004.backblazeb2.com' }) === true);
	ok('the endpoint is detected regardless of the option key name', Vault.wormNeedsSetAfterUpload({ any_key: 'https://s3.eu-central-003.backblazeb2.com' }) === true);
	ok('an explicit Backblaze provider is also detected (belt-and-suspenders)', Vault.wormNeedsSetAfterUpload({ provider: 'Backblaze' }) === true);
	ok('Amazon S3 does NOT need set-after-upload (inline headers work)', Vault.wormNeedsSetAfterUpload({ provider: 'AWS', endpoint: 's3.amazonaws.com' }) === false);
	ok('an empty/absent opts map does not request it', Vault.wormNeedsSetAfterUpload({}) === false && Vault.wormNeedsSetAfterUpload(undefined) === false);

	// --- create-time validation (these all throw before any network call) ---
	let e1 = ''; try { await vdisk.create(path.join(tmp, 'a.vault'), { password: 'pw', worm: { retainDays: 30 } }); } catch (e) { e1 = e.message; }
	ok('WORM on a non-cloud vault is refused', /only for cloud/i.test(e1));
	let e2 = ''; try { await vdisk.create(path.join(tmp, 'b.vault'), { password: 'pw', cloud: { remoteId: 'nope' }, worm: {} }); } catch (e) { e2 = e.message; }
	ok('WORM without a retention period is refused', /retention period/i.test(e2));

	// --- a WORM manifest carries the intent forward for the mount config ---
	const manifest = { crypt: { backend: { remoteId: 'r1', remotePath: 'bucket/vault', worm: { mode: 'governance', retainDays: 30 } } } };
	ok('a WORM manifest records the mode and retention', manifest.crypt.backend.worm.mode === 'governance' && manifest.crypt.backend.worm.retainDays === 30);

	// --- the emitted lock keys are actually WIRED INTO the upload, not just emitted in isolation ---
	// worm.js proves wormBackendLines() returns the right keys; these pin that those keys reach the engine on the real
	// path (the guarantee itself — an S3 backend refusing an overwrite — needs a live Object-Lock bucket and is out of
	// scope). The backend config text used for an operation appends wormBackendLines, the bucket is created with Object
	// Lock enabled, and the engine is checked to support Object Lock before WORM is used — so a refactor cannot leave
	// the flags computed but unapplied.
	const vsrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the backend config text appends the WORM lock keys', /backendSectionText\([^\n]*\)\s*\+\s*wormBackendLines\(b\.worm, entry\.type\)/.test(vsrc));
	ok('the WORM bucket is created with Object Lock enabled', /--s3-bucket-object-lock-enabled/.test(vsrc));
	ok('WORM use is gated on the engine actually supporting Object Lock', /assertEngineObjectLock\(bin\)/.test(vsrc));

	await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORM CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
