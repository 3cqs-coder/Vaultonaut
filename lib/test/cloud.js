'use strict';
// lib/test/cloud.js — cloud-backed vaults: a vault whose encrypted store lives on a remote BACKEND instead of
// a local data/ folder. Exercised over an rclone `alias` backend (a named remote wrapping a local directory),
// which uses the exact same two-section (backend + crypt) config a real cloud remote (s3/b2/webdav) uses, but
// needs no external service or credentials. Needs the engine; no mount driver required (create/list/snapshot/
// audit all run unmounted through the shared config path).
//
// Run:  node lib/test/cloud.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-cloud-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;                       // isolate settings (cloud remotes), cred key, ledger
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// A local directory stands in for the cloud, reached through an `alias` backend (persistent, no service).
	const cloudStore = path.join(tmp, 'cloudstore'); await fsp.mkdir(cloudStore, { recursive: true });
	const { id } = await vdisk.saveCloudRemote({ type: 'alias', label: 'test store', opts: { remote: cloudStore } });
	ok('a cloud remote is saved', !!id);
	ok('the saved cloud remote lists without secrets', (await vdisk.listCloudRemotes()).some(r => r.id === id && r.type === 'alias'));
	const reach = await vdisk.testCloudRemote(id, 'store');
	ok('the cloud remote is reachable', reach.ok === true);

	// Create a cloud-backed vault: manifest local, encrypted store on the remote at "store".
	const v = path.join(tmp, 'Cloud.vault');
	await vdisk.create(v, { password: 'pw1', cloud: { remoteId: id, remotePath: 'store' } });
	const manifest = JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
	ok('the vault records its cloud backend', manifest.crypt.backend && manifest.crypt.backend.remoteId === id);
	ok('a cloud vault keeps no local data/ folder', !fs.existsSync(path.join(v, 'data')));
	const remoteObjs = await fsp.readdir(path.join(cloudStore, 'store')).catch(() => []);
	ok('the encrypted store was initialized ON the remote', remoteObjs.length > 0);

	// The password opens the cloud store end-to-end (list decrypts names through the two-section config).
	let opens = true; try { await vdisk.list(v, { password: 'pw1' }); } catch (_) { opens = false; }
	ok('the password opens the cloud vault (read path works)', opens);

	// Write + read to the cloud store: a snapshot writes a signed baseline into the remote; audit verifies it.
	await vdisk.snapshot(v, { password: 'pw1' });
	const rep = await vdisk.audit(v, { password: 'pw1' });
	ok('a snapshot writes to the cloud store and the audit verifies it (write + read)', rep.clean === true);

	// Anti-clobber: refuse to create a second vault over a non-empty cloud location.
	let refusedClobber = false;
	try { await vdisk.create(path.join(tmp, 'Cloud2.vault'), { password: 'pw2', cloud: { remoteId: id, remotePath: 'store' } }); }
	catch (e) { refusedClobber = /already contains data/i.test(e.message); }
	ok('creating over a non-empty cloud location is refused', refusedClobber);

	// Rotation is not supported for cloud vaults (clear refusal, not a crash).
	let rotateRefused = false;
	try { await vdisk.rotate(v, { password: 'pw1' }); } catch (e) { rotateRefused = /not yet supported for cloud/i.test(e.message); }
	ok('key rotation is cleanly refused for a cloud vault', rotateRefused);

	// A cloud vault keeps only its manifest locally, so operations that copy/derive from the LOCAL cipher store
	// would silently produce keys-only output (a false "backup" / data-less shards). Each must refuse clearly.
	const refuses = async (label, fn) => { let msg = ''; try { await fn(); } catch (e) { msg = e.message || ''; } ok(label, /cloud provider/i.test(msg)); };
	await refuses('a local backup of a cloud vault is refused with guidance', () => vdisk.backup(v, path.join(tmp, 'bk')));
	await refuses('scheduling a cloud vault backup is refused', () => vdisk.setBackupSchedule(v, { mode: 'daily', dest: path.join(tmp, 'bk') }));
	await refuses('packing a cloud vault is refused', () => vdisk.pack(v, path.join(tmp, 'c' + require('../Brand').packExt)));
	await refuses('dispersing a cloud vault is refused', () => vdisk.disperse(v, { n: 3, k: 2, dests: [path.join(tmp, 's1'), path.join(tmp, 's2'), path.join(tmp, 's3')] }));
	await refuses('mirroring a cloud vault is refused', () => vdisk.setMirrorDest(v, path.join(tmp, 'mir')));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLOUD-VAULT CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
