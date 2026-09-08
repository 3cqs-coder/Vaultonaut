'use strict';
// lib/test/concurrency.js — the cross-process manifest lock. Every key/membership change re-reads and rewrites
// the whole manifest, so two changes that overlap must not clobber each other (a revoked key resurrected, or an
// added key lost). withVaultLock serializes them and each re-reads inside the lock, so overlapping changes all
// land. This test runs the changes concurrently in one process; the same file lock also coordinates separate
// processes (a CLI command and the background service).
//
// Run:  node lib/test/concurrency.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-conc-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;                       // isolate the lock files (they live under the app data dir)
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'doc.txt'), 'hello');
	const v = path.join(tmp, 'C.vault');
	await vdisk.importFolder(v, { password: 'rw-pass', sourceDir: src });
	const before = (await vdisk.listKeys(v)).slots.length; // the original slot

	// Three key additions at once. Without the lock they read the same manifest and the last write wins, so only
	// one of the three added keys survives. With the lock they serialize and each re-reads, so all three land.
	const results = await Promise.allSettled([
		vdisk.addRecoveryKey(v, { password: 'rw-pass', label: 'Key A' }),
		vdisk.addRecoveryKey(v, { password: 'rw-pass', label: 'Key B' }),
		vdisk.addRecoveryKey(v, { password: 'rw-pass', label: 'Key C' }),
	]);
	const added = results.filter(r => r.status === 'fulfilled').length;
	ok('all three concurrent key additions succeeded', added === 3);
	const after = await vdisk.listKeys(v);
	ok('every concurrently-added key persisted (none clobbered)', after.slots.length === before + 3);
	ok('each added key is present by its label', ['Key A', 'Key B', 'Key C'].every(l => after.slots.some(s => s.label === l)));

	// Each recovery key must actually open the vault — proof its slot was written intact, not half-overwritten.
	const keys = results.filter(r => r.status === 'fulfilled').map(r => r.value.recoveryKey);
	let allOpen = true;
	for (const rk of keys) { try { const st = await vdisk.verify(v, { password: rk, deep: false }); if (st.password !== 'ok') allOpen = false; } catch (_) { allOpen = false; } }
	ok('every concurrently-added recovery key still opens the vault', allOpen);

	// A stale lock left by a crashed process (a dead pid on this machine) must be reclaimed, never a permanent wedge.
	const crypto = require('crypto');
	const h = crypto.createHash('sha256').update(path.resolve(v)).digest('hex').slice(0, 16); // must match resolveVaultDir (path.resolve, not realpath)
	const lockDir = path.join(dataDir, 'locks');
	await fsp.mkdir(lockDir, { recursive: true });
	// A dead pid: 2^31-1 is never a live process. Same host, so liveness (not the TTL) governs — it is reclaimable at once.
	await fsp.writeFile(path.join(lockDir, h + '.lock'), JSON.stringify({ pid: 2147483646, host: os.hostname(), at: Date.now() }));
	let reclaimed = false;
	try { await vdisk.addRecoveryKey(v, { password: 'rw-pass', label: 'Key D' }); reclaimed = true; } catch (_) {}
	ok('a lock from a crashed (dead-pid) holder on this machine is reclaimed, not a permanent wedge', reclaimed);

	// PID reuse: a stale lease whose pid is now a LIVE unrelated process (our own pid) must still be reclaimed via
	// the timestamp backstop, so a reused pid can never wedge key/membership changes forever.
	await fsp.writeFile(path.join(lockDir, h + '.lock'), JSON.stringify({ pid: process.pid, host: os.hostname(), at: Date.now() - 60 * 1000 }));
	let reusedReclaimed = false;
	try { await vdisk.addRecoveryKey(v, { password: 'rw-pass', label: 'Key E' }); reusedReclaimed = true; } catch (_) {}
	ok('a stale lease held by a reused (live) pid is reclaimed via the timestamp backstop, never a permanent wedge', reusedReclaimed);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CONCURRENCY CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
