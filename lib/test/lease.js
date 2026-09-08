'use strict';
// lib/test/lease.js — the cross-machine write lease (advisory). A vault mirrored to a shared
// destination refuses a second machine's writable mount while one machine holds it, but allows a
// read-only or forced mount, treats an old lease as abandoned, and releases cleanly. Exercised
// against a local folder destination (no mount driver needed) by driving the lease helpers directly
// and simulating "another machine" by writing the lease file at the destination.
//
// Run:  node lib/test/lease.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const threw = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-lease-'));
	workspace = tmp;

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.bin'), crypto.randomBytes(120 * 1024));
	const v = path.join(tmp, 'Shared.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const dest = path.join(tmp, 'dest');
	await vdisk.setMirrorDest(v, dest);
	await vdisk.syncMirror(v, { prime: true });
	const leaseFile = path.join(dest, 'Shared.vault', '.vaultlease.json');
	const putForeign = (sinceMs) => fsp.writeFile(leaseFile, JSON.stringify({ holder: 'other-machine-id', name: 'OtherPC', since: new Date(sinceMs).toISOString() }));

	console.log('[claim + status]');
	let st = await vdisk.mirrorLeaseStatus(v);
	ok('a fresh mirror has no lease held', st.configured === true && st.held === false);
	await vdisk.claimLeaseForMount(v, {}); // as if mounting for writing here
	st = await vdisk.mirrorLeaseStatus(v);
	ok('claiming records this machine as the holder', st.held === true && st.mine === true);

	console.log('[another machine holds it]');
	await putForeign(Date.now()); // a fresh lease from a different machine
	st = await vdisk.mirrorLeaseStatus(v);
	ok('status shows it held by another machine', st.held === true && st.mine === false && st.holder === 'OtherPC');
	const e = await threw(() => vdisk.claimLeaseForMount(v, {}));
	ok('a writable mount is refused while another machine holds it', e && e.locked === true);
	ok('the refusal names the other machine and offers options', /OtherPC/.test(e.message) && /read-only|force/i.test(e.message));

	console.log('[read-only and force override]');
	await putForeign(Date.now());
	ok('a read-only mount is allowed (it cannot conflict)', (await threw(() => vdisk.claimLeaseForMount(v, { readOnly: true }))) === null);
	await putForeign(Date.now());
	ok('a forced mount is allowed and takes the lease', (await threw(() => vdisk.claimLeaseForMount(v, { force: true }))) === null);
	ok('after forcing, this machine holds the lease', (await vdisk.mirrorLeaseStatus(v)).mine === true);

	console.log('[abandoned lease self-clears]');
	await putForeign(Date.now() - 13 * 60 * 60 * 1000); // older than the 12h stale window
	st = await vdisk.mirrorLeaseStatus(v);
	ok('an old lease is reported stale, not active', st.held === false && st.stale === true);
	ok('a stale lease does not block a normal mount', (await threw(() => vdisk.claimLeaseForMount(v, {}))) === null);

	console.log('[heartbeat: precise liveness via a short per-record TTL]');
	await vdisk.refreshLease(v); // as a long-running owner would, every few minutes
	let hs = await vdisk.mirrorLeaseStatus(v);
	ok('a heartbeated lease is held by us', hs.held === true && hs.mine === true);
	// A short-TTL lease from another machine that has gone quiet (older than its own 10-min TTL) is
	// stale fast — no 12-hour wait — even though a long-TTL lease of the same age would still be active.
	await fsp.writeFile(leaseFile, JSON.stringify({ v: 1, holder: 'other', name: 'OtherPC', since: new Date(Date.now() - 15 * 60 * 1000).toISOString(), ttlMs: 10 * 60 * 1000 }));
	hs = await vdisk.mirrorLeaseStatus(v);
	ok('a quiet short-TTL (heartbeated) lease is stale within its TTL', hs.held === false && hs.stale === true);
	await fsp.writeFile(leaseFile, JSON.stringify({ v: 1, holder: 'other', name: 'OtherPC', since: new Date(Date.now() - 15 * 60 * 1000).toISOString(), ttlMs: 12 * 60 * 60 * 1000 }));
	ok('a long-TTL (CLI) lease of the same age is still active', (await vdisk.mirrorLeaseStatus(v)).held === true);
	await vdisk.claimLeaseForMount(v, { force: true }); // retake it so the release step below applies to us

	console.log('[release]');
	await vdisk.releaseLease(v);
	ok('releasing clears the lease so another machine is free to take it', (await vdisk.mirrorLeaseStatus(v)).held === false);

	console.log('[lease never enters the vault]');
	ok('the lease file lives only at the destination, never in the local vault', !fs.existsSync(path.join(v, '.vaultlease.json')));
	await fsp.writeFile(leaseFile, JSON.stringify({ holder: 'x', name: 'X', since: new Date().toISOString() }));
	await vdisk.syncMirror(v); // a normal sync must not pull the lease into the vault (it is filtered out)
	ok('a sync never pulls the lease file into the vault', !fs.existsSync(path.join(v, '.vaultlease.json')));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LEASE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	try { for (const kv of await vdisk.listKnownVaults()) if ((kv.path || kv).includes('vdisk-lease-')) await vdisk.removeKnownVault(kv.path || kv); } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
}
main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
