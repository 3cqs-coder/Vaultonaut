'use strict';
// lib/test/resilience.js — a vault that was NOT closed cleanly (a crash, a hard kill, or power loss
// while mounted) must not look like tampering the next time it is opened. This verifies the session
// marker: a read-write session records a signed, baseline-bound marker at mount and clears it on a
// clean unmount, so if the marker survives to the next mount the previous session was interrupted and
// its file changes are the owner's own writes — accepted into the baseline with a gentle notice —
// whereas the SAME changes with no live-session evidence are still reported as a change to investigate,
// and a SEALED vault is never softened. Driver-free: it drives the on-mount check directly (no FUSE).
//
// Run:  node lib/test/resilience.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Delete the largest encrypted blob in the vault's ciphertext store — a driver-free stand-in for "a
// user file changed through the (now-crashed) mount session", so the crypt listing loses one file.
async function removeBiggestBlob(dataDir) {
	const files = [];
	async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else files.push(p); } }
	await walk(dataDir);
	let best = null, bestSize = -1;
	for (const f of files) { const st = await fsp.stat(f); if (st.size > bestSize) { best = f; bestSize = st.size; } }
	if (best) await fsp.unlink(best);
	return best;
}

async function makeVault(tmp, label) {
	const src = path.join(tmp, label + '-src'); await fsp.mkdir(src, { recursive: true });
	// Three sizeable files: one is clearly the biggest so removeBiggestBlob targets user content, not a
	// small metadata blob, and two remain so the vault stays valid after one is removed.
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(400 * 1024));
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4 * 1024));
	await fsp.writeFile(path.join(src, 'b.txt'), crypto.randomBytes(4 * 1024));
	const v = path.join(tmp, label + '.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	return { v, dataDir: path.join(v, 'data') };
}

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-resilience-')); workspace = tmp;

	// ── Interrupted session: changes are accepted, not flagged ──────────────────────────────────
	console.log('[interrupted session — changes accepted, not flagged as tamper]');
	const A = await makeVault(tmp, 'Interrupted');
	// First on-mount check establishes the baseline AND writes the session marker (this is the "mount").
	const first = await vdisk.checkOnMount(A.v, 'pw');
	ok('a first open establishes a clean baseline (no warning)', first.warn === null && first.trusted === true);
	// The session writes a file, then the process is hard-killed: no clean unmount runs, so the marker
	// is left behind. Simulate exactly that: change the file set, then open again.
	await removeBiggestBlob(A.dataDir);
	const afterCrash = await vdisk.checkOnMount(A.v, 'pw');
	ok('after an interrupted session the change is classified as interrupted, not tamper', afterCrash.warn && afterCrash.warn.kind === 'interrupted');
	ok('the interrupted changes are accepted (session stays trusted)', afterCrash.trusted === true);
	ok('the interrupted change lists the affected file', (afterCrash.warn.removed.length + afterCrash.warn.added.length + afterCrash.warn.modified.length) >= 1);
	// Having been accepted, the next open is clean — the warning does not keep returning.
	const settled = await vdisk.checkOnMount(A.v, 'pw');
	ok('once accepted, the next open is clean (no repeated warning)', settled.warn === null && settled.trusted === true);

	// ── A change with NO live-session evidence is still reported ─────────────────────────────────
	console.log('[change with no session evidence — still reported]');
	const B = await makeVault(tmp, 'Offline');
	await vdisk.snapshot(B.v, { password: 'pw' }); // baseline via the manual path — no session marker written
	await removeBiggestBlob(B.dataDir);
	const offline = await vdisk.checkOnMount(B.v, 'pw');
	ok('a change with no session marker is reported as changed', offline.warn && offline.warn.kind === 'changed');
	ok('such a change is NOT trusted (baseline is not blessed)', offline.trusted === false);

	// ── A sealed vault is never softened, even with a live-session marker present ────────────────
	console.log('[sealed vault — tripwire holds regardless of an interrupted session]');
	const C = await makeVault(tmp, 'Sealed');
	await vdisk.seal(C.v, { password: 'pw' });        // a deliberate tripwire baseline
	await vdisk.checkOnMount(C.v, 'pw');              // clean open writes a marker bound to the sealed baseline
	await removeBiggestBlob(C.dataDir);
	const sealed = await vdisk.checkOnMount(C.v, 'pw');
	ok('a sealed vault reports a change even with a session marker present', sealed.warn && sealed.warn.kind !== 'interrupted');
	ok('a sealed vault is never auto-accepted (stays untrusted)', sealed.trusted === false);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RESILIENCE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-resilience-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
