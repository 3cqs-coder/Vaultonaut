'use strict';
// lib/test/pollreaddedup.js — the web UI polls /api/state every few seconds, and each poll reads the control
// files (state.json, settings.json) that live in the data directory. With --data-dir on a network or removable
// mount that wedges, an un-deduped read would start a fresh hanging read per caller and per poll, stacking until
// the libuv threadpool is exhausted — a process-wide freeze the "never freeze / hangs must fail fast" invariant
// forbids. The read-only settings and state readers therefore share ONE in-flight read per file, so a wedged data
// dir pins at most one threadpool thread no matter how many callers or polls pile up. This test proves that the
// de-dup collapses concurrent reads into a single filesystem read (and that the mutation path stays un-deduped so
// its read-modify-write always sees the latest content).
//
// Run:  node lib/test/pollreaddedup.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const Common = require('../Common');
const Vault = require('../Vault');
const State = require('../State');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-polldedup-'));
	Common.setDataDir(tmp); // a fresh data dir, so no memo from earlier tests is warm

	// Count and slow every capped read so many concurrent callers genuinely overlap on one pending read.
	const realCapped = Common.readFileCapped;
	let reads = 0;
	Common.readFileCapped = function (p, max, enc) { reads++; return new Promise((res, rej) => setTimeout(() => realCapped(p, max, enc).then(res, rej), 40)); };

	try {
		// --- settings: many concurrent getSettings() share ONE read ---
		await fsp.writeFile(path.join(tmp, 'settings.json'), JSON.stringify({ autoLockMinutes: 15 }), 'utf8');
		reads = 0;
		const settingsResults = await Promise.all(Array.from({ length: 25 }, () => Vault.getSettings()));
		ok('25 concurrent getSettings() collapse to a single filesystem read', reads === 1);
		ok('every concurrent getSettings() returns the same value', settingsResults.every(s => s && s.autoLockMinutes === 15));

		// --- state: many concurrent read-only reads share ONE read ---
		await State.addVault(path.join(tmp, 'One.vault')); // seed a state file
		reads = 0;
		const stateResults = await Promise.all(Array.from({ length: 25 }, () => State.readState()));
		ok('25 concurrent read-only readState() collapse to a single filesystem read', reads === 1);
		ok('every concurrent readState() returns the seeded vault', stateResults.every(s => Array.isArray(s.vaults) && s.vaults.length === 1));

		// The mutation path must NOT share the read-only in-flight read: two mutations in flight each read fresh so
		// neither builds on a stale snapshot. addVault(repair=true) reads under its lock; firing two adds and seeing
		// BOTH land proves the mutation read is not being served a pre-write deduped snapshot.
		await Promise.all([State.addVault(path.join(tmp, 'Two.vault')), State.addVault(path.join(tmp, 'Three.vault'))]);
		const after = await State.listVaults();
		ok('concurrent mutations both persist (mutation path reads fresh, not deduped)', after.length === 3);
	} finally {
		Common.readFileCapped = realCapped;
		try { await fsp.rm(tmp, { recursive: true, force: true }); } catch (_) {}
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL POLL-READ-DEDUP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
