'use strict';
// lib/test/ramcache-winsweep.js — the Windows RAM-disk crash-sweep. A Windows RAM disk is an ImDisk unit at a
// drive letter, so a crash between allocating it and recording its handle would leak locked physical memory
// until reboot. Provisioning drops a marker file recording the letter; the next sweep frees any orphaned marker
// with the same `imdisk -D` release, and leaves an in-use or just-provisioned one. The imdisk command is mocked
// and the platform is forced to win32, so the reclaim logic runs on any host.
//
// Run:  node lib/test/ramcache-winsweep.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
const originalPlatform = process.platform;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-winsweep-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	const Rclone = require('../Rclone');
	const calls = [];
	Rclone.exec = async (cmd, args) => { calls.push(cmd + ' ' + args.join(' ')); return { status: 0, stdout: '', stderr: '' }; };
	Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
	const RamCache = require('../RamCache');

	const markerDir = path.join(dataDir, 'ramdisk-pending');
	await fsp.mkdir(markerDir, { recursive: true });
	const old = Date.now() - 5 * 60 * 1000; // well past the grace window
	await fsp.writeFile(path.join(markerDir, 'R.json'), JSON.stringify({ device: 'R:', dir: 'R:\\', at: old }));   // orphaned, not in use
	await fsp.writeFile(path.join(markerDir, 'S.json'), JSON.stringify({ device: 'S:', dir: 'S:\\', at: old }));   // in use
	await fsp.writeFile(path.join(markerDir, 'T.json'), JSON.stringify({ device: 'T:', dir: 'T:\\', at: Date.now() })); // just provisioned

	await RamCache.sweep(['S:\\']); // S is the active mount

	ok('an orphaned RAM disk is freed with the same imdisk -D release', calls.includes('imdisk -D -m R:'));
	ok('an in-use RAM disk is not freed', !calls.includes('imdisk -D -m S:'));
	ok('a just-provisioned RAM disk is not freed (grace window protects a concurrent mount)', !calls.includes('imdisk -D -m T:'));
	ok('the orphaned marker is removed after freeing', !fs.existsSync(path.join(markerDir, 'R.json')));
	ok('the in-use marker is left in place', fs.existsSync(path.join(markerDir, 'S.json')));
	ok('the fresh marker is left in place', fs.existsSync(path.join(markerDir, 'T.json')));

	// A malformed marker is discarded, never acted on. Start from a clean marker dir so only it is present.
	await fsp.rm(markerDir, { recursive: true, force: true });
	await fsp.mkdir(markerDir, { recursive: true });
	await fsp.writeFile(path.join(markerDir, 'bad.json'), 'not json');
	calls.length = 0;
	await RamCache.sweep([]);
	ok('a malformed marker is cleaned up and never triggers a release', !fs.existsSync(path.join(markerDir, 'bad.json')) && calls.length === 0);

	return done();
}

function done() {
	Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WIN-SWEEP CHECKS PASSED'));
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true }); console.error(e); if (tmp) fs.rmSync(tmp, { recursive: true, force: true }); process.exit(1); });
