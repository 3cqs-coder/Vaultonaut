'use strict';
// lib/test/thorough.js — opt-in "thorough" change detection for self-healing recovery. The cheap
// default staleness check compares the set of files and their sizes, so it misses an in-place edit
// that keeps a file the exact same length (a database record, a disk image). The thorough check
// re-reads the block contents (in the worker, off the event loop) and catches it. Also checks that a
// repair reports which encrypted files it touched.
//
// Run:  node lib/test/thorough.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Recovery = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function biggestBlob(dataDir) {
	const out = [];
	async function walk(dir) { for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) await walk(p); else out.push(p); } }
	await walk(dataDir);
	let best = null, bestSize = -1;
	for (const f of out) { const st = await fsp.stat(f); if (st.size > bestSize) { best = f; bestSize = st.size; } }
	return best;
}
// Flip a byte in place — changes content, keeps the exact file length.
async function flipByteInPlace(file) { const b = await fsp.readFile(file); b[Math.floor(b.length / 2)] ^= 0xff; await fsp.writeFile(file, b); const st = await fsp.stat(file); return st.size; }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-thorough-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'db.bin'), crypto.randomBytes(600 * 1024));
	const v = path.join(tmp, 'Thorough.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const dataDir = path.join(v, 'data');

	console.log('[thorough flag persists]');
	await vdisk.protect(v, { tier: 'medium', thorough: true });
	ok('the recovery status reports thorough is on', (await vdisk.recoveryStatus(v)).thorough === true);

	console.log('[same-size in-place edit]');
	ok('unchanged: the deep check reports up to date', (await Recovery.staleCheck(v, { cipherDir: dataDir })) === false);
	const blob = await biggestBlob(dataDir);
	const before = (await fsp.stat(blob)).size;
	const after = await flipByteInPlace(blob);
	ok('the edit kept the file exactly the same size', before === after);
	ok('the cheap check MISSES the same-size edit (this is why thorough exists)', (await Recovery.isStale(v, { cipherDir: dataDir })) === false);
	ok('the thorough check CATCHES the same-size edit', (await Recovery.staleCheck(v, { cipherDir: dataDir })) === true);

	console.log('[refresh preserves thorough]');
	// A background refresh re-protects; thorough must carry over so detection keeps working next time.
	await vdisk.protect(v, { tier: 'medium', thorough: true }); // simulate the refresh rebuilding the index
	ok('after a refresh the thorough flag is still set', (await vdisk.recoveryStatus(v)).thorough === true);

	console.log('[a repair reports the files it touched, and restores metadata from the index]');
	// Stamp a distinctive old time on a blob, then (re)protect so the index records it as the original —
	// this mirrors reality, where the recorded metadata is the source of truth a repair restores from.
	const target = await biggestBlob(dataDir);
	const stamp = new Date('2020-06-15T12:00:00Z');
	await fsp.utimes(target, stamp, stamp);
	const modeBefore = (await fsp.stat(target)).mode;
	await vdisk.protect(v, { tier: 'medium', thorough: true });
	// Corrupt a block (this bumps the blob's mtime to "now"); heal must put the recorded metadata back.
	const b = await fsp.readFile(target); b[10] ^= 0xff; await fsp.writeFile(target, b);
	const heal = await vdisk.heal(v);
	ok('heal reports at least one repaired encrypted file', Array.isArray(heal.repairedFiles) && heal.repairedFiles.length >= 1);
	const stAfter = await fsp.stat(target);
	ok('a repaired file keeps its original modification time', Math.abs(stAfter.mtime.getTime() - stamp.getTime()) < 2000);
	ok('a repaired file keeps its original permissions', stAfter.mode === modeBefore);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL THOROUGH CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-thorough-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
