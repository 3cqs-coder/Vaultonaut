'use strict';
// lib/test/mirrordeletionguard.js — the mirror's all-or-nothing source-loss guard. A two-way mirror reads a
// shrunken local vault as deletions and propagates them to the destination; with version history off, both copies
// then lose those files unrecoverably. The guard refuses a steady sync BEFORE bisync runs when the local copy has
// lost a suspicious fraction of its files since the last successful sync, so the destination stays a recovery
// point. This proves: an ordinary small deletion still propagates (no false alarm), and a mass loss is refused
// with the destination left completely intact.
//
// Run:  node lib/test/mirrordeletionguard.js   (needs the engine; local destination, no network)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
// Count the ciphertext FILES in a vault's data folder (names are encrypted, so we work by entry, not by name).
const dataFiles = (dir) => { try { return fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isFile()).map(e => e.name); } catch (_) { return []; } };
const dataCount = (dir) => dataFiles(dir).length;

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-mirrorguard-'));
	workspace = tmp;

	// A vault with many files, so the >50%-of-at-least-20 threshold applies.
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	for (let i = 0; i < 40; i++) await fsp.writeFile(path.join(src, 'f' + i + '.bin'), crypto.randomBytes(1024));
	const v = path.join(tmp, 'Guard.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const localData = path.join(v, 'data');
	const dest = path.join(tmp, 'dest');
	const destData = path.join(dest, 'Guard.vault', 'data');

	await vdisk.setMirrorDest(v, dest);
	await vdisk.syncMirror(v, { prime: true });
	const primed = dataCount(destData);
	ok('priming copied every file to the destination', primed >= 40 && dataCount(localData) === primed);

	// 1. An ordinary small deletion (2 files) must still propagate — the guard must not false-alarm.
	for (const f of dataFiles(localData).slice(0, 2)) { try { await fsp.rm(path.join(localData, f)); } catch (_) {} }
	await vdisk.syncMirrorIfConfigured(v);
	ok('a small local deletion still propagates to the destination', dataCount(destData) === primed - 2);

	// 2. A mass local loss (delete ~28 of the remaining files) must be REFUSED, destination untouched.
	const destAfterSmall = dataCount(destData);
	for (const f of dataFiles(localData).slice(0, 28)) { try { await fsp.rm(path.join(localData, f)); } catch (_) {} }
	let refused = false;
	try { await vdisk.syncMirrorIfConfigured(v); }
	catch (e) { refused = /mirror skipped/i.test(e.message); }
	ok('a mass local loss is refused before syncing', refused);
	ok('the destination is left completely intact after the refusal', dataCount(destData) === destAfterSmall);

	return done();
}

function done() {
	if (workspace) { try { fs.rmSync(workspace, { recursive: true, force: true }); } catch (_) {} }
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MIRROR-DELETION-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
