'use strict';
// lib/test/newlinenames.js — a filename containing a control character such as a newline is legal on Unix, and the
// listing and tamper paths parse the engine's line-oriented output by splitting on newlines. This would be a trap
// if a real newline reached that output — EXCEPT the engine encodes control characters in file names to their
// visible Unicode symbols (a newline becomes U+240A) in every listing, so a real newline never appears in a name.
// This test pins that safety end to end: such a file lists as ONE entry (never split into two), sits alongside
// ordinary files, and a deep snapshot + audit of the unchanged vault is clean — no false "a file was added,
// removed, or changed" from a mis-parsed name. It guards against a future engine or config change quietly removing
// that protection. Needs the bundled engine (no mount driver).
//
// Run:  node lib/test/newlinenames.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-nl-'));
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'appdata'); Common.statePath = () => path.join(tmp, 'appdata', 'state.json');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(src, 'normal.txt'), 'a');
	await fsp.writeFile(path.join(src, 'sub', 'deep.txt'), 'cc');
	let nlCreated = true;
	try { await fsp.writeFile(path.join(src, 'line1\nline2.txt'), 'bb'); } catch (_) { nlCreated = false; } // a legal Unix name with a newline
	if (!nlCreated) { console.log('  skip  (this filesystem rejected a newline in a filename)'); return done(); }

	const v = path.join(tmp, 'NL.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// The control-character file lists as exactly ONE entry that carries both halves of the name, never split into
	// a phantom "line1" plus a phantom "line2.txt". Its exact spelling is the engine's encoded form, so match on the
	// two literal halves rather than the raw newline.
	const listed = await vdisk.list(v, { password: 'pw1' });
	const nlEntries = listed.filter(n => n.startsWith('line1') && n.endsWith('line2.txt'));
	ok('a newline-named file lists as exactly one entry, not split into two', nlEntries.length === 1);
	ok('no phantom half-name entry is produced', !listed.includes('line1') && !listed.includes('line2.txt'));
	ok('ordinary files alongside it are still listed', listed.includes('normal.txt') && listed.includes('sub/deep.txt'));

	// A deep snapshot then a deep audit of the unchanged vault must be clean — a mis-parsed name would show up as a
	// phantom added/removed/changed file. Two rounds, to confirm the baseline and the live capture agree on it.
	await vdisk.snapshot(v, { password: 'pw1', deep: true });
	const a = await vdisk.audit(v, { password: 'pw1', deep: true });
	ok('a deep audit of an unchanged vault with a control-character name is clean', !!a && a.clean === true && a.tamper.length === 0);
	await vdisk.snapshot(v, { password: 'pw1', deep: true });
	const a2 = await vdisk.audit(v, { password: 'pw1', deep: true });
	ok('a second snapshot + audit round is still clean', !!a2 && a2.clean === true && a2.tamper.length === 0);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NEWLINE-NAME CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
