'use strict';
// lib/test/notes.js — secure notes: encrypted notes/secrets kept as ordinary files inside a MOUNTED
// vault, so the engine encrypts them transparently and the plaintext never touches persistent disk. The
// vault must be open to read or write them. Needs the bundled engine; the mounted checks also need a
// mount driver and are skipped gracefully without one. Cleanup always unmounts through the product's own
// unmount (never a force-kill), per the never-wedge rule.
//
// Run:  node lib/test/notes.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the notes checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-notes-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(512));
	const v = path.join(tmp, 'Notes.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// Notes require an OPEN vault — refuse cleanly when it is not mounted.
	let refused = false;
	try { await vdisk.notesList(v); } catch (_) { refused = true; }
	ok('notes refuse when the vault is not open', refused);

	if (!d.driver.ok) { console.log('No mount driver — skipping the mounted-notes checks.'); await vdisk.removeKnownVault(v).catch(() => {}); return done(); }

	const cacheDir = path.join(tmp, 'cache');
	await vdisk.mount(v, { password: 'pw1', cacheDir });
	try {
		ok('a fresh vault has no notes', (await vdisk.notesList(v)).notes.length === 0);
		const s = await vdisk.noteSave(v, { title: 'Wifi', body: 'ssid: home\npw: hunter2unique' });
		ok('saving a note returns an id', !!s.id);
		const list = await vdisk.notesList(v);
		ok('the note appears in the list', list.notes.length === 1 && list.notes[0].title === 'Wifi');
		ok('the note body round-trips', (await vdisk.noteGet(v, s.id)).body.includes('hunter2unique'));
		await vdisk.noteSave(v, { id: s.id, title: 'Wifi', body: 'updatedbodymarker' });
		ok('editing keeps one note and updates the body', (await vdisk.notesList(v)).notes.length === 1 && (await vdisk.noteGet(v, s.id)).body === 'updatedbodymarker');

		// The note must be stored ENCRYPTED — its plaintext must not appear anywhere in the vault's cipher dir.
		let leaked = false;
		const walk = async (dir) => { for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) await walk(p); else { const b = await fsp.readFile(p); if (b.includes(Buffer.from('updatedbodymarker')) || b.includes(Buffer.from('hunter2unique'))) leaked = true; } } };
		try { await walk(path.join(v, 'data')); } catch (_) {}
		ok('the note is stored encrypted (plaintext not on disk)', !leaked);

		await vdisk.noteDelete(v, s.id);
		ok('deleting removes the note', (await vdisk.notesList(v)).notes.length === 0);

		let bad = false;
		try { await vdisk.noteGet(v, '../../etc/passwd'); } catch (_) { bad = true; }
		ok('a path-traversal id is rejected', bad);
	} finally {
		await vdisk.unmount(v, {}).catch(() => {}); // always release cleanly through the product's own unmount
	}
	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTES CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
