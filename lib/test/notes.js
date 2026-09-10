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
	const NOTES_SUBDIR = '.' + require('../Brand').slug + '-notes';
	const TITLE = 'WifiSecretTitleXYZ', BODY = 'ssid: home\npw: hunter2uniqueSECRET';
	let mp = (await vdisk.mount(v, { password: 'pw1', cacheDir })).mountpoint;
	let s;
	try {
		ok('a fresh vault has no notes', (await vdisk.notesList(v)).notes.length === 0);
		s = await vdisk.noteSave(v, { title: TITLE, body: BODY });
		ok('saving a note returns an id', !!s.id);
		const list = await vdisk.notesList(v);
		ok('the note appears in the list with its (decrypted) title', list.notes.length === 1 && list.notes[0].title === TITLE);
		const got = await vdisk.noteGet(v, s.id);
		ok('the note title and body decrypt correctly', got.title === TITLE && got.body === BODY);
		ok('the note carries createdAt and updatedAt', !!got.createdAt && !!got.updatedAt);
		ok('the list carries the (decrypted) timestamps', !!list.notes[0].createdAt && !!list.notes[0].updatedAt);

		// APP-LAYER ENCRYPTION: even the note file INSIDE THE OPEN MOUNT is ciphertext — its title, body AND timestamps
		// must NOT appear in the note JSON, and the record must be the encrypted v2 shape (sealed t/b fields). This is
		// stronger than the engine's at-rest encryption: another process reading the open mount cannot read the note.
		const rawInMount = await fsp.readFile(path.join(mp, NOTES_SUBDIR, s.id + '.json'), 'utf8');
		const recJson = JSON.parse(rawInMount);
		ok('the in-mount note file is the encrypted v2 shape (sealed metadata + body)', recJson.v === 2 && !!recJson.t && !!recJson.b && recJson.title === undefined && recJson.body === undefined);
		ok('no plaintext title, body, or timestamp in the file inside the open mount', !rawInMount.includes(TITLE) && !rawInMount.includes('hunter2uniqueSECRET') && recJson.updatedAt === undefined && recJson.createdAt === undefined && !/\d{4}-\d{2}-\d{2}T\d\d:\d\d/.test(rawInMount));

		// VIEW WITHOUT MOUNTING: the read-only viewer (in-app or phone) opens notes with NO mount. Prove the session
		// layer hands it the notes key and the notes-folder name, and that this key opens THIS note's sealed fields
		// with the exact byte layout the browser's Web Crypto uses — iv is the first 12 bytes, then ciphertext with
		// the tag appended. This is the server half of the no-mount notes path; it must match the mounted read above.
		const Mobile = require('../Mobile');
		const sess = await Mobile.start(v, { password: 'pw1', local: true }); // local: an ephemeral grant, no access-roster entry
		const red = Mobile.redeem(sess.code);
		ok('the viewer session carries the notes key and the notes-folder name', !!red.notesKey && red.notesDir === NOTES_SUBDIR);
		const gcmOpen = (sealedB64, nckB64) => { const b = Buffer.from(sealedB64, 'base64'); const iv = b.subarray(0, 12), tag = b.subarray(b.length - 16), ct = b.subarray(12, b.length - 16); const dc = crypto.createDecipheriv('aes-256-gcm', Buffer.from(nckB64, 'base64'), iv); dc.setAuthTag(tag); return Buffer.concat([dc.update(ct), dc.final()]).toString('utf8'); };
		ok('the viewer key decrypts the note title without mounting', JSON.parse(gcmOpen(recJson.t, red.notesKey)).title === TITLE);
		ok('the viewer key decrypts the note body without mounting', gcmOpen(recJson.b, red.notesKey) === BODY);
		Mobile.stop(sess.sessionId);

		// createdAt is set once and PRESERVED across edits; updatedAt advances each save.
		await new Promise(r => setTimeout(r, 15));
		const edited = await vdisk.noteSave(v, { id: s.id, title: TITLE, body: BODY + ' more' });
		ok('editing preserves createdAt and advances updatedAt', edited.createdAt === got.createdAt && edited.updatedAt > got.updatedAt);

		// The wrapped notes key lives in the manifest (so it survives password changes), never the note file.
		const man = JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));
		ok('the manifest holds the wrapped notes key', !!(man.crypt && man.crypt.notesKey));

		// The engine's at-rest layer still holds too: the plaintext is nowhere in the cipher dir either.
		let leaked = false;
		const walk = async (dir) => { for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) await walk(p); else { const b = await fsp.readFile(p); if (b.includes(Buffer.from('hunter2uniqueSECRET')) || b.includes(Buffer.from(TITLE))) leaked = true; } } };
		try { await walk(path.join(v, 'data')); } catch (_) {}
		ok('the note plaintext is not on persistent disk (cipher dir)', !leaked);

		let bad = false;
		try { await vdisk.noteGet(v, '../../etc/passwd'); } catch (_) { bad = true; }
		ok('a path-traversal id is rejected', bad);
	} finally {
		await vdisk.unmount(v, {}).catch(() => {}); // always release cleanly through the product's own unmount
	}

	// ROTATION SURVIVAL: a key rotation changes the vault master, but the wrapped notes key is re-wrapped, so the note
	// stays readable afterward. Rotate requires the vault unmounted, so this runs after the unmount above.
	if (s) {
		await vdisk.rotate(v, { password: 'pw1', reason: 'test' });
		mp = (await vdisk.mount(v, { password: 'pw1', cacheDir })).mountpoint;
		try {
			const afterRotate = await vdisk.noteGet(v, s.id);
			ok('a note is still readable after a key rotation (notes key re-wrapped)', afterRotate.title === TITLE && afterRotate.body === BODY + ' more' && !!afterRotate.createdAt);
		} finally { await vdisk.unmount(v, {}).catch(() => {}); }
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
