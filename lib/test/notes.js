'use strict';
// lib/test/notes.js — secure notes: encrypted notes/secrets kept as ordinary encrypted files inside a vault. Each
// note is read and written DIRECTLY to the store through the crypt engine (not the mount's write-back cache), so a
// note is durable the instant it is saved on every platform and survives a key rotation — a mount can lose an atomic
// temp-then-rename save if it is unmounted before its cache flushes. The vault must still be OPEN (the crypt config
// comes from the mount session), so the plaintext never touches persistent disk. Needs the bundled engine; the checks
// that require an open vault also need a mount driver and are skipped gracefully without one. Cleanup always unmounts
// through the product's own unmount (never a force-kill), per the never-wedge rule.
//
// Run:  node lib/test/notes.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const notesRaw = require('../Vault')._notesRaw; // store-direct read/write of a note's sealed record (no mount), for inspection and crafting legacy/newer records

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	// Source-level guard (runs even without a mount driver): a note WRITE (save or delete) changes the vault, so it must
	// be refused on a READ-ONLY mount. rclone crypt uses one data key for read and write, so a store-direct note write
	// would otherwise succeed and bypass the read-only promise the UI makes to a read-only-key holder. Lock that the two
	// writers both go through the read-only check and that the mounted session records its read-only capability.
	const fs = require('fs');
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the mounted session records whether the credential is read-only', /sessionKeys\.set\([^)]*readOnly: readOnlyCred/.test(vaultSrc));
	ok('the note-write guard refuses a read-only session', /function assertNotesWritable\([\s\S]*?sk\.readOnly[\s\S]*?throw new Error/.test(vaultSrc));
	ok('both noteSave and noteDelete call the read-only write guard', (vaultSrc.match(/await assertNotesWritable\(vaultDir\)/g) || []).length >= 2);

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the notes checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-notes-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(512));
	const v = path.join(tmp, 'Notes.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// Notes require an OPEN vault — every entry point refuses cleanly when it is not mounted (a locked vault has no
	// session, so there is no notes engine and no notes key). None may hang or crash; each must throw a clear error.
	let refused = false;
	try { await vdisk.notesList(v); } catch (_) { refused = true; }
	ok('notes refuse when the vault is not open', refused);
	let refusedSave = false, refusedGet = false, refusedDelete = false;
	try { await vdisk.noteSave(v, { title: 'x', note: 'y' }); } catch (_) { refusedSave = true; }
	try { await vdisk.noteGet(v, 'a'.repeat(24)); } catch (_) { refusedGet = true; }
	try { await vdisk.noteDelete(v, 'a'.repeat(24)); } catch (_) { refusedDelete = true; }
	ok('save, get, and delete all refuse when the vault is not open', refusedSave && refusedGet && refusedDelete);

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
		ok('the note title and text decrypt correctly', got.title === TITLE && got.note === BODY);
		ok('a plain note reads back as type "note"', got.type === 'note');
		ok('the note carries createdAt and updatedAt', !!got.createdAt && !!got.updatedAt);
		ok('the list carries the type and the (decrypted) timestamps', list.notes[0].type === 'note' && !!list.notes[0].createdAt && !!list.notes[0].updatedAt);

		// TYPED ITEM: a login with typed fields (username, password, a TOTP secret, a website) plus a custom field. The
		// field labels AND values are encrypted, and they round-trip through noteGet. The type reaches the list.
		const TOTP_SECRET = 'JBSWY3DPEHPK3PXP', SECRETPW = 'corge-Login-Pw-9Z', CUSTOMVAL = 'custom-field-secret-value';
		const login = await vdisk.noteSave(v, { title: 'GitHub', type: 'login', note: 'work account', fields: [
			{ id: 'u1', kind: 'text', label: 'Username', value: 'octocat' },
			{ id: 'p1', kind: 'password', label: 'Password', value: SECRETPW },
			{ id: 't1', kind: 'totp', label: 'One-time code', value: 'otpauth://totp/GitHub:octocat?secret=' + TOTP_SECRET + '&issuer=GitHub' },
			{ id: 'w1', kind: 'url', label: 'Website', value: 'https://github.com' },
			{ id: 'c1', kind: 'secret', label: 'Backup code', value: CUSTOMVAL } ] });
		ok('saving a typed item returns its id and type', !!login.id && login.type === 'login');
		const loginGot = await vdisk.noteGet(v, login.id);
		ok('the typed item round-trips its type, note, and field values', loginGot.type === 'login' && loginGot.note === 'work account'
			&& loginGot.fields.length === 5
			&& loginGot.fields[1].kind === 'password' && loginGot.fields[1].value === SECRETPW
			&& loginGot.fields[2].kind === 'totp' && loginGot.fields[2].value.indexOf(TOTP_SECRET) >= 0
			&& loginGot.fields[4].value === CUSTOMVAL);
		ok('the typed item shows its type in the list', (await vdisk.notesList(v)).notes.some(n => n.id === login.id && n.type === 'login'));

		// APP-LAYER ENCRYPTION: the stored item record is itself ciphertext — its title, type, field labels, field
		// values, note, AND timestamps must NOT appear in the JSON, and the record must be the encrypted v3 shape
		// (sealed t/b). Read straight from the store through the crypt remote with NO mount (the same durable path the
		// product uses), so this proves the property that actually persists — not a transient mount-cache view.
		const recLogin = await notesRaw.read(v, login.id);
		const rawLogin = JSON.stringify(recLogin);
		ok('the stored item record is the encrypted v3 shape (sealed metadata + content)', recLogin.v === 3 && !!recLogin.t && !!recLogin.b && recLogin.title === undefined && recLogin.fields === undefined && recLogin.type === undefined);
		ok('no plaintext label, value, secret, or timestamp in the item record', !rawLogin.includes('Password') && !rawLogin.includes(SECRETPW) && !rawLogin.includes(CUSTOMVAL) && !rawLogin.includes(TOTP_SECRET) && !rawLogin.includes('github.com') && !rawLogin.includes('login') && !/\d{4}-\d{2}-\d{2}T\d\d:\d\d/.test(rawLogin));

		const recJson = await notesRaw.read(v, s.id);
		const rawInStore = JSON.stringify(recJson);
		ok('the plain note is also the encrypted v3 shape', recJson.v === 3 && !!recJson.t && !!recJson.b && recJson.title === undefined && recJson.body === undefined);
		ok('no plaintext title, text, or timestamp in the plain note record', !rawInStore.includes(TITLE) && !rawInStore.includes('hunter2uniqueSECRET') && recJson.updatedAt === undefined && recJson.createdAt === undefined && !/\d{4}-\d{2}-\d{2}T\d\d:\d\d/.test(rawInStore));

		// VIEW WITHOUT MOUNTING: the read-only viewer (in-app or phone) opens items with NO mount. Prove the session
		// layer hands it the notes key and the notes-folder name, and that this key opens THIS item's sealed content
		// with the exact byte layout the browser's Web Crypto uses — iv is the first 12 bytes, then ciphertext with
		// the tag appended. This is the server half of the no-mount path; it must match the mounted read above.
		const Mobile = require('../Mobile');
		const sess = await Mobile.start(v, { password: 'pw1', local: true }); // local: an ephemeral grant, no access-roster entry
		const red = Mobile.redeem(sess.code);
		ok('the viewer session carries the notes key and the notes-folder name', !!red.notesKey && red.notesDir === NOTES_SUBDIR);
		const gcmOpen = (sealedB64, nckB64) => { const b = Buffer.from(sealedB64, 'base64'); const iv = b.subarray(0, 12), tag = b.subarray(b.length - 16), ct = b.subarray(12, b.length - 16); const dc = crypto.createDecipheriv('aes-256-gcm', Buffer.from(nckB64, 'base64'), iv); dc.setAuthTag(tag); return Buffer.concat([dc.update(ct), dc.final()]).toString('utf8'); };
		ok('the viewer key decrypts the note title and type without mounting', JSON.parse(gcmOpen(recJson.t, red.notesKey)).title === TITLE && JSON.parse(gcmOpen(recJson.t, red.notesKey)).type === 'note');
		ok('the viewer key decrypts the plain note text without mounting', JSON.parse(gcmOpen(recJson.b, red.notesKey)).note === BODY);
		const loginContent = JSON.parse(gcmOpen(recLogin.b, red.notesKey));
		ok('the viewer key decrypts the typed item fields without mounting', loginContent.fields[1].value === SECRETPW && loginContent.fields[4].value === CUSTOMVAL);
		Mobile.stop(sess.sessionId);

		// HIDDEN FROM FILE LISTINGS: the notes live in an in-mount folder that is real vault content (so it stays in
		// the tamper baseline), but it is the tool's own store, not files the user put there. A "list a vault" and a
		// name search must never surface the notes folder or its item files — a user browsing or searching their files
		// should see only their own. (The content indexer skips it too; that is covered by the search suite.)
		const listed = await vdisk.list(v, { password: 'pw1' });
		ok('list() hides the notes folder and its item files', !listed.some(p => p === NOTES_SUBDIR || p.startsWith(NOTES_SUBDIR + '/') || p.includes(login.id)));
		const searched = await vdisk.searchNames(v, { query: 'notes' });
		ok('name search never surfaces the notes folder', !searched.matches.some(p => p.startsWith(NOTES_SUBDIR)));

		// PASSWORD HEALTH: two logins that share the same weak password must be reported as BOTH reused and weak,
		// while the strong unique GitHub password stays clean. Run locally (breach:false) so the test needs no network.
		// The report must expose only ids/titles and issue flags — never any password value.
		await vdisk.noteSave(v, { title: 'Site A', type: 'login', fields: [{ id: 'p', kind: 'password', label: 'Password', value: 'password1' }] });
		await vdisk.noteSave(v, { title: 'Site B', type: 'login', fields: [{ id: 'p', kind: 'password', label: 'Password', value: 'password1' }] });
		const health = await vdisk.notesHealth(v, { breach: false });
		ok('the health scan flags the shared weak password as reused and weak on both items', health.counts.reused >= 2 && health.counts.weak >= 2 && health.items.filter(x => x.issues.reused && x.issues.weak).length >= 2);
		ok('the strong unique GitHub password is not flagged', !health.items.some(x => x.id === login.id));
		ok('the health report never includes any password value', !JSON.stringify(health).includes('password1') && !JSON.stringify(health).includes(SECRETPW));
		ok('the health scan reports it ran without a breach check', health.breachChecked === false);

		// BREACH PATH (stubbed, no network): an "exposed" password is flagged and sorted most-severe; a failed lookup
		// marks the scan incomplete rather than reporting a false "safe".
		const PwnedCheck = require('../PwnedCheck');
		const realCount = PwnedCheck.count;
		PwnedCheck.count = async (val) => (String(val).indexOf('pwned') >= 0 ? 5 : 0);
		await vdisk.noteSave(v, { title: 'Breached', type: 'login', fields: [{ id: 'p', kind: 'password', label: 'Password', value: 'pwned-Unique-Str0ng-x8!' }] });
		const bh = await vdisk.notesHealth(v, { breach: true });
		ok('an exposed password is flagged and sorted most-severe first', bh.breachChecked === true && bh.counts.exposed >= 1 && bh.items[0].issues.exposed === true && bh.breachIncomplete === false);
		PwnedCheck.count = async (val, opts) => { if (opts && opts.onFail) opts.onFail(); return 0; };
		const bi = await vdisk.notesHealth(v, { breach: true });
		ok('a failed breach lookup marks the scan incomplete, not a false safe', bi.breachIncomplete === true && bi.counts.exposed === 0);
		PwnedCheck.count = realCount;

		// v2 READ SHIM: a legacy v2 record (body sealed as a bare string, no type) must still read back as a plain
		// note — never lost. Craft one with the vault's own notes key and confirm noteGet surfaces its text.
		const Kdf = require('../Kdf');
		const v2id = 'aaaaaaaaaaaaaaaaaaaaaaaa';
		await notesRaw.write(v, v2id, { v: 2, id: v2id, t: recJson.t, b: Kdf.wrapSecret('legacy v2 body text', Buffer.from(red.notesKey, 'base64')) });
		const v2got = await vdisk.noteGet(v, v2id);
		ok('a legacy v2 note reads back as a plain note (text preserved, no fields)', v2got.note === 'legacy v2 body text' && v2got.fields.length === 0);
		await vdisk.noteDelete(v, v2id).catch(() => {});

		// FORWARD-REFUSE: a record written by a NEWER format is refused on BOTH edit and read (so its extra data is
		// never dropped or mis-rendered), and it still LISTS (flagged) rather than vanishing.
		const v99id = 'ffffffffffffffffffffffff';
		await notesRaw.write(v, v99id, { v: 99, id: v99id, t: recJson.t, b: recJson.b });
		let refusedNewer = false, refusedRead = false;
		try { await vdisk.noteSave(v, { id: v99id, title: 'x' }); } catch (_) { refusedNewer = true; }
		try { await vdisk.noteGet(v, v99id); } catch (_) { refusedRead = true; }
		ok('a newer-format item is refused on both edit and read rather than overwritten or mis-read', refusedNewer && refusedRead);
		ok('a newer-format item still appears in the list (flagged), not dropped', (await vdisk.notesList(v)).notes.some(n => n.id === v99id));
		await vdisk.noteDelete(v, v99id).catch(() => {});

		// createdAt is set once and PRESERVED across edits; updatedAt advances each save.
		await new Promise(r => setTimeout(r, 15));
		const edited = await vdisk.noteSave(v, { id: s.id, title: TITLE, note: BODY + ' more' });
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

		// SIZE CAP: an item over the 1 MB content limit is refused, and nothing partial is left behind (the store still
		// lists only the notes already there, with no orphaned record for the rejected save).
		const beforeBig = (await vdisk.notesList(v)).notes.length;
		let tooBig = false;
		try { await vdisk.noteSave(v, { title: 'huge', note: 'A'.repeat(1024 * 1024 + 32) }); } catch (_) { tooBig = true; }
		const afterBig = (await vdisk.notesList(v)).notes.length;
		ok('an item over the 1 MB limit is refused and leaves nothing behind', tooBig && afterBig === beforeBig);

		// CONCURRENCY: many saves to DISTINCT ids fired at once must all persist intact — writes are serialized per
		// vault, so none can clobber another on the shared temp. Save N in parallel, then confirm all N read back.
		const CONC = 12;
		const ids = await Promise.all(Array.from({ length: CONC }, (_, i) => vdisk.noteSave(v, { title: 'conc-' + i, note: 'body-' + i }).then(r => r.id)));
		const reads = await Promise.all(ids.map((id, i) => vdisk.noteGet(v, id).then(g => g.title === 'conc-' + i && g.note === 'body-' + i)));
		ok('many concurrent saves to distinct ids all persist intact', ids.length === CONC && reads.every(Boolean));
		for (const id of ids) await vdisk.noteDelete(v, id).catch(() => {}); // clean up the concurrency fixtures
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
			ok('a note is still readable after a key rotation (notes key re-wrapped)', afterRotate.title === TITLE && afterRotate.note === BODY + ' more' && !!afterRotate.createdAt);
		} finally { await vdisk.unmount(v, {}).catch(() => {}); }
	}

	// DURABLE DELETE ACROSS UNMOUNT: a delete goes straight to the store, so it must stay deleted after the vault is
	// closed and reopened (a mount-filesystem delete could be lost to the write-back cache and resurrect the note on
	// remount). Save a throwaway note, delete it, unmount, remount, and confirm it is gone from get AND from the list.
	{
		mp = (await vdisk.mount(v, { password: 'pw1', cacheDir })).mountpoint;
		let goneId = null;
		try {
			goneId = (await vdisk.noteSave(v, { title: 'to-delete', note: 'temporary' })).id;
			await vdisk.noteDelete(v, goneId);
		} finally { await vdisk.unmount(v, {}).catch(() => {}); }
		mp = (await vdisk.mount(v, { password: 'pw1', cacheDir })).mountpoint;
		try {
			let stillGone = false;
			try { await vdisk.noteGet(v, goneId); } catch (_) { stillGone = true; }
			const inList = (await vdisk.notesList(v)).notes.some(n => n.id === goneId);
			ok('a deleted note stays deleted after unmount and remount (durable delete)', stillGone && !inList);
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
