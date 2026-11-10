'use strict';
// lib/test/notemode.js — the mount-free password-manager session. A vault opens with its password, its notes are read
// and written store-direct, and NO mount process, mountpoint, or state row is created. The same Vault note functions
// serve the mounted and mount-free paths; this test pins the no-mount half without needing a FUSE/WinFsp driver.
//
// Needs the bundled engine (for the crypt remote). No mount driver is needed, so this runs on every CI platform.
//
// Run:  node -r ./lib/test/_setup.js lib/test/notemode.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function cleanup() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

function walkFiles(dir, out = []) {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) walkFiles(p, out);
		else if (e.isFile()) out.push(p);
	}
	return out;
}

async function main() {
	// Source-level wiring: the focused route, the one note-target helper, the idle sweep, and the shared text map.
	{
		const web = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
		const ejs = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'views', 'index.ejs'), 'utf8');
		const app = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');
		const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
		ok('the /notes route renders the focused notes mode', /app\.get\('\/notes'[\s\S]{0,200}notesMode: true/.test(web));
		ok('the session routes open, ping, and close through Vault', /app\.post\('\/api\/notes-session'/.test(web) && /Vault\.openNotesSession\(/.test(web) && /app\.post\('\/api\/notes-session-ping'/.test(web) && /Vault\.notesSessionInfo\(/.test(web) && /app\.post\('\/api\/notes-session-close'/.test(web) && /Vault\.closeNotesSession\(/.test(web));
		ok('every note route resolves a session id before a vault path', /const notesTarget = \(body, query\)/.test(web) && (web.match(/notesTarget\(/g) || []).length >= 6);
		ok('the service health tick sweeps idle notes sessions', /Vault\.sweepNotesSessions\(\)/.test(web));
		ok('Lock all ends every mount-free notes session', /closeAllNotesSessions\(\)/.test(vaultSrc));
		ok('the focused page uses the shared text map', /<%= notesText\.title %>/.test(ejs) && /notes-mode-text\.js/.test(ejs));
		ok('the client routes every note request through one scope helper', /const notesScope = \(\)/.test(app) && (app.match(/notesScope\(\)/g) || []).length >= 8);
		ok('a read-only view keeps Delete hidden even after an item is selected', /let notesReadOnly = false/.test(app) && /hidden = !it\.id \|\| notesReadOnly/.test(app) && /notesReadOnly = true/.test(app));
		ok('a read-only view shows a top-of-dialog notice and hides New item', /id="notesReadOnly"/.test(ejs) && /ro\.textContent = NOTES_TEXT\.readOnlyNotice/.test(app) && /if \(newBtn\) newBtn\.hidden = true/.test(app));
		ok('the session ping pauses while the tab is hidden or the dialog is closed', /if \(document\.hidden\) return/.test(app) && /const dlg = \$\('#notesDialog'\); if \(!dlg \|\| !dlg\.open\) return/.test(app));
		ok('a bfcache restore locks a focused session instead of leaving a dead editor', /addEventListener\('pageshow'[\s\S]{0,120}ev\.persisted[\s\S]{0,80}notesModeLock\(true\)/.test(app));
		ok('a late note-list response is rejected across a session change, not only a path change', /const scopeKey = notesSession \? notesSession\.id/.test(app) && /scopeKey !== \(notesSession \? notesSession\.id/.test(app));
		ok('restoring or receiving into a vault closes its mount-free session', (vaultSrc.match(/closeNotesSessionsForVault\(dest\)/g) || []).length >= 2);
		ok('the session-id-to-path resolver is shared (Send does not duplicate it)', /function notesBackingPath/.test(vaultSrc) && /const abs = notesBackingPath\(vaultDir\)/.test(vaultSrc));
		const css = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'css', 'app.css'), 'utf8');
		const text = require('../webserver/public/shared/notes-mode-text');
		ok('the focused mode hides the normal app shell', /body\.notes-mode \.app \{ display: none; \}/.test(css));
		ok('the focused dialog offers a Vaults home action wired to the root page', /id="notesModeHome"/.test(ejs) && /notesModeHome'\)[\s\S]{0,320}location\.href = '\/'/.test(app));
		ok('the focused page offers a Back to vaults link', /class="notes-mode-back" href="\/"/.test(ejs) && !!text.backToVaults);
		ok('both large dialogs scroll inside their rounded frame', /\.dialog\.dialog-scroll \{[^}]*overflow: hidden/.test(css) && /\.dialog\.dialog-scroll > form \{[^}]*overflow-y: auto/.test(css) && /class="dialog dialog-scroll"/.test(ejs) && /class="dialog manage-dialog dialog-scroll"/.test(ejs));
		ok('the Manage surface offers Password manager with its own icon', /\['notes-mode', 'Password manager'/.test(app) && /'notes-mode': '<path/.test(app));
		ok('the shared focused-mode text map is complete', !!(text.title && text.vault && text.open && text.lock && text.dialogTitle && text.backToVaults && text.vaults && text.backToVaultsLabel && text.readOnlyNotice));
	}

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the no-mount note session checks.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-notemode-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(512));
	const v = path.join(tmp, 'Pocket.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// Opening a password-manager session must NOT mount anything. Compare against the mounts already recorded before
	// the test (another test in the same .test-data area may own one) and require that this vault gains none.
	const mountsFor = async () => (await vdisk.listMounts()).filter((m) => m.vault === v || m.mountpoint === v);
	const baselineMounts = (await vdisk.listMounts()).length;
	const session = await vdisk.openNotesSession(v, { password: 'pw1' });
	ok('a mount-free session opens with the vault password', !!session.id && session.readOnly === false);
	ok('opening it creates no mount', (await vdisk.listMounts()).length === baselineMounts && (await mountsFor()).length === 0);
	ok('a fresh mount-free session lists an empty note set', (await vdisk.notesList(session.id)).notes.length === 0);

	const title = 'PocketLoginTitleXYZ';
	const body = 'a unique secret body 8431';
	const saved = await vdisk.noteSave(session.id, {
		title, type: 'login',
		fields: [
			{ id: 'u', kind: 'username', label: 'Username', value: 'alice' },
			{ id: 'p', kind: 'password', label: 'Password', value: 'unique-Str0ng-pw-8431' },
			{ id: 't', kind: 'totp', label: 'One-time code', value: 'JBSWY3DPEHPK3PXP' }
		],
		note: body
	});
	ok('a note saves through the mount-free session', !!saved.id);
	ok('the saved item appears without a mount', (await vdisk.notesList(session.id)).notes.some(n => n.id === saved.id && n.title === title && n.type === 'login'));
	const got = await vdisk.noteGet(session.id, saved.id);
	ok('the full item decrypts through the mount-free session', got.note === body && got.fields.some(f => f.value === 'alice') && got.fields.some(f => f.kind === 'password'));
	ok('the item is still absent from the mount list after writing', (await vdisk.listMounts()).length === baselineMounts && (await mountsFor()).length === 0);
	const send = await vdisk.sealItemForSend(session.id, { id: saved.id });
	ok('a Send link can be sealed from the mount-free session', !!send.ciphertext && !!send.key && send.vault === v);

	// The note payload must be ciphertext on disk, exactly like a mounted note.
	const dataDir = path.join(v, 'data');
	const plaintextHit = walkFiles(dataDir).some((p) => {
		let b; try { b = fs.readFileSync(p); } catch (_) { return false; }
		return b.includes(Buffer.from(title)) || b.includes(Buffer.from(body)) || b.includes(Buffer.from('unique-Str0ng-pw-8431'));
	});
	ok('no note plaintext reaches the encrypted store', !plaintextHit);

	// The same health scan works through the session.
	const health = await vdisk.notesHealth(session.id, { breach: false });
	ok('password health scans through the mount-free session', health.scanned >= 1 && health.items.length === 0);

	// Concurrent writes through the one session remain serialized and intact.
	const concurrent = await Promise.all(Array.from({ length: 6 }, (_, i) => vdisk.noteSave(session.id, { title: 'Concurrent-' + i, note: 'body-' + i })));
	const listed = (await vdisk.notesList(session.id)).notes;
	ok('concurrent mount-free saves all persist', concurrent.every((r) => listed.some((n) => n.id === r.id)));
	ok('editing and deleting work through the session', await (async () => {
		const edited = await vdisk.noteSave(session.id, { id: saved.id, title: title + ' edited', note: body + ' edited' });
		const after = await vdisk.noteGet(session.id, edited.id);
		await vdisk.noteDelete(session.id, concurrent[0].id);
		const gone = !(await vdisk.notesList(session.id)).notes.some((n) => n.id === concurrent[0].id);
		return after.note === body + ' edited' && gone;
	})());

	// Import runs through the same noteSave/notesList path.
	const imported = await vdisk.notesImport(session.id, {
		text: 'name,username,password,url,notes\nImported Site,bob,imported-pw-123,https://example.test,from csv\n',
		filename: 'export.csv'
	});
	ok('CSV import works without a mount', imported.imported === 1 && (await vdisk.notesList(session.id)).notes.some((n) => n.title === 'Imported Site'));

	// Closing the session destroys its access immediately.
	vdisk.closeNotesSession(session.id);
	let locked = false;
	try { await vdisk.notesList(session.id); } catch (e) { locked = /locked|Open the vault again/i.test(e.message); }
	ok('a closed session refuses further note access', locked);

	// Reopening reads the same store, proving the notes are durable with no mount.
	const reopened = await vdisk.openNotesSession(v, { password: 'pw1' });
	ok('reopening the mount-free session sees the saved items', (await vdisk.notesList(reopened.id)).notes.some((n) => n.title === 'Imported Site'));
	let wrong = false;
	try { await vdisk.openNotesSession(v, { password: 'not-the-password' }); } catch (e) { wrong = !!e.wrongPassword || /incorrect/i.test(e.message); }
	ok('a wrong password is rejected as a password error (not a crypt failure)', wrong);

	// A read-only key can read through the session but cannot write.
	await vdisk.addReadOnlyKey(v, { password: 'pw1', readOnlyPassword: 'ro-pw' });
	const ro = await vdisk.openNotesSession(v, { password: 'ro-pw' });
	ok('a read-only key opens a read-only mount-free session', ro.readOnly === true);
	ok('the read-only session can list notes', Array.isArray((await vdisk.notesList(ro.id)).notes));
	let roSave = false, roDelete = false;
	try { await vdisk.noteSave(ro.id, { title: 'nope', note: 'no' }); } catch (e) { roSave = /read-only/i.test(e.message); }
	try { await vdisk.noteDelete(ro.id, saved.id); } catch (e) { roDelete = /read-only/i.test(e.message); }
	ok('the read-only session cannot save', roSave);
	ok('the read-only session cannot delete', roDelete);

	// A read capability opens the same read-only mode with no password at all.
	const cap = await vdisk.makeReadCap(v, { password: 'pw1', label: 'notes mode test' });
	const capSession = await vdisk.openNotesSession(v, { readCap: cap.token });
	ok('a read capability opens a read-only mount-free session', capSession.readOnly === true && (await vdisk.notesList(capSession.id)).notes.length > 0);

	// Idle expiry is enforced by the service sweep, not only by the next request. The minimum session lifetime is
	// one minute, so sweep past that floor.
	const short = await vdisk.openNotesSession(v, { password: 'pw1', ttlMs: 60000 });
	vdisk.sweepNotesSessions(Date.now() + 61000);
	let expired = false;
	try { await vdisk.notesList(short.id); } catch (e) { expired = /locked/i.test(e.message); }
	ok('an idle session is swept and cannot be used afterward', expired);

	// Closing all sessions for a vault is the lock hook.
	const closedCount = vdisk.closeNotesSessionsForVault(v);
	let gone = false;
	try { await vdisk.notesList(reopened.id); } catch (_) { gone = true; }
	ok('closing a vault\'s sessions closes them all', closedCount >= 1 && gone);

	// Duress parity: the decoy password must open the paired decoy through the SAME notes-session path, presented
	// under the REAL vault's name, exactly as a mount redirect does.
	const decoyVault = path.join(tmp, 'Pocket Decoy.vault');
	await vdisk.create(decoyVault, { password: 'decoy-pw' });
	const dSess = await vdisk.openNotesSession(decoyVault, { password: 'decoy-pw' });
	await vdisk.noteSave(dSess.id, { title: 'DECOY-ONLY-ITEM', note: 'decoy body' });
	vdisk.closeNotesSession(dSess.id);
	await vdisk.decoySet({ realVault: v, decoyVault, decoyPassword: 'decoy-pw', managerPassword: 'mgr-pw' });
	const duress = await vdisk.openNotesSession(v, { password: 'decoy-pw' });
	const duressList = await vdisk.notesList(duress.id);
	ok('the decoy password opens the paired decoy through the notes session', !!duress.id && duressList.notes.some((n) => n.title === 'DECOY-ONLY-ITEM'));
	ok('the duress session lists the decoy items, never the real ones', !duressList.notes.some((n) => n.title === title));
	ok('the duress session presents the real vault name', duress.name === 'Pocket');
	const duressClosed = vdisk.closeNotesSessionsForVault(v);
	let duressGone = false;
	try { await vdisk.notesList(duress.id); } catch (e) { duressGone = /locked/i.test(e.message); }
	ok('closing the real vault also closes its duress session', duressClosed >= 1 && duressGone);
	await vdisk.decoyRemove({ realVault: v, managerPassword: 'mgr-pw' });

	// Forgetting a vault (Remove from list) must end any mount-free session for it, even though the files stay.
	const forgetSession = await vdisk.openNotesSession(v, { password: 'pw1' });
	await vdisk.removeKnownVault(v).catch(() => {});
	let forgotLocked = false;
	try { await vdisk.notesList(forgetSession.id); } catch (e) { forgotLocked = /locked/i.test(e.message); }
	ok('forgetting a vault closes its mount-free session', forgotLocked);
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOUNT-FREE NOTE-MODE CHECKS PASSED'));
	await cleanup();
	process.exit(failures ? 1 : 0);
}
main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
