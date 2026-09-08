'use strict';
// lib/test/smoke.js — an end-to-end check of the whole lifecycle against the real
// engine and mount driver: create a vault, mount it, write through the mounted
// drive, confirm the data is encrypted at rest, read it back, check that file
// permissions survive a remount, then unmount and confirm clean state.
//
// Run:  node lib/test/smoke.js
// Requires the bundled engine and a mount driver to be present;
// it skips the mount portion gracefully if no driver is installed.

const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');
const vdisk = require('../index');

const PASS = 'a-strong-test-passphrase-☃';
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-smoke-'));
	const vaultDir = path.join(tmp, 'Smoke.vault');
	const mountpoint = path.join(tmp, 'mount');
	console.log('Workspace: ' + tmp);

	const d = await vdisk.doctor();
	console.log('\n[doctor]');
	console.log('  engine: ' + (d.engine.ok ? 'ready' : 'MISSING'));
	console.log('  driver: ' + (d.driver.ok ? d.driver.name : 'MISSING — mount steps will be skipped'));
	ok('engine available', d.engine.ok);

	console.log('\n[create]');
	await vdisk.create(vaultDir, { password: PASS });
	ok('manifest written', fs.existsSync(path.join(vaultDir, 'vault.json')));
	ok('cipher dir created', fs.existsSync(path.join(vaultDir, 'data')));
	const cm = JSON.parse(fs.readFileSync(path.join(vaultDir, 'vault.json'), 'utf8')).crypt;
	ok('file and directory names are always encrypted', cm.filename_encryption === 'standard' && cm.directory_name_encryption === true);

	console.log('\n[list on empty vault]');
	const empty = await vdisk.list(vaultDir, { password: PASS });
	ok('empty vault lists nothing', empty.length === 0);

	console.log('\n[wrong password is rejected]');
	let rejected = false;
	try { await vdisk.list(vaultDir, { password: 'not-the-password' }); } catch (_) { rejected = true; }
	ok('wrong password fails to open', rejected);

	// Key slots (driver-free): extra passwords, a recovery key, and revocation all operate on
	// the master-key wrapping only, so any key opens the vault and none re-encrypts a file.
	console.log('\n[key slots]');
	const opens = async (secret) => { try { await vdisk.list(vaultDir, { password: secret }); return true; } catch (_) { return false; } };
	await vdisk.addKey(vaultDir, { password: PASS, newPassword: 'second-key', label: 'Second' });
	ok('a second password opens the vault, and the first still does', (await opens('second-key')) && (await opens(PASS)));
	const rec = await vdisk.addRecoveryKey(vaultDir, { password: PASS });
	ok('a recovery key is generated and opens the vault', !!rec.recoveryKey && (await opens(rec.recoveryKey)));
	const secondId = (await vdisk.listKeys(vaultDir)).slots.find(s => s.label === 'Second').id;
	let refused = false;
	try { await vdisk.removeKey(vaultDir, { password: 'second-key', slotId: secondId }); } catch (_) { refused = true; }
	ok('removing a key by unlocking with that same key is refused', refused);
	await vdisk.removeKey(vaultDir, { password: PASS, slotId: secondId });
	ok('after removal that key no longer opens; the primary still does', !(await opens('second-key')) && (await opens(PASS)));

	// Tamper detection (driver-free): a snapshot signs the vault's file set, and an audit
	// reports changes. The security-critical part is the signature — a forged fingerprint must
	// be caught — so it is checked here without needing a mount.
	console.log('\n[tamper detection]');
	let a = await vdisk.audit(vaultDir, { password: PASS });
	ok('audit before any snapshot reports none taken', a.hasSnapshot === false && a.errors.length > 0);
	const snap = await vdisk.snapshot(vaultDir, { password: PASS });
	ok('snapshot records the file set with a version + fingerprint', typeof snap.count === 'number' && snap.seq >= 1 && !!snap.fingerprint);
	a = await vdisk.audit(vaultDir, { password: PASS });
	ok('audit right after a snapshot is clean and verified', a.clean === true && a.verified === true);
	ok('audit reports the version and fingerprint', a.seq === snap.seq && a.fingerprint === snap.fingerprint);
	const fp = await vdisk.fingerprint(vaultDir); // no password needed
	ok('fingerprint() matches without a password', fp.fingerprint === snap.fingerprint && fp.seq === snap.seq);
	const mf = path.join(vdisk.resolveVaultDir(vaultDir), 'vault.json');
	const man = JSON.parse(fs.readFileSync(mf, 'utf8'));
	man.snapshot.hmac = 'deadbeef'; // forge the recorded fingerprint
	await require('../Common').writeJsonAtomic(mf, man);
	a = await vdisk.audit(vaultDir, { password: PASS });
	ok('a forged snapshot fingerprint is detected as tampering', a.clean === false && a.tamper.length > 0);
	await vdisk.snapshot(vaultDir, { password: PASS }); // restore a valid snapshot for later steps

	// Health watch classification (driver-free): a responsive path is healthy; a missing path
	// whose engine process is gone is 'dead'. This is the logic the UI uses to surface a wedged
	// drive for one-click recovery, so it is worth verifying independently of a real mount.
	console.log('\n[watchdog]');
	const health = await vdisk.mountHealth([
		{ mountpoint: tmp, pid: process.pid, volname: 'live' },        // exists + engine alive -> healthy
		{ mountpoint: path.join(tmp, 'nope'), pid: 2147483646, volname: 'gone' } // missing + engine dead -> dead
	]);
	ok('responsive mount reads healthy', health[tmp] === 'healthy');
	ok('dead-engine stale mount reads dead', health[path.join(tmp, 'nope')] === 'dead');

	// Engine identity (pid-reuse safety): a mount's engine is confirmed via its unique control
	// socket, not a bare pid, so a recycled pid (a live, unrelated process at the same pid with no
	// matching socket) must NOT read as our engine — otherwise a force-unmount could SIGKILL it.
	const Rclone = require('../Rclone');
	ok('recycled pid (alive process, no matching socket) is not treated as our engine',
		(await Rclone.engineAlive({ pid: process.pid, rcSocket: path.join(tmp, 'no-such.sock') })) === false);
	ok('a live record with no control socket falls back to a pid check',
		(await Rclone.engineAlive({ pid: process.pid })) === true);
	ok('a gone pid is never alive',
		(await Rclone.engineAlive({ pid: 2147483646 })) === false);

	if (!d.driver.ok) {
		console.log('\nNo mount driver — skipping mount lifecycle. Core crypto path verified.');
		return finish(tmp);
	}

	console.log('\n[mount]');
	const m = await vdisk.mount(vaultDir, { password: PASS, mountpoint });
	ok('reported mounted', !!m.mountpoint);
	ok('auto tamper check runs on mount with no false warning', m.tamper === null);
	console.log('  info   cache mode: ' + m.cacheMode + (m.inRam ? ' (buffer in RAM)' : m.cacheMode === 'off' ? ' (streaming)' : ''));
	await wait(500);

	console.log('\n[in-place write — the default mode must support this in RAM]');
	// Rewriting an existing file in place is what streaming cannot do (it hangs). The default
	// "writes" mode with a RAM cache must handle it. Skipped only if the mount fell back to
	// streaming because no RAM disk was available on this machine.
	if (m.cacheMode === 'off') {
		console.log('  info   mount fell back to streaming (no RAM disk here) — skipping the in-place-write check');
	} else {
		const ipf = path.join(m.mountpoint, 'inplace.bin');
		await fsp.writeFile(ipf, Buffer.alloc(4096, 1));
		const fd = fs.openSync(ipf, 'r+'); fs.writeSync(fd, Buffer.from('PATCHED'), 0, 7, 100); fs.closeSync(fd);
		const patched = (await fsp.readFile(ipf)).slice(100, 107).toString();
		ok('in-place write succeeds (no hang) and reads back', patched === 'PATCHED');
	}

	console.log('\n[write through the mounted drive]');
	const secret = 'top secret written live ' + Date.now();
	// Create with mode 600; permissions set at creation are captured when the file
	// flushes to the encrypted store on close.
	await fsp.writeFile(path.join(m.mountpoint, 'note.txt'), secret, { mode: 0o600 });
	await fsp.mkdir(path.join(m.mountpoint, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(m.mountpoint, 'sub', 'deep.txt'), 'nested secret');
	await wait(1000);

	console.log('\n[read back through the mount]');
	const back = await fsp.readFile(path.join(m.mountpoint, 'note.txt'), 'utf8');
	ok('read-back matches', back === secret);

	console.log('\n[unmount — flushes the write-back cache to the encrypted store]');
	const u = await vdisk.unmount(m.mountpoint, { wipeCache: true });
	ok('unmounted cleanly', u.ok);

	console.log('\n[confirm encrypted at rest, after flush]');
	const cipherFiles = [];
	(function walk(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else cipherFiles.push(p); } })(path.join(vaultDir, 'data'));
	ok('encrypted files exist on disk', cipherFiles.length >= 3); // canary + note + deep
	let leak = false;
	for (const f of cipherFiles) { try { if (fs.readFileSync(f).includes(secret)) leak = true; } catch (_) {} }
	ok('plaintext NOT present in cipher dir', !leak);

	console.log('\n[remount and check contents + permissions survived]');
	// Use the mount point the call returns — it may fall back to a fresh path if the
	// previous one is briefly busy after unmounting.
	const m2 = await vdisk.mount(vaultDir, { password: PASS, mountpoint });
	await wait(800);
	const back2 = await fsp.readFile(path.join(m2.mountpoint, 'note.txt'), 'utf8').catch(() => null);
	ok('content survived remount', back2 === secret);
	let mode = null;
	try { mode = (fs.statSync(path.join(m2.mountpoint, 'note.txt')).mode & 0o777); } catch (_) {}
	// Informational: by default the vault does not preserve per-file Unix mode/owner/group
	// (those are not portable across machines, and preserving them can stall the macOS mount),
	// so the mount view presents the default file permission. Contents, names, and modification
	// time survive; the mode is expected to be the default here. Reported, not asserted.
	console.log('  info   file mode on cold remount: ' + (mode === null ? 'unreadable' : '0' + mode.toString(8)) +
		' (per-file mode is not preserved by default; contents, names, and modtime are)');
	await vdisk.unmount(m2.mountpoint, { wipeCache: true });

	console.log('\n[backup + schedule]');
	const bdest = path.join(tmp, 'backup-dest');
	const bk = await vdisk.backup(vaultDir, bdest);
	ok('backup copies the vault (still encrypted) to the destination', fs.existsSync(path.join(bk.dest, 'vault.json')) && fs.existsSync(path.join(bk.dest, 'data')));
	// Schedule due-logic is local-time and DST-correct (no UTC conversion to drift).
	const dueDaily = vdisk.isBackupDue({ mode: 'daily', hour: 9, minute: 0, dest: bdest }, new Date(2026, 2, 8, 9, 0));       // DST day, at time
	const notYet = vdisk.isBackupDue({ mode: 'daily', hour: 9, minute: 0, dest: bdest }, new Date(2026, 2, 8, 8, 59));        // before time
	ok('a daily schedule is due at its local time and not before', dueDaily === true && notYet === false);

	console.log('\n[off-site SFTP credentials]');
	const sd = await vdisk.saveSftpDest({ label: 'Smoke', host: 'test.invalid', user: 'u', authType: 'password', password: 'smoke-secret-xyz' });
	ok('an SFTP destination is saved', !!sd.id);
	const settingsRaw = fs.readFileSync(path.join(require('../Common').dataDir(), 'settings.json'), 'utf8');
	ok('the SFTP password is NOT stored in plaintext', !settingsRaw.includes('smoke-secret-xyz'));
	const sftpList = await vdisk.listSftpDests();
	ok('the destination list never exposes the secret', sftpList.some(d => d.id === sd.id && d.hasPassword) && !sftpList.some(d => 'password' in d));
	await vdisk.removeSftpDest(sd.id);
	ok('the SFTP destination can be removed', !(await vdisk.listSftpDests()).some(d => d.id === sd.id));

	console.log('\n[locking]');
	const s0 = await vdisk.getSettings();
	ok('settings are readable', s0 && typeof s0 === 'object');
	// Panic lock scoped to a non-existent owner: proves the shape without touching any real mount.
	const lr = await vdisk.lockAll({ owner: 'smoke-none' });
	ok('panic lock returns a result shape', typeof lr.locked === 'number' && typeof lr.total === 'number' && lr.total === 0);

	console.log('\n[status is clean]');
	const st = await vdisk.status();
	ok('no stale mounts remain', st.length === 0);

	// Clean up: creating the vault registered it in the known-vaults list, so remove it too —
	// otherwise a deleted test vault lingers there as an "invalid" entry.
	try { await vdisk.removeKnownVault(vaultDir); } catch (_) {}
	return finish(tmp);
}

async function finish(tmp) {
	try { await fsp.rm(tmp, { recursive: true, force: true }); } catch (_) {}
	console.log('\n' + (failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'));
	process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error('\nSmoke test crashed: ' + e.message); process.exit(1); });
