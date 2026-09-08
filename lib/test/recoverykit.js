'use strict';
// lib/test/recoverykit.js — the printable Recovery Kit. It gathers a vault's stable identity, its
// current content fingerprint, and (unless opted out) a freshly generated recovery key, and renders a
// self-contained HTML page from the template data file. This checks the render is safe (values are
// HTML-escaped, every placeholder and both branch markers are consumed) and that the recovery key it
// prints is a real, working credential for the vault.
//
// Run:  node lib/test/recoverykit.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const RecoveryKit = require('../RecoveryKit');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let workspace = null;
async function main() {
	// --- Unit: the renderer, no engine needed ---
	const nasty = 'Secrets <script>"&\'</script>';
	const withKey = RecoveryKit.render({ appName: 'App', cli: 'vdisk', vaultName: nasty, vaultPath: '/tmp/x', identity: 'AAAA-BBBB', fingerprint: 'CCCC', seq: 3, recoveryKey: 'KKKK-LLLL-MMMM' });
	ok('a user-controlled name is HTML-escaped (no raw <script>)', !withKey.includes('<script>'));
	ok('the escaped name is present', withKey.includes('&lt;script&gt;'));
	ok('every placeholder is filled (no {{TOKEN}} left)', !/\{\{\w+\}\}/.test(withKey));
	ok('the branch markers are stripped (no <!--KEY / <!--NOKEY left)', !withKey.includes('<!--KEY') && !withKey.includes('<!--NOKEY'));
	ok('a kit with a key shows the recovery key', withKey.includes('KKKK-LLLL-MMMM'));
	const noKey = RecoveryKit.render({ appName: 'App', cli: 'vdisk', vaultName: 'plain', vaultPath: '/tmp/x', identity: 'AAAA', fingerprint: null, seq: null });
	ok('an identity-only kit shows no recovery key', !noKey.includes('class="key-box"'));
	ok('an identity-only kit explains how to add a key', noKey.includes('recovery'));
	ok('a missing fingerprint renders a friendly placeholder', noKey.includes('not yet recorded'));

	// --- Integration: against a real vault (needs the engine) ---
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the live-vault checks.'); }
	else {
		const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-kit-')); workspace = tmp;
		const src = path.join(tmp, 'src'); await fsp.mkdir(src);
		await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(2048));
		const v = path.join(tmp, 'A.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
		await vdisk.snapshot(v, { password: 'pw1' }); // establishes the baseline (identity + fingerprint)

		// Identity-only kit: no password, changes nothing, records the real identity/fingerprint.
		const before = await vdisk.listKeys(v);
		const idOnly = await vdisk.recoveryKit(v, { addKey: false });
		const after0 = await vdisk.listKeys(v);
		ok('an identity-only kit needs no new key slot', after0.slots.length === before.slots.length);
		ok('the kit carries the vault identity', !!idOnly.identity && idOnly.html.includes(idOnly.identity));
		ok('the kit carries the content fingerprint', !!idOnly.fingerprint && idOnly.html.includes(idOnly.fingerprint));
		ok('an identity-only kit returns no recovery key', idOnly.recoveryKey === null);

		// Full kit: adds a recovery key and embeds it in the page.
		const kit = await vdisk.recoveryKit(v, { password: 'pw1', addKey: true });
		ok('a full kit returns a recovery key', !!kit.recoveryKey);
		ok('the recovery key appears in the printable page', kit.html.includes(kit.recoveryKey));
		const after1 = await vdisk.listKeys(v);
		ok('a recovery key slot was added', after1.slots.length === before.slots.length + 1);
		ok('the new slot is labeled as a recovery key', after1.slots.some(k => k.kind === 'recovery'));

		// The printed recovery key must actually open the vault: audit unlocks with it.
		let unlocked = false;
		try { await vdisk.audit(v, { password: kit.recoveryKey }); unlocked = true; } catch (_) {}
		ok('the printed recovery key genuinely unlocks the vault', unlocked);

		// Adding a key needs the current password — a full kit with no password must refuse, not silently
		// produce a keyless kit.
		let refused = false;
		try { await vdisk.recoveryKit(v, { addKey: true }); } catch (_) { refused = true; }
		ok('a full kit without the password is refused', refused);

		await vdisk.removeKnownVault(v).catch(() => {});
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RECOVERY-KIT CHECKS PASSED'));
	if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
