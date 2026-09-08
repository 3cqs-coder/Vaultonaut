'use strict';
// lib/test/teamdevices.js — per-device key tier: one member (person) holding several device keys. Verifies a
// second device can be enrolled under the same member identity, both devices unlock, listMembers groups devices
// under the person, revoking one device keeps the other working (and truly revokes the removed device via rotate),
// and the last-device guard routes you to removeMember instead. Real encrypted content, no mount.
//
// Run:  node lib/test/teamdevices.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Vault = require('../Vault');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function cryptCfg(bin, dataDir, mf, master) { const c = mf.crypt; return Rclone.writeEphemeralConfig(Rclone.buildConfig({ cipherDir: dataDir, passwordObscured: await Rclone.obscure(bin, master), saltObscured: c.salt, filenameEnc: c.filename_encryption, dirNameEnc: c.directory_name_encryption })); }
async function get(bin, cfg, name) { const r = await Rclone.run(bin, ['cat', 'vault:' + name], { configPath: cfg }); return r.status === 0 ? r.stdout : null; }
const mfOf = async (v) => JSON.parse(await fsp.readFile(path.join(v, 'vault.json'), 'utf8'));

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const bin = require('../RcloneSetup').resolve();
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-teamdevices-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'doc.txt'), 'DEVICES');
	const v = path.join(tmp, 'TD.vault');
	await vdisk.importFolder(v, { password: 'owner-pw', sourceDir: src });
	await vdisk.snapshot(v, { password: 'owner-pw' });
	await vdisk.enableTeam(v, { password: 'owner-pw' });

	// Alice joins with her laptop (device 1).
	const laptop = vdisk.emergencyKeypair();
	const a = await vdisk.addMember(v, { password: 'owner-pw', memberPub: laptop.publicKey, role: 'read', label: 'Alice' });

	// Enroll Alice's phone (device 2) under the SAME member identity.
	const phone = vdisk.emergencyKeypair();
	const d2 = await vdisk.addDevice(v, { password: 'owner-pw', memberId: a.memberId, devicePub: phone.publicKey, label: 'Alice phone' });
	ok('a second device is enrolled under the same member', !!d2.slotId && d2.memberId === a.memberId);

	let roster = await vdisk.listMembers(v);
	const alice = roster.members.find(m => m.memberId === a.memberId);
	ok('the roster groups both devices under one person', roster.members.length === 1 && alice.deviceCount === 2 && alice.devices.length === 2);
	ok('the roster stays validly signed after enrolling a device', roster.rosterValid === true);

	// Both devices unlock and decrypt.
	const mf = await mfOf(v);
	const c1 = await vdisk.unlockByMemberKey(laptop.privateKey, mf);
	const c2 = await vdisk.unlockByMemberKey(phone.privateKey, mf);
	ok('both devices open the vault (same role)', !!c1 && !!c2 && c1.capability === 'ro' && c2.capability === 'ro');
	const cfg1 = await cryptCfg(bin, path.join(v, 'data'), mf, c1.master);
	ok('a device decrypts the content', (await get(bin, cfg1, 'doc.txt')) === 'DEVICES');
	await Rclone.removeConfig(cfg1);

	// Revoke the phone (hard): the laptop keeps working under the new key; the phone's key is dead.
	const phoneMasterBefore = c2.master;
	await vdisk.removeDevice(v, { password: 'owner-pw', slotId: d2.slotId, rotate: true });
	const mf2 = await mfOf(v);
	ok('the revoked device can no longer unlock', (await vdisk.unlockByMemberKey(phone.privateKey, mf2)) === null);
	const laptopAfter = await vdisk.unlockByMemberKey(laptop.privateKey, mf2);
	ok('the member\'s other device still opens under the new key', !!laptopAfter);
	const cfgStale = await cryptCfg(bin, path.join(v, 'data'), mf2, phoneMasterBefore);
	ok('a key captured on the revoked device no longer decrypts (true revocation)', (await get(bin, cfgStale, 'doc.txt')) !== 'DEVICES');
	await Rclone.removeConfig(cfgStale);
	ok('the person remains with one device after revoking the other', (await vdisk.listMembers(v)).members.find(m => m.memberId === a.memberId).deviceCount === 1);

	// The last device cannot be removed via removeDevice (that is removeMember).
	const onlySlot = (await mfOf(v)).crypt.keySlots.find(s => s.kind === 'member' && s.memberId === a.memberId).id;
	let lastRefused = false;
	try { await vdisk.removeDevice(v, { password: 'owner-pw', slotId: onlySlot, rotate: false }); } catch (_) { lastRefused = true; }
	ok('removing a member\'s last device is refused (use remove member)', lastRefused);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TEAM-DEVICE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-teamdevices-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
