'use strict';
// lib/test/emergencyinherit.js — granular (per-beneficiary) dead-man's-switch inheritance. Enroll two
// beneficiaries, route one vault to each, and on release confirm each gets their OWN folder holding only their
// vault's sealed grant — and that each beneficiary's private key opens exactly their own grant, never the other's.
// Also that removing a beneficiary drops only their grant. Needs the engine (arm mints a read cap; open unseals);
// no mount driver and no network. Release is forced deterministically by passing a far-future `now` to the tick.
//
// Run:  node lib/test/emergencyinherit.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-eminherit-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const A = vdisk.emergencyKeypair(), B = vdisk.emergencyKeypair(); // two beneficiaries' keypairs
	const mk = async (name) => { const s = path.join(tmp, name + '-src'); await fsp.mkdir(s, { recursive: true }); await fsp.writeFile(path.join(s, 'f.txt'), name); const v = path.join(tmp, name + '.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: s }); return v; };
	const vBank = await mk('Bank'), vBiz = await mk('Business');

	const en = await vdisk.emergencyEnroll({ contactPubKey: A.publicKey, contactLabel: 'Spouse', inactivityDays: 30, graceDays: 14 });
	const spouse = en.contactId;
	const partnerAdd = await vdisk.emergencyAddContact({ label: 'Partner', pubKey: B.publicKey });
	const partner = partnerAdd.contactId;
	ok('two beneficiaries are enrolled with distinct ids', spouse && partner && spouse !== partner && (await vdisk.emergencyStatus()).contacts.length === 2);

	// Route the bank vault to the spouse and the business vault to the partner.
	await vdisk.emergencyArm(vBank, { password: 'pw', contactId: spouse });
	await vdisk.emergencyArm(vBiz, { password: 'pw', contactId: partner });
	const st = await vdisk.emergencyStatus();
	ok('each armed vault records which beneficiary it is routed to', st.armed.length === 2
		&& st.armed.find(a => a.name === 'Bank').contactLabel === 'Spouse'
		&& st.armed.find(a => a.name === 'Business').contactLabel === 'Partner');
	// With more than one beneficiary, arming MUST name one (never silently seal to the wrong person).
	let mustChoose = false; try { await vdisk.emergencyArm(vBank, { password: 'pw' }); } catch (_) { mustChoose = true; }
	ok('arming with several beneficiaries requires choosing one', mustChoose);

	// Force a release by ticking far in the future (past inactivity + grace). Then each beneficiary must get their
	// own folder with only their vault's grant.
	const rel = await vdisk.emergencyTick(Date.now() + 100 * 86400000);
	ok('the switch releases when overdue', rel.released === true && rel.count === 2);
	const releaseDir = path.join(dataDir, 'emergency-release');
	const folders = (await fsp.readdir(releaseDir, { withFileTypes: true })).filter(e => e.isDirectory()).map(e => e.name);
	ok('release writes one folder per beneficiary', folders.length === 2 && folders.some(f => /^Spouse-/.test(f)) && folders.some(f => /^Partner-/.test(f)));

	// Gather every sealed grant and confirm cross-beneficiary isolation: A (spouse) opens exactly one grant, B
	// (partner) opens exactly one, and neither can open the other's — and each folder holds only its own grant.
	const sealedFiles = [];
	for (const f of folders) { const files = (await fsp.readdir(path.join(releaseDir, f))).filter(n => n.endsWith('.sealed')); ok('the ' + f.split('-')[0] + ' folder holds exactly one sealed grant + a how-to', files.length === 1 && fs.existsSync(path.join(releaseDir, f, 'HOW-TO-OPEN.txt'))); for (const n of files) sealedFiles.push(await fsp.readFile(path.join(releaseDir, f, n), 'utf8')); }
	const tryOpen = (priv, sealed) => { try { return vdisk.emergencyOpen(priv, sealed); } catch (_) { return null; } };
	const aOpens = sealedFiles.map(s => tryOpen(A.privateKey, s)).filter(Boolean); // the read-cap TOKENS A can recover
	const bOpens = sealedFiles.map(s => tryOpen(B.privateKey, s)).filter(Boolean);
	ok('the spouse key opens exactly one grant, the partner key exactly one (no overlap)', aOpens.length === 1 && bOpens.length === 1 && aOpens[0] !== bOpens[0]);
	ok('each opened grant is a valid read capability', !!vdisk.parseReadCap(aOpens[0]) && !!vdisk.parseReadCap(bOpens[0]));

	// Removing the spouse drops only the bank grant; the partner's business grant remains.
	await vdisk.emergencyCheckIn(); // withdraw the release first (a real owner would)
	const rm = await vdisk.emergencyRemoveContact(spouse);
	const after = await vdisk.emergencyStatus();
	ok('removing a beneficiary drops only their grant', rm.droppedGrants === 1 && after.armed.length === 1 && after.armed[0].name === 'Business');
	ok('the remaining beneficiary is untouched', after.contacts.length === 1 && after.contacts[0].label === 'Partner');

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-INHERIT CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}
main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
