'use strict';
// lib/test/scrub.js — the scheduled integrity scrub for ordinary vaults. A scrub is a PASSWORD-LESS check of a
// vault's recovery data (bit-rot detection) with an optional repair from it, run on a schedule so an idle vault
// is proactively kept whole. This verifies: a scrub of a protected vault is clean; a scrub after silent bit-rot
// finds the damage; a scrub with --heal repairs it and a re-scrub is clean again; a scrub of an unprotected
// vault is skipped; and the schedule stores and clears. Needs the bundled engine (no mount driver).
//
// Run:  node lib/test/scrub.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function walk(dir) { const out = []; for (const e of await fsp.readdir(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) out.push(...await walk(p)); else out.push(p); } return out; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-scrub-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	for (let i = 0; i < 12; i++) await fsp.writeFile(path.join(src, 'file' + i + '.bin'), crypto.randomBytes(128 * 1024));
	await fsp.writeFile(path.join(src, 'sub', 'nested.bin'), crypto.randomBytes(96 * 1024));
	const v = path.join(tmp, 'Scrub.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });
	const cipher = path.join(v, 'data');

	// A scrub of a vault with NO recovery data is skipped, not an error.
	const noProt = await vdisk.runScrub(v, {});
	ok('a scrub of an unprotected vault is skipped (nothing to check)', !!noProt.skipped);

	await vdisk.protect(v, { tier: 'high' });

	// Clean protected vault: the scrub verifies with no damage.
	const clean = await vdisk.runScrub(v, {});
	ok('a scrub of a freshly protected vault is clean', clean.checked === true && clean.clean === true);

	// Silent bit-rot: flip a byte in a ciphertext block. A check-only scrub must FIND the damage, not repair it.
	const blobs = (await walk(cipher)).filter(p => !p.includes(path.sep + '.recovery' + path.sep)); // a real data blob
	const victim = blobs.sort((a, b) => a.localeCompare(b))[0];
	const b = await fsp.readFile(victim); b[Math.floor(b.length / 2)] ^= 0xff; await fsp.writeFile(victim, b);
	const found = await vdisk.runScrub(v, { autoHeal: false });
	ok('a scrub finds silent bit-rot (damage reported, not repaired)', found.checked === true && found.clean === false && found.healed === false);

	// With auto-heal, the same scrub repairs the damage from the recovery data.
	const healed = await vdisk.runScrub(v, { autoHeal: true });
	ok('a scrub with auto-heal repairs the damage', healed.checked === true && healed.healed === true);
	const after = await vdisk.runScrub(v, {});
	ok('a re-scrub after repair is clean again', after.clean === true);

	// The schedule stores and clears, carrying the auto-heal flag.
	const set = await vdisk.setScrubSchedule(v, { mode: 'daily', hour: 3, minute: 30, autoHeal: true });
	ok('a scrub schedule is stored (daily, auto-heal on)', set.schedule.mode === 'daily' && set.schedule.hour === 3 && set.schedule.autoHeal === true);
	ok('the stored schedule reads back', (await vdisk.getScrubSchedule(v)).mode === 'daily');
	await vdisk.setScrubSchedule(v, { mode: 'off' });
	ok('the schedule turns off', (await vdisk.getScrubSchedule(v)).mode === 'off');

	// The tick is a no-op when nothing is due/scheduled, and never throws.
	ok('the scrub tick runs without error when nothing is scheduled', Array.isArray((await vdisk.scrubScheduleTick()).ran));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SCRUB CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
