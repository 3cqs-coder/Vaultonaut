'use strict';
// lib/test/repairschedule.js — scheduled cross-node shard repair. Disperse a vault, lose a shard,
// register a repair schedule for the folders, and confirm the tick re-creates the missing shard and
// records its result. Also checks the schedule is due immediately when fresh, not due right after a
// run, and that saving with mode "off" clears it. Reuses the same schedule model as backups.
//
// Run:  node lib/test/repairschedule.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const exists = (p) => { try { fs.statSync(p); return true; } catch (_) { return false; } };

let workspace = null, scheduleId = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-rsched-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'f.txt'), 'schedule repair ' + crypto.randomBytes(6).toString('hex'));
	const v = path.join(tmp, 'S.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	console.log('[disperse then lose a shard]');
	const nodes = Array.from({ length: 4 }, (_, i) => path.join(tmp, 'n' + i));
	const d = await vdisk.disperse(v, { n: 4, k: 2, dests: nodes });
	await fsp.rm(d.shards[1], { force: true }); // node 1 churned out
	ok('a shard is missing before repair', !exists(d.shards[1]));

	console.log('[schedule + due checks]');
	const saved = await vdisk.saveRepairSchedule({ folders: nodes, mode: 'interval', intervalHours: 24 });
	scheduleId = saved.id;
	ok('the schedule is listed', (await vdisk.listRepairSchedules()).some(s => s.id === scheduleId));

	console.log('[tick repairs the missing shard]');
	const first = await vdisk.dispersalRepairTick();
	ok('the tick repaired this schedule (it was due immediately)', first.ran.includes(scheduleId));
	ok('the missing shard was re-created', exists(d.shards[1]));
	ok('all four shards are healthy again', (await vdisk.inspectShards(d.shards)).good === 4);
	const after = (await vdisk.listRepairSchedules()).find(s => s.id === scheduleId);
	ok('the schedule recorded a result and a run time', !!after && /repaired/.test(after.lastResult) && !!after.lastRunAt);

	console.log('[not due again right after a run]');
	const second = await vdisk.dispersalRepairTick();
	ok('a fresh run is not due again within the interval', !second.ran.includes(scheduleId));

	console.log('[turning it off clears it]');
	await vdisk.saveRepairSchedule({ folders: nodes, mode: 'off' });
	ok('the schedule is gone after mode off', !(await vdisk.listRepairSchedules()).some(s => s.id === scheduleId));
	scheduleId = null;

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REPAIR-SCHEDULE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { if (scheduleId) await vdisk.removeRepairSchedule(scheduleId); } catch (_) {}
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-rsched-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
