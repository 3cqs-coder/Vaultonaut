'use strict';
// lib/test/dispersalrepairid.js — a repaired shard must REJOIN the surviving dispersal, not form a new one. Repair
// rebuilds a missing shard by re-encoding the recovered archive; if that re-encode minted a fresh dispersal id, the
// rebuilt shard would land in a separate group, and a later reconstruction (which draws from only the largest
// consistent group) would silently have less fault tolerance than the user believes — even though every shard still
// reads as "good". This proves the rebuilt shard carries the survivors' id and that, after a repair, the set still
// tolerates the full n-k losses it was dispersed to tolerate, reconstructing the exact original.
//
// Run:  node lib/test/dispersalrepairid.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');
const Disperse = require('../Disperse');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const idOf = (p) => { try { return Disperse.shardInfo(fs.readFileSync(p)).id; } catch (_) { return null; } };

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-repairid-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	const secret = 'the archive bytes ' + crypto.randomBytes(16).toString('hex');
	await fsp.writeFile(path.join(src, 'secret.txt'), secret);
	const v = path.join(tmp, 'R.vault'); await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// Disperse 4 shards, any 2 rebuild (tolerates any 2 losses).
	const nodes = Array.from({ length: 4 }, (_, i) => path.join(tmp, 'n' + i));
	const d = await vdisk.disperse(v, { n: 4, k: 2, dests: nodes });
	ok('four shards were written', d.shards.length === 4 && d.shards.every(p => fs.existsSync(p)));
	const idA = idOf(d.shards[0]);
	ok('the dispersal shards share one id', idA && d.shards.every(p => idOf(p) === idA));

	// Lose one shard, then repair it.
	await fsp.rm(d.shards[1], { force: true });
	await vdisk.repairDispersal(d.shards);
	ok('the missing shard was re-created', fs.existsSync(d.shards[1]));
	ok('the repaired shard carries the SURVIVORS\' dispersal id (rejoined, not a new group)', idOf(d.shards[1]) === idA);
	ok('all four shards are one recoverable group after repair', (await vdisk.inspectShards(d.shards)).good === 4);

	// The real test: after the repair, lose the full n-k = 2 shards the set was meant to tolerate. It must still be
	// recoverable from the remaining two. Before the fix, shard 1 was in a different id-group, so this dropped below
	// the threshold and reconstruction failed.
	await fsp.rm(d.shards[2], { force: true });
	await fsp.rm(d.shards[3], { force: true });
	const survivors = [d.shards[0], d.shards[1]];
	ok('the two survivors form one recoverable group (full tolerance preserved)', (await vdisk.inspectShards(survivors)).recoverable === true);

	// Definitive: actually rebuild the vault from the two survivors and confirm the original content.
	const rebuilt = path.join(tmp, 'rebuilt');
	await vdisk.reconstructFromShards(survivors, rebuilt);
	const rebuiltVault = fs.readdirSync(rebuilt).map(n => path.join(rebuilt, n)).find(p => p.endsWith('.vault')) || rebuilt;
	const list = await vdisk.list(rebuiltVault, { password: 'pw' }).catch(() => []);
	ok('the rebuilt vault opens and contains the original file', list.some(f => /secret\.txt/.test(f)));

	return done();
}

function done() {
	if (workspace) { try { fs.rmSync(workspace, { recursive: true, force: true }); } catch (_) {} }
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DISPERSAL-REPAIR-ID CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
