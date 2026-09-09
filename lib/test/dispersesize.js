'use strict';
// lib/test/dispersesize.js — dispersal refuses a vault larger than the shard-codec's archive ceiling CLEANLY and
// EARLY. The codec loads the whole packed archive into one Buffer, so a tree above Disperse.MAX_ARCHIVE_BYTES cannot
// be dispersed on any machine no matter how much memory it has. Without an upfront check, a big-RAM computer sails
// past the memory heuristic and only fails deep in the worker with an opaque "file too large" Buffer error. This
// test stubs the whole-tree size so the refusal can be exercised without staging gigabytes, and confirms it fires
// before any packing or engine work. Needs the bundled engine to create the vault; runs unmounted.
//
// Run:  node lib/test/dispersesize.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');

let failures = 0, workspace = null;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const vdisk = require('../index');
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const Common = require('../Common');
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-dispsize-')); workspace = tmp;
	Common.dataDir = () => path.join(tmp, 'data'); await fsp.mkdir(Common.dataDir(), { recursive: true });
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(4096));
	const v = path.join(tmp, 'Big.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	const dests = [0, 1, 2].map(i => path.join(tmp, 'shard' + i));
	for (const d of dests) await fsp.mkdir(d, { recursive: true });

	const Disperse = require('../Disperse');
	const Net = require('../Net');
	const realTreeSize = Net.treeSize;
	// Report a tree one byte over the ceiling. The real vault is tiny, so nothing gigabyte-sized is staged.
	Net.treeSize = async () => Disperse.MAX_ARCHIVE_BYTES + 1;
	let msg = '';
	try { await vdisk.disperse(v, { n: 3, k: 2, dests }); } catch (e) { msg = (e && e.message) || ''; }
	Net.treeSize = realTreeSize;
	ok('an over-ceiling vault is refused with a clear "too large to split" message', /too large to split into shards/i.test(msg));
	ok('the refusal names the size limit and points to backup or mirror', /limit for dispersal/i.test(msg) && /backup|mirror/i.test(msg));
	// Nothing was written: the refusal must fire BEFORE any shard is staged.
	let anyShard = false;
	for (const d of dests) { try { if ((await fsp.readdir(d)).length) anyShard = true; } catch (_) {} }
	ok('no shard files are written when the vault is refused', anyShard === false);

	// Control: with the real (tiny) size, dispersal proceeds — the guard only blocks the over-ceiling case.
	const okRes = await vdisk.disperse(v, { n: 3, k: 2, dests });
	ok('a normal-size vault still disperses (the guard is not over-eager)', !!okRes && !okRes.error);

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DISPERSE-SIZE CHECKS PASSED'));
	if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
