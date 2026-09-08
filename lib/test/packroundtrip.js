'use strict';
// lib/test/packroundtrip.js — the streaming packer/unpacker (Net.zipDir / Net.unzip) must round-trip a realistic
// vault TREE, not just a flat file: nested subfolders, an EMPTY directory, a binary file, a non-ASCII (unicode)
// name, plus the container marker (extra) and a manifest OVERRIDE (share-with-selected-keys). This exercises the
// entry-by-entry streaming path — directory entries, deep paths, override substitution — directly, with no engine
// or network, so a structural regression in packing surfaces here instead of only in a full mounted-vault test.
//
// Run:  node -r ./lib/test/_setup.js lib/test/packroundtrip.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const readOr = (p) => { try { return fs.readFileSync(p); } catch (_) { return null; } };
const statOr = (p) => { try { return fs.statSync(p); } catch (_) { return null; } };

let tmp = null;
async function main() {
	tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-pkrt-'));
	const src = path.join(tmp, 'src');
	await fsp.mkdir(path.join(src, 'sub', 'deep'), { recursive: true });
	await fsp.mkdir(path.join(src, 'empty'), { recursive: true }); // an empty directory must survive the round-trip
	const rootTxt = Buffer.from('root file contents');
	const binBytes = Buffer.from([0, 1, 2, 253, 254, 255, 0, 42]);
	const deepTxt = Buffer.from('deep unicode café ☕ résumé');
	await fsp.writeFile(path.join(src, 'vault.json'), '{"real":"manifest"}'); // will be OVERRIDDEN below
	await fsp.writeFile(path.join(src, 'root.txt'), rootTxt);
	await fsp.writeFile(path.join(src, 'sub', 'a.bin'), binBytes);
	await fsp.writeFile(path.join(src, 'sub', 'deep', 'café.txt'), deepTxt);

	const out = path.join(tmp, 'container.zip');
	const overrideManifest = Buffer.from('{"filtered":"manifest"}');
	await Net.zipDir(src, out, {
		prefix: 'MyVault.vault',
		extra: { [Net.CONTAINER_MARKER]: Buffer.from('marker') },
		override: { 'vault.json': overrideManifest } // substitute a filtered manifest in place of the real bytes
	});
	ok('the packed container was written', !!statOr(out) && statOr(out).size > 0);

	const dest = path.join(tmp, 'dest');
	const tops = await Net.unzip(out, dest);
	const base = path.join(dest, 'MyVault.vault');
	ok('unpack reports the vault folder and the marker as top-level entries', tops.includes('MyVault.vault') && tops.includes(Net.CONTAINER_MARKER));

	ok('a root file round-trips byte-identically', (readOr(path.join(base, 'root.txt')) || Buffer.alloc(0)).equals(rootTxt));
	ok('a binary file in a subfolder round-trips byte-identically', (readOr(path.join(base, 'sub', 'a.bin')) || Buffer.alloc(0)).equals(binBytes));
	ok('a deeply-nested unicode-named file round-trips byte-identically', (readOr(path.join(base, 'sub', 'deep', 'café.txt')) || Buffer.alloc(0)).equals(deepTxt));
	const ed = statOr(path.join(base, 'empty'));
	ok('an empty directory survives the round-trip', !!ed && ed.isDirectory());
	ok('the container marker is present at the top level', !!statOr(path.join(dest, Net.CONTAINER_MARKER)));
	ok('an override buffer replaces the real file bytes', (readOr(path.join(base, 'vault.json')) || Buffer.alloc(0)).equals(overrideManifest));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PACK-ROUND-TRIP CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
