'use strict';
// lib/test/import.js — the streaming "Add files" import copies files INTO a mounted vault with plain
// read/write streams (no OS copy call), so a large file lands reliably even where the macOS Finder's
// copy hits the FUSE-T "-36" bug. Verifies: it refuses when unmounted, a file and a whole folder both
// import (folder structure preserved), the bytes are identical through the encrypt/decrypt round-trip,
// and the anti-clobber guard blocks an overwrite unless forced. Needs the bundled engine + a mount
// driver; skips the mount checks when no driver is present.
//
// Run:  node lib/test/import.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sha = (p) => new Promise((res, rej) => { const h = crypto.createHash('sha256'); const s = fs.createReadStream(p); s.on('data', c => h.update(c)); s.on('end', () => res(h.digest('hex'))); s.on('error', rej); });

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-import-')); workspace = tmp;
	const src = path.join(tmp, 'big.bin'); await fsp.writeFile(src, crypto.randomBytes(64 * 1024 * 1024)); // 64 MB
	const srcHash = await sha(src);
	const folder = path.join(tmp, 'set'); await fsp.mkdir(folder);
	await fsp.writeFile(path.join(folder, 'a.txt'), 'alpha');
	await fsp.writeFile(path.join(folder, 'b.txt'), 'bravo');
	const v = path.join(tmp, 'Import.vault'); await vdisk.create(v, { password: 'pw' });

	let refused = false; try { await vdisk.importFiles(v, [src]); } catch (e) { refused = /mount the vault/i.test(e.message); }
	ok('refuses to import into an unmounted vault', refused);

	if (!d.driver.ok) { console.log('No mount driver — skipping the mounted-import checks.'); }
	else {
		const m = await vdisk.mount(v, { password: 'pw' });
		let last = 0;
		const r = await vdisk.importFiles(v, [src, folder], { onProgress: p => { last = p.percent; } });
		ok('imports a file and a folder (3 files total)', r.added === 3);
		ok('progress reaches 100%', last === 100);
		ok('the big file is byte-identical through the vault', fs.existsSync(path.join(m.mountpoint, 'big.bin')) && (await sha(path.join(m.mountpoint, 'big.bin'))) === srcHash);
		ok('the folder is imported with its structure', fs.existsSync(path.join(m.mountpoint, 'set', 'a.txt')) && fs.existsSync(path.join(m.mountpoint, 'set', 'b.txt')));

		let clash = false; try { await vdisk.importFiles(v, [src]); } catch (e) { clash = !!e.clash; }
		ok('anti-clobber refuses to overwrite an existing file without force', clash);
		const forced = await vdisk.importFiles(v, [src], { force: true });
		ok('force overwrites the existing file', forced.added === 1);
		await vdisk.unmount(v, {});
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL IMPORT CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-import-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
