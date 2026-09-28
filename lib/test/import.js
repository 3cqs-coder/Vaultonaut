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
	// Stamp the sources with a known past time so the import can be checked to PRESERVE it (like an OS drag), not
	// stamp "now". Set the folder's own time last, after its files, since writing entries bumps a directory's mtime.
	const OLD = new Date('2019-03-04T05:06:07Z'); const OLD_MS = OLD.getTime();
	await fsp.utimes(src, OLD, OLD);
	await fsp.utimes(path.join(folder, 'a.txt'), OLD, OLD);
	await fsp.utimes(path.join(folder, 'b.txt'), OLD, OLD);
	await fsp.utimes(folder, OLD, OLD);
	const v = path.join(tmp, 'Import.vault'); await vdisk.create(v, { password: 'pw' });

	let refused = false; try { await vdisk.importFiles(v, [src]); } catch (e) { refused = /mount the vault/i.test(e.message); }
	ok('refuses to import into an unmounted vault', refused);

	// Mount-independent guard (runs on every CI leg, including those with no mount driver): the import must carry the
	// source timestamps onto the copy, so "Add files" matches dragging files into the mount rather than stamping "now".
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('collectImportFiles captures each file\'s modification time', /out\.push\(\{ src: full,[^}]*mtimeMs: st\.mtimeMs/.test(vaultSrc));
	ok('importFiles restores each file\'s timestamps after the copy', /await restoreImportTimes\(dst, it\.atimeMs, it\.mtimeMs, it\.mode\)/.test(vaultSrc));
	ok('importFiles re-stamps the copied directories to their source mtime', /restoreImportTimes\(dst, d\.atimeMs, d\.mtimeMs/.test(vaultSrc));
	ok('restoreImportTimes applies the source times through fsp.utimes', /fsp\.utimes\(dst, new Date\(atimeMs\), new Date\(mtimeMs\)\)/.test(vaultSrc));

	// Mount-independent guard for the cancelable import: the copy must stop promptly when the request is aborted, so the
	// Add-files dialog's Cancel/Escape actually stops the work instead of finishing every file in the background.
	ok('importFiles accepts an abort signal and stops before the next file', /const canceled = \(\) => signal && signal\.aborted/.test(vaultSrc) && /if \(canceled\(\)\) throw cancelErr\(\);/.test(vaultSrc));
	ok('the import honors cancel during the pre-scan (tree walk + anti-clobber probe)', /collectImportFiles\(dir, base, out, dirsOut, depth = 0, signal\)[\s\S]{0,200}signal\.aborted\) throw/.test(vaultSrc) && /mapLimit\(items, 12, async \(it\) => \{ if \(canceled\(\)\) throw cancelErr\(\)/.test(vaultSrc));
	ok('the in-flight copy is abortable mid-file (signal threaded into streamCopyFile)', /streamCopyFile\(it\.src, dst, \{ onChunk, flags: force \? 'w' : 'wx', signal \}\)/.test(vaultSrc) && /signal\.addEventListener\('abort', onAbort, \{ once: true \}\)/.test(vaultSrc));
	const idxSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the import route aborts the copy when the request closes', /app\.post\('\/api\/import-files'[\s\S]{0,900}new AbortController\(\)[\s\S]{0,400}req\.once\('close', stop\)[\s\S]{0,300}signal: ac\.signal/.test(idxSrc));
	const appSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'js', 'app.js'), 'utf8');
	ok('the Add-files dialog can cancel an in-flight import with a confirmation', /#importCancel'\)\.addEventListener\('click'[\s\S]{0,400}uiConfirm\(\{ title: 'Stop adding files\?'[\s\S]{0,400}importAbort\.abort\(\)/.test(appSrc));
	ok('Escape during an import is intercepted to the confirmed cancel (not a silent close)', /#importDialog'\)\.addEventListener\('cancel', \(e\) => \{ if \(importing\) \{ e\.preventDefault\(\); \$\('#importCancel'\)\.click\(\)/.test(appSrc));
	ok('apiStream forwards an abort signal to fetch', /const apiStream = async \(path, body, onProgress, opts\) =>[\s\S]{0,200}signal: opts && opts\.signal/.test(appSrc));
	const ejsSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'views', 'index.ejs'), 'utf8');
	ok('the import dialog markup has the Close and hidden Cancel buttons', /id="importClose"/.test(ejsSrc) && /id="importCancel"[^>]*hidden/.test(ejsSrc));

	if (!d.driver.ok) { console.log('No mount driver — skipping the mounted-import checks.'); }
	else {
		const m = await vdisk.mount(v, { password: 'pw' });
		let last = 0;
		const r = await vdisk.importFiles(v, [src, folder], { onProgress: p => { last = p.percent; } });
		ok('imports a file and a folder (3 files total)', r.added === 3);
		ok('progress reaches 100%', last === 100);
		ok('the big file is byte-identical through the vault', fs.existsSync(path.join(m.mountpoint, 'big.bin')) && (await sha(path.join(m.mountpoint, 'big.bin'))) === srcHash);
		ok('the folder is imported with its structure', fs.existsSync(path.join(m.mountpoint, 'set', 'a.txt')) && fs.existsSync(path.join(m.mountpoint, 'set', 'b.txt')));
		// The core of the fix: the copy keeps the source's modification time (within a second's rounding), not "now".
		const impMs = (await fsp.stat(path.join(m.mountpoint, 'big.bin'))).mtimeMs;
		ok('the imported file keeps its original modification time (not "now")', Math.abs(impMs - OLD_MS) < 2000);
		const aMs = (await fsp.stat(path.join(m.mountpoint, 'set', 'a.txt'))).mtimeMs;
		ok('a file inside an imported folder keeps its original modification time', Math.abs(aMs - OLD_MS) < 2000);

		let clash = false; try { await vdisk.importFiles(v, [src]); } catch (e) { clash = !!e.clash; }
		ok('anti-clobber refuses to overwrite an existing file without force', clash);
		const forced = await vdisk.importFiles(v, [src], { force: true });
		ok('force overwrites the existing file', forced.added === 1);
		// Cancel path: an already-aborted signal stops the import before it copies anything (a fresh source proves it).
		const cx = path.join(tmp, 'cancel-me.txt'); await fsp.writeFile(cx, 'x');
		let earlyStop = false; try { await vdisk.importFiles(v, [cx], { signal: AbortSignal.abort() }); } catch (e) { earlyStop = (e && e.code === 'CANCELED') || /cancel/i.test((e && e.message) || ''); }
		ok('a pre-aborted import stops before copying any file', earlyStop && !fs.existsSync(path.join(m.mountpoint, 'cancel-me.txt')));
		await vdisk.unmount(v, {});
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL IMPORT CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => {
	try { for (const kv of await vdisk.listKnownVaults()) { const p = kv.path || kv; if (p.includes('vdisk-import-')) await vdisk.removeKnownVault(p); } } catch (_) {}
	try { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }); } catch (_) {}
});
