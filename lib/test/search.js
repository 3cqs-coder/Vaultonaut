'use strict';
// lib/test/search.js — filename search. A mounted vault searches with no password (reads decrypted names from
// the mount point); an unmounted vault decrypts names through a crypt config (password required). Names only —
// no content is read. Needs the engine; the mounted case additionally needs a mount driver (skipped if absent).
//
// Run:  node lib/test/search.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-search-'));
	const Common = require('../Common');
	Common.statePath = () => path.join(tmp, 'state.json'); // isolate the known-vaults list from real state
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src');
	await fsp.mkdir(path.join(src, 'sub'), { recursive: true });
	await fsp.writeFile(path.join(src, 'Budget.xlsx'), 'x');
	await fsp.writeFile(path.join(src, 'sub', 'meeting-notes.md'), 'y');
	await fsp.writeFile(path.join(src, 'sub', 'photo.jpg'), 'z');
	await fsp.writeFile(path.join(src, 'café-résumé.txt'), 'u'); // an accented name, to test Unicode-normalization-insensitive search
	const v = path.join(tmp, 'Docs.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// --- Unmounted search (password) ---
	const r1 = await vdisk.searchNames(v, { query: 'notes', password: 'pw1' });
	ok('unmounted search finds a file by a name fragment', r1.matches.some(m => m === 'sub/meeting-notes.md') && r1.mounted === false);
	const r2 = await vdisk.searchNames(v, { query: 'BUDGET', password: 'pw1' });
	ok('search is case-insensitive', r2.matches.some(m => m === 'Budget.xlsx'));
	const r3 = await vdisk.searchNames(v, { query: 'nope-no-match', password: 'pw1' });
	ok('a non-matching query returns nothing', r3.matches.length === 0);
	const r4 = await vdisk.searchNames(v, { query: 'sub', password: 'pw1' });
	ok('a folder name matches too', r4.matches.some(m => m === 'sub/'));

	// Unicode-normalization-insensitive search: an accented name must match whether the query is typed composed
	// (NFC) or decomposed (NFD) — macOS stores names NFD while the browser sends NFC, so without normalization one
	// form silently misses. Searching BOTH forms and requiring both to match fails if the fix regresses, whatever
	// form the OS actually stored, since only the query matching the stored form would hit.
	const rNfc = await vdisk.searchNames(v, { query: 'résumé', password: 'pw1' });        // "résumé" precomposed
	const rNfd = await vdisk.searchNames(v, { query: 'résumé', password: 'pw1' });      // "résumé" as e + combining acute
	ok('an accented name matches whether the query is composed (NFC) or decomposed (NFD)', rNfc.matches.length >= 1 && rNfd.matches.length >= 1);

	let refusedNoPw = false;
	try { await vdisk.searchNames(v, { query: 'notes' }); } catch (e) { refusedNoPw = /not mounted/i.test(e.message); }
	ok('an unmounted vault refuses to search without a password', refusedNoPw);

	// --- Mounted search (no password) — needs a mount driver ---
	const drv = await require('../Driver').detect().catch(() => ({ ok: false }));
	if (drv && drv.ok) {
		const mp = path.join(tmp, 'mnt');
		let m = null;
		try { m = await vdisk.mount(v, { password: 'pw1', mountpoint: mp }); } catch (e) { console.log('  skip  mounted search (mount failed: ' + (e && e.message || e) + ')'); }
		if (m && m.mountpoint) {
			try {
				// Once the vault is actually mounted, a search MUST succeed — an error here is a real failure, not a
				// skip (a prior refactor broke the mounted search path and a catch-to-skip here hid the regression).
				const r = await vdisk.searchNames(v, { query: 'photo' }); // NO password
				ok('a mounted vault searches with no password', r.mounted === true && r.matches.some(x => x === 'sub/photo.jpg'));
			} catch (e) { ok('a mounted vault searches with no password (threw: ' + (e && e.message || e) + ')', false); }
			finally { await vdisk.unmount(m.mountpoint).catch(() => {}); }
		}
	} else { console.log('  skip  mounted search (no mount driver)'); }

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SEARCH CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
