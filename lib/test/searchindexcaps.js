'use strict';
// lib/test/searchindexcaps.js — the search reindex has two fail-CLOSED ceilings that protect a large or pathological
// vault, and BOTH must refuse rather than destroy the existing index:
//   • the file-COUNT ceiling (MAX_INDEX_FILES): past it, the partial scan map would mark every un-scanned file
//     "removed" and gut the index, so the reindex must stop and keep the last good index untouched (tooManyFiles).
//   • the index-BYTE ceiling (MAX_SEARCH_INDEX_BYTES): if the freshly built index would inflate past it, persisting it
//     would make every future load fail the gunzip cap and rebuild from scratch forever, so the write is refused and
//     the last loadable index is kept (indexTooLarge).
// Both are otherwise untested (they need millions of files / a huge index in normal use). This drives the reindex
// handler in-process over a plain directory with the ceilings temporarily lowered, and asserts each refuses AND leaves
// the on-disk index exactly as it was. No mount driver, no engine.
//
// Run:  node lib/test/searchindexcaps.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const D = require('../SearchDefs');
const SW = require('../SearchWorker');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const noop = () => {};

async function main() {
	const idx = SW._handlers.index;
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-sic-'));
	const indexPath = path.join(tmp, D.SEARCH_DIR, D.INDEX_NAME);
	try {
		// Seed a few indexable text files and build a first, good index.
		for (let i = 0; i < 4; i++) await fsp.writeFile(path.join(tmp, 'doc' + i + '.txt'), 'hello world document number ' + i + ' with some searchable words');
		const first = await idx({ mountpoint: tmp }, noop);
		ok('a normal reindex builds an index (files added)', first && first.added === 4 && !first.tooManyFiles && !first.indexTooLarge);
		ok('the index file was written', fs.existsSync(indexPath));
		const goodBytes = await fsp.readFile(indexPath);

		// --- file-COUNT ceiling: lower it below the file count; the reindex must refuse and NOT gut the index. ---
		const savedFiles = D.MAX_INDEX_FILES;
		D.MAX_INDEX_FILES = 2; // below the 4 files present
		let tmf;
		try { tmf = await idx({ mountpoint: tmp }, noop); } finally { D.MAX_INDEX_FILES = savedFiles; }
		ok('past the file-count ceiling the reindex reports tooManyFiles', tmf && tmf.tooManyFiles === true);
		ok('past the file-count ceiling nothing is marked removed (index not gutted)', tmf.removed === 0 && tmf.added === 0 && tmf.changed === 0);
		ok('past the file-count ceiling the on-disk index is left exactly as it was', (await fsp.readFile(indexPath)).equals(goodBytes));

		// --- index-BYTE ceiling: lower it below the envelope size; the reindex must refuse to persist and keep the
		//     last good index. (A tiny cap also fails the existing-index READ, so this exercises the write-side refusal
		//     on a fresh build — exactly the "would inflate past the cap" case.) ---
		const savedBytes = D.MAX_SEARCH_INDEX_BYTES;
		D.MAX_SEARCH_INDEX_BYTES = 64; // far below any real index
		let itl;
		try { itl = await idx({ mountpoint: tmp }, noop); } finally { D.MAX_SEARCH_INDEX_BYTES = savedBytes; }
		ok('past the index-byte ceiling the reindex reports indexTooLarge', itl && itl.indexTooLarge === true);
		ok('past the index-byte ceiling the on-disk index is left exactly as it was (not overwritten with nothing)', (await fsp.readFile(indexPath)).equals(goodBytes));

		// Sanity: with the ceilings restored, a reindex is clean again (no destructive after-effect from the tests).
		const back = await idx({ mountpoint: tmp }, noop);
		ok('with the ceilings restored the reindex is healthy again', back && !back.tooManyFiles && !back.indexTooLarge);
	} finally {
		await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SEARCH-INDEX-CAPS CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
