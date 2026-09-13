'use strict';
// lib/test/enginedownload.js — the engine setup must not launch two concurrent downloads of the same ~30 MB binary,
// and must clean up a temp orphaned by a prior hard-killed download. Two independent callers reach RcloneSetup.ensure
// (the background auto-installer startEngineSetup, and a real operation's ensureEngine); without coalescing they each
// launched a full download that raced, wasting bandwidth and — if the process was killed mid-download — leaving an
// orphaned temp in the bin dir. This pins the single-flight coalescing (statically, since a live test would download)
// and exercises the orphan sweep (behaviorally, age-gated so a still-writing temp is never removed).
//
// Run:  node lib/test/enginedownload.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const RcloneSetup = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// 1. SOURCE GUARD: ensure() coalesces concurrent callers through an in-flight map into a single ensureImpl run,
	//    keyed so a --latest install never shares a pinned run. A regression that drops this reintroduces the race.
	const src = fs.readFileSync(path.join(__dirname, '..', 'RcloneSetup.js'), 'utf8');
	ok('ensure() coalesces concurrent calls via an in-flight map', /_ensureInFlight = new Map\(\)/.test(src) && /function ensure\(opts[\s\S]{0,260}_ensureInFlight\.get\(key\)[\s\S]{0,160}ensureImpl\(opts\)/.test(src));
	ok('the coalescing key separates a --latest run from a pinned run', /opts && opts\.latest \? 'latest' : 'pinned'/.test(src));
	ok('a fresh download sweeps orphaned temps first', /sweepDownloadTemps\(dir\)/.test(src));

	// 2. BEHAVIORAL: the orphan sweep removes an OLD download/extract temp but keeps a fresh one (age-gated) and leaves
	//    real files alone.
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-enginedl-'));
	try {
		const oldZip = path.join(tmp, '_rclone_download.99999-abc.zip');
		const oldPart = path.join(tmp, '_rclone_download.99999-abc.zip.part-99999-1-deadbeef');
		const oldExtract = path.join(tmp, '_rclone_extract.99999-abc');
		const freshZip = path.join(tmp, '_rclone_download.11111-xyz.zip');
		const realBinary = path.join(tmp, 'rclone');
		await fsp.writeFile(oldZip, 'x'); await fsp.writeFile(oldPart, 'x'); await fsp.mkdir(oldExtract); await fsp.writeFile(freshZip, 'x'); await fsp.writeFile(realBinary, 'x');
		// Backdate the "old" temps well past the 30-minute sweep age; leave the fresh one and the real binary at "now".
		const old = new Date(Date.now() - 40 * 60 * 1000);
		for (const p of [oldZip, oldPart, oldExtract]) await fsp.utimes(p, old, old);

		await RcloneSetup._test.sweepDownloadTemps(tmp);

		ok('an old orphaned download temp is swept', !fs.existsSync(oldZip));
		ok('an old orphaned .part temp is swept', !fs.existsSync(oldPart));
		ok('an old orphaned extract dir is swept', !fs.existsSync(oldExtract));
		ok('a FRESH download temp is NOT swept (age-gated, could still be writing)', fs.existsSync(freshZip));
		ok('the real engine binary is never touched', fs.existsSync(realBinary));
	} finally { await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-DOWNLOAD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
