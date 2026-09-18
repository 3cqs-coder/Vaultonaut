'use strict';
// lib/test/bakeengine.js — guards the BUILD-TIME engine bake (docker/bake-engine.js), the script the container's
// builder stage runs to place a checksum-verified engine and its license into the image. Two properties matter and
// neither is reachable from the normal unit suite:
//   1. it FAILS CLOSED when misconfigured — no target directory means a hard error and a non-zero exit, never a
//      silent build that ships an image with no engine;
//   2. it is a true OFFLINE NO-OP when a valid engine and license are already present — the path that lets a fully
//      air-gapped build (engine pre-placed) succeed without fetching the license. This exercises the skip-if-present
//      branch added to bake-engine.js.
// Skips the offline-no-op case cleanly when no engine can be primed on this host.
//
// Run:  node -r ./lib/test/_setup.js lib/test/bakeengine.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const { spawnSync } = require('child_process');
const Common = require('../Common');
const RcloneSetup = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const REPO = path.join(__dirname, '..', '..');
const BAKE = path.join(REPO, 'docker', 'bake-engine.js');
// A plausible MIT license body: long enough and carrying the phrase the bake validates, so a pre-placed copy is
// accepted as-is and no fetch is attempted.
const VALID_LICENSE = 'MIT License\n\nCopyright (c) rclone contributors\n\n' +
	'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated ' +
	'documentation files (the "Software"), to deal in the Software without restriction, including without limitation ' +
	'the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and ' +
	'to permit persons to whom the Software is furnished to do so, subject to the following conditions. The above ' +
	'copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.';

async function main() {
	// 1. FAIL CLOSED: no VAULTONAUT_ENGINE_DIR → non-zero exit and a clear message. Strip the variable from the child's
	//    environment (a test process would not have it, but be explicit) so the guard is what trips.
	const env0 = { ...process.env };
	delete env0.VAULTONAUT_ENGINE_DIR;
	const miss = spawnSync(process.execPath, [BAKE], { cwd: REPO, encoding: 'utf8', env: env0 });
	ok('the bake fails closed when no target directory is set (non-zero exit)', miss.status !== 0);
	ok('the bake explains why it failed (the target directory must be set)', /VAULTONAUT_ENGINE_DIR/.test((miss.stderr || '') + (miss.stdout || '')));

	// 2. OFFLINE NO-OP: prime the real engine, copy it and its sidecars into a throwaway dir alongside a valid license,
	//    then run the bake pointed there. With a verified engine and a present license it must exit 0 without fetching.
	const primed = await RcloneSetup.ensure().catch(() => ({ ok: false }));
	if (!primed.ok) { console.log('  skip  (no engine could be primed; skipping the offline-no-op case)'); return finish(); }

	const srcBin = path.join(Common.binDir(), Common.exeName('rclone'));
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-bake-'));
	try {
		const dstBin = path.join(tmp, Common.exeName('rclone'));
		await fsp.copyFile(srcBin, dstBin);
		if (process.platform !== 'win32') { try { await fsp.chmod(dstBin, 0o755); } catch (_) {} } // copyFile may drop the +x bit; works() must be able to run it
		for (const ext of ['.sha256', '.tag']) { try { await fsp.copyFile(srcBin + ext, dstBin + ext); } catch (_) {} }
		await fsp.writeFile(path.join(tmp, 'rclone-LICENSE.txt'), VALID_LICENSE);

		const run = spawnSync(process.execPath, [BAKE], { cwd: REPO, encoding: 'utf8', env: { ...process.env, VAULTONAUT_ENGINE_DIR: tmp } });
		const out = (run.stdout || '') + (run.stderr || '');
		ok('the bake is a clean no-op when a verified engine and license are already present (exit 0)', run.status === 0);
		ok('the bake reports it fetched nothing on the offline path', /nothing fetched/i.test(out));
		ok('the pre-placed license is left intact (not overwritten)', (await fsp.readFile(path.join(tmp, 'rclone-LICENSE.txt'), 'utf8')) === VALID_LICENSE);
	} finally {
		await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	}
	finish();
}

function finish() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BAKE-ENGINE CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
