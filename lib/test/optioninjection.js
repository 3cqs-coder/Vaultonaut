'use strict';
// lib/test/optioninjection.js — engine spawns must never let a config-controlled path be read as a command-line
// OPTION ("option smuggling"). A mount point, cache directory, volume name, or served folder that began with "-"
// would be handed to the bundled engine as a flag instead of a path. These are always real paths or a label, so a
// leading "-" is never legitimate — the spawn guards reject it BEFORE the engine is launched. Pure and fast: each
// guard throws synchronously (well, before any spawn), so no engine, mount driver, or network is needed.
//
// Run:  node lib/test/optioninjection.js

const Rclone = require('../Rclone');
const Serve = require('../Serve');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function rejects(p, re) { try { await p; return false; } catch (e) { return re.test(e.message); } }

async function main() {
	const BIN = '/nonexistent/rclone'; // never actually spawned: the guard throws first

	// --- mount: the mount point, cache dir, and volume name are all rejected when they start with "-" ---
	ok('a mount point starting with "-" is refused', await rejects(
		Rclone.spawnMount(BIN, { configPath: '/tmp/x.conf', mountpoint: '-o' }), /may not start with "-"/));
	ok('a cache directory starting with "-" is refused', await rejects(
		Rclone.spawnMount(BIN, { configPath: '/tmp/x.conf', mountpoint: '/tmp/mnt', cacheDir: '--foo' }), /may not start with "-"/));
	ok('a volume name starting with "-" is refused', await rejects(
		Rclone.spawnMount(BIN, { configPath: '/tmp/x.conf', mountpoint: '/tmp/mnt', volname: '-bad' }), /may not start with "-"/));

	// --- the guard is specifically about a LEADING dash: a normal absolute path passes the guard (it then fails later
	//     trying to launch the nonexistent engine — NOT with the guard message, proving the guard let it through) ---
	const normalErr = await Rclone.spawnMount(BIN, { configPath: '/tmp/x.conf', mountpoint: '/tmp/mnt' }).then(() => '', e => e.message);
	ok('a normal mount point passes the option guard (fails later, not on the guard)', !/may not start with "-"/.test(normalErr));

	// --- serve: the served folder path is guarded the same way ---
	ok('a served folder starting with "-" is refused', await rejects(
		Serve.serveWebdav(BIN, '-x'), /may not start with "-"/));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OPTION-INJECTION CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(1); });
