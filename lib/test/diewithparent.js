'use strict';
// lib/test/diewithparent.js — the supervised backend must DIE WITH ITS PARENT. The packaged desktop shell launches the
// Node backend as a child with a piped stdin; when the shell goes away by ANY means — a clean quit, a Force-Quit, a
// crash, a power loss — the OS closes that stdin's write end and the child hits EOF. ProcRegistry.watchStdinForQuit
// treats that EOF exactly like a stop request and runs the graceful drain-and-lock, so a force-terminated shell can
// never orphan a backend that keeps the loopback port and the user's vaults mounted. Without this, orphaned mounts
// accumulate (the next launch finds the vault's path in use and stacks a suffixed mount), which is the leak this guards.
//
// The test drives the REAL ProcRegistry: it spawns a child that registers a drain task and calls watchStdinForQuit,
// then closes the child's stdin — the exact EOF a dying parent produces — and asserts the child ran its drain and
// exited on its own. Deterministic and engine-free (the drain task just writes a marker), cross-platform (stdin EOF is
// the same signal on macOS, Linux, and Windows). Run twice-over as its own child via a flag, so it needs no fixtures.
//
// Run:  node lib/test/diewithparent.js

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

// ── Child mode: behave like the supervised desktop backend, then let stdin EOF drive the shutdown ──────────────────
if (process.argv[2] === '--child') {
	const PR = require('../ProcRegistry');
	const marker = process.env.DWP_MARKER;
	PR.onShutdown(async () => { try { fs.writeFileSync(marker, 'drained-and-locked'); } catch (_) {} }); // stand-in for unmountAll
	PR.installShutdownHandlers();
	PR.watchStdinForQuit(); // active here because VDISK_SUPERVISED=1 makes isSupervisedChild() true (see Common)
	setInterval(() => {}, 1000); // stay alive until the parent's stdin EOF (or a real signal) triggers the drain
	try { process.stdout.write('child-ready\n'); } catch (_) {}
	return;
}

// ── Parent mode: the test proper ───────────────────────────────────────────────────────────────────────────────────
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function runEofDrains() {
	return new Promise((resolve) => {
		const marker = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-dwp-')), 'marker');
		const child = spawn(process.execPath, [__filename, '--child'], {
			stdio: ['pipe', 'pipe', 'ignore'],
			env: { ...process.env, VDISK_SUPERVISED: '1', DWP_MARKER: marker },
		});
		let done = false;
		const finish = (drained, exited) => { if (done) return; done = true; clearTimeout(to); resolve({ drained, exited }); };
		child.stdout.on('data', (d) => { if (String(d).includes('child-ready')) { try { child.stdin.end(); } catch (_) {} } }); // close stdin = the EOF a dying parent produces
		child.once('exit', () => { let drained = false; try { drained = fs.readFileSync(marker, 'utf8') === 'drained-and-locked'; } catch (_) {} finish(drained, true); });
		const to = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} finish(false, false); }, 15000);
		if (to.unref) to.unref();
	});
}

async function main() {
	const r = await runEofDrains();
	ok('a supervised backend runs its drain-and-lock when its parent goes away (stdin EOF)', r.drained);
	ok('and it then exits on its own, so nothing is orphaned', r.exited);

	// Source guards: the mechanism must stay wired — the backend must watch stdin when it is the desktop/supervised
	// child, and the watcher must treat stdin EOF (not only a "quit" line) as a shutdown, or a dying parent would
	// silently orphan it.
	const pr = fs.readFileSync(path.join(__dirname, '..', 'ProcRegistry.js'), 'utf8');
	ok("watchStdinForQuit treats stdin EOF ('end') as a graceful shutdown", /process\.stdin\.on\('end', \(\) => gracefulExit\(0\)\)/.test(pr));
	const server = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the backend arms the stdin watcher when it is the desktop or a supervised child', /if \(Common\.isDesktopApp\(\) \|\| Common\.isSupervisedChild\(\)\) ProcRegistry\.watchStdinForQuit\(\)/.test(server));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DIE-WITH-PARENT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
