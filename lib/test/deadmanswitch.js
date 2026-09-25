'use strict';
// lib/test/deadmanswitch.js — the cross-platform dead-man's switch that stops a supervised service from ever being
// orphaned. A service spawned as a supervised child (piped stdin + VDISK_SUPERVISED) watches its stdin; when the parent
// goes away by ANY means, the OS closes that stdin, and the child drains and exits on its own. This is what prevents the
// leaked-service processes an interrupted test run used to leave behind. The mechanism check spawns a real child, closes
// its stdin, and asserts it exits without being signaled; the rest pins the env flag and the wiring.
//
// Run:  node lib/test/deadmanswitch.js

const cp = require('child_process');
const path = require('path');
const fs = require('fs');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');

async function main() {
	console.log('[Common.isSupervisedChild / supervisedChildEnv]');
	{
		const saved = process.env[Common.SUPERVISED_ENV];
		try {
			delete process.env[Common.SUPERVISED_ENV];
			ok('isSupervisedChild is false without the flag', Common.isSupervisedChild() === false);
			process.env[Common.SUPERVISED_ENV] = '1';
			ok('isSupervisedChild is true with VDISK_SUPERVISED=1', Common.isSupervisedChild() === true);
			ok('supervisedChildEnv sets the flag for a spawned child', Common.supervisedChildEnv({ PATH: 'x' })[Common.SUPERVISED_ENV] === '1');
			ok('supervisedChildEnv preserves the base env', Common.supervisedChildEnv({ PATH: 'x' }).PATH === 'x');
		} finally { if (saved === undefined) delete process.env[Common.SUPERVISED_ENV]; else process.env[Common.SUPERVISED_ENV] = saved; }
	}

	console.log('[mechanism: a watched child exits when its stdin closes — no signal sent]');
	{
		// The child arms the same watch the service uses, then stays alive on a timer. Closing its stdin from here (as the
		// OS does automatically when a parent dies) must make it exit on its own. We never signal it — proving the exit
		// came from the dead-man's switch, not from a kill.
		const code = "const P=require(" + JSON.stringify(path.join(ROOT, 'lib', 'ProcRegistry')) + ");P.installShutdownHandlers();P.watchStdinForQuit();setInterval(function(){}, 1000);process.stdout.write('ready\\n');";
		const child = cp.spawn(process.execPath, ['-e', code], { stdio: ['pipe', 'pipe', 'ignore'] });
		let ready = false; child.stdout.on('data', (d) => { if (String(d).indexOf('ready') >= 0) ready = true; });
		let exited = null; child.on('exit', (c) => { exited = c; });
		// Wait for the child to be up and watching.
		for (let i = 0; i < 40 && !ready; i++) await new Promise(r => setTimeout(r, 50));
		ok('the supervised child started and armed the watch', ready === true);
		ok('the child is still alive before its stdin closes', exited === null && Common.isProcessAlive(child.pid));
		// Close its stdin — the exact signal the OS delivers when a parent dies. Do NOT kill it.
		child.stdin.end();
		for (let i = 0; i < 100 && exited === null; i++) await new Promise(r => setTimeout(r, 50));
		ok('the child exits on its own when stdin closes (dead-man switch fired)', exited !== null);
		ok('it exited cleanly (code 0), not by a signal', exited === 0);
		if (exited === null) { try { child.kill('SIGKILL'); } catch (_) {} } // never leak the test child if the mechanism regressed
	}

	console.log('[wiring: the service arms the watch when supervised; the test spawner opts in]');
	{
		const idx = fs.readFileSync(path.join(ROOT, 'lib', 'webserver', 'index.js'), 'utf8');
		ok('the service arms watchStdinForQuit for a supervised child (not only the desktop app)', /isDesktopApp\(\)\s*\|\|\s*Common\.isSupervisedChild\(\)\)\s*ProcRegistry\.watchStdinForQuit\(\)/.test(idx));
		const own = fs.readFileSync(path.join(ROOT, 'lib', 'test', 'ownermount.js'), 'utf8');
		ok('the ownermount test spawns its service with a piped stdin', /stdio:\s*\[\s*'pipe'/.test(own));
		ok('the ownermount test marks the spawn supervised', /env:\s*Common\.supervisedChildEnv\(\)/.test(own));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DEAD-MAN-SWITCH CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
