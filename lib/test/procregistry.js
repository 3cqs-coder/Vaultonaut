'use strict';
// lib/test/procregistry.js — the child-process registry that keeps the tool from orphaning processes. Every
// short-lived child is tracked; killAll must terminate them all (so nothing is left running when the tool exits),
// a child that ends on its own must drop out of tracking (so killAll never targets a dead process), and the
// one-time shutdown handler must run the registered cleanup tasks and exit cleanly on a stop signal.
//
// Run:  node lib/test/procregistry.js  (no engine; spawns short-lived node children)

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const P = require('../ProcRegistry');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
	// --- killAll terminates a tracked child (never orphan) ---
	const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
	P.track(child);
	await wait(200);
	const exited = new Promise(res => child.once('exit', () => res(true)));
	const n = P.killAll('SIGKILL');
	ok('killAll reports it killed at least the tracked child', n >= 1);
	ok('the tracked child is actually terminated', await Promise.race([exited, wait(3000).then(() => false)]));

	// --- a child that exits on its own drops out of tracking ---
	const quick = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' }); // exits immediately
	P.track(quick);
	// track() removes the child on its 'close' event; register ours AFTER track's, so by the time this resolves the
	// registry has already dropped it — no fixed-time sleep, no race.
	await new Promise(res => quick.once('close', res));
	ok('killAll no longer targets a child that already exited', P.killAll('SIGKILL') === 0);

	// --- the shutdown handler runs the registered tasks and exits cleanly on a stop request ---
	// There are two clean-stop channels. The packaged desktop app stops its backend by writing a "quit" line on the
	// child's stdin (and stdin EOF if the shell dies); this is the ONLY clean-stop channel on Windows, where a
	// windowless child cannot honor a stop signal — child.kill('SIGTERM') there maps to an immediate
	// TerminateProcess, killing the child before any handler runs. A headless service under a POSIX supervisor is
	// stopped by a real SIGTERM. Test the stdin channel on every platform (it is what the app actually uses, and it
	// works everywhere), and the signal channel only off Windows, where signals are real.
	let seq = 0;
	async function checkCleanStop(label, stdin, args, trigger) {
		const marker = path.join(os.tmpdir(), 'vdisk-procreg-' + process.pid + '-' + Date.now() + '-' + (seq++));
		const svc = spawn(process.execPath, [path.join(__dirname, '_procshutdownchild.js'), marker, ...args], { stdio: [stdin, 'pipe', 'ignore'] });
		if (svc.stdin) svc.stdin.on('error', () => {}); // the child closing its read end after exit must not crash the test
		await new Promise((res) => { let buf = ''; svc.stdout.on('data', d => { buf += d; if (buf.includes('ready')) res(); }); });
		const svcExit = new Promise(res => svc.once('exit', (code, sig) => res({ code, sig })));
		try { trigger(svc); } catch (_) {}
		const result = await Promise.race([svcExit, wait(5000).then(() => ({ code: null, sig: 'TIMEOUT' }))]);
		ok('[' + label + '] the service exits cleanly (code 0)', result.code === 0);
		ok('[' + label + '] the registered shutdown task ran during the stop', (() => { try { return fs.readFileSync(marker, 'utf8') === 'shutdown-ran'; } catch (_) { return false; } })());
		try { fs.rmSync(marker, { force: true }); } catch (_) {}
	}

	// The desktop shell's stdin "quit" line — the cross-platform clean-stop channel (and the only one on Windows).
	await checkCleanStop('stdin quit', 'pipe', ['--watch-stdin'], (svc) => svc.stdin.write('quit\n'));
	// A real stop signal — POSIX only; Windows has no deliverable SIGTERM a child can drain on.
	if (process.platform !== 'win32') {
		await checkCleanStop('SIGTERM', 'ignore', [], (svc) => svc.kill('SIGTERM'));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PROC-REGISTRY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
