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

	// --- the shutdown handler runs the registered tasks and exits cleanly on a stop signal ---
	const marker = path.join(os.tmpdir(), 'vdisk-procreg-' + process.pid + '-' + Date.now());
	const svc = spawn(process.execPath, [path.join(__dirname, '_procshutdownchild.js'), marker], { stdio: ['ignore', 'pipe', 'ignore'] });
	await new Promise((res) => { let buf = ''; svc.stdout.on('data', d => { buf += d; if (buf.includes('ready')) res(); }); });
	const svcExit = new Promise(res => svc.once('exit', (code, sig) => res({ code, sig })));
	svc.kill('SIGTERM');
	const result = await Promise.race([svcExit, wait(5000).then(() => ({ code: null, sig: 'TIMEOUT' }))]);
	ok('the service exits cleanly (code 0) on SIGTERM', result.code === 0);
	ok('the registered shutdown task ran during the stop', (() => { try { return fs.readFileSync(marker, 'utf8') === 'shutdown-ran'; } catch (_) { return false; } })());
	try { fs.rmSync(marker, { force: true }); } catch (_) {}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PROC-REGISTRY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
