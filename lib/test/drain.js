'use strict';
// lib/test/drain.js — the drain-before-unmount durability protocol (lib/Rclone.js drain). It must wait until BOTH
// the write-back queue (vfs/stats) and in-flight transfers (core/stats) are idle before a teardown, defer (return
// false) if they never settle, treat a vanished engine as 'engine-gone' (cache must be preserved, not wiped), and
// treat "no control channel" as 'drained' (the caller handles the fallback). This drives the REAL drain loop and the
// real `rclone rc` client against a Node HTTP mock on a unix socket that speaks the rc responses — so the protocol
// and timeout logic are covered without a live mount/driver. POSIX only (the mount's control endpoint is a unix
// socket on macOS/Linux; Windows uses a TCP endpoint and is exercised end-to-end elsewhere).
//
// Run:  node lib/test/drain.js

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const Rclone = require('../Rclone');
const RcloneSetup = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DRAIN CHECKS PASSED')); process.exitCode = failures ? 1 : 0; }

// A mock rc endpoint: a unix-socket HTTP server whose vfs/stats and core/stats answers follow a mutable `state`, so
// a test can drive it from busy to idle mid-drain, exactly as a real mount's control channel would report.
function startMock(state) {
	const sock = path.join(os.tmpdir(), 'vd-drain-' + process.pid + '-' + Math.random().toString(16).slice(2, 8) + '.sock');
	try { fs.unlinkSync(sock); } catch (_) {}
	const srv = http.createServer((req, res) => {
		let b = ''; req.on('data', c => b += c); req.on('end', () => {
			let out = '{}';
			if (req.url === '/vfs/stats') out = JSON.stringify({ diskCache: { uploadsInProgress: 0, uploadsQueued: state.busy ? 3 : 0 } });
			else if (req.url === '/core/stats') out = JSON.stringify(state.busy ? { transferring: [{ name: 'x' }] } : { bytes: 0 });
			res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(out);
		});
	});
	return new Promise((resolve) => srv.listen(sock, () => resolve({ sock, close: () => { try { srv.close(); } catch (_) {} try { fs.unlinkSync(sock); } catch (_) {} } })));
}

async function main() {
	if (process.platform === 'win32') { console.log('  skip  (unix-socket mock is POSIX; Windows uses a TCP endpoint)'); return done(); }
	let bin; try { bin = (await RcloneSetup.ensure()).rclone; } catch (_) { bin = null; }
	if (!bin) { console.log('  skip  (bundled engine not available)'); return done(); }
	const alive = { pid: process.pid }; // a live engine (this process) so the "engine gone" early-out never trips

	// 1) No control channel -> 'drained' (the caller then handles the fallback).
	ok("no endpoint returns 'drained'", (await Rclone.drain(bin, null, alive, 2000)) === 'drained');

	// 2) Both channels idle from the start -> 'drained'.
	{
		const m = await startMock({ busy: false });
		try { ok("both channels idle returns 'drained'", (await Rclone.drain(bin, m.sock, alive, 30000)) === 'drained'); }
		finally { m.close(); }
	}

	// 3) Busy first, then idle -> waits, reports progress, then 'drained'.
	{
		const state = { busy: true };
		const m = await startMock(state);
		setTimeout(() => { state.busy = false; }, 1500); // flip to idle mid-drain
		let sawProgress = false;
		try {
			const r = await Rclone.drain(bin, m.sock, alive, 30000, (p) => { if (p > 0) sawProgress = true; });
			ok("busy-then-idle returns 'drained'", r === 'drained');
			ok('progress was reported while busy', sawProgress);
		} finally { m.close(); }
	}

	// 4) Never settles -> false (the caller DEFERS the unmount rather than lose data).
	{
		const m = await startMock({ busy: true });
		try { ok('never-idle returns false (defer, do not tear down)', (await Rclone.drain(bin, m.sock, alive, 2500)) === false); }
		finally { m.close(); }
	}

	// 5) Engine gone mid-wait -> 'engine-gone' (safe to tear down, but preserve the cache — it was not a clean flush).
	{
		const m = await startMock({ busy: true });
		try { ok("a vanished engine returns 'engine-gone'", (await Rclone.drain(bin, m.sock, { pid: 2 ** 30 }, 5000)) === 'engine-gone'); }
		finally { m.close(); }
	}

	done();
}

main().catch(e => { console.error(e); process.exitCode = 1; });
