'use strict';
// lib/test/servewatch.js — the served-node crash-restart supervisor (Serve.superviseWebdav). A served node must
// self-heal: if the engine process dies unexpectedly, the supervisor restarts it on the SAME port and credentials
// (so a client's saved peer keeps working); and an intentional stop() must NOT trigger a restart (no orphaned open
// endpoint). This drives the supervisor with a tiny fake "engine" whose behavior a control file steers — no real
// rclone, no network peer — so a death and its restart happen deterministically.
//
// POSIX only: the fake engine is a shebang script the supervisor exec()s as the bin; Windows cannot exec a
// shebang, and the supervisor logic under test is platform-agnostic, so it is skipped there.
//
// Run:  node lib/test/servewatch.js

const os = require('os');
const net = require('net');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Serve = require('../Serve');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function connects(port) { return new Promise((resolve) => { const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); }); s.once('error', () => { s.destroy(); resolve(false); }); }); }
function waitEvent(events, type, ms = 6000) { const t0 = Date.now(); return (async () => { while (Date.now() - t0 < ms) { if (events.some(e => e.type === type)) return true; await sleep(50); } return false; })(); }

let workspace = null;
async function cleanupWs() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

async function main() {
	if (process.platform === 'win32') { console.log('Windows cannot exec a shebang fixture — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-servewatch-')); workspace = tmp;
	const ctrl = path.join(tmp, 'mode'); // the fake engine reads its behavior from here on each (re)spawn
	// The fake "engine": ignore the rclone args except --addr, then behave per the control file. `up` = listen and
	// stay up; `die:<ms>` = listen, then exit after <ms> (an unexpected death the supervisor must recover).
	const bin = path.join(tmp, 'fake-engine.js');
	await fsp.writeFile(bin, '#!/usr/bin/env node\n' + `
const net = require('net'), fs = require('fs');
const a = process.argv; const addr = a[a.indexOf('--addr') + 1] || '127.0.0.1:0';
const [host, port] = addr.split(':');
let mode = 'up'; try { mode = fs.readFileSync(process.env.CTRL, 'utf8').trim(); } catch (_) {}
const s = net.createServer(c => c.destroy());
s.listen(Number(port), host, () => { if (mode.indexOf('die:') === 0) setTimeout(() => process.exit(1), Number(mode.slice(4))); });
process.on('SIGTERM', () => process.exit(0));
`, { mode: 0o755 });
	process.env.CTRL = ctrl;

	// --- crash → restart on the same port ---
	await fsp.writeFile(ctrl, 'die:400'); // the first serve comes up, then dies after 400ms
	const events = [];
	const h = await Serve.superviseWebdav(bin, path.join(tmp, 'vault'), { onEvent: (e) => events.push(e) });
	const port = h.port;
	ok('the supervised serve comes up on a fixed port', await connects(port));
	await fsp.writeFile(ctrl, 'up'); // make the RESTART stay up
	ok('an unexpected death is observed (down)', await waitEvent(events, 'down'));
	ok('the supervisor schedules a restart (restarting)', await waitEvent(events, 'restarting'));
	ok('the restart comes back up', await waitEvent(events, 'up', 8000));
	await sleep(300);
	ok('the restarted serve listens on the SAME pinned port', await connects(port));
	ok('the port and credentials are stable across the restart', h.port === port && !!h.user && !!h.pass);
	await h.stop();
	ok('after stop() nothing is listening on the port', !(await connects(port)));

	// --- stop() prevents any further restart ---
	await fsp.writeFile(ctrl, 'die:400');
	const ev2 = [];
	const h2 = await Serve.superviseWebdav(bin, path.join(tmp, 'vault'), { onEvent: (e) => ev2.push(e) });
	const p2 = h2.port;
	ok('the second supervised serve comes up', await connects(p2));
	await h2.stop();                 // intentional stop BEFORE the fixture's death timer fires
	await sleep(1800);               // past the die (400ms) + the first backoff (~1s)
	// Only a RESTART emits 'up' (the initial start does not), so a supervisor stopped before any restart must have
	// emitted no 'up' at all — proof it did not respawn the engine after the intentional stop.
	ok('a stopped supervisor never restarts (no restart "up" event)', ev2.filter(e => e.type === 'up').length === 0);
	ok('the port is free after an intentional stop (no orphaned endpoint)', !(await connects(p2)));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SERVE-WATCH CHECKS PASSED'));
	await cleanupWs();
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); await cleanupWs(); process.exit(1); });
