'use strict';
// lib/test/ownermount.js — the CLI routes mount/unmount through a RUNNING owner (the web/background service)
// so both paths finalize the tamper session identically, and falls back to a direct in-process mount when no
// owner is running. Uses REAL separate processes: a spawned service, then `vdisk mount/unmount` as their own
// child processes, exactly as a user runs them.
//
// Run:  node lib/test/ownermount.js   (needs the bundled engine)

const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const cp = require('child_process');
const vdisk = require('../index');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const ROOT = path.join(__dirname, '..', '..');
const PORT = 7798;
const PW = 'ownertest123';
// Child processes must share this test's data/engine directory, not the real per-user one. The isolation preload
// pins both, so spawn every child with `-r _setup.js` — otherwise the spawned service and CLI would use the
// production data dir while this parent uses .test-data, and owner discovery (the service.pid handshake) would
// never line up. See lib/test/_setup.js.
const SETUP = path.join(__dirname, '_setup.js');

// Run the real CLI as a child process, feeding the password on stdin when needed. Returns { code, out }.
function runCli(args, input) {
	return new Promise((resolve) => {
		const c = cp.spawn('node', ['-r', SETUP, path.join(ROOT, 'vaultonaut.js'), ...args], { cwd: ROOT });
		let out = '';
		c.stdout.on('data', (d) => out += d); c.stderr.on('data', (d) => out += d);
		if (input != null) { c.stdin.write(input); c.stdin.end(); }
		c.on('close', (code) => resolve({ code, out }));
	});
}
async function ownerOf(mp) { const st = await vdisk.status().catch(() => []); const e = (st || []).find(x => path.resolve(x.mountpoint) === path.resolve(mp)); return e ? String(e.owner || '') : null; }

(async () => {
	const pidFile = path.join(Common.runDir(), 'service.pid');
	let savedPid = null; try { savedPid = await fsp.readFile(pidFile, 'utf8'); } catch (_) {}
	// If a real service is already running, don't disturb it — skip rather than clobber its pidfile.
	if (savedPid) { try { const r = JSON.parse(savedPid); if (r.pid && Common.isProcessAlive(r.pid)) { console.log('  ok   skipped (a service is already running; not disturbing it)'); process.exit(0); } } catch (_) {} }

	const base = await fsp.mkdtemp(path.join(require('os').tmpdir(), 'vdisk-owner-'));
	const vault = path.join(base, 'O.vault');
	const mp = path.join(base, 'mnt');
	let svc = null;
	try {
		await vdisk.create(vault, { password: PW });

		// ── Part 1: with a running owner, the CLI delegates and the session finalizes cleanly ──
		svc = cp.spawn('node', ['-r', SETUP, '-e', "require('" + ROOT.replace(/\\/g, '\\\\') + "/lib/webserver').start(" + PORT + ").catch(e=>{console.error(e);process.exit(1)})"], { cwd: ROOT, stdio: 'ignore' });
		let url = null;
		for (let i = 0; i < 80 && !url; i++) { try { const r = JSON.parse(await fsp.readFile(pidFile, 'utf8')); if (r.url && r.pid && Common.isProcessAlive(r.pid)) url = r.url; } catch (_) {} if (!url) await sleep(250); }
		ok('the owner advertises a loopback control url', !!url && /^http:\/\/127\.0\.0\.1:/.test(url));

		let r = await runCli(['mount', vault, '--mountpoint', mp], PW + '\n');
		const owner1 = await ownerOf(mp);
		ok('a CLI mount is owned by the running service (delegated)', /^ui:/.test(owner1 || ''));

		await fsp.writeFile(path.join(mp, 'a.txt'), 'hello', { mode: 0o600 });
		r = await runCli(['unmount', mp], null);
		ok('the CLI unmount succeeds (routed to the owner)', /Unmounted /.test(r.out));
		await sleep(400);

		r = await runCli(['mount', vault, '--mountpoint', mp], PW + '\n');
		ok('the remount is clean — the owner finalized the session (no "interrupted" notice)', !/not closed cleanly|Changes from your last session/i.test(r.out));
		await runCli(['unmount', mp], null);
		await sleep(300);

		// A remembered mode preference must survive a plain delegated mount: choosing --streaming records it, and a
		// later plain (no-flag) delegated mount must REUSE that mode and NOT wipe the stored preference.
		const prefKey = path.resolve(vdisk.resolveVaultDir(vault));
		await runCli(['mount', vault, '--mountpoint', mp, '--streaming'], PW + '\n');
		await runCli(['unmount', mp], null); await sleep(300);
		let prefs = ((await vdisk.getSettings()).mountPrefs || {})[prefKey] || {};
		ok('a mode chosen via a delegated mount is remembered', prefs.streaming === true);
		r = await runCli(['mount', vault, '--mountpoint', mp], PW + '\n');
		prefs = ((await vdisk.getSettings()).mountPrefs || {})[prefKey] || {};
		ok('a plain delegated mount reuses the remembered mode and does not wipe it', /streaming mode/i.test(r.out) && prefs.streaming === true);
		await runCli(['unmount', mp], null); await sleep(300);
		try { await vdisk.recordMountPrefs(vault, {}); } catch (_) {} // reset so Part 2 uses the default cache

		// ── Part 2: with NO owner, the CLI falls back to a direct mount (today's lazy-finalize behavior) ──
		try { svc.kill('SIGTERM'); } catch (_) {}
		for (let i = 0; i < 40; i++) { try { await fsp.stat(pidFile); await sleep(250); } catch (_) { break; } } // wait for the service to drop its pidfile
		svc = null;

		r = await runCli(['mount', vault, '--mountpoint', mp], PW + '\n');
		const owner2 = await ownerOf(mp);
		ok('with no owner, a CLI mount is standalone (owner "cli")', owner2 === 'cli');
		await fsp.writeFile(path.join(mp, 'b.txt'), 'world', { mode: 0o600 });
		await runCli(['unmount', mp], null);
		await sleep(300);
		r = await runCli(['mount', vault, '--mountpoint', mp], PW + '\n');
		ok('a standalone remount reports the saved-session notice (lazy finalize at next open)', /Changes from your last session/i.test(r.out));
		await runCli(['unmount', mp], null);
	} finally {
		try { if (svc) svc.kill('SIGKILL'); } catch (_) {}
		try { await vdisk.unmount(mp, { force: true }); } catch (_) {}
		for (const kv of await vdisk.listKnownVaults().catch(() => [])) { const p = kv.path || kv; if (typeof p === 'string' && p.includes(path.basename(base))) await vdisk.removeKnownVault(p).catch(() => {}); }
		await fsp.rm(base, { recursive: true, force: true }).catch(() => {});
		// Restore any pre-existing service.pid we saved (we should not have had one, but be safe).
		try { if (savedPid) await fsp.writeFile(pidFile, savedPid); else await fsp.unlink(pidFile).catch(() => {}); } catch (_) {}
	}

	console.log(failures ? ('\n' + failures + ' CHECK(S) FAILED') : '\nALL OWNER-MOUNT CHECKS PASSED');
	process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
