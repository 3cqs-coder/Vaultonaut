'use strict';
// lib/test/watchdog.js — the runtime mount health watch must not cry "not responding" when a drive is
// merely BUSY. A large write (especially over the SMB backend) can miss a probe occasionally while the
// drive is perfectly fine, so a missed probe is held under a grace window and only a CONTINUOUSLY
// failing mount is flagged. This checks the grace (no false positive), that a live+answering mount is
// healthy, and that a dead engine is still reported immediately. Driver-free; no engine needed.
//
// Run:  node lib/test/watchdog.js

const path = require('path');
const Watchdog = require('../Watchdog');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// A mount whose stat FAILS (nonexistent path) but whose engine pid is alive (this process): a real
	// wedge would look like this, but so does a transient miss — it must NOT be flagged immediately.
	const busy = { mountpoint: '/nonexistent/vdisk-watchdog-' + Date.now(), pid: process.pid, volname: 'busy' };
	let r = await Watchdog.refresh([busy]);
	ok('a failing probe with a live engine is held healthy during the grace window (no false "not responding")', r.snapshot[busy.mountpoint] === 'healthy');
	r = await Watchdog.refresh([busy]);
	ok('a second quick failing probe is still healthy (grace not yet elapsed)', r.snapshot[busy.mountpoint] === 'healthy');

	// A mount that answers its stat and whose engine is alive is healthy.
	const good = { mountpoint: process.cwd(), pid: process.pid, volname: 'good' };
	r = await Watchdog.refresh([good]);
	ok('a mount that answers with a live engine reads healthy', r.snapshot[good.mountpoint] === 'healthy');

	// The engine being gone is decisive and immediate, even if the mount point still stats fine.
	const dead = { mountpoint: process.cwd(), pid: 2147483646, volname: 'dead' };
	r = await Watchdog.refresh([dead]);
	ok('a stale mount whose engine is gone reads dead immediately', r.snapshot[dead.mountpoint] === 'dead');

	// The transition that the whole module exists for: a mount that keeps failing its probe with a live engine must
	// flip to 'unresponsive' once it has been failing CONTINUOUSLY past the grace window, and report that change.
	// An injected clock crosses the grace window without a real 12-second wait.
	{
		const wedged = { mountpoint: '/nonexistent/vdisk-watchdog-wedged-' + Date.now(), pid: process.pid, volname: 'wedged' };
		const t0 = 1000000000; // an arbitrary base for the injected clock
		let r = await Watchdog.refresh([wedged], t0);
		ok('a wedged mount is still healthy at the start of the grace window', r.snapshot[wedged.mountpoint] === 'healthy');
		r = await Watchdog.refresh([wedged], t0 + 13000); // 13s of continuous failure > the 12s grace
		ok('a continuously-failing live mount flips to unresponsive after the grace window', r.snapshot[wedged.mountpoint] === 'unresponsive');
		ok('the flip is reported as a healthy -> unresponsive change', r.changes.some(c => c.mountpoint === wedged.mountpoint && c.from === 'healthy' && c.to === 'unresponsive'));
		// It stays flagged while it keeps failing...
		r = await Watchdog.refresh([wedged], t0 + 14000);
		ok('an unresponsive mount stays unresponsive while it keeps failing', r.snapshot[wedged.mountpoint] === 'unresponsive');
	}
	// ...and recovers to healthy once its probe answers again. Use a real temp directory as the mountpoint so the
	// SAME mount can fail (deleted) then answer (recreated), exercising the failing-streak clear on the same key.
	{
		const os = require('os'), fs = require('fs');
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-wd-recov-'));
		const m = { mountpoint: dir, pid: process.pid, volname: 'recov' };
		const t0 = 2000000000;
		await Watchdog.refresh([m], t0);                    // stats OK -> healthy
		fs.rmSync(dir, { recursive: true, force: true });   // now the probe will fail
		let r = await Watchdog.refresh([m], t0);            // start the failing streak
		r = await Watchdog.refresh([m], t0 + 13000);        // past the grace window
		ok('the recovery mount first reaches unresponsive', r.snapshot[dir] === 'unresponsive');
		fs.mkdirSync(dir, { recursive: true });             // the drive answers again
		r = await Watchdog.refresh([m], t0 + 14000);
		ok('an unresponsive mount recovers to healthy once its probe answers', r.snapshot[dir] === 'healthy');
		ok('the recovery is reported as an unresponsive -> healthy change', r.changes.some(c => c.mountpoint === dir && c.from === 'unresponsive' && c.to === 'healthy'));
		fs.rmSync(dir, { recursive: true, force: true });
	}

	// The shared liveness primitive underneath the watch: access() of the mount root — NOT stat(), which a healthy
	// WinFsp directory mount can fail — with a Windows drive letter normalized to its root. This is the exact bug
	// class that flashed a working Windows drive as "not responding", so guard both properties.
	{
		const os = require('os'), fs = require('fs');
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-probe-'));
		let resolved = false; try { await Rclone.mountProbeCall(dir); resolved = true; } catch (_) {}
		ok('mountProbeCall answers on a real, accessible mount root', resolved === true);
		let rejected = false; try { await Rclone.mountProbeCall(path.join(dir, 'gone')); } catch (_) { rejected = true; }
		ok('mountProbeCall rejects on a missing path (so a departed mount reads as not responding)', rejected === true);
		fs.rmSync(dir, { recursive: true, force: true });
		// Windows drive-letter normalization: a bare "X:" is drive-RELATIVE, so it must be probed as "X:\". Force
		// the platform and capture the path access() actually receives, so this is verified from any host.
		const realPlat = process.platform, seen = [], origAccess = fs.promises.access;
		try {
			Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
			fs.promises.access = (p) => { seen.push(p); return Promise.resolve(); };
			Rclone.mountProbeCall('X:'); Rclone.mountProbeCall('C:\\Vaults\\v');
			ok('mountProbeCall probes a bare drive letter "X:" as its root "X:\\"', seen[0] === 'X:\\');
			ok('mountProbeCall leaves an already-rooted path unchanged', seen[1] === 'C:\\Vaults\\v');
		} finally {
			fs.promises.access = origAccess;
			Object.defineProperty(process, 'platform', { value: realPlat, configurable: true });
		}
	}

	// refresh never throws, even on odd input.
	let threw = false; try { await Watchdog.refresh(null); await Watchdog.refresh([{}]); } catch (_) { threw = true; }
	ok('refresh never throws', threw === false);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WATCHDOG CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
