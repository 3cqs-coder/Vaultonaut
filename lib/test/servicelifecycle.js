'use strict';
// lib/test/servicelifecycle.js — the service stop/attach lifecycle. Covers OwnerClient.servicePid (the trusted
// pidfile read that decides which process `stop` signals) and the `stop` command's guards: it refuses while a vault
// is open unless --force, and reports cleanly when nothing is running. Non-blocking and cross-platform by design;
// this pins the behavior so a future change cannot make `stop` signal the wrong process or stop an open vault
// without --force. See lib/OwnerClient.js and lib/Commands.js (cmdStop).
//
// Run:  node lib/test/servicelifecycle.js

const os = require('os');
const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const Common = require('../Common');
const OwnerClient = require('../OwnerClient');
const Commands = require('../Commands');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Capture console.log output of an async block.
async function capture(fn) {
	const lines = [];
	const orig = console.log;
	console.log = (...a) => lines.push(a.join(' '));
	try { await fn(); } finally { console.log = orig; }
	return lines.join('\n');
}

async function main() {
	console.log('[OwnerClient.servicePid — trusted pidfile read]');
	const origRunDir = Common.runDir;
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-svc-'));
	Common.runDir = () => dir;
	const pidFile = path.join(dir, 'service.pid');
	try {
		await fsp.writeFile(pidFile, JSON.stringify({ pid: process.pid, url: 'http://127.0.0.1:7420' }));
		ok('returns the pid for a live, well-owned pidfile', (await OwnerClient.servicePid()) === process.pid);

		await fsp.writeFile(pidFile, JSON.stringify({ pid: 2 ** 30, url: 'x' })); // a pid that is not running
		ok('returns null when the recorded pid is not alive', (await OwnerClient.servicePid()) === null);

		await fsp.rm(pidFile, { force: true });
		ok('returns null when there is no pidfile', (await OwnerClient.servicePid()) === null);

		if (process.platform !== 'win32') {
			await fsp.writeFile(pidFile, JSON.stringify({ pid: process.pid }));
			await fsp.chmod(pidFile, 0o666); // group/other-writable — untrusted, could have been planted
			ok('refuses a group/other-writable pidfile (POSIX)', (await OwnerClient.servicePid()) === null);
		}
	} finally { Common.runDir = origRunDir; await fsp.rm(dir, { recursive: true, force: true }).catch(() => {}); }

	console.log('[stop command guards]');
	const origExit = process.exitCode;
	const origServicePid = OwnerClient.servicePid, origListMounts = vdisk.listMounts;
	try {
		// Nothing running: servicePid null and no service on the port (nothing listens in the test env).
		OwnerClient.servicePid = async () => null;
		let out = await capture(() => Commands.dispatch('stop', [], {}));
		ok('stop reports when nothing is running', /is not running/i.test(out));

		// A service is running AND a vault is open, without --force: must refuse and not signal anything.
		OwnerClient.servicePid = async () => process.pid; // pretend the current process is the service
		vdisk.listMounts = async () => [{ mountpoint: '/tmp/x', vault: '/tmp/v' }];
		process.exitCode = 0;
		const origKill = process.kill;
		let killed = false;
		process.kill = (p, sig) => { killed = true; return origKill.call(process, p, 0); }; // never actually signal in the test
		try {
			out = await capture(() => Commands.dispatch('stop', [], {}));
		} finally { process.kill = origKill; }
		ok('stop refuses while a vault is open (no --force)', /open/i.test(out) && /--force/.test(out));
		ok('stop does not signal any process when it refuses', killed === false);
		ok('stop sets a non-zero exit code when it refuses', process.exitCode === 1);
	} finally {
		OwnerClient.servicePid = origServicePid; vdisk.listMounts = origListMounts; process.exitCode = origExit;
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SERVICE-LIFECYCLE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
