'use strict';
// lib/test/cliguards.js — pins a few CLI input guards that would otherwise regress silently:
//   • A bare numeric flag (no value) parses to boolean true, and Number(true) is 1, which used to slip the
//     >=1 / >=0 range checks and be forwarded as a nonsense value. The handlers now reject a bare flag outright.
//   • A missing --secrets-file (the off-argv way to give cloud secrets) fails with a clear, path-naming message,
//     not a raw ENOENT.
// Dispatches in-process (no prompts, no process-level side effects for these commands).
//
// Run:  node lib/test/cliguards.js

const { dispatch, _serviceLaunchArgs } = require('../Commands');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function throwsMatching(fn, re) { try { await fn(); return false; } catch (e) { return re.test(e && e.message || ''); } }

async function main() {
	// Bare --inactive-days / --grace-days (value omitted → boolean true) must be rejected with an example, not
	// forwarded as 1. A dummy --contact-key is present so the day-flag guard (which runs first) is what fires.
	ok('a bare --inactive-days is rejected with a clear message',
		await throwsMatching(() => dispatch('emergency', ['enroll'], { 'contact-key': 'dummy', 'inactive-days': true }), /--inactive-days needs a positive number/));
	ok('a bare --grace-days is rejected with a clear message',
		await throwsMatching(() => dispatch('emergency', ['enroll'], { 'contact-key': 'dummy', 'grace-days': true }), /--grace-days needs a number/));

	// A --secrets-file that cannot be read gives a clear, path-naming error (not a raw ENOENT).
	ok('a missing cloud --secrets-file gives a clear error, not a raw ENOENT',
		await throwsMatching(() => dispatch('cloud', ['add'], { type: 's3', 'secrets-file': '/no/such/secrets/file/here' }), /Could not read the secrets file/));

	// A bare value-expecting string flag (value omitted → boolean true) must be rejected with an example, before any
	// password prompt or vault read — not forwarded as `true` and hit later as a raw fsp.readFile(true) type error.
	ok('a bare --keyfile on mount is rejected with a clear message',
		await throwsMatching(() => dispatch('mount', ['/tmp/x.vault'], { keyfile: true }), /--keyfile needs a value/));
	ok('a bare --read-cap on mount is rejected with a clear message',
		await throwsMatching(() => dispatch('mount', ['/tmp/x.vault'], { 'read-cap': true }), /--read-cap needs a value/));
	ok('a bare --keyfile on verify is rejected with a clear message',
		await throwsMatching(() => dispatch('verify', ['/tmp/x.vault'], { keyfile: true }), /--keyfile needs a value/));

	// The service launcher (used by `open`'s detached start and the Windows crash supervisor) must ALWAYS forward
	// the resolved --data-dir, so a --data-dir override is never silently dropped and the service is never brought up
	// on the wrong (default) data directory. Regression guard for that propagation.
	const dd = Common.dataDir();
	const hasDataDir = (args) => { const i = args.indexOf('--data-dir'); return i >= 0 && args[i + 1] === dd; };
	const detached = _serviceLaunchArgs('vaultonaut.js', { port: 7777 });
	ok('the detached service argv forwards the resolved --data-dir', hasDataDir(detached));
	ok('the detached service argv is a plain UI start (no --child/--bind)', !detached.includes('--child') && !detached.includes('--bind'));
	const supervised = _serviceLaunchArgs('vaultonaut.js', { port: 7777, child: true, bind: '192.168.1.5', allowIp: '10.0.0.0/8', denyIp: '1.2.3.4' });
	ok('the supervisor server-child argv forwards the resolved --data-dir', hasDataDir(supervised));
	ok('the supervisor server-child argv carries --child and forwards bind/allow/deny', supervised.includes('--child') && supervised.includes('--bind') && supervised.includes('--allow-ip') && supervised.includes('--deny-ip'));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CLI-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
