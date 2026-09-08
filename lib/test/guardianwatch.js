'use strict';
// lib/test/guardianwatch.js — the crash-time safety net's ACTION path. Guardian.decide() (the pure verdict) is
// covered by wedge.js; this covers what watch() actually DOES: when the service is gone it must unmount and
// wipe-cache every vault the service opened, and when the service is genuinely wedged AND health-restart is on it
// must SIGKILL the wedged pid before locking. A regression here (firing on defer, not firing on death, killing the
// wrong pid) would either leave decrypted mounts exposed after a crash or kill a healthily-draining service.
//
// It stubs the module functions watch() calls (they are cached singletons, so watch sees the stubs) rather than
// spawning a real service. No engine needed.
//
// Run:  node lib/test/guardianwatch.js

const Common = require('../Common');
const Vault = require('../Vault');
const Phase = require('../Phase');
const Guardian = require('../Guardian');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// --- pid gone -> unmount + wipe cache every owned vault ---
	let fired = null;
	Vault.unmountAll = async (opts) => { fired = opts; return { count: 0 }; };
	Common.isProcessAlive = () => false; // the watched service is gone
	await Guardian.watch(999001, 'owner-A'); // resolves once it has locked the vaults
	ok('a gone service triggers unmountAll for its owner', fired && fired.owner === 'owner-A');
	ok('the crash lock wipes the RAM cache (no decrypted data left)', fired && fired.wipeCache === true);

	// --- pid alive but genuinely wedged, with health-restart ON -> SIGKILL the pid, then lock ---
	fired = null;
	let killed = null;
	const realKill = process.kill;
	process.kill = (pid, sig) => { killed = { pid, sig }; }; // record instead of actually killing
	Common.isProcessAlive = () => true;                       // pid is (or was recycled onto) something alive
	Vault.isOwnerAlive = async () => false;                   // but the owner heartbeat is stale (twice)
	Vault.getSettings = async () => ({ wedgeRestart: true });  // health-based restart enabled -> escalate
	Phase.readPhaseSync = () => null;                          // no fresh 'stopping' phase -> not a clean shutdown
	try { await Guardian.watch(424242, 'owner-B'); } finally { process.kill = realKill; }
	ok('a wedged service with restart enabled is SIGKILLed', killed && killed.pid === 424242 && killed.sig === 'SIGKILL');
	ok('the wedged service\'s vaults are then locked and cache-wiped', fired && fired.owner === 'owner-B' && fired.wipeCache === true);

	// --- pid wedged but restart OFF -> lock the vaults, do NOT kill the pid ---
	fired = null; killed = null;
	process.kill = (pid, sig) => { killed = { pid, sig }; };
	Common.isProcessAlive = () => true;
	Vault.isOwnerAlive = async () => false;
	Vault.getSettings = async () => ({ wedgeRestart: false }); // restart disabled -> lock, never kill
	Phase.readPhaseSync = () => null;
	try { await Guardian.watch(535353, 'owner-C'); } finally { process.kill = realKill; }
	ok('a wedged service with restart OFF is NOT killed (locked only)', killed === null);
	ok('its vaults are still locked and cache-wiped', fired && fired.owner === 'owner-C' && fired.wipeCache === true);

	// --- a cleanly-draining service (fresh 'stopping' heartbeat) is DEFERRED, never killed; it fires only once
	// the pid is actually gone, so a flush in progress is never wiped out from under it ---
	fired = null; killed = null;
	const realKill2 = process.kill;
	process.kill = (pid, sig) => { killed = { pid, sig }; };
	let aliveCalls = 0;
	Common.isProcessAlive = () => { aliveCalls++; return aliveCalls <= 1; }; // alive on the first check, gone afterward
	Vault.isOwnerAlive = async () => false;                                   // a clean shutdown clears its own nonce early
	Phase.readPhaseSync = () => ({ pid: 646464, phase: 'stopping' });
	Phase.isFresh = () => true;                                               // its 'stopping' heartbeat is fresh -> defer
	try { await Guardian.watch(646464, 'owner-D'); } finally { process.kill = realKill2; }
	ok('a cleanly-draining service is never killed (defer)', killed === null);
	ok('once it finishes and the pid is gone, its vaults are locked', fired && fired.owner === 'owner-D' && fired.wipeCache === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL GUARDIAN-WATCH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
