'use strict';
// lib/Guardian.js — a tiny, separate watchdog process that guarantees open vaults
// are locked even if the service CRASHES. Graceful shutdown handlers cannot run on
// a hard kill (SIGKILL), a segfault, or a power event, and a mount is a detached
// process that would otherwise outlive its manager and stay exposed. So when the
// service starts it launches this guardian, detached, with the service's process
// id. The guardian does one thing: watch that process, and the instant it is gone
// — for any reason — unmount (and wipe the cache of) every vault the service
// opened, then exit.
//
// The guardian is its own process, so a crash of the service does not take it down.
// A reboot or power loss removes FUSE mounts anyway, so the only window this closes
// is "service dies but the machine keeps running" — which is exactly the exposure a
// detached mount would otherwise leave open.

const path = require('path');
const { spawn } = require('child_process');
const Common = require('./Common');
const Phase = require('./Phase');

// Decide what a stale-nonce owner means, so the choice is pure and testable:
//   'defer'    — the service is CLEANLY shutting down (a fresh 'stopping' heartbeat proves its loop is alive,
//                even through a slow drain); wait, never race its teardown or kill it mid-flush.
//   'escalate' — genuinely wedged AND health-based restart is enabled: kill it so the OS supervisor relaunches
//                it, then lock any orphaned mounts.
//   'lock'     — genuinely wedged with escalation off: lock its vaults (the long-standing behavior).
function decide({ ownerPid, phase, killEnabled }) {
	const cleanShutdown = phase && phase.pid === ownerPid && phase.phase === 'stopping' && Phase.isFresh(phase);
	if (cleanShutdown) return 'defer';
	return killEnabled ? 'escalate' : 'lock';
}

// Run the watch loop (invoked in the guardian process). Resolves — and the process
// exits — once the watched owner is gone and its vaults are locked.
async function watch(ownerPid, owner) {
	// The guardian is the safety net that locks vaults if the service dies — it must itself never die
	// from a stray error, so it survives an uncaught error and keeps watching. Install the resilient
	// process guards FIRST, before requiring Vault, so even a load-time error in that module is logged
	// and survived rather than exiting the guardian.
	require('./ProcRegistry').beResilient();
	const Vault = require('./Vault');
	// Give the service a moment to come up before we start judging its liveness.
	await Common.sleep(1500);
	const fire = async () => { try { await Vault.unmountAll({ owner, wipeCache: true }); } catch (_) {} };
	const killEnabled = async () => { try { return (await Vault.getSettings()).wedgeRestart === true; } catch (_) { return false; } };
	for (;;) {
		// Fast path: the pid is gone — the common crash case — fire immediately.
		if (!Common.isProcessAlive(ownerPid)) { await fire(); return; }
		// The pid is alive, but on a hard kill the OS can RECYCLE it onto an unrelated long-lived process, which
		// would make a pid-only check believe the service is still up forever, leaving the vaults exposed until
		// reboot. The owner nonce heartbeat — refreshed only by the live service, every health tick — distinguishes
		// a recycled pid from a genuine service. Require it to read stale TWICE, a beat apart, so a one-off stat
		// glitch or a brief event-loop stall can never make the guardian evict a truly-live service.
		let stale = false;
		try { stale = !(await Vault.isOwnerAlive(owner)); } catch (_) { stale = false; }
		if (stale) {
			await Common.sleep(2000);
			let stillStale = false;
			try { stillStale = !(await Vault.isOwnerAlive(owner)); } catch (_) { stillStale = false; }
			if (stillStale) {
				const decision = decide({ ownerPid, phase: Phase.readPhaseSync(), killEnabled: await killEnabled() });
				// A clean shutdown clears its own nonce early, so the nonce reads stale even though the service is
				// healthily draining — DEFER while its 'stopping' heartbeat stays fresh, so we never wipe the cache
				// out from under a flush in progress. It finishes and exits; the pid-gone path then fires harmlessly.
				if (decision === 'defer') { await Common.sleep(1000); continue; }
				// Genuinely wedged. Optionally kill it so the OS supervisor restarts a HUNG (not just crashed)
				// service — the un-flushed data of a dead event loop is unrecoverable either way, so this loses
				// nothing a lock wouldn't. Off by default; the drain interlock above still protects a clean stop.
				if (decision === 'escalate') { try { process.kill(ownerPid, 'SIGKILL'); } catch (_) {} }
				await fire();
				return;
			}
		}
		await Common.sleep(1000);
	}
}

// Launch a guardian for the current process (the service). Detached and unref'd so
// it survives a crash of the service. Runs through the branded launcher so it shows
// under the branded process name (from Brand.slug) in the OS process viewers. Returns the guardian's pid.
function launch(owner) {
	const script = Common.appScriptPath(); // single-sourced launcher path (same as Autostart/Shortcut), so a repackaged entry point can't leave the guardian pointing at a stale name
	const node = require('./Launcher').ensure({ background: true }); // hot path (health tick / mount): never block the loop on a cross-volume ~100 MB copy — brand on the next launch instead
	// Pass the RESOLVED data directory so the guardian reads the same locks/state/settings as the service, even
	// when the service was started with a --data-dir override (the guardian's own entry re-applies it before use).
	const child = spawn(node, [script, '_guard', String(process.pid), owner, '--data-dir', Common.dataDir()], { detached: true, stdio: 'ignore', windowsHide: true });
	child.on('error', () => {}); // a detached spawn without this would crash the host on a spawn failure
	child.unref();
	return child.pid;
}

module.exports = { watch, launch, decide };
