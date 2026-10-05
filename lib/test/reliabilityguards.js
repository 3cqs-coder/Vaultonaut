'use strict';
// lib/test/reliabilityguards.js — pins the non-blocking / crash-proof guards on the health tick and the periodic
// scheduler ticks, which live in the web server's orchestration layer and in lib/Vault.js and are not otherwise
// unit-tested (their functions are not exported). These guards keep a wedged drive or a slow housekeeping pass from
// stalling the 12-second health tick that gates the systemd watchdog ping, and keep one bad mount from aborting a
// whole pass. A source-level guard (like routeguards.js) is the right, cheap level here — an end-to-end wedged-fs
// test would be flaky. If any of these regresses, the reliability property it protects is silently lost.
//
// Run:  node lib/test/reliabilityguards.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
// Slice a function body from its declaration to the start of the next top-level function, for scoped assertions.
function body(src, decl, span = 2500) { const at = src.indexOf(decl); return at >= 0 ? src.slice(at, at + span) : ''; }

async function main() {
	const server = read('webserver/index.js');
	const vault = read('Vault.js');

	// 1. The housekeeping sweep must be DETACHED from the health tick (not awaited), with an overlap guard — an
	//    awaited sweep over several stale mounts (or a resumed rekey) could delay the health stamp. Scope the check
	//    to watchTick: an awaited sweep in a user-triggered request handler (e.g. /api/repair) is fine.
	const watch = body(server, 'async function watchTick(', 10500);
	ok('the health tick does not await Vault.sweep() (it is detached)', watch.length > 0 && !/await\s+Vault\.sweep\(\)/.test(watch));
	ok('the health tick guards the detached sweep against overlap (sweepRunning)', /sweepRunning/.test(watch) && /Vault\.sweep\(\)/.test(watch));

	// 1b. watchBusy must be latched INSIDE the try whose finally clears it — the whole tick body, including the
	//     sleep/clock-jump prologue, runs under that try. Otherwise a synchronous throw before the try would latch
	//     watchBusy true and silently stop the health watch (and the systemd ping it gates) forever.
	ok('watchTick opens its try immediately after latching watchBusy', /watchBusy = true;\s*try \{/.test(watch));

	// 2. The backup/scrub preflight must time-bound the manifest read, so an unmounted vault on a wedged path can
	//    never hang (and stack) the sequential schedule pass.
	ok('the scheduled-tick preflight bounds readManifest with a timeout', /withTimeout\(readManifest\(abs\)/.test(vault));

	// 3. autoLockTick must guard the WHOLE per-mount body (the activity probe can reject under fd pressure), so one
	//    bad mount cannot abort the pass and skip the rest.
	const autoLock = body(vault, 'async function autoLockTick(');
	const tryAt = autoLock.indexOf('try {'), probeAt = autoLock.indexOf('vfsActivitySig(bin, rcEndpointOf(m))');
	ok('autoLockTick wraps the activity probe in a try (per-mount isolation)', tryAt >= 0 && probeAt > tryAt);

	// 3b. Auto-lock is a SECURITY timer, so its idle interval must be measured on a MONOTONIC clock — a wall-clock
	//     step backward (NTP correction, a manual clock change) must never make the interval appear to reset and keep
	//     a vault mounted past its timeout. The elapsed is the max of the monotonic delta and a FLOORED wall delta, so
	//     a backward step falls back to monotonic while a forward step (a resumed suspend) still locks promptly.
	ok('autoLockTick measures idle on a monotonic clock (max with a floored wall delta)', /Math\.max\(mono - prev\.mono,\s*Math\.max\(0,\s*now - prev\.wall\)\)/.test(autoLock));

	// 4. cloudTokenTick must be a true in-flight mutex, not just a timestamp throttle, so a slow sweep can't overlap.
	ok('cloudTokenTick has an in-flight mutex', /_cloudTokenSweeping/.test(vault));

	// 4a. An ephemeral rclone config reused across a long, multi-call operation (a rekey's copy+check+purge, a deep
	//     verify's lsf+hashsum, a note save's rcat+moveto) must be kept fresh against the 30s stale-config sweep, or a
	//     concurrent mount/list in ANY process could unlink it out from under the operation and spuriously abort it
	//     (a rekey would roll back hours of work). Rclone.run bumps the config's mtime before every spawn, keeping any
	//     in-use config inside the grace window (mirrors the rc-socket touch).
	const rcloneSrc = read('Rclone.js');
	ok('Rclone.run refreshes an in-use config mtime before spawning (stale-config-sweep race guard)', /if \(configPath\) \{[\s\S]{0,700}fsp\.utimes\(configPath/.test(rcloneSrc));

	// 4b. runScheduleTick must not overlap itself: each schedule tick fires detached every ~12s, and the pass awaits
	//     each vault in turn, so without a per-store in-flight guard a long op would let the next tick start another
	//     due vault, piling up unbounded concurrent operations when many vaults are due at once. A per-store guard
	//     keeps at most one pass of each tick running (due vaults are then processed serially, as one pass already is).
	const sched = body(vault, 'async function runScheduleTick(', 3000);
	ok('runScheduleTick guards against overlapping passes (per-store in-flight set)', /tickInFlight\.has\(store\)/.test(sched) && /tickInFlight\.add\(store\)/.test(sched) && /finally\s*\{\s*tickInFlight\.delete\(store\)/.test(sched));

	// 4c. Rotation must FENCE the lease BEFORE staging the commit anchor (MANIFEST_NEW). Once that anchor exists the
	//     interruption-recovery path treats the rotation as committed, so a fence placed after it could not abort a
	//     stolen-lease rotation — it would silently commit a superseded manifest over a concurrent key/member change.
	// Span is generous (rotate() grew when cloud key rotation was added — it now re-encrypts and re-uploads the
	// store, staging a sibling remote path — so the fence and the commit anchor sit deeper in the body); keep it
	// large enough to cover the whole fence→anchor region while staying inside rotate() (before cryptOptsOf).
	const rot = body(vault, 'async function rotate(', 26000);
	const fenceAt = rot.indexOf('assertStillHoldLease(abs)');
	const anchorAt = rot.indexOf('MANIFEST_NEW), newManifest');
	ok('rotation fences the lease before staging the commit anchor (MANIFEST_NEW)', fenceAt >= 0 && anchorAt >= 0 && fenceAt < anchorAt);

	// 5. emergencyRelease must guard its filesystem writes so a write failure never rejects out of the health tick.
	const rel = body(vault, 'async function emergencyRelease(');
	const relTry = rel.indexOf('try {'), relMkdir = rel.indexOf('fsp.mkdir(dir');
	ok('emergencyRelease wraps its writes in a try (never throws out of the tick)', relTry >= 0 && relMkdir > relTry);

	// 6. A long-lived mount log must not grow without bound. rclone honors RCLONE_LOG_LEVEL / RCLONE_VERBOSE from the
	//    environment even with an explicit --config, so the mount must pin the level on argv (an explicit flag wins
	//    over the env) and disable the periodic stats printer. Without these a user with a verbose level in their
	//    shell would grow the per-mount log quickly over a days-long session.
	const rclone = read('Rclone.js');
	const mount = body(rclone, 'async function spawnMount(', 4000);
	ok('the mount pins --log-level NOTICE (overrides any verbose env)', /'--log-level',\s*'NOTICE'/.test(mount));
	ok('the mount disables the periodic stats printer (--stats 0)', /'--stats',\s*'0'/.test(mount));

	// 6b. The headless-OAuth capture accumulates the engine's stdout/stderr while waiting for the browser redirect;
	//     it must BOUND those accumulators (keep only a tail) so a chatty or hostile backend cannot grow memory
	//     without bound, and so the per-chunk scan stays bounded instead of re-scanning an ever-growing string. The
	//     consent URL latches on first sight and the token is the last complete object, so a tail never loses either.
	const auth = body(rclone, 'function authorize(', 4000);
	ok('the OAuth capture caps its accumulators to a bounded tail', /AUTH_MAX_BYTES/.test(auth) && /slice\(s\.length - AUTH_MAX_BYTES\)/.test(auth) && /cap\(out \+/.test(auth));

	// 6c. spawnP's STREAMING branch (used for progress on a possibly-multi-hour bisync) accumulates the non-progress
	//     lines it keeps for the result. It must bound BOTH the retained stdout and stderr, exactly like the
	//     non-streaming branch, so a chatty or hostile remote emitting an unbounded number of distinct notice/error
	//     lines cannot grow memory without bound (the "any size, no OOM" invariant). Lock that both accumulators are
	//     capped at MAX_STDERR_BYTES inside the line loop.
	const spawnp = body(rclone, 'function spawnP(', 3000);
	ok('the streaming branch caps the retained stderr (MAX_STDERR_BYTES)', /err\.length\s*<\s*MAX_STDERR_BYTES\s*\)\s*err\s*\+=\s*ln/.test(spawnp));
	ok('the streaming branch caps the retained stdout (MAX_STDERR_BYTES)', /out\.length\s*<\s*MAX_STDERR_BYTES\s*\)\s*out\s*\+=\s*ln/.test(spawnp));

	// 7. Lock-on-sleep must fire DETACHED behind a guard, like every other lock/schedule tick — never awaited on the
	//    hot tick. lockAll gently unmounts every open vault, and a gentle unmount DRAINS its write-back cache, so an
	//    awaited call would park the health stamp for the whole drain and could get the service killed mid-flush.
	ok('the sleep-lock is detached, not awaited (no await Vault.lockAll on the tick)', !/await\s+Vault\.lockAll\(\)/.test(watch) && /sleepLockRunning/.test(watch) && /Vault\.lockAll\(\)/.test(watch));

	// 8. Watchdog.refresh is awaited on the hot tick, so it must be time-bounded — its per-mount liveness probes are
	//    each bounded, but the aggregate over a large mount set must never delay the health stamp.
	ok('the health tick bounds Watchdog.refresh with a timeout', /withTimeout\(Watchdog\.refresh\(mounts\)/.test(watch));

	// 9. emergencyTick fires detached every ~12s, so it must (a) bound its settings read (a wedged data dir must not
	//    pin a thread forever) and (b) hold an in-flight guard so a slow pass never queues another behind it.
	const etick = body(vault, 'async function emergencyTick(', 1600);
	ok('emergencyTick bounds its settings read with a timeout', /withTimeout\(getSettings\(\)/.test(etick));
	ok('emergencyTick has an in-flight guard (_emergencyTicking)', /_emergencyTicking/.test(etick));

	// 10. Idle auto-lock must work on Windows too (a security-timer parity gap otherwise): the mount creates a control
	//     endpoint for EVERY Windows mount (not just caching ones), and the activity probe builds its client args
	//     through the shared helper so it speaks BOTH the unix socket and the Windows TCP endpoint.
	ok('the mount gives every Windows mount a control endpoint (not only caching mounts)', /process\.platform === 'win32' \? await Rclone\.rcTcpEndpoint\(\)/.test(vault));
	const sig = body(vault, 'async function vfsActivitySig(', 1400);
	ok('the activity probe builds client args for both transports (works on Windows)', /Rclone\.rcClientArgs\(endpoint\)/.test(sig) && !/--unix-socket', rcSocket/.test(sig));

	// 11. Teardown of one mountpoint must be SERIALIZED, so an impatient force cannot overlap a gentle drain that is
	//     still flushing buffered writes (killing the engine mid-flush and then wiping the cache would lose data). The
	//     unmount wrapper serializes per mountpoint through a keyed queue AND re-reads the state entry inside that
	//     queue, so a second unmount sees the fresh post-drain state rather than acting on a stale entry.
	ok('unmount serializes teardown per mountpoint (a keyed queue, not a bare Set added after an await)', /const unmountQueue = Common\.serialQueueByKey\(\)/.test(vault));
	const unmountFn = body(vault, 'async function unmount(target, opts = {})', 900);
	ok('unmount runs unmountImpl inside the per-mountpoint queue', /unmountQueue\(key, async \(\) => \{[\s\S]{0,300}unmountImpl\(/.test(unmountFn));
	ok('unmount re-reads the state entry inside the serialized section', /unmountQueue\(key, async \(\) => \{[\s\S]{0,200}await State\.find\(target\)/.test(unmountFn));

	// 12. Reed–Solomon dispersal is non-streaming, so it must hold the whole packed archive (up to the multi-GB cap)
	//     plus the full shard set in memory at once. That MUST run in an isolated child PROCESS (runProcess), not a
	//     worker thread: a thread shares the long-running web/background service's address space, so an over-large or
	//     unusually large dispersal would OOM-kill the WHOLE service, whereas a child process's working set is its own
	//     and the OS reclaims it on exit — an over-large job ends only the child, cleanly rejecting to the caller.
	//     Lock the wiring so a future refactor cannot silently move it back onto a shared thread and reintroduce the
	//     OOM risk. It also runs under an idle watchdog (a wedged shard read fails fast) with no false-killing caps.
	ok('dispersal is dispatched to an isolated child PROCESS (runProcess), not a worker thread',
		/function dispersalInProcess\([\s\S]{0,400}WorkerRun\.runProcess\(path\.join\(__dirname, 'DisperseProcess\.js'\)/.test(vault));
	ok('the dispersal process runs under the idle watchdog with no false-killing memory/time caps (isolation is the net)',
		/dispersalInProcess[\s\S]{0,600}rssLimitMb: 0[\s\S]{0,200}idleMs: 120000[\s\S]{0,120}maxMs: 0/.test(vault));
	const disperseProc = read('DisperseProcess.js');
	ok('DisperseProcess.js is a child-process handler (runProcessChild), not a worker-thread one',
		/WorkerRun\.runProcessChild\(\{ encode, decode, repair, inspect \}/.test(disperseProc) && !/runChild\(/.test(disperseProc));

	// 13. A wedged macOS FUSE-T mount (its remote dead) keeps the kernel pinned through a SEPARATE go-nfsv4 backend that
	//     OUTLIVES the rclone engine, so reaping the engine cannot free it and a reboot used to be the only recovery. The
	//     explicit force-unmount (recover) path must kill that backend, which unblocks the mount in place. Pin that the
	//     helper is macOS-gated (no separate backend elsewhere), targets ONLY this mount (matches the mountpoint in the
	//     backend's args, so it never kills another mount's server), and is invoked from the recover path.
	ok('killMountBackend is macOS-gated (Linux/Windows have no separate backend)', /async function killMountBackend\([\s\S]{0,140}process\.platform !== 'darwin'\) return false/.test(rcloneSrc));
	ok('killMountBackend targets only this mount (matches the mountpoint in the backend args)', /async function killMountBackend[\s\S]{0,600}go-nfsv4[\s\S]{0,300}includes\(mp\)/.test(rcloneSrc));
	ok('the force-unmount recover path kills the wedged mount backend', /opts\.recover && \(await live\(\)\)[\s\S]{0,1100}Rclone\.killMountBackend\(mountpoint\)/.test(vault));
	// Behavioral, deterministic on every platform: an unknown mountpoint matches nothing, so it is always a safe no-op.
	ok('killMountBackend is a safe no-op for an unknown mountpoint', (await require('../Rclone').killMountBackend('/no/such/mountpoint/xyz')) === false);

	// 14. Auto-recover a WEDGED mount (opt-in): when a mount flips to 'unresponsive', the health tick may recover it in
	//     place instead of only warning, but ONLY when the user turned the setting on, and it must be fail-safe and
	//     non-blocking. Pin that the setting defaults OFF (read strictly as `=== true`, so an absent/odd value warns and
	//     never tears a mount down on its own), and that the recover call is DETACHED (not awaited) so it can never delay
	//     the health stamp that gates the systemd watchdog ping.
	ok('auto-recover of a wedged mount defaults OFF (strict === true, so absent means warn-only)', /autoRecoverMount = await Vault\.getSettings\(\)\.then\(s => s\.autoRecoverMount === true\)/.test(watch));
	ok('the unresponsive branch is gated on the opt-in setting before recovering', /if \(autoRecoverMount\)[\s\S]{0,700}Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)/.test(watch));
	ok('the auto-recover call is detached (not awaited) so it never delays the health tick', /Promise\.resolve\(\)\.then\(\(\) => Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)\)\.catch/.test(watch) && !/await Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)/.test(watch));

	// 15. Auto-reconnect a DROPPED mount (default ON): a vault whose engine dropped unexpectedly is re-mounted from the
	//     live session so it is never left inaccessible. Must be non-blocking (detached, never awaited on the tick),
	//     self-overlap-guarded, backoff-capped so a down backend can never spin or leak engines, gated on the setting
	//     (default ON), and it must reuse the existing pre-derived-credential mount seam (no password, no on-disk secret)
	//     — never fighting a deliberate unmount.
	ok('the health tick pokes reconnectDueMounts detached and never awaits it', /Promise\.resolve\(\)\.then\(\(\) => Vault\.reconnectDueMounts\(\)\)\.catch/.test(watch) && !/await Vault\.reconnectDueMounts/.test(watch));
	const reconnectFn = body(vault, 'async function reconnectDueMounts(', 2600);
	ok('reconnectDueMounts defaults ON (autoReconnect !== false) and self-guards against overlap', /_reconnectRunning/.test(reconnectFn) && /s\.autoReconnect !== false/.test(reconnectFn));
	ok('reconnectDueMounts is backoff-capped and gives up (never spins or leaks engines)', /RECONNECT_BACKOFFS_MS/.test(vault) && /attempt > RECONNECT_BACKOFFS_MS\.length[\s\S]{0,200}reconnectState\.delete/.test(reconnectFn));
	ok('a flapping mount (reconnects then drops right back) escalates and GIVES UP at the cap, never looping forever',
		/RECONNECT_FLAP_MS/.test(vault) && /const flaps = \(rr\.flaps \|\| 0\) \+ 1/.test(vault) && /flaps > RECONNECT_BACKOFFS_MS\.length\)[\s\S]{0,220}return;/.test(vault));
	ok('a lock-everything event (Lock all / lock-on-sleep / secure-remove) cancels and suppresses auto-reconnect, so a dropped vault stays locked',
		/async function lockAll[\s\S]{0,400}suppressReconnects\(\)/.test(vault) && /if \(monoMs\(\) < _reconnectSuppressedUntilMono\) return/.test(vault));
	ok('a dropped mount is captured for reconnect only when the setting is ON (no key material lingers when off)', /if \(reconnectOn && sk && sk\.master && !sk\.decoy\) markForReconnect/.test(vault));
	ok('reconnect reuses the pre-derived credential seam (no password), not a fresh unlock', /mountImpl\(key, \{ _cred: st\.cred/.test(reconnectFn));
	ok('a dropped mount is captured for reconnect BEFORE its session secrets are erased',
		/markForReconnect\(sk\.backing[\s\S]{0,700}sessionKeys\.delete\(m\.mountpoint\)/.test(vault));
	ok('a deliberate unmount cancels any pending reconnect (never fights the user)', /sessionKeys\.delete\(mountpoint\);\s*\n\s*if \(sk && sk\.backing\) clearReconnect\(sk\.backing\)/.test(vault));
	ok('the mount entry allows the internal pre-derived credential without a password', /!opts\.readCap && !opts\.memberKey && !opts\._cred\)/.test(vault));

	// 16. FAIL-FAST cloud timeout: the per-request idle timeout must be SHORTER than the old 5m (so a stalled backend op
	//     errors and retries before the FUSE-T/NFS client disconnects the volume), and parameterized so it stays tunable.
	ok('the cloud IO timeout is fail-fast (not the old 5m) and parameterized', /--timeout', String\(opts\.cloudTimeout \|\| '90s'\)/.test(rcloneSrc) && !/--timeout', '5m'/.test(rcloneSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELIABILITY-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
