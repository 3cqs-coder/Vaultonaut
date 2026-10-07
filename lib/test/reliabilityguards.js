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
	const watch = body(server, 'async function watchTick(', 11200);
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
	const spawnp = body(rclone, 'function spawnP(', 3600);
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
	ok('killMountBackend targets only this mount (matches the mountpoint at an argument boundary in the backend args)', /async function killMountBackend[\s\S]{0,600}go-nfsv4[\s\S]{0,300}argHasPath\(m\[2\], mp\)/.test(rcloneSrc));
	ok('the force-unmount recover path kills the wedged mount backend', /opts\.recover && \(await live\(\)\)[\s\S]{0,1100}Rclone\.killMountBackend\(mountpoint\)/.test(vault));
	// Behavioral, deterministic on every platform: an unknown mountpoint matches nothing, so it is always a safe no-op.
	ok('killMountBackend is a safe no-op for an unknown mountpoint', (await require('../Rclone').killMountBackend('/no/such/mountpoint/xyz')) === false);

	// 14. Auto-recover a WEDGED mount (opt-in): when a mount flips to 'unresponsive', the health tick may recover it in
	//     place instead of only warning, but ONLY when the user turned the setting on, and it must be fail-safe and
	//     non-blocking. Pin that the setting defaults OFF (read strictly as `=== true`, so an absent/odd value warns and
	//     never tears a mount down on its own), and that the recover call is DETACHED (not awaited) so it can never delay
	//     the health stamp that gates the systemd watchdog ping.
	ok('auto-recover of a wedged mount defaults OFF (strict === true, so absent means warn-only), and the settings read is timeout-bounded on the tick', /autoRecoverMount = await Common\.withTimeout\(Vault\.getSettings\(\), \d+\)\.then\(s => s && s\.autoRecoverMount === true\)/.test(watch));
	ok('the unresponsive branch is gated on the opt-in setting before recovering', /if \(autoRecoverMount\)[\s\S]{0,700}Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)/.test(watch));
	ok('the auto-recover call is detached (not awaited) so it never delays the health tick', /Promise\.resolve\(\)\.then\(\(\) => Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)\)\.catch/.test(watch) && !/await Vault\.unmount\(c\.mountpoint, \{ recover: true \}\)/.test(watch));

	// 15. Auto-reconnect a DROPPED mount (default ON): a vault whose engine dropped unexpectedly is re-mounted from the
	//     live session so it is never left inaccessible. Must be non-blocking (detached, never awaited on the tick),
	//     self-overlap-guarded, backoff-capped so a down backend can never spin or leak engines, gated on the setting
	//     (default ON), and it must reuse the existing pre-derived-credential mount seam (no password, no on-disk secret)
	//     — never fighting a deliberate unmount.
	ok('the health tick pokes reconnectDueMounts detached and never awaits it', /Promise\.resolve\(\)\.then\(\(\) => Vault\.reconnectDueMounts\(\)\)\.catch/.test(watch) && !/await Vault\.reconnectDueMounts/.test(watch));
	const reconnectFn = body(vault, 'async function reconnectDueMounts(', 3400);
	ok('reconnectDueMounts defaults ON (autoReconnect !== false) and self-guards against overlap', /_reconnectRunning/.test(reconnectFn) && /s\.autoReconnect !== false/.test(reconnectFn));
	ok('reconnectDueMounts is backoff-capped and gives up (never spins or leaks engines)', /RECONNECT_BACKOFFS_MS/.test(vault) && /attempt > RECONNECT_BACKOFFS_MS\.length[\s\S]{0,200}reconnectState\.delete/.test(reconnectFn));
	ok('a flapping mount (reconnects then drops right back) escalates and GIVES UP at the cap, never looping forever',
		/RECONNECT_FLAP_MS/.test(vault) && /const flaps = \(rr\.flaps \|\| 0\) \+ 1/.test(vault) && /flaps > RECONNECT_BACKOFFS_MS\.length\)[\s\S]{0,220}return;/.test(vault));
	ok('a lock-everything event (Lock all / lock-on-sleep / secure-remove) cancels and suppresses auto-reconnect, so a dropped vault stays locked',
		/async function lockAll[\s\S]{0,400}suppressReconnects\(\)/.test(vault) && /if \(monoMs\(\) < _reconnectSuppressedUntilMono\) return/.test(vault));
	// reconnectDueMounts holds its own snapshot, so it must re-check suppression INSIDE the loop (not just in
	// markForReconnect) — otherwise a lock-all firing after the snapshot, or during an in-flight remount, could bring a
	// vault back UNLOCKED. The loop bails on suppression, and a remount that completed during suppression is undone.
	ok('reconnectDueMounts re-checks the lock-everything suppression inside its loop and undoes an in-flight remount',
		/if \(monoMs\(\) < _reconnectSuppressedUntilMono\) break;/.test(reconnectFn) &&
		/if \(monoMs\(\) < _reconnectSuppressedUntilMono\) \{ try \{ await unmount\([\s\S]{0,80}force: true/.test(reconnectFn));
	ok('a dropped mount is captured for reconnect only when the setting is ON (no key material lingers when off)', /if \(reconnectOn && sk && sk\.master && !sk\.decoy\) markForReconnect/.test(vault));
	ok('reconnect reuses the pre-derived credential seam (no password), not a fresh unlock', /mountImpl\(key, \{ _cred: st\.cred/.test(reconnectFn));
	ok('a dropped mount is captured for reconnect BEFORE its session secrets are erased',
		/markForReconnect\(sk\.backing[\s\S]{0,1100}sessionKeys\.delete\(m\.mountpoint\)/.test(vault));
	ok('a deliberate unmount cancels any pending reconnect (never fights the user)', /sessionKeys\.delete\(mountpoint\);\s*\n\s*if \(sk && sk\.backing\) clearReconnect\(sk\.backing\)/.test(vault));
	ok('the mount entry allows the internal pre-derived credential without a password', /!opts\.readCap && !opts\.memberKey && !opts\._cred\)/.test(vault));

	// 16. FAIL-FAST cloud timeout: the per-request idle timeout must be SHORTER than the old 5m (so a stalled backend op
	//     errors and retries before the FUSE-T/NFS client disconnects the volume), and parameterized so it stays tunable.
	ok('the cloud IO timeout is fail-fast (not the old 5m) and parameterized', /--timeout', String\(opts\.cloudTimeout \|\| '90s'\)/.test(rcloneSrc) && !/--timeout', '5m'/.test(rcloneSrc));

	// 17. CREATE is serialized by its TARGET, so an impatient double-click (or any second API/CLI caller) can never run
	//     two creations against the same folder/remote at once — two racing the same empty-check, manifest write, and
	//     canary is corruption or a duplicate vault. The claim must be taken SYNCHRONOUSLY, before the first await, or
	//     two overlapping calls both pass the check. The public create() is the guard wrapper; createImpl does the work.
	ok('create() serializes by target (a synchronous claim on the destination, released in finally)',
		/const creatingTargets = new Set\(\)/.test(vault) &&
		/async function create\(vaultDir, opts = \{\}\) \{[\s\S]{0,400}creatingTargets\.has\(key\)[\s\S]{0,200}creatingTargets\.add\(key\);[\s\S]{0,200}return await createImpl\(vaultDir, opts\);[\s\S]{0,120}creatingTargets\.delete\(key\)/.test(vault));
	ok('the create target key is computed synchronously (resolveVaultDir / cloud remote+path), before any await',
		/function createTargetKey\(vaultDir, cloud\) \{[\s\S]{0,260}'cloud\\0'[\s\S]{0,180}'local\\0' \+ resolveVaultDir\(vaultDir\)/.test(vault));

	// 18. HONEST cloud errors at unlock: a wrong crypt key and a transient cloud failure both read back as a non-zero
	//     canary cat, so the mount must NOT call every failed read "wrong password" — a store it simply could not reach
	//     is reported as unreachable (retryable), never as a credential error. verifyPassword classifies; the mount acts.
	const verifyFn = body(vault, 'async function verifyPassword(', 1600);
	ok('verifyPassword can classify ok / mismatch / unreachable (transient engine error ⇒ unreachable, not a mismatch)',
		/classify = false/.test(verifyFn) && /REMOTE_TRANSIENT_ERROR\.test\(String\(r\.stderr/.test(verifyFn) && /return 'unreachable'/.test(verifyFn));
	// A read-write key-wrapping unlock is already proven locally, so verifyPassword must do NO cloud I/O for it — no
	// canary read and no canary "repair" write. Over a slow/throttled cloud those round-trips made every mount crawl
	// and burned the backend's write quota. The RW short-circuit must come BEFORE the only Rclone.run (the canary cat).
	ok('verifyPassword does NO cloud I/O for a read-write key-wrapping unlock (RW short-circuit precedes the canary cat)',
		/if \(!readOnly && hasKeyWrapping\(manifest\.crypt\)\) return classify \? 'ok' : true;/.test(verifyFn) &&
		verifyFn.indexOf('if (!readOnly && hasKeyWrapping') >= 0 &&
		verifyFn.indexOf('if (!readOnly && hasKeyWrapping') < verifyFn.indexOf("Rclone.run(bin, ['cat'") &&
		!/rcat', 'vault:' \+ CANARY_NAME/.test(verifyFn)); // the canary-repair write is gone from the unlock path
	ok('a transient-error classifier exists and is distinct from the target-absent one', /const REMOTE_TRANSIENT_ERROR = \//.test(vault) && /rate\[- \]\?limit/.test(vault));
	ok('the mount surfaces an unreachable store as a retryable error, never "wrong password"',
		/const verdict = await verifyPassword\(bin, probeCfg, manifest, \{ readOnly: readOnlyCred, classify: true \}\)/.test(vault) &&
		/if \(verdict === 'unreachable'\) throw cloudUnreachableError\(\)/.test(vault));
	ok('cloudUnreachableError carries a stable flag and says the password was not the problem', /function cloudUnreachableError\([\s\S]{0,260}unreachable: true/.test(vault) && /was not the problem/.test(vault));

	// 19. A FAILED cloud create cleans up robustly, so a partial canary does not survive to block a retry with "already
	//     contains data". The empty-check proved the path was ours, so a bounded, retried purge of the crypt root is safe.
	ok('a failed cloud create purges the crypt root with a bounded retry (not a single swallowed deletefile)',
		/for \(let attempt = 0; attempt < 3; attempt\+\+\) \{[\s\S]{0,400}Rclone\.run\(bin, \['purge', 'vault:'\][\s\S]{0,200}REMOTE_TARGET_ABSENT\.test\(String\(p\.stderr/.test(vault));

	// 20. A transient key-derivation ENGINE failure must NEVER be reported as a wrong password. A wrong secret makes
	//     unwrapSecret fail, NOT deriveKey — deriveKey throws only when Argon2id cannot run (resource pressure). The
	//     unlock must retry a transient derive and, if a slot still cannot be checked, surface a retryable error instead
	//     of returning null (which the caller turns into "wrong password"), so pressure never locks a user out.
	const unwrapOne = body(vault, 'async function unwrapMasterOneForm(', 4600);
	ok('unwrapMasterOneForm separates a derivation-engine failure from a wrong secret (does not blind-continue on deriveKey throw)',
		/deriveErr = e;/.test(unwrapOne) && /engineFailure = deriveErr; continue;/.test(unwrapOne) && !/catch \(_\) \{ continue; \}[\s\S]{0,40}unwrapSecret/.test(unwrapOne));
	ok('the transient-derivation retry is bounded by a SHARED budget across all forms/slots (not per-slot), and never retries a KDF_PARAMS rejection',
		/const budget = \{ retries: \d+, until: Date\.now\(\) \+ \d+, backoff: \d+ \}/.test(vault) &&
		/budget && budget\.retries > 0 && Date\.now\(\) < budget\.until/.test(unwrapOne) &&
		/code === 'KDF_PARAMS'\) throw e/.test(unwrapOne));
	ok('an unchecked slot (engine failure) throws a retryable error, not a false wrong-password (null)',
		/if \(engineFailure\) throw kdfUnavailableError\(engineFailure\)/.test(unwrapOne));
	ok('kdfUnavailableError is retryable and says the password was not rejected', /function kdfUnavailableError\([\s\S]{0,320}kdfUnavailable: true, retryable: true/.test(vault) && /was not rejected/.test(vault));

	// 21. A rotation's new baseline seq must floor against the vault's OWN recorded snapshot.seq (prevSeq), not just the
	//     local ledger — otherwise a machine whose ledger lags writes a LOWER seq and other copies see a false rollback.
	const establish = body(vault, 'async function establishBaselineInStore(', 1300);
	ok('the rotation baseline floors its seq against the recorded snapshot.seq (no false rollback alarm after rotation)',
		/prevSeq = 0/.test(establish) && /Math\.max\(\(seen && seen\.seq\) \|\| 0, prevSeq \|\| 0, 0\) \+ 1/.test(establish) &&
		/prevSeq: \(manifest\.snapshot && manifest\.snapshot\.seq\) \|\| 0/.test(vault));

	// 22. OCR must reject an image whose DECLARED dimensions exceed the pixel ceiling BEFORE decoding it, so a decode
	//     bomb can never trigger a giant RGBA allocation (the PDF path already caps; the image path now does too).
	const ocr = read('Ocr.js');
	ok('OCR skips an over-ceiling image by its header dimensions before any decode (decode-bomb guard)',
		/function imageDimsFromHeader\(/.test(ocr) &&
		/const dims = imageDimsFromHeader\(buffer\);[\s\S]{0,160}dims\.w \* dims\.h > MAX_RENDER_PIXELS\) return \[\]/.test(ocr));

	// 23. Heavy workers that set a heap cap must also pass execArgv:[] so an inherited --max-old-space-size can't silently
	//     disable the cap (WorkerRun's own documented contract).
	ok('the index / query / recovery workers pin execArgv:[] alongside their heap cap', /resourceLimits: \{ maxOldGenerationSizeMb: 2560 \}, execArgv: \[\] \}/.test(vault) && /resourceLimits: \{ maxOldGenerationSizeMb: 2560 \}, execArgv: \[\] \}/.test(read('Recovery.js')));

	// 24. An AUTO-RECONNECTED mount must carry the ORIGINAL owner tag. If it defaulted to 'cli', the service's clean
	//     shutdown (which filters by its own owner) and both startup orphan sweeps would skip it, leaving a decrypted
	//     mount and its detached engine alive past exit — a zero-knowledge AND a leaked-process violation. Pin that the
	//     reconnect info captures the owner and the reconnect mountImpl call forwards it.
	ok('the reconnect record captures the mount owner (markForReconnect info includes owner)', /mountpoint: m\.mountpoint, owner: m\.owner \}/.test(vault));
	ok('the auto-reconnect remount forwards the original owner tag to mountImpl', /mountpoint: st\.mountpoint, owner: st\.owner, timeoutMs: 20000/.test(vault));

	// 25. Process shutdown must FREEZE auto-reconnect and stop the health tick before the drain, or a reconnect fired
	//     mid-drain would spawn a fresh detached engine after unmountAll snapshotted its targets — leaking it past exit.
	const shutdown = body(server, '// Mark an INTENTIONAL shutdown', 1800);
	ok('shutdown suppresses auto-reconnect before the drain', shutdown.length > 0 && /Vault\.suppressReconnects\(/.test(shutdown));
	ok('shutdown stops the health watch tick (clears watchTimer)', shutdown.length > 0 && /clearInterval\(watchTimer\)/.test(shutdown));

	// 26. killMountBackend (macOS FUSE-T) must match the mount point at an argument BOUNDARY, never as a bare substring,
	//     or recovering vault "…/Work" would SIGKILL the backend of a sibling "…/Work2" and wedge a healthy vault.
	const rcloneKill = read('Rclone.js');
	ok('killMountBackend matches the mount point at a boundary (argHasPath), not a bare .includes', /function argHasPath\(/.test(rcloneKill) && /argHasPath\(m\[2\], mp\)/.test(rcloneKill) && !/m\[2\]\.includes\(mp\)/.test(rcloneKill));

	// 27. The owner marker is single-sourced in makeSlot (set from the wrapped bundle's ownerSeed), so a password change
	//     or content re-key — both of which rebuild the owner's slot through makeSlot — can never silently drop it and
	//     defeat the last-owner guard and owner-key rotation.
	ok('makeSlot sets the owner marker from the wrapped bundle (single-sourced)', /bundle && bundle\.ownerSeed \? \{ owner: true \} : \{\}\)/.test(vault));

	// 28. The hybrid verifier's classical-only fallback must gate on the ARTIFACT (no published PQ key) before the
	//     runtime capability, so a record sealed without ML-DSA does not false-alarm as tampered on a PQ-capable runtime
	//     while a stripped sigPq with a published pqPub still fails closed.
	const integ = read('Integrity.js');
	ok('verifyHybrid accepts classical-only only when no PQ key was published (then falls back on runtime capability)', /if \(!pqPub\) return true;\s*\n\s*if \(!pqAvailable\(\)\) return true;/.test(integ));

	// 29. A lease write that silently failed (Rclone.run resolves non-zero, never throws) must NOT be reported as a
	//     refresh success, or the split-brain staleness watch never fires. writeLeaseAt returns a boolean and
	//     refreshLease returns null (not true) when the write did not land.
	ok('writeLeaseAt returns the engine exit status (does not swallow a failed write)', /async function writeLeaseAt[\s\S]{0,400}return r\.status === 0;/.test(vault));
	ok('refreshLease returns null (not true) when the lease write did not succeed', /writeLeaseAt\(bin, target, makeLease\(me, false, LEASE_TTL_HEARTBEAT\)\)\) \? true : null/.test(vault));

	// 30. receiveVault/restore must not delete or merge into a pre-existing NON-vault folder: guard on a foreign,
	//     non-empty destination, and only remove a folder this call actually created.
	ok('receiveVault only removes a folder it created (created = !destPreExisted)', /created = !destPreExisted;/.test(vault));
	ok('receiveVault refuses a destination that already holds unrelated files', /already contains files\. Receive into a new, empty folder/.test(vault));
	ok('restore refuses to merge into a non-vault folder that already holds files', /already contains files that are not this vault/.test(vault));

	// 31. A hole-punched node tunnel must never outlive a deliberate stop or a failed hub registration: a stopped flag
	//     gates add()/onSignal, and the error path tears tunnels down too.
	ok('serveDirTransport gates tunnels on a stopped flag (add stops a tunnel registered after stop)', /add: \(h\) => \{ if \(stopped\) \{ try \{ h\.stop\(\); \} catch \(_\) \{\} return; \}/.test(vault));
	ok('serveDirTransport tears down tunnels on the registration-failure path', /stopped = true; \/\/ a punch answered during the failed-registration window/.test(vault));

	// 32. A managed-Tor live-onion counter must be released when the control socket closes on its own, not only on an
	//     explicit stop(), or a dead onion pins the managed-Tor reuse guard. And the stale-Tor pgrep child must be
	//     tracked and time-bounded so it can neither leak nor hang the sweep.
	const onion = read('Onion.js');
	ok('publishOnion releases the live-onion count on socket close, not only on stop()', /sock\.on\('close', release\)/.test(onion));
	ok('the stale-Tor reaper tracks and time-bounds its pgrep child', /ProcRegistry\.track\(p\)/.test(onion) && /setTimeout\(\(\) => finish\(o\), 4000\)/.test(onion));

	// 33. runProcess must default a JS-heap cap when the caller omits execArgv (so a forgetful caller is not uncapped),
	//     while still letting an explicit [] opt out (dispersal, which is deliberately allowed the memory).
	const workerRun = read('WorkerRun.js');
	ok('runProcess defaults a heap cap when execArgv is omitted (explicit [] still opts out)', /opts\.execArgv !== undefined \? opts\.execArgv : \['--max-old-space-size=/.test(workerRun));

	// 34. The deniable-slot registry must keep its one-generation .bak in step with the CURRENT record (never a
	//     superseded one) and remove .bak BEFORE the primary — so a "removed" decoy/travel pairing is never left
	//     recoverable in .bak, and a corrupt-primary fallback cannot roll back to a removed generation.
	const slotReg = read('SlotRegistry.js');
	ok('SlotRegistry writes .bak to the CURRENT record after the primary (no superseded remnant)', /writeJsonAtomic\(filePath\(\)[\s\S]{0,900}writeJsonAtomic\(bakPath\(\), reg/.test(slotReg) && !/copyFile\(filePath\(\), bakPath\(\)\)/.test(slotReg));
	ok('SlotRegistry.remove unlinks .bak before the primary', /rm\(bakPath\(\), \{ force: true \}\); await fsp\.rm\(filePath\(\)/.test(slotReg));

	// 35. secure-remove must report any surviving mirror/backup copy, so the caller never claims total destruction
	//     while an openable off-site copy remains.
	ok('secureRemove reports survivingCopies (mirror/backup still openable)', /survivingCopies\b/.test(vault) && /survivingCopies\.push\(\{ kind: 'mirror'/.test(vault) && /survivingCopies\.push\(\{ kind: 'backup'/.test(vault));

	// 36. The downloaded Tor binary must be re-verified against a recorded sha once per process (parity with the
	//     storage engine), not trusted on a tag match alone.
	const torSetup = read('TorSetup.js');
	ok('TorSetup re-verifies the cached binary against a recorded sha (fail-closed re-download otherwise)', /binShaSidecar\(/.test(torSetup) && /_binVerified/.test(torSetup) && /Net\.sha256File\(binPath\)/.test(torSetup));

	// 37. The "target absent = reachable" classifier must exclude auth/permission errors, so a 403/forbidden that also
	//     prints a path is never read as "folder does not exist yet".
	ok('remoteTargetAbsent excludes access/auth errors from the absent classification', /function remoteTargetAbsent\(stderr\)[\s\S]{0,200}REMOTE_ACCESS_ERROR\.test/.test(vault));

	// 38. The decoy resolver must burn an equivalent KDF when the registry is present-but-unreadable, matching the
	//     no-registry branch, so a failed unlock there is not measurably faster (a timing oracle).
	const decoy = read('Decoy.js');
	ok('resolveDecoy burns a KDF on an unreadable registry (constant-work timing)', /catch \(_\) \{ try \{ await SR\.deriveK\(String\(password \|\| ''\), SR\.newKdfParams\(\)\); \} catch \(_\) \{\} return null; \}/.test(decoy));

	// 39. The dead-man tick must sweep stale release material whenever the phase is neither due nor released, so a
	//     crash between a check-in's settings commit and its folder removal cannot leave an openable grant on disk.
	ok('emergencyTick sweeps stale release material when not releasing/released', /if \(phase !== 'released'\) \{ try \{ await withdrawEmergencyRelease\(\); \} catch \(_\) \{\} \}/.test(vault));
	// 40. emergencyEnroll must spread ...prev so a re-enroll never drops the trustee backstop.
	ok('emergencyEnroll preserves prior config (spreads ...prev) so a re-enroll keeps the backstop', /emergency: \{ \.\.\.prev, contacts, inactivityMs, graceMs/.test(vault));

	// 41. Passwordless verify must be scoped to the named credential (one KDF per attempt, not one per enrolled key).
	ok('verifyUiWebauthn verifies the named credential only (single derivation per attempt)', /const legacy = \(auth\.webauthn \|\| \[\]\)\.filter\(w => w\.hash && !w\.pubKey\)/.test(vault));

	// 42. The strong passwordless sign-in must be a real assertion: a single-use, size-capped server challenge, verified
	//     against the stored public key, with the challenge consumed on use so it cannot be replayed.
	ok('the login challenge store is single-use and size-capped (OOM-proof)', /loginChallenges\.delete\(key\); return exp > Date\.now\(\)/.test(server) && /loginChallenges\.size >= LOGIN_CHALLENGE_MAX/.test(server));
	ok('the login POST consumes the challenge then verifies the assertion against the stored key', /consumeLoginChallenge\(chal\)/.test(server) && /verifyUiWebauthnAssertion\(body\.webauthnId/.test(server));
	ok('verifyUiWebauthnAssertion verifies via WebAuthn.verifyAssertion and advances the signature counter', /WebAuthn\.verifyAssertion\(\{/.test(vault) && /res\.signCount > \(w\.signCount \|\| 0\)/.test(vault));
	ok('an assertion-format credential stores a public key and algorithm (not a reusable secret)', /entry = \{ \.\.\.base, pubKey:/.test(vault));
	// 43. The webauthn-add route must forward the public key + algorithm (dropping them would silently fall back to the
	//     weak format), and every webauthn mutation must bust the 1-second UI-auth cache so the login page reflects it.
	ok('the webauthn-add route forwards publicKey and alg to enrollment', /webauthn-add[\s\S]{0,200}addUiWebauthn\(\{ secret, credentialId, prfSalt, publicKey, alg, label, password \}\)/.test(server));
	ok('webauthn add / remove / remove-all each bust the UI-auth cache', (server.match(/invalidateUiAuthCache\(\)/g) || []).length >= 5);
	ok('removeAllUiWebauthn clears every enrolled key and reports the count', /async function removeAllUiWebauthn\(\)[\s\S]{0,300}webauthn: \[\]/.test(vault));

	// 44. The single-file proof must be a full hybrid signature (v2): it carries the ML-DSA key/co-signature and both
	//     verifiers check it with verifyHybrid, so a classical-only forgery cannot pass. FILE_PROOF_VERSION must match
	//     the standalone verifier (the parity test cross-checks the verdict composition).
	const verifyBundle = read('verify-bundle.js');
	ok('fileProof emits the post-quantum co-signature (sigPq + pqPubkey)', /pqPubkey: pqPub,/.test(vault) && /sigPq: record\.sigPq \|\| null/.test(vault));
	ok('verifyFileProof checks the hybrid signature in BOTH verifiers', /verifyHybrid\(pub, p\.pqPubkey \|\| null,[\s\S]{0,500}p\.baseline\.sigPq/.test(vault) && /verifyHybrid\(pub, p\.pqPubkey \|\| null,[\s\S]{0,500}p\.baseline\.sigPq/.test(verifyBundle));
	ok('FILE_PROOF_VERSION is 2 in both the tool and the standalone verifier', /const FILE_PROOF_VERSION = 2;/.test(vault) && /const FILE_PROOF_VERSION = 2;/.test(verifyBundle));
	ok('the standalone verifyHybrid gates classical-only on the published key, not only the runtime', /if \(!pqPub\) return true; if \(!pqAvailable\(\)\) return true;/.test(verifyBundle));
	ok('enrollment validates the stored public key against its algorithm', /WebAuthn\.validatePublicKey\(String\(publicKey\), Number\(alg\)\)/.test(vault));

	// 45. The per-poll settings read must be O(1) parses, not O(vaults): the hot read-only callers share one memoized,
	//     frozen parse (getSettingsCached), and the machine credential key is memoized after the first successful read.
	ok('mirrorStatus and the SFTP/cloud/peer listers use the shared cached settings parse', (vault.match(/getSettingsCached\(\)/g) || []).length >= 4 && /async function getSettingsCached\(\)/.test(vault));
	ok('machineCredKey memoizes the valid key (no mkdir + read on every call)', /let _credKeyMemo = null;[\s\S]{0,200}if \(_credKeyMemo\) return _credKeyMemo;/.test(vault));

	// 46. The mobile trace-tag dark amber must be gated behind a dark system for the "auto" theme, or it renders
	//     unreadably (~2:1) on the light default. Pin that "auto" gets it only inside a prefers-color-scheme: dark block.
	const mobileCss = read('webserver/public/mobile/app.css');
	ok('the mobile trace-tag dark amber is gated behind prefers-color-scheme: dark for the auto theme', /@media \(prefers-color-scheme: dark\) \{ :root\[data-theme="auto"\] \.tracetag\.stored/.test(mobileCss));

	// 47. The vault list must reconcile PER CARD, not rebuild wholesale. The old path set the list's innerHTML from
	//     `ordered.map(vaultCard).join('')` whenever any one field changed, destroying and recreating every card's DOM
	//     each poll — losing focus and scroll, and re-laying-out the whole list at scale. The keyed diff keys each card
	//     on its vault path (data-key), signs it with the HTML vaultCard() produced (lastCardSig), and replaces ONLY
	//     the changed cards, adding/removing/reordering the rest with plain DOM moves. A regression back to a wholesale
	//     innerHTML rebuild would silently return the focus-loss and relayout, so pin the reconciliation structure and
	//     lock out the wholesale rebuild. Scope the innerHTML check to renderVaults so the per-badge writes elsewhere
	//     (refreshLiveBadges) are not falsely flagged.
	const app = read('webserver/public/js/app.js');
	const renderBody = body(app, 'function renderVaults(', 4800);
	ok('each vault card carries a stable key (data-key = vault path)', /<div class="card[^"]*"[^>]*data-key="\$\{esc\(v\.path\)\}"/.test(app));
	ok('the per-card signature store is keyed by path (lastCardSig), not one list-wide HTML string', /let lastCardSig = \{\};/.test(app) && !/lastCardsHtml/.test(app));
	ok('renderVaults reconciles per card by key and signature (keep / replace / create)', renderBody.length > 0 && /byKey\.get\(key\)/.test(renderBody) && /lastCardSig\[key\] === html/.test(renderBody) && /el = cardEl\(html\)/.test(renderBody) && /lastCardSig = nextSig;/.test(renderBody));
	ok('renderVaults orders cards with DOM moves, not a wholesale rebuild', renderBody.length > 0 && /list\.insertBefore\(el, after\)/.test(renderBody));
	ok('renderVaults never rebuilds the whole list with innerHTML, and the old wholesale map/join is gone', renderBody.length > 0 && !/\.innerHTML\s*=/.test(renderBody) && !/ordered\.map\(vaultCard\)\.join/.test(app));
	ok('a dialog still holds the list in place and refreshes only live badges (focus-return safety)', renderBody.length > 0 && /if \(!force && document\.querySelector\('dialog\[open\]'\)\)/.test(renderBody) && /refreshLiveBadges\(list\)/.test(renderBody));
	ok('cardEl parses a card without throwing into the poll (returns null on bad input)', /function cardEl\(html\) \{[\s\S]{0,260}catch \(_\) \{ return null; \}/.test(app));
	// 48. The reconciliation key must match the value the DOM carries (data-key = esc(v.path) reads back as
	//     strip(v.path)); keying on the raw path would miss the node for a path with a stripped control/bidi character
	//     and rebuild that card every poll. And the focus-safety deferral must key on the REAL open control (the color
	//     popover) or the active element — not a menu the card no longer has — or a live-badge flip would destroy an
	//     open picker and drop focus.
	ok('the reconciliation keys on strip(v.path), matching the DOM data-key', renderBody.length > 0 && /const key = strip\(v\.path\);/.test(renderBody));
	ok('a card with an open popover or holding focus is kept in place (not replaced)', renderBody.length > 0 && /cur\.querySelector\('\.color-pop:not\(\[hidden\]\)'\) \|\| cur\.contains\(document\.activeElement\)/.test(renderBody) && !/details\.more\[open\]/.test(renderBody));

	// 49. No-mount viewing of a CLOUD vault is store-direct and SIZE-BOUNDED: the service lists/fetches encrypted
	//     objects through the engine (never decrypting), the fetch is binary (ciphertext not UTF-8-mangled) and capped,
	//     and the viewer refuses large/media files to a mount. Pin the structure so none of these guards is lost.
	const mobileJs = read('Mobile.js');
	ok('mobilePrepare returns the cloud backend config + ciphertext remote for the no-mount viewer', /cloud,\s*\n\s*cipherRoot: cloud \? null : cipherDirOf\(abs\),\s*\n\s*cloudBackendText,/.test(vault));
	ok('Mobile.list routes a cloud session to the store-direct cloud lister', /if \(session\.cloud\) return listCloud\(session, opts\);/.test(mobileJs));
	ok('fetchCloud validates the path fail-closed and caps the binary ciphertext fetch', /function fetchCloud\([\s\S]{0,1600}binary: true/.test(mobileJs) && /norm\.startsWith\('\.\.\/'\)/.test(mobileJs));
	ok('the ciphertext fetch is bounded (CLOUD_VIEW_MAX), not unbounded', /const CLOUD_VIEW_MAX = 8 \* 1024 \* 1024;/.test(mobileJs));
	ok('the /files route serves a cloud session store-direct (no local sendFile)', /if \(s\.cloud\) \{[\s\S]{0,300}Mobile\.fetchCloud\(s, rel, Mobile\.CLOUD_VIEW_MAX\)/.test(read('webserver/mobileRoutes.js')));
	ok('the rclone spawn supports a binary (Buffer) stdout mode so ciphertext is not UTF-8-corrupted', /binary: binary \? Buffer\.concat\(outBin, outBinLen\) : /.test(read('Rclone.js').replace('stdout: ', '')) || /stdout: binary \? Buffer\.concat\(outBin, outBinLen\)/.test(read('Rclone.js')));
	ok('the cloud viewer skips media streaming and applies the small cap', /!\(session && session\.cloud\) && MEDIA_EXT\.test/.test(read('webserver/public/mobile/app.js')) && /var cap = cloud \? CLOUD_VIEW_MAX : MAX_INMEM_BYTES;/.test(read('webserver/public/mobile/app.js')));
	// 50. No-mount web access is allowed for a cloud vault, but ONLY blocked when the backend uses a filename encoding
	//     the in-browser reader cannot decode (base32768); the default base32 (WebDAV/SFTP/object storage) is allowed.
	//     Pin that the blanket cloud block is gone and the encoding-aware guard is in its place.
	ok('web access is gated on the cloud filename encoding, not blocked outright', /isCloudVault\(manifest\) && c\.filename_encoding && c\.filename_encoding !== 'base32'/.test(vault) && !/Web access is not yet supported for cloud vaults/.test(vault));

	// 51. A flood of no-mount cloud reads must not spawn an unbounded number of engine children (each rclone cat is a
	//     process + an ephemeral config): the listing and the fetch acquire a bounded slot and REJECT past a queue cap,
	//     and every path releases the slot exactly once (the config-write failure path releases BEFORE the try so the
	//     finally never double-releases). Losing the limiter reopens an OOM / fork-bomb under concurrent phone reads.
	ok('cloud engine calls are bounded by a semaphore with a queue cap', /const CLOUD_MAX_INFLIGHT = 6;/.test(mobileJs) && /const CLOUD_MAX_QUEUED = 64;/.test(mobileJs) && /cloudWaiters\.length >= CLOUD_MAX_QUEUED/.test(mobileJs) && /busy: true/.test(mobileJs));
	ok('listCloud and fetchCloud both acquire and release a cloud slot', (mobileJs.match(/await acquireCloudSlot\(\);/g) || []).length >= 2 && (mobileJs.match(/releaseCloudSlot\(\);/g) || []).length >= 3);
	ok('a config-write failure releases the slot BEFORE the try (no double-release in the finally)', /writeEphemeralConfig\(session\.cloudBackendText\)\.catch\(\(e\) => \{ releaseCloudSlot\(\); throw e; \}\)/.test(mobileJs) && /catch \(_\) \{ releaseCloudSlot\(\); return \[\]; \}/.test(mobileJs));
	ok('the /files route turns a busy rejection into a 503 (not a 500)', /e && e\.busy[\s\S]{0,80}status\(503\)/.test(read('webserver/mobileRoutes.js')));

	// 52. Liveness must be CHEAP: a 30s heartbeat and a tab-resume must hit /m/ping (a bare 200/401), never re-walk the
	//     whole vault via the list endpoint — on a cloud vault a re-list is a full recursive engine listing. Pin that the
	//     ping route exists and that both client timers use session.ping, not session.list.
	const appJs = read('webserver/public/mobile/app.js');
	ok('a cheap /m/ping liveness route exists (authorize only, no engine)', /mobile\.get\('\/ping\/:sid'/.test(read('webserver/mobileRoutes.js')));
	ok('the client builds session.ping and the heartbeat + resume use it (not session.list)', /ping: '\/m\/ping\/' \+ res\.j\.sessionId/.test(appJs) && !/setInterval\(function \(\) \{ if \(session\) authFetch\(session\.list\)/.test(appJs) && (appJs.match(/authFetch\(session\.ping\)/g) || []).length >= 2);

	// 53. A no-mount cloud vault re-fetches the same ciphertext on every open (list metadata, then open, then re-open):
	//     an in-memory LRU avoids re-hitting the network, and loadNotesMeta fans out with BOUNDED concurrency so a vault
	//     with many notes lists in parallel, not one serial round-trip at a time. The LRU must be wiped on lock/forget,
	//     and the client cap must match the server cap or a file the server serves would be refused by the client.
	ok('an in-memory ciphertext LRU exists, is byte-bounded, and getCipher consults it', /var MEM_CIPHER_MAX = 12 \* 1024 \* 1024;/.test(appJs) && /function memCacheGet\(/.test(appJs) && /var mem = memCacheGet\(enc\);/.test(appJs) && /memCachePut\(enc,/.test(appJs));
	ok('forget() wipes the in-memory ciphertext cache on lock', /memCacheClear\(\);/.test(appJs) && /function forget\([\s\S]{0,900}memCacheClear\(\)/.test(appJs));
	ok('loadNotesMeta fans out with bounded concurrency (a worker pool), not one serial fetch at a time', /var NOTES_META_CONCURRENCY = 5;/.test(appJs) && /for \(var w = 0; w < NOTES_META_CONCURRENCY; w\+\+\) pool\.push\(worker\(\)\);/.test(appJs) && /Promise\.all\(pool\)/.test(appJs));
	ok('the client CLOUD_VIEW_MAX matches the server CLOUD_VIEW_MAX (a server-served file is never client-refused)', /var CLOUD_VIEW_MAX = 8 \* 1024 \* 1024;/.test(appJs) && /const CLOUD_VIEW_MAX = 8 \* 1024 \* 1024;/.test(mobileJs));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL RELIABILITY-GUARD CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
