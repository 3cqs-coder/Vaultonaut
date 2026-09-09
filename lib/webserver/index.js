'use strict';
// lib/webserver/index.js — a small local web UI for the encrypted disks. It binds
// to 127.0.0.1 only by default (never the network); it exposes a network address
// only via an explicit `--bind`, which is refused unless a login password is set
// and is then served over HTTPS. It renders one EJS page and exposes a thin JSON
// API that calls the same async library the CLI uses. Passwords are entered in the
// browser and posted to the server; they are used to derive the key and are never stored.
//
//   start(port) -> { server, port }

const express = require('express');
const http = require('http');
const https = require('https');
const net = require('net'); // net.isIP — validate a network bind address before installing autostart with it
const path = require('path');
const { performance } = require('perf_hooks'); // monotonic clock, to tell a forward clock jump from ordinary sleep
const os = require('os');
const fsp = require('fs/promises');
const Vault = require('../Vault');
const UiAuth = require('../UiAuth');
const Cert = require('../Cert');
const SelfCheck = require('../SelfCheck');
const UpdateCheck = require('../UpdateCheck');
const ReleaseIntegrity = require('../ReleaseIntegrity');
const Rclone = require('../Rclone');
const Mobile = require('../Mobile');
const MobileRoutes = require('./mobileRoutes');
const Watchdog = require('../Watchdog');
const ProcRegistry = require('../ProcRegistry');
const Guardian = require('../Guardian');
const Common = require('../Common');
const Brand = require('../Brand');
const IpMatch = require('../IpMatch');
const SdNotify = require('../SdNotify');
const Phase = require('../Phase');

const PKG = require('../../package.json');
const ROOT = path.join(__dirname);

// A bind address that stays on this machine only. Anything else is "exposed" and triggers the mandatory
// login + TLS below. The one shared, DNS-safe predicate lives in Common so every security gate agrees.
const isLoopbackAddr = Common.isLoopbackHost;

// The CURRENT web-interface auth config, re-read (briefly cached) rather than captured once at startup,
// so changing or clearing the password — which mints a fresh signing secret — takes effect on a running
// server: old sessions stop verifying and the new password is accepted, without a restart.
let _uiAuthCache = { at: 0, val: null };
async function currentUiAuth() {
	const now = Date.now();
	if (_uiAuthCache.val && now - _uiAuthCache.at < 1000) return _uiAuthCache.val;
	const val = await Vault.getUiAuth();
	_uiAuthCache = { at: now, val };
	return val;
}
// Drop the 1-second auth cache immediately, so a secret rotation done in THIS process (logout, or setting/changing
// the web password) takes effect at once. Without this, a signed-out or just-changed session's OLD cookie would
// keep validating against the cached old secret for up to a second — exactly the window a "sign out to kill a
// stolen token" or a "lock everyone out" password change is meant to close.
function invalidateUiAuthCache() { _uiAuthCache = { at: 0, val: null }; }

// Background recovery refreshes in flight (keyed by resolved vault path). After a vault is unmounted
// with changes, its recovery data is rebuilt off to the side; this lets the vault list show a quiet
// "updating protection" indicator while it runs, without blocking anything.
const refreshingRecovery = new Map(); // vaultPath -> { percent, label }

// The per-vault reads for the poll: the manifest, self-heal status, and mirror status. These touch the
// vault's BACKING store (where the vault folder lives, which may be a removable or network drive), so any
// of them can hang if that drive wedges. Kept together so one cache entry covers all three.
// A single global cap on how many vaults' backing-store probes run at once, across ALL vaults. freshCache dedups to
// one in-flight compute per vault, but launches those detached, so without this a large vault list on several
// independently-wedged drives could pin one slow syscall each and swamp libuv's file thread pool, starving every
// other file operation (mounts, note reads, settings writes). Keeping the cap well below the pool size guarantees
// some threads always remain for that other work, even if every gated probe is stuck; a wedged drive holds one slot
// until its own per-op timeouts fire, never the whole pool. The pool itself is enlarged at startup (see vaultonaut.js).
const pollProbeGate = Common.semaphore(6);
async function computeVaultState(dir) {
	return pollProbeGate(async () => {
		let manifest = null, ok = true;
		try { manifest = await Vault.readManifestForPoll(dir); } catch (_) { ok = false; } // stat-keyed and per-op time-bounded: a single stat when unchanged, not a full read+parse every poll
		let recovery = { protected: false };
		try { recovery = await Vault.recoveryStatus(dir); } catch (_) {} // reads only the small index meta (off the event loop in the recovery worker on a change)
		let mirror = { configured: false };
		try { mirror = await Vault.mirrorStatus(dir); } catch (_) {}
		return { manifest, recovery, mirror, ok };
	});
}

// Stale-while-revalidate cache for those reads (Common.freshCache): /api/state is polled every few seconds,
// so a vault on a wedged drive must not hang the poll or start a fresh (thread-pinning) read on every poll.
// It returns the last-known value immediately, refreshes in the background, and keeps at most one read per
// vault outstanding — so a wedged drive pins a single operation, not one per poll. A pending vault (first
// read not yet back) reads as undefined and is shown optimistically. computeVaultState always resolves (a
// broken vault resolves to { ok:false }), so an undefined value means genuinely-slow I/O, not a bad vault.
const readVaultState = Common.freshCache(computeVaultState, { firstWaitMs: 2500 });

// Gather everything the page needs in one call: environment readiness, known
// vaults with their details, and which are currently mounted.
// The exact settings shape the client sees — built in ONE place so the initial state poll and the
// /api/settings save response can never drift (a field returned by one but not the other would silently
// fail to restore in the UI on the next load). Every user-facing setting the interface reads belongs here.
// Turn the stored last-check record into a live status against the CURRENT running version. Recomputing here (rather
// than trusting a stored updateAvailable flag) means that after the user updates, an old "update available" record
// resolves to up-to-date on its own, without another network call.
function updateStatusFrom(last) {
	if (!last || !last.latest) return null;
	const current = ReleaseIntegrity.appVersion() || '0.0.0';
	return { current, latest: last.latest, at: last.at || null, updateAvailable: UpdateCheck.compareVersions(last.latest, current) > 0, ahead: UpdateCheck.isAhead(current, last.latest), releasesUrl: UpdateCheck.RELEASES_URL };
}
function publicSettings(s) {
	s = s || {};
	return {
		autoLockMinutes: s.autoLockMinutes || 0,
		autoAttest: !!s.autoAttest,
		lockOnSleep: !!s.lockOnSleep,
		autoUpdateCheck: !!s.autoUpdateCheck,
		// The last successful update check, evaluated LIVE against the running version: after the user updates, the
		// stored `latest` no longer exceeds the current version, so the banner clears with no re-fetch. Null until a
		// check has run. Only a version number and a timestamp are stored — never anything about the machine.
		updateStatus: updateStatusFrom(s.lastUpdateCheck),
		versionsKeep: (s.versionsKeep == null ? 10 : s.versionsKeep),
		versionsMaxAgeDays: s.versionsMaxAgeDays || 0,
		versionsMaxSizeMB: s.versionsMaxSizeMB || 0,
		bwlimit: s.bwlimit || '',
	};
}

async function buildState() {
	// Read the tracked mounts WITHOUT statting them (listMounts, not status): this runs on every
	// UI poll, and statting a wedged mount here could tie up worker threads. Responsiveness comes
	// from the Watchdog's cached, de-duplicated probe instead.
	const [doctor, mv] = await Promise.all([Vault.doctor(), Vault.listMountsAndVaults()]); // mounts + known vaults from ONE state read, not two
	const mounts = mv.mounts, known = mv.vaults;
	const healthMap = Watchdog.snapshot(); // cached; instant; { <mountpoint>: 'healthy'|'unresponsive'|'dead' }
	const settings = await Vault.getSettings();
	const backupDests = settings.backupDests || {};
	const backupSchedules = settings.backupSchedules || {};
	// Read every vault's bundle CONCURRENTLY (readVaultState is in-flight-deduped), so a poll's worst case is
	// ONE stale-while-revalidate window, not that window stacked once per vault — otherwise several wedged
	// drives would serialize their wait times onto a single request.
	// Look up a vault's mount by its folded resolved path in O(1), instead of a linear samePath scan per vault
	// (O(vaults x mounts)). foldPath(resolve(...)) is the same case-aware key samePath compares on.
	const mountByVault = new Map(mounts.map(m => [Common.foldPath(path.resolve(m.vault)), m]));
	// Bound the fan-out: on a cold cache (first poll) a large vault list would otherwise launch every per-vault
	// compute (stat + settings + baseline probe) at once, a threadpool burst. mapLimit keeps at most a handful in
	// flight while preserving order; the per-vault reads are still in-flight-deduped by freshCache.
	const vaults = await Common.mapLimit(known, 12, async (dir) => {
		const abs = path.resolve(dir); // resolve ONCE per vault, not ~7x below (known-vault paths are stored resolved, but this stays correct if one isn't)
		// Stale-while-revalidate: never let a vault on a wedged drive hang the poll. A pending bundle
		// (first read not back yet) is treated optimistically as valid, so a healthy vault never flashes as
		// broken; if the read then fails, the next poll corrects it.
		const st = await readVaultState(abs);
		const pending = st === undefined;
		const manifest = st ? st.manifest : null;
		const valid = st ? st.ok : true;
		const m = mountByVault.get(Common.foldPath(abs)) || null;
		const mountpoint = m ? m.mountpoint : null;
		const health = mountpoint ? (healthMap[mountpoint] || 'healthy') : null;
		let recovery = st ? st.recovery : { protected: false };
		const refreshing = refreshingRecovery.get(abs);
		if (refreshing) recovery = { ...recovery, refreshing: true, refreshPercent: refreshing.percent, refreshLabel: refreshing.label };
		let mirror = st ? st.mirror : { configured: false };
		if (mirroringNow.has(abs)) mirror = { ...mirror, syncing: true };
		// Whether this server is serving the vault as a node (no password in the broad poll — the
		// serve dialog fetches it on demand from /api/serve-info).
		const se = servedVaults.get(abs);
		const serving = se ? { serving: true, url: se.url, user: se.user, bind: se.bind } : { serving: false };
		return {
			path: dir,
			name: Vault.displayName(dir),
			valid,
			checking: pending,                        // first read not back yet (e.g. a slow/wedged backing drive)
			createdAt: manifest ? manifest.createdAt : null,
			mounted: !!m,
			mountpoint,
			health,                                  // null when not mounted
			responsive: !mountpoint || health === 'healthy',
			sealed: !!(manifest && manifest.snapshot && manifest.snapshot.sealed), // strict tamper tripwire active
			hasBaseline: !!(manifest && manifest.snapshot),                        // a tamper baseline has been recorded
			biometric: manifest ? Vault.deviceDescriptors(manifest) : [], // enrolled device-unlock credentials
			keyfile: !!(manifest && manifest.crypt && Array.isArray(manifest.crypt.keySlots) && manifest.crypt.keySlots.some(s => s.kind === 'keyfile')), // a keyfile slot exists
			cloud: !!(manifest && manifest.crypt && manifest.crypt.backend && manifest.crypt.backend.remoteId), // stored on a cloud remote
			worm: (manifest && manifest.crypt && manifest.crypt.backend && manifest.crypt.backend.worm) || null, // tamper-proof (Object Lock) mode + retention, if any

			backupDest: backupDests[abs] || null,           // last backup destination, for one-click repeat
			backupSchedule: backupSchedules[abs] || { mode: 'off' },
			mountPrefs: (settings.mountPrefs || {})[abs] || null, // remembered mount options
			favorite: !!((settings.favorites || {})[abs]),         // surfaced first, one-tap unlock
			recovery,                                                      // self-healing status ({ protected, tier, ... })
			mirror,                                                        // Tier-1 mirror status ({ configured, dest, primed, ... })
			serving                                                        // node/serve status ({ serving, url, user, bind })
		};
	});
	// These four are independent reads; run them together (not one awaited after another) since buildState is on
	// the frequent /api/state poll.
	const [sftpDests, cloudRemotes, peers, uiAuth] = await Promise.all([Vault.listSftpDests(), Vault.listCloudRemotes(), Vault.listPeers(), currentUiAuth()]);
	// Deliberately NOT reporting whether per-vault decoy protection is configured. The client never used that
	// field, and broadcasting it on the frequent poll would disclose that a decoy pairing exists — defeating the
	// deniability the feature exists for. Decoy state is revealed only to a caller that holds the manager password.
	return { doctor, vaults, mounts, settings: publicSettings(settings), sftpDests, cloudRemotes, peers, auth: { enabled: uiAuth.enabled }, selfCheck: SelfCheck.last(), vaultsDir: Vault.vaultsDir(), defaultRoot: Vault.defaultMountRoot(), home: os.homedir() };
}

// One health-watch pass: refresh each mount's responsiveness, report any change in plain language,
// and auto-recover a stale mount (engine gone, still mounted) so the user never has to. A mount
// that is wedged with its engine still alive is reported but NOT torn down here — recovery is left
// to the explicit one-click Force unmount, so a healthy-but-busy drive is never disrupted. Never
// throws, so the watch can never disturb a mount.
let watchBusy = false; // guard so a slow tick can't overlap the next one
let autoLockRunning = false; // guard so the detached auto-lock pass can't overlap itself across ticks
let sweepRunning = false;    // same, for the detached housekeeping sweep (force-unmount stale mounts, resume a rekey)
let sleepLockRunning = false; // same, for the detached lock-on-sleep pass (a gentle unmount of every open vault drains)
let autoUpdateRunning = false; // guard for the detached opt-in update check
let lastAutoUpdateAt = 0;      // throttle the opt-in update check to roughly once a day
const AUTO_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000;
// The monotonic time the last health tick COMPLETED its work. The systemd watchdog pings only while this is
// recent, so a wedged tick (this never advances) stops the pings and systemd restarts us. Seeded so an early
// ping before the first tick is not a false "healthy".
let lastHealthyMono = SdNotify.monoMs();
let stopWatchdog = () => {}; // set once the health loop is running (systemd watchdog); a no-op off systemd

// The external crash-safety guardian (locks vaults if THIS service is hard-killed). We keep its owner tag and
// pid so the health tick can confirm it is still alive and RE-LAUNCH it if it died — otherwise a guardian that
// failed to start, or was itself killed, would silently void the "even on a crash it unmounts" guarantee and
// leave a decrypted vault mounted. Best-effort, warn-once.
let guardianOwner = null, guardianPid = null, guardianWarned = false;
// Periodically re-run the self-check so its findings (shown in the UI from the cached last sweep) reflect
// conditions that change WITHOUT a restart or an explicit re-check — e.g. the disk filling up or being freed,
// or a registered vault's drive reconnecting. Time-gated so the cheap checks don't run on every 12s tick.
let lastSelfCheckAt = 0;
const SELFCHECK_REFRESH_MS = 5 * 60 * 1000;
function ensureGuardian() {
	if (!guardianOwner) return;
	if (guardianPid && Common.isProcessAlive(guardianPid)) return; // still watching
	try {
		guardianPid = Guardian.launch(guardianOwner);
		if (guardianWarned) { Common.log('Crash-safety guardian re-launched.'); guardianWarned = false; Vault.setSettings({ guardianDownAt: null }).catch(() => {}); } // recovered — clear the self-check notice
	} catch (e) {
		if (!guardianWarned) { Common.warn('Could not launch the crash-safety guardian — open vaults could stay mounted if this service is killed. ' + ((e && e.message) || e)); guardianWarned = true; Vault.setSettings({ guardianDownAt: new Date().toISOString() }).catch(() => {}); } // also surface it in the self-check banner
	}
}
// Detect a resume from system SLEEP/SUSPEND without any OS event hook: while the machine sleeps this 12s timer
// does not fire, so a gap far larger than the interval means we just woke. Spawn-free and cross-platform. On
// resume, if lock-on-sleep is on, lock every open vault — the "walk-away" protection for closing the laptop.
const SLEEP_RESUME_GAP_MS = 90 * 1000;
const WATCH_TICK_MS = 12 * 1000;              // how often watchTick runs; also the yardstick for the clock-jump test below
const CLOCK_FORWARD_JUMP_MS = 5 * 60 * 1000;  // a wall-vs-monotonic gap beyond this, while running, is a forward clock jump
let lastWatchAt = Date.now();
let lastWatchMono = performance.now();        // monotonic companion to lastWatchAt; suspended during sleep, so it separates a sleep from a real clock jump
async function watchTick() {
	if (watchBusy) return;
	watchBusy = true;
	try {
		// Everything from here to the finally runs INSIDE the try, so a synchronous throw anywhere is caught and the
		// finally still clears watchBusy — otherwise a throw in this prologue would latch watchBusy true and silently
		// stop the health watch (and the guardian supervision, auto-lock, and systemd ping it drives) forever.
		// Measure the gap from the PREVIOUS tick's END (stamped in the finally), not this tick's start — otherwise a
		// single slow health pass (many unresponsive mounts, a debugger pause) would look like a sleep gap on the
		// next tick and spuriously lock the vaults. A real sleep still shows a large gap because no tick ran meanwhile.
		const wokeFromSleep = (Date.now() - lastWatchAt) > SLEEP_RESUME_GAP_MS;
		// Detect a forward CLOCK jump WHILE running (an NTP correction of a badly-wrong clock, or a manual change), which
		// can prematurely expire write leases, the dead-man timer, and skew tamper timestamps. It is told apart from
		// ordinary sleep by the monotonic clock: during sleep the monotonic clock is suspended (a near-zero mono gap),
		// whereas a jump-while-running fires this tick roughly on schedule (a normal mono gap) yet shows the wall clock
		// far ahead of the elapsed monotonic time. The bands keep a merely delayed tick from being mistaken for a jump.
		const monoGap = performance.now() - lastWatchMono, wallGap = Date.now() - lastWatchAt;
		if (monoGap >= WATCH_TICK_MS * 0.5 && monoGap <= WATCH_TICK_MS * 4 && (wallGap - monoGap) > CLOCK_FORWARD_JUMP_MS) {
			const jumpMin = Math.round((wallGap - monoGap) / 60000);
			Common.log('The system clock appears to have jumped forward about ' + jumpMin + ' minute(s) while running — write leases, the dead-man timer, and tamper timestamps use the clock, so any that were pending may have advanced. Check the system date and time.');
			Vault.setSettings({ clockAnomalyAt: new Date().toISOString(), clockAnomalyJumpMin: jumpMin }).catch(() => {}); // best-effort; surfaced by the clock_forward_jump self-check for a day
			// Discount the spurious advance from the dead-man timer so a forward jump cannot fire it early (genuine
			// time away, on or off, still counts — the monotonic clock above told this apart from ordinary sleep).
			Vault.emergencyNoteClockDrift(wallGap - monoGap).catch(() => {});
		}
		// Bound the two data-directory reads on this hot tick: the data dir can now be a per-user home that, on a
		// network/NFS mount, could wedge — an unbounded read here would pin a thread and stall the health watch (and
		// the guardian supervision it drives) indefinitely. A timeout degrades ONE cycle (treat as no mounts / default
		// settings) rather than hanging; the next tick recovers. Reads elsewhere (mutations) keep their own handling.
		const mounts = await Common.withTimeout(Vault.listMounts(), 5000).catch(() => []);
		// Lock-on-sleep: gently lock open vaults after the machine wakes (never forces, so unsaved work and a
		// vault with an open file are safe — the same semantics as Lock all / idle auto-lock).
		if (wokeFromSleep && mounts.length && !sleepLockRunning && (await Common.withTimeout(Vault.getSettings(), 5000).catch(() => ({}))).lockOnSleep) {
			// Run DETACHED behind a guard, exactly like the auto-lock and schedule ticks below. lockAll gently
			// unmounts every open vault, and a gentle unmount DRAINS its write-back cache (bounded per vault, but the
			// aggregate over several vaults is not) — awaiting it here would park the hot tick for the whole drain, so
			// the health stamp that gates the systemd watchdog ping would stall and the service could be killed
			// MID-FLUSH (losing undrained writes). afterLock runs the same lease/viewer teardown and mirror/recovery
			// refresh as every other lock. The guard stops a slow drain from overlapping the next wake check.
			sleepLockRunning = true;
			Vault.lockAll()
				.then(r => { afterLock(r.vaults); if (r.locked) Common.log('Resumed from sleep — locked ' + r.locked + ' open vault' + (r.locked === 1 ? '' : 's') + ' (lock-on-sleep).'); })
				.catch(() => {})
				.finally(() => { sleepLockRunning = false; });
		}
		// While we hold any open vault, make sure the crash-safety guardian is still alive — re-launch it if it
		// died, so the "even on a crash it unmounts" net is never silently down while a decrypted vault is open.
		if (mounts.length > 0) ensureGuardian();
		if (guardianOwner) Vault.touchOwnerAlive(guardianOwner).catch(() => {}); // refresh our liveness heartbeat so a later instance's orphan sweep never mistakes a recycled pid for us
		checkLeaseStaleness(); // warn if a writable mirrored vault's write-lease is silently going stale
		// Self-correct a leaked write-lease: if we are still refreshing a lease for a vault we no longer have
		// mounted — e.g. it was torn down directly by a separate `vdisk unmount --force`, bypassing our
		// /api/unmount — stop the heartbeat so it stops re-publishing the lease and never blocks another machine
		// from taking the write. (A normal delegated unmount already stops it via stopLeaseHeartbeat.)
		if (leaseHeartbeats.size) {
			const ownedNow = new Set(mounts.filter(m => m.owner === guardianOwner && m.vault).map(m => path.resolve(m.vault)));
			for (const key of [...leaseHeartbeats.keys()]) if (!ownedNow.has(key)) stopLeaseHeartbeat(key);
		}
		if (Date.now() - lastSelfCheckAt > SELFCHECK_REFRESH_MS) { lastSelfCheckAt = Date.now(); SelfCheck.run({ label: 'periodic' }).catch(() => {}); } // keep the self-check findings fresh (disk space, reconnected drives) without a restart
		// Keep each live mount's control socket from being reaped by an OS temp-file cleaner: touch its
		// mtime every tick so a long-running healthy mount is never mistaken for a dead one. Bounded like the
		// other awaits on this hot tick, so it can never pin the health watch even in a pathological case.
		await Common.withTimeout(Rclone.touchSockets(mounts), 5000).catch(() => {});
		// Best-effort: capture a rotating cloud sign-in token (OneDrive) that changed mid-session, so a hard crash
		// before a clean unmount does not leave the saved token stale. Throttled internally; never blocks this tick.
		Vault.cloudTokenTick(mounts).catch(() => {});
		// Bounded like the other awaits on this hot tick: refresh probes each mount's engine liveness (a per-mount
		// socket connect), and although each probe is itself bounded, a very large mount set makes the aggregate wall
		// time worth capping so it can never delay the health stamp. A timed-out cycle simply reports no changes and
		// recovers next tick.
		const { changes } = await Common.withTimeout(Watchdog.refresh(mounts), 8000).catch(() => ({ changes: [] }));
		let sawDead = false;
		for (const c of changes) {
			if (Vault.isUnmounting(c.mountpoint)) continue; // a normal unmount is already handling this one
			const name = c.name || path.basename(c.mountpoint);
			if (c.to === 'unresponsive') {
				Common.warn('Vault "' + name + '" stopped responding. Open ' + Brand.name + ' and click "Force unmount" to recover it — no reboot is needed.');
			} else if (c.to === 'dead') {
				sawDead = true;
				Common.warn('Vault "' + name + '" was left mounted by a stopped engine; recovering it automatically.');
			} else if (c.to === 'healthy' && (c.from === 'unresponsive' || c.from === 'dead')) {
				Common.log('Vault "' + name + '" is responding again.');
			}
		}
		// Stale mounts (engine dead) are safe to clear on their own — do it promptly. Run it DETACHED (not awaited),
		// like the auto-lock and schedule ticks below: sweep force-unmounts each dead mount (each bounded, but the
		// aggregate over several is not) and can resume a heavy in-place rekey, so awaiting it on the hot tick could
		// delay the health stamp that gates the systemd watchdog ping — a stalled ping would let systemd kill the
		// service. A self-guard stops it overlapping itself across ticks; its internal steps are all bounded/idempotent.
		if (!sweepRunning && (sawDead || Object.values(Watchdog.snapshot()).some(h => h === 'dead'))) {
			sweepRunning = true;
			Promise.resolve().then(() => Vault.sweep()).catch(() => {}).finally(() => { sweepRunning = false; });
		}
		// Auto-lock: gently unmount vaults left idle past the configured timeout (best-effort; never forces, so
		// active use is never interrupted). Off unless the user set a timeout. Run it DETACHED (not awaited), like
		// the backup/scrub/repair ticks below: it makes per-mount activity probes (bounded rclone rc calls) and a
		// gentle-unmount drain, and awaiting several briefly-slow mounts here could delay the health stamp that
		// gates the systemd watchdog ping — a stalled ping would let systemd kill the service and the guardian then
		// unmount every live vault. A self-guard stops it overlapping itself across ticks.
		// Bounded like the other data-dir reads on this hot tick (listMounts above): the data dir can be a per-user
		// home that wedges on a network/NFS mount, and an unbounded read here would pin the tick's thread so watchBusy
		// never clears — silently stopping the health watch, guardian supervision, and schedule ticks (unrecoverable
		// on macOS/Windows, which have no systemd watchdog to restart the process). Fall back to empty settings.
		const s = await Common.withTimeout(Vault.getSettings(), 5000).catch(() => ({}));
		if (s.autoLockMinutes > 0 && !autoLockRunning) {
			autoLockRunning = true;
			Vault.autoLockTick(mounts, s.autoLockMinutes * 60 * 1000)
				.then(r => {
					for (const mp of r.locked) Common.log('Auto-locked "' + path.basename(mp) + '" after ' + s.autoLockMinutes + ' min idle.');
					// Keep an auto-locked vault current in the background, exactly like a manual unmount, via the one
					// shared follow-up (lease + viewer teardown + recovery/mirror refresh). Fire-and-forget.
					afterLock(r.vaults);
				})
				.catch(() => {})
				.finally(() => { autoLockRunning = false; });
		}
		// Automatic update check — ONLY when the user opted in (off by default, since it makes an outbound request).
		// Throttled to roughly once a day and run DETACHED and best-effort, so it never blocks the tick and a slow or
		// unreachable host is harmless. It only records the latest published version; the interface computes "update
		// available" live against the running version, and nothing is ever downloaded automatically.
		if (s.autoUpdateCheck && !autoUpdateRunning && (Date.now() - lastAutoUpdateAt > AUTO_UPDATE_INTERVAL_MS)) {
			autoUpdateRunning = true; lastAutoUpdateAt = Date.now();
			UpdateCheck.checkForUpdate()
				.then(r => { if (r && r.ok) return Vault.setSettings({ lastUpdateCheck: { at: r.checkedAt, latest: r.latest } }); })
				.catch(() => {})
				.finally(() => { autoUpdateRunning = false; });
		}
		// Drop expired mobile sessions and pairing codes promptly, rather than only when the next mobile request
		// happens to sweep them — so bearer material for a finished session does not linger on a quiet service.
		try { Mobile.sweep(); } catch (_) {}
		// Scheduled backups run DETACHED (not awaited) so a long transfer can never delay health
		// checks or auto-lock; it is best-effort, self-guards against overlap, and never throws.
		Vault.backupScheduleTick()
			.then(bk => { for (const abs of bk.ran) Common.log('Backed up "' + path.basename(abs) + '" on schedule.'); })
			.catch(() => {});
		// Scheduled integrity scrub runs the same way — detached, best-effort — so an idle vault is proactively
		// checked for bit-rot (and optionally repaired from its recovery data) without a password and without ever
		// delaying the health watch.
		Vault.scrubScheduleTick()
			.then(sc => { for (const r of sc.ran) Common.log('Integrity scrub of "' + path.basename(r.abs) + '" on schedule: ' + r.result + '.'); })
			.catch(() => {});
		// Scheduled shard repair runs the same way — detached, best-effort — so a dispersed vault's shards
		// are kept whole as nodes churn, without ever delaying the health watch.
		Vault.dispersalRepairTick()
			.then(rp => { for (const id of rp.ran) Common.log('Repaired dispersed shards on schedule (' + id + ').'); })
			.catch(() => {});
		// The emergency dead-man's switch: detached, best-effort. Releases sealed read access only after the
		// owner has missed the whole inactivity + grace window; a check-in vetoes it. Never throws or blocks.
		Vault.emergencyTick()
			.then(e => { if (e && e.released) Common.warn('Emergency access released to your trusted contact (' + e.count + ' vault(s)) — no check-in within the window. Check in to withdraw it.'); })
			.catch(() => {});
		// First-run engine setup: only the long-running service downloads the engine in the background, so a fresh
		// user never faces a blocked page. Fire-and-forget and self-guarding — it dedupes, backs off on failure, and
		// no-ops instantly once the engine is installed — so it never blocks the tick (no awaited probe) and never
		// re-downloads once ready. A real operation still waits on its own ensureEngine().
		Promise.resolve(Vault.startEngineSetup()).catch(() => {}); // detached like the other tick calls; startEngineSetup may return null (already installed / backing off) or a promise — wrap so a rejection never surfaces as an unhandled rejection
		// Reaching here means this tick's awaited health work completed without wedging — stamp progress so the
		// systemd watchdog keeps pinging. A tick that hangs earlier never updates this, and the pings stop.
		lastHealthyMono = SdNotify.monoMs();
	} catch (_) {}
	finally { lastWatchAt = Date.now(); lastWatchMono = performance.now(); watchBusy = false; } // stamp the END (both clocks), so the next tick measures the true idle gap
}

// Every filesystem probe here is ASYNC and time-bounded: the folder picker can point at a mounted
// but unresponsive network volume or an ejecting drive, and a synchronous stat on one of those
// would block the whole event loop (stalling every mount's health watch). fsp runs on the libuv
// threadpool and the timeout skips a wedged path instead of waiting on it.
const FS_PROBE_TIMEOUT_MS = 2000;
const FS_FANOUT_LIMIT = 8; // max concurrent directory-entry probes — bounds the fan-out so a wedged drive can't pin the whole libuv threadpool
async function isDirBounded(abs) {
	try { return (await Common.withTimeout(fsp.stat(abs), FS_PROBE_TIMEOUT_MS)).isDirectory(); } catch (_) { return false; }
}
const fileExistsBounded = (abs) => Common.pathExistsBounded(abs, FS_PROBE_TIMEOUT_MS); // single-sourced bounded exists probe

// Browsable roots for the folder picker: the home folder plus every mounted volume / external
// drive. No child processes. macOS mounts volumes under /Volumes, Linux under /media·/run/media·
// /mnt, and Windows exposes drive letters. A volume that has been ejected or is unresponsive is
// skipped by the bounded stat rather than allowed to stall the request.
async function listVolumes() {
	const home = os.homedir();
	const vols = [{ name: 'Home', path: home, kind: 'home' }];
	const seen = new Set([path.resolve(home)]);
	// Gather every candidate root first, then probe them IN PARALLEL — each stat is individually bounded, so one
	// ejected or unresponsive drive can no longer serialize its timeout onto the request. In sequence, 24 Windows
	// drive letters at up to FS_PROBE_TIMEOUT_MS each would be ~48s; in parallel the whole scan costs one timeout.
	const candidates = []; // { p, name, kind }
	if (process.platform === 'win32') {
		for (const L of 'CDEFGHIJKLMNOPQRSTUVWXYZ') candidates.push({ p: L + ':\\', name: L + ':', kind: 'drive' }); // absent letters fail the bounded stat
	} else {
		const user = (() => { try { return os.userInfo().username; } catch (_) { return ''; } })();
		const parents = process.platform === 'darwin' ? ['/Volumes'] : ['/media/' + user, '/run/media/' + user, '/media', '/mnt'];
		for (const parent of parents) {
			let entries = [];
			try { entries = await Common.withTimeout(fsp.readdir(parent, { withFileTypes: true }), FS_PROBE_TIMEOUT_MS); } catch (_) { continue; }
			for (const e of entries) { if (e.isDirectory() && !e.name.startsWith('.')) candidates.push({ p: path.join(parent, e.name), name: e.name, kind: 'drive' }); }
		}
	}
	// Promise.all preserves candidate order, so volumes are still added deterministically (drive letters A→Z).
	const probed = await Promise.all(candidates.map(async c => ({ c, abs: path.resolve(c.p), ok: await isDirBounded(path.resolve(c.p)) })));
	for (const { c, abs, ok } of probed) {
		if (!ok || seen.has(abs)) continue;
		seen.add(abs);
		vols.push({ name: c.name || path.basename(abs) || abs, path: abs, kind: c.kind });
	}
	return vols;
}

// List the sub-folders of a directory for the in-page folder picker. Works the same on every
// platform, no external commands. Confined to the home folder and mounted volumes so the loopback
// UI can't enumerate the whole disk (paths outside are reachable by pasting them). Hidden
// dot-folders are omitted; a folder that contains a vault.json is marked isVault so it can be
// chosen directly. Defaults to the home directory.
async function browseDir(reqPath, { includeFiles = false } = {}) {
	const home = os.homedir();
	let dir = reqPath && String(reqPath).trim() ? String(reqPath) : home;
	if (dir.startsWith('~')) dir = path.join(home, dir.slice(1));
	dir = path.resolve(dir);
	const vols = await listVolumes(); // computed once, used for both the containment check and `places`
	const within = (p) => vols.some(v => Common.pathWithin(p, v.path)); // case-aware on Windows; boundary-aware
	if (!within(dir)) throw new Error('That folder is outside the browsable area — paste its full path to add a vault there.');
	const dirents = await Common.withTimeout(fsp.readdir(dir, { withFileTypes: true }), FS_PROBE_TIMEOUT_MS); // errors reported by handle()
	// Bucket entries first (skipping dot-folders BEFORE any stat, so a dot-symlink costs nothing), then probe each
	// bucket IN PARALLEL — the per-folder vault.json check and per-file size stat are independent and each bounded,
	// so a directory of many entries on a slow drive no longer serializes one bounded stat after another.
	const folderEnts = [], fileEnts = [];
	for (const e of dirents) {
		if (e.name.startsWith('.')) continue;
		const full = path.join(dir, e.name);
		let isDir = e.isDirectory();
		if (!isDir && e.isSymbolicLink()) isDir = await isDirBounded(full);
		if (isDir) folderEnts.push({ name: e.name, full });
		else if (includeFiles && e.isFile()) fileEnts.push({ name: e.name, full });
	}
	// Probe entries with BOUNDED CONCURRENCY, not a full Promise.all: a directory can hold thousands of entries, and
	// a per-call timeout cannot free a wedged stat's libuv threadpool thread — so the fan-out itself is capped to
	// keep the small pool available for the mount health-watch and everything else in the long-running service.
	const folders = await Common.mapLimit(folderEnts, FS_FANOUT_LIMIT, async fe => ({ name: fe.name, path: fe.full, isVault: await fileExistsBounded(path.join(fe.full, 'vault.json')) }));
	const files = await Common.mapLimit(fileEnts, FS_FANOUT_LIMIT, async fe => { let size = null; try { size = (await Common.withTimeout(fsp.stat(fe.full), FS_PROBE_TIMEOUT_MS)).size; } catch (_) {} return { name: fe.name, path: fe.full, size }; });
	folders.sort((a, b) => (Number(b.isVault) - Number(a.isVault)) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
	files.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
	const parent = path.dirname(dir);
	return { path: dir, home, parent: (parent !== dir && within(parent)) ? parent : null, places: vols, folders, files, isVault: await fileExistsBounded(path.join(dir, 'vault.json')) };
}

// Small helper so each route reports errors uniformly as JSON.
// When the interface is exposed to the network, scrub absolute filesystem paths out of an error before it is sent
// to a remote caller, so a provoked error cannot disclose where vaults, keys, or the install live. Messages stay
// verbatim on the loopback default (same machine, one owner), where they are actionable. Precise by design: it
// redacts only the known sensitive roots (the data dir, the install dir, the home dir), leaving the rest of the
// message intact so the error still explains itself. Set once at startup from the bind address.
let redactErrorPaths = false;
function errorRedactRoots() {
	const roots = [];
	try { roots.push(Common.dataDir()); } catch (_) {}
	try { roots.push(path.join(ROOT, '..', '..')); } catch (_) {} // the app install root (lib/webserver -> project root)
	try { roots.push(os.homedir()); } catch (_) {}
	return roots.filter(Boolean).sort((a, b) => b.length - a.length); // longest first, so a nested root is redacted before its parent
}
function safeError(msg, fallback) {
	const s = String(msg == null ? '' : msg) || (fallback || 'The operation failed.');
	return redactErrorPaths ? Common.redactPaths(s, errorRedactRoots()) : s;
}

function handle(fn) {
	return async (req, res) => {
		try {
			// `res` is passed as an optional second argument for the rare handler that must set a response header
			// itself (e.g. re-issuing the session cookie after rotating the login secret). Handlers that only
			// return a body ignore it. A handler that writes to `res` and also returns an object is fine — the
			// header is set before the JSON body is sent below.
			const r = await fn(req, res);
			// A library call that reports its own failure (e.g. an unmount that could not
			// complete because the volume is busy) returns { ok: false }. Surface that as
			// a real error instead of letting a blanket ok:true flatten it — otherwise the
			// client sees ok:false with no message.
			if (r && r.ok === false) return res.status(409).json({ ...r, ok: false, error: safeError(r.error, 'The operation could not be completed.') });
			res.json({ ok: true, ...r });
		}
		catch (e) { res.status(400).json({ ok: false, error: safeError(e.message), install: e.install || null, locked: !!e.locked, holder: e.holder || null, passwordRequired: !!e.passwordRequired }); }
	};
}

// Like handle(), but for a long operation that reports progress: the response is a stream of
// newline-delimited JSON messages — { progress: { percent, label } } as work proceeds, then a final
// { done: true, result } (or { error }). One request, no job bookkeeping: the stream's lifetime is
// the operation's. The worker gets an emit(progress) it can call at will.
function stream(fn) {
	return async (req, res) => {
		res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', Connection: 'keep-alive' });
		const send = (obj) => { try { res.write(JSON.stringify(obj) + '\n'); } catch (_) {} };
		try {
			const result = await fn(req, (progress) => send({ progress }));
			send({ done: true, result: result || {} });
		} catch (e) { send({ error: safeError(e && e.message, 'The operation failed.'), clash: !!(e && e.clash), passwordRequired: !!(e && e.passwordRequired) }); }
		res.end();
	};
}

// After a clean unmount, keep a vault current in the background: first refresh its self-healing
// recovery data if the contents changed, then sync its mirror if one is set up and primed. Both are
// fire-and-forget and fully guarded — they never throw into the caller and never block it — and run
// in sequence (recovery first) so the mirror captures the refreshed recovery data. The vault list
// shows an indicator only while real work is happening, so an unchanged vault never flickers.
const postUnmountInFlight = new Set(); // vault paths whose post-unmount maintenance is running
const mirroringNow = new Set();        // vault paths whose mirror is syncing (for the list indicator)
const dispersingNow = new Set();       // vault paths whose disperse is running (manual-overlap guard)
const importingNow = new Set();         // vault paths whose file import is running (manual-overlap guard)
const unpackingNow = new Set();         // packed-file paths currently being imported (double-import guard)
const reindexingNow = new Set();        // vault paths whose content reindex is running (double-reindex guard)
// Run a heavy per-vault operation under an in-flight guard, so a double-click or a disconnect-and-retry
// can't start a second overlapping run against the same vault's workdir. Keyed by resolved vault path.
async function oncePerVault(set, vaultPath, what, fn) {
	const key = path.resolve(String(vaultPath || ''));
	if (set.has(key)) throw new Error('A ' + what + ' is already running for this vault — wait for it to finish.');
	set.add(key);
	try { return await fn(); } finally { set.delete(key); }
}
function schedulePostUnmount(vaultPath) {
	if (!vaultPath) return;
	const key = path.resolve(vaultPath);
	if (postUnmountInFlight.has(key)) return;
	postUnmountInFlight.add(key);
	(async () => {
		try { await Vault.refreshRecoveryIfStale(vaultPath, { onProgress: (p) => { if (p) refreshingRecovery.set(key, { percent: p.percent, label: p.label }); } }); }
		catch (e) { try { Common.log('Recovery auto-refresh skipped for ' + key + ': ' + (e && e.message)); } catch (_) {} }
		refreshingRecovery.delete(key);
		// Route through the same guard the manual endpoint uses, so a manual sync already running isn't
		// joined concurrently (and its indicator isn't cleared early) — the guard rejects the overlap instead.
		try { await oncePerVault(mirroringNow, vaultPath, 'mirror sync', () => Vault.syncMirrorIfConfigured(vaultPath)); }
		catch (e) { try { Common.log('Mirror auto-sync skipped for ' + key + ': ' + (e && e.message)); } catch (_) {} }
	})().finally(() => postUnmountInFlight.delete(key));
}

// Lease heartbeat: while THIS long-running server owns a writable mount of a mirrored vault, refresh
// its cross-machine write lease on a short interval so its liveness is precise — another machine can
// take over promptly if this one crashes, without a 12-hour wait. Non-blocking and best-effort: each
// beat is fire-and-forget, the timer is unref'd so it never holds the process open, and it stops on
// its own if another machine takes the lease. A read-only mount holds no lease, so it is skipped.
const leaseHeartbeats = new Map(); // vaultPath -> interval handle
const leaseLastOk = new Map();     // vaultPath -> ms of the last SUCCESSFUL lease refresh
const leaseStaleWarned = new Set();// vaultPaths already warned about a stale lease (warn-once)
// If the lease hasn't refreshed for this long, the write is silently failing (destination unreachable) while
// we still hold a writable mount — the lease at the destination is going stale and another machine could take
// it, risking split-brain writes. Three heartbeat intervals is comfortably past one missed beat.
const LEASE_STALE_MS = 3 * Vault.LEASE_HEARTBEAT_INTERVAL_MS;
function startLeaseHeartbeat(vaultPath, readOnly) {
	if (readOnly || !vaultPath) return;
	const key = path.resolve(vaultPath);
	if (leaseHeartbeats.has(key)) return;
	leaseLastOk.set(key, Date.now()); // optimistic baseline so a just-started heartbeat isn't flagged before its first beat
	leaseStaleWarned.delete(key);
	const beat = () => { Vault.refreshLease(vaultPath).then((kept) => {
		// kept === 'no-lease': this vault has no mirror to coordinate, so there is no write-lease at all. Stop the
		// heartbeat QUIETLY (and drop it from staleness tracking via stopLeaseHeartbeat) — an ordinary non-mirrored
		// writable mount must never raise the split-brain warning or a "going stale" alarm for a lease it never held.
		if (kept === 'no-lease') { stopLeaseHeartbeat(vaultPath); return; }
		// kept === false: another machine has actively TAKEN the write-lease while we still hold a writable mount —
		// the split-brain moment. Warn loudly (once) so the user knows both machines may now be writing; the only
		// recovery is the conflict-preservation on the next sync. Then stop beating (the lease is no longer ours).
		if (kept === false) { Common.warn('The write-lease for "' + Vault.displayName(vaultPath) + '" was taken by another machine while this one still has it open for writing. Both machines may now write to the mirror; stop editing this vault on one of them, then re-sync — conflicting changes are preserved, not overwritten.'); stopLeaseHeartbeat(vaultPath); }
		else if (kept === true) { leaseLastOk.set(key, Date.now()); if (leaseStaleWarned.delete(key)) Common.log('Write-lease for "' + Vault.displayName(vaultPath) + '" is refreshing again.'); }
		// kept === null: a transient failure — do NOT advance leaseLastOk, so a persistent failure eventually trips the staleness warning in watchTick.
	}).catch(() => {}); };
	const timer = setInterval(beat, Vault.LEASE_HEARTBEAT_INTERVAL_MS);
	if (timer.unref) timer.unref(); // never keep the process alive just for a heartbeat
	leaseHeartbeats.set(key, timer);
	beat(); // beat once immediately so the short-TTL lease is published right away
}
function stopLeaseHeartbeat(vaultPath) {
	if (!vaultPath) return;
	const key = path.resolve(vaultPath);
	const t = leaseHeartbeats.get(key);
	if (t) { clearInterval(t); leaseHeartbeats.delete(key); }
	leaseLastOk.delete(key); leaseStaleWarned.delete(key);
}
function stopAllLeaseHeartbeats() { for (const t of leaseHeartbeats.values()) clearInterval(t); leaseHeartbeats.clear(); leaseLastOk.clear(); leaseStaleWarned.clear(); }
// The follow-up every lock/unmount path must run for each vault it just closed: stop its write-lease heartbeat, end
// any phone/in-app viewer session (so locking really ends access), and refresh its recovery data + mirror in the
// background so both stay current. Single-sourced here because these steps had drifted across the lock paths — the
// sleep-lock ran none of them and idle auto-lock skipped the viewer teardown. Fire-and-forget; never blocks a caller.
function afterLock(vaults) {
	for (const v of (vaults || [])) { stopLeaseHeartbeat(v); Mobile.stopByVaultPath(v); schedulePostUnmount(v); }
}
// Warn (once) about any writable mirrored vault whose write-lease has not refreshed for too long — a silently
// failing heartbeat that could let another machine take the lease and cause split-brain writes. Called from
// the health tick; warn-only, never throws.
function checkLeaseStaleness() {
	const now = Date.now();
	for (const key of leaseHeartbeats.keys()) {
		const last = leaseLastOk.get(key) || now;
		if (now - last > LEASE_STALE_MS && !leaseStaleWarned.has(key)) {
			leaseStaleWarned.add(key);
			Common.warn('The write-lease for "' + Vault.displayName(key) + '" has not refreshed for ' + Math.round((now - last) / 1000) + 's — its mirror destination may be unreachable. Another machine could take the lease; avoid editing this vault elsewhere until the destination is reachable again.');
		}
	}
}

// Served nodes owned by THIS server (act-as-a-server): a vault whose encrypted folder is being served
// over WebDAV so another machine can mirror to it. The serve is supervised (it restarts the engine if
// it dies) and stopped cleanly on shutdown. Only ciphertext is served — the key and contents never
// leave the machine. Keyed by resolved vault path.
const servedVaults = new Map(); // vaultPath -> { handle, url, user, pass, bind, startedAt }
const startingServe = new Map(); // vaultPath -> in-flight start promise (coalesces concurrent serve-start)
async function startServing(vaultPath, { bind, useRelay } = {}) {
	const key = path.resolve(vaultPath);
	if (servedVaults.has(key)) return servingInfo(servedVaults.get(key)); // already serving
	// A start for this vault may already be in flight (a double-click or a disconnect-and-retry). Join
	// that one instead of spawning a second supervised serve + relay registration that would be orphaned
	// (only one handle can land in servedVaults).
	if (startingServe.has(key)) return startingServe.get(key);
	const label = path.basename(vaultPath);
	// Surface the supervisor's lifecycle events (which are otherwise logged nowhere): note a restart
	// and, on a permanent give-up, flag the entry as failed so the UI stops reporting it as reachable.
	const onEvent = (ev) => {
		try {
			if (!ev || !ev.type) return;
			if (ev.type === 'gaveup') { Common.warn('Stopped serving "' + label + '": the node could not be kept running after repeated restarts. Start it again once the cause is fixed.'); stopServing(key).catch(() => {}); } // tear the entry down (stops the relay registration and worker pool, not just a status flag) so nothing keeps reconnecting to a dead local port, and a later re-serve starts cleanly
			else if (ev.type === 'down') Common.warn('Served node "' + label + '" went down; attempting to restart it.');
		} catch (_) {}
	};
	const p = (async () => {
		const relay = useRelay ? await Vault.relayForServe() : null;
		if (useRelay && !relay) throw new Error('Set up a relay first — enter the hub address and token.');
		const handle = await Vault.serveVault(vaultPath, { bind: relay ? undefined : bind, relay, onEvent });
		const entry = { handle, url: handle.url, user: handle.user, pass: handle.pass, ca: handle.ca || null, secure: !!handle.secure, bind: relay ? 'relay' : (bind || '127.0.0.1'), startedAt: new Date().toISOString() };
		servedVaults.set(key, entry);
		return servingInfo(entry);
	})();
	startingServe.set(key, p);
	try { return await p; } finally { startingServe.delete(key); }
}
async function stopServing(vaultPath) {
	const key = path.resolve(vaultPath);
	const entry = servedVaults.get(key);
	if (!entry) return { ok: true };
	servedVaults.delete(key);
	try { await entry.handle.stop(); } catch (_) {}
	return { ok: true };
}
function servingInfo(e) {
	if (!e) return { serving: false };
	// For a relay serve, include a one-paste connection code (address + login + pinned cert) for the
	// other machine, and whether the hop is encrypted.
	const code = e.bind === 'relay' ? Vault.makePeerCode({ url: e.url, user: e.user, pass: e.pass, ca: e.ca }) : null;
	return { serving: true, failed: !!e.failed, url: e.url, user: e.user, pass: e.pass, bind: e.bind, secure: e.secure, code, startedAt: e.startedAt };
}
async function stopAllServing() { const all = [...servedVaults.values()]; servedVaults.clear(); for (const e of all) { try { await e.handle.stop(); } catch (_) {} } }

async function start(port = Common.DEFAULT_UI_PORT, { bind, allowIp, denyIp } = {}) {
	// Resolve the bind address and the login requirement up front, before any side effects, so a
	// misconfiguration fails fast and cleanly. By default the interface binds to loopback and needs
	// no login (its long-standing single-user model). Binding anywhere else exposes it to the network
	// and therefore REQUIRES a password to have been set — and every request is served over TLS, so a
	// login never crosses the wire in the clear.
	const bindAddr = (bind && String(bind).trim()) || '127.0.0.1';
	const exposed = !isLoopbackAddr(bindAddr);
	redactErrorPaths = exposed; // on an exposed bind, keep absolute paths out of error responses sent to remote callers
	// On a network-exposed bind, refuse to INTRODUCE a caller-supplied outbound destination (a cloud endpoint, an
	// SFTP host, a peer address, a relay host). A request from the network could otherwise make this machine open
	// a connection to an arbitrary internal address — an SSRF / internal-port-probe lever. The operator adds these
	// from the app on THIS computer (loopback), where the caller is the machine's owner. Mirrors the attest guard,
	// which refuses a caller-supplied timestamp-authority URL on an exposed bind for the same reason.
	const refuseOutboundIfExposed = (what) => { if (exposed) throw new Error('Adding ' + what + ' is not allowed over a network-exposed connection, because a request from the network could make this computer connect to an arbitrary address. Add it from the app on this computer instead.'); };
	// Reading host files INTO a vault, or writing a rebuilt/unpacked vault OUT to a host folder, names a path on this
	// computer's own disk. Like reveal and start-at-login, those are loopback-only: a network caller must never make
	// this machine read from or write to an arbitrary location on its disk (an arbitrary-file-read or drop-file lever).
	// Refuse on an exposed bind; the owner does these from the app on this computer.
	const refuseHostFsIfExposed = (action) => { if (exposed) throw new Error(action + ' works only from the app on the computer running it, not over a network connection, so a remote request cannot point this computer at an arbitrary location on its disk.'); };
	// Copying a vault's ciphertext (with its wrapped key slots) off this machine — or serving it to the network —
	// exposes those slots to an unthrottled offline password attack, so it should be done only by someone who can
	// actually open the vault. On a network-exposed interface, require a credential that opens THIS vault first; on
	// loopback it is a no-op, since a local process already has the ciphertext on disk and the interface is
	// intentionally unauthenticated there. A missing password asks the caller for one (passwordRequired); a wrong one
	// is rejected. Verifies read access (a read-only credential is enough to copy ciphertext).
	const requireVaultReadIfExposed = async (vaultPath, password) => {
		if (!exposed) return;
		if (!password) throw Object.assign(new Error('This vault\'s password is required to copy or serve it over a network connection.'), { passwordRequired: true });
		await Vault.assertReadable(vaultPath, password);
	};
	// Optional network access list for an EXPOSED interface: only client addresses matching the allow list (and
	// not the deny list) may reach it, checked before auth. Parsed here so a bad rule fails fast and is reported,
	// and loopback is always exempt below so a mistake can never lock out the local user.
	const ipAllow = IpMatch.parseList(allowIp), ipDeny = IpMatch.parseList(denyIp);
	for (const bad of ipAllow.dropped.concat(ipDeny.dropped)) Common.warn('Ignoring an invalid IP access rule: "' + bad + '" (use an exact address, a CIDR range, or an IPv4 wildcard like 192.168.1.*).');
	// FAIL CLOSED on an EXPOSED interface: if the operator asked to restrict access but EVERY rule was invalid, the
	// list would be empty and the gate below would not install — silently accepting all clients, the opposite of
	// what was asked. Refuse to start instead, so a typo can never turn a requested restriction into an open
	// interface. On a loopback bind the access list is moot (the gate never installs), so a bad rule only warns.
	if (exposed && ipAllow.dropped.length && !ipAllow.list.length) throw new Error('Every --allow-ip rule was invalid, so no addresses would be allowed through. Fix the rules (an exact address, a CIDR range, or an IPv4 wildcard like 192.168.1.*) and start again — refusing to expose the interface with an access list that does not apply.');
	if (exposed && ipDeny.dropped.length && !ipDeny.list.length) throw new Error('Every --deny-ip rule was invalid, so nothing would be blocked. Fix the rules (an exact address, a CIDR range, or an IPv4 wildcard like 192.168.1.*) and start again.');
	const uiAuth = await Vault.getUiAuth();
	if (exposed && !uiAuth.enabled) {
		throw new Error('Refusing to expose the web interface on ' + bindAddr + ' without a password. Set one first with "' + Brand.cli + ' web-password", then start again. (The default loopback interface needs no password.)');
	}
	let tls = null;
	if (exposed) {
		// Reuse the same self-signed-certificate helper the relay uses (pure Node, cross-platform — no external tool).
		// It should always succeed; if it somehow cannot produce a valid certificate, refuse rather than serve a
		// password prompt over plain HTTP.
		const cert = await Cert.ensureCert(bindAddr);
		if (!cert) throw new Error('Cannot expose the web interface securely: a TLS certificate could not be created. Run the interface on loopback only, or try again.');
		tls = { key: await fsp.readFile(cert.keyFile), cert: await fsp.readFile(cert.certFile) };
	}
	const secure = !!tls;                 // TLS in effect -> the session cookie gets the Secure flag
	const authEnabled = !!uiAuth.enabled; // whether a login was set at startup (for the startup log line; the gate itself is always installed and reads the live state)
	ProcRegistry.installShutdownHandlers();
	// In the packaged desktop app, the native shell asks for a clean shutdown by writing "quit" on our stdin (the only
	// cross-platform stop channel — Windows has no SIGTERM for a windowless child). Watch for it so a quit drains and
	// locks exactly as a signal would, on every platform. Loopback CLI runs are unaffected (it no-ops on a terminal stdin).
	if (Common.isDesktopApp()) ProcRegistry.watchStdinForQuit();
	// The web server is long-running: a stray error in any subsystem (a background auto-sync, an
	// auto-refresh, a mirror, a notification) is logged and survived rather than taking the server
	// down or ejecting the user's mounted disks. A real stop signal still locks vaults and exits.
	ProcRegistry.beResilient();
	// Vaults opened by THIS server instance are tagged with its process id, so it
	// locks only its own on shutdown and never disturbs another running instance or
	// an independently-mounted vault.
	const owner = Vault.ownerTag(); // "ui:<pid>:<nonce>" — the nonce lets the boot-time orphan sweep tell our mounts from a recycled pid
	await Vault.touchOwnerAlive(owner); // publish our liveness heartbeat before serving (refreshed each health tick)
	// Second-instance guard: this tool's state lock is IN-PROCESS only, so two services sharing one data
	// directory can race each other's writes. The common double-start is already blocked by the port bind;
	// this catches the rarer case of a second instance on a DIFFERENT port. Warn (never block) if another live
	// instance's pid is recorded, then record ours; a clean exit removes it. Best-effort.
	const servicePidFile = path.join(Common.runDir(), 'service.pid'); // runtime state lives under data/run/ (already git-ignored), never the data/ root
	// Harden the run directory to owner-only BEFORE writing the pidfile the CLI reads to route a mount (and its
	// password) to this owner — so another local user can neither plant nor alter it. On POSIX the CLI also
	// re-checks the pidfile's ownership/perms; on Windows, where that check can't read the owner, this ACL is the
	// ONLY guard. So we only ADVERTISE the loopback url (below) when hardening verifiably succeeded — if it did
	// not (a non-NTFS data volume, say, where icacls can't apply an owner-only ACL), the pidfile carries no url,
	// the CLI treats it as "no owner", and it mounts directly instead of posting the password to a plantable file.
	let runDirHardened = false;
	try { await fsp.mkdir(Common.runDir(), { recursive: true, mode: 0o700 }); runDirHardened = await Common.hardenDir(Common.runDir()); } catch (_) {}
	if (process.platform === 'win32' && !runDirHardened) Common.warn('Could not lock the runtime directory to your account (' + Common.runDir() + '), so command-line mounts will not route through this app — they mount directly instead. This can happen on a non-NTFS (FAT/exFAT) drive.');
	try {
		const prior = await fsp.readFile(servicePidFile, 'utf8').then(JSON.parse).catch(() => null);
		const priorPid = prior && Number(prior.pid);
		if (priorPid && priorPid !== process.pid && Common.isProcessAlive(priorPid)) {
			// A live instance already owns this data directory. We are a duplicate that will fail to bind the port and
			// exit shortly, so DO NOT overwrite its pidfile: clobbering the running instance's advertised url with our
			// own url-less record (we never reach listen, so we never add the url) is exactly what made `open` stop
			// finding the live service and cold-start a fresh doomed duplicate on every launch. Leave its record intact.
			Common.warn('Another ' + Brand.name + ' service (pid ' + priorPid + ') appears to be running against this data directory. Running two at once can corrupt shared state — stop the other one.');
		} else {
			await Common.writeJsonAtomic(servicePidFile, { pid: process.pid, at: new Date().toISOString() });
		}
	} catch (_) {}
	// Stopping the server — cleanly OR by a caught crash — locks every vault it
	// opened (draining writes first) so a stopped service never leaves a vault
	// mounted and exposed.
	ProcRegistry.onShutdown(async () => {
		// Mark an INTENTIONAL shutdown and heartbeat it every second while we tear down. As long as this loop is
		// alive — even through a minutes-long drain — the marker stays fresh, so the external Guardian defers
		// instead of racing our teardown or wiping the cache mid-flush; if we truly wedge, the beat stops and the
		// Guardian proceeds. Cleared once teardown completes. (Runs before clearOwnerAlive, which makes our nonce
		// read stale.)
		const phaseHeartbeat = setInterval(() => { Phase.setPhase('stopping'); }, 1000);
		if (phaseHeartbeat.unref) phaseHeartbeat.unref();
		try { await Phase.setPhase('stopping'); } catch (_) {}
		stopAllLeaseHeartbeats();
		Mobile.stopAll(); // mobile sessions are in-memory; drop them so no bearer outlives this process
		// Tell systemd this exit is INTENTIONAL: it switches from the runtime watchdog to the stop timeout,
		// so a legitimate drain-on-stop is never mistaken for a wedge and killed. No-op off systemd.
		try { stopWatchdog(); SdNotify.stopping(); } catch (_) {}
		try { await Vault.clearOwnerAlive(owner); } catch (_) {} // drop our liveness heartbeat on a clean exit
		try { const cur = await fsp.readFile(servicePidFile, 'utf8').then(JSON.parse).catch(() => null); if (cur && Number(cur.pid) === process.pid) await fsp.unlink(servicePidFile).catch(() => {}); } catch (_) {}
		await stopAllServing();
		// Use listMounts (a plain state read), not status(), so this never stats a possibly-wedged
		// mount on the exit path; presence in state means it is mounted, which is all we need here.
		const mine = (await Vault.listMounts()).some(m => m.owner === owner);
		if (mine) { Common.log('Locking open vaults before exit…'); await Vault.unmountAll({ owner, wipeCache: true }); }
		// Deliberately DON'T clear the marker here: it stays fresh (the unref'd heartbeat keeps beating) right up
		// to process exit, so the Guardian never mistakes the final instant of a clean stop for a wedge and
		// restarts it. Once the process is gone the Guardian's pid-gone path takes over, and a stale-pid marker is
		// ignored on the next start. phaseHeartbeat is unref'd, so it never keeps the process alive.
		void phaseHeartbeat;
	});
	// Launch the external guardian FIRST — before the (possibly slow) orphan reap below. If THIS process is
	// hard-killed (SIGKILL, a segfault, no chance to run any handler), the guardian notices and locks the vaults;
	// that is what makes "even on a crash it unmounts" true. Starting it first means the new process is crash-covered
	// during the reap. Supervised: the health tick re-launches it if it ever dies (see ensureGuardian / watchTick).
	guardianOwner = owner;
	ensureGuardian();
	// Backstop: lock any vaults left mounted by a PREVIOUS service instance that was hard-killed (so even its guardian
	// could not run). Only vaults whose owning instance is gone are touched. Run it in the BACKGROUND, NOT on the
	// pre-listen critical path: a drain can take minutes on a wedged or caching mount, and awaiting it here would leave
	// the interface unresponsive for that whole time. The guardian just launched covers a crash in the meantime.
	Vault.unmountOrphans({ wipeCache: true }).catch(() => {});
	// Periodic housekeeping so a long-running instance never accumulates stale mount logs
	// or ephemeral configs in the run folder. Unref'd so it can never keep the process
	// alive on its own.
	const sweepTimer = setInterval(() => { Vault.sweep().catch(() => {}); }, 15 * 60 * 1000);
	if (sweepTimer.unref) sweepTimer.unref();

	// Health watch: probe each mount's responsiveness (bounded, de-duplicated) so a wedged drive
	// is surfaced in the UI for one-click recovery instead of leaving the user to reboot. A drive
	// whose engine has died (a stale mount) is force-released here automatically; a drive that is
	// wedged with its engine still alive is only reported — recovery stays an explicit user action.
	const watchTimer = setInterval(() => { watchTick(); }, WATCH_TICK_MS);
	if (watchTimer.unref) watchTimer.unref();
	// Arm the systemd runtime watchdog (Linux + WatchdogSec only; a no-op everywhere else). It pings only while
	// the health tick above keeps completing, so a genuinely wedged service stops pinging and systemd restarts
	// it — belt-and-suspenders on top of crash-restart, and it can only ever RESTART, never touch vault data.
	stopWatchdog = SdNotify.startWatchdog(() => lastHealthyMono);
	// Anchor the self-check cadence to now BEFORE the immediate seed tick, so the boot self-check runs exactly
	// once — the explicit 'startup' run below — instead of the first watchTick ALSO firing a 'periodic' one
	// (which it would, since lastSelfCheckAt starts at 0). The next periodic refresh then lands 5 minutes later.
	lastSelfCheckAt = Date.now();
	// Also anchor the sleep-gap clock to now, so a slow startup (e.g. a first-run engine download that takes
	// longer than the sleep threshold between module load and here) can't make this seed tick look like a
	// wake-from-sleep and auto-lock mounts that were never actually suspended.
	lastWatchAt = Date.now();
	lastWatchMono = performance.now(); // seed both clocks together so the first real tick never reads a bogus jump
	watchTick(); // seed health immediately so the first page load already reflects reality
	const app = express();
	app.disable('x-powered-by');
	// Security headers on every response. The UI is fully self-hosted (its script and styles are
	// same-origin files, no inline code, no external requests), so a strict content-security policy
	// costs nothing and blocks injected or third-party script, framing (clickjacking), and MIME
	// sniffing. no-store keeps vault lists, key metadata, and paths out of the browser's disk cache.
	// Network access list (exposed interface only): reject a client whose real socket address is not allowed,
	// BEFORE anything else runs — even the login form and static assets. It keys on req.socket.remoteAddress, the
	// actual peer, never a forwarded header a client could forge (this interface is reached directly, not through
	// a trusted reverse proxy). Loopback is always exempt, so the local user is never locked out by a bad rule.
	// Installed only when exposed AND a list was given, so the default loopback interface is completely unaffected.
	if (exposed && (ipAllow.list.length || ipDeny.list.length)) {
		app.use((req, res, next) => {
			const ip = req.socket && req.socket.remoteAddress;
			const verdict = IpMatch.evaluate(ip, { allow: ipAllow.list, deny: ipDeny.list }, { allowLoopback: true });
			if (!verdict.allowed) { res.status(403).type('text/plain').end('Forbidden'); return; }
			next();
		});
		Common.log('Web interface access list active: ' + (ipAllow.list.length ? 'allow [' + ipAllow.list.join(', ') + ']' : 'allow all') + (ipDeny.list.length ? ', deny [' + ipDeny.list.join(', ') + ']' : '') + ' (loopback always allowed).');
	}
	app.use((req, res, next) => {
		res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
		res.setHeader('X-Content-Type-Options', 'nosniff');
		res.setHeader('X-Frame-Options', 'DENY');
		res.setHeader('Referrer-Policy', 'no-referrer');
		res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), usb=(), payment=()');
		res.setHeader('Cache-Control', 'no-store');
		next();
	});
	app.use(express.json({ limit: '256kb' }));
	app.use(express.urlencoded({ extended: false, limit: '16kb' })); // the login form posts a plain urlencoded body
	app.set('view engine', 'ejs');
	app.set('views', path.join(ROOT, 'public', 'views'));
	// Serve only the asset folders — never the views directory, so the raw template
	// is not fetchable.
	app.use('/css', express.static(path.join(ROOT, 'public', 'css')));
	// Locally-vendored web fonts (DM Sans / DM Mono), so the UI loads no font from the network and works offline.
	// Immutable, content-hashed filenames, so cache them hard. Allowed before the login gate (the login page uses them).
	app.use('/fonts', express.static(path.join(ROOT, 'public', 'fonts'), { immutable: true, maxAge: '365d' }));
	// Serve the shared password-strength estimator (it lives in lib/ and is required by the CLI too),
	// so both surfaces score passwords with one implementation instead of a duplicated copy. Declared
	// before the static /js mount so it owns this path.
	app.get('/js/strength.js', (req, res) => res.type('application/javascript').sendFile(path.join(__dirname, '..', 'passwordStrength.js'), { dotfiles: 'allow' })); // dotfiles:'allow' so serving never 404s when the install path has a dot-directory component (e.g. under ~/.local)
	app.use('/js', express.static(path.join(ROOT, 'public', 'js')));
	// The browser-tab icon for the desktop views, reusing the one brand icon the mobile client already ships (rather
	// than a second copy). Also answer /favicon.ico with it — some browsers hard-probe that path regardless of the
	// <link rel="icon"> tag — so no client ever logs a 404 for a missing icon.
	const sendBrandIcon = (req, res) => res.type('image/svg+xml').sendFile(path.join(ROOT, 'public', 'mobile', 'icon.svg'), { dotfiles: 'allow' }); // dotfiles:'allow': serving must not 404 under a dot-directory install path
	app.get('/icon.svg', sendBrandIcon);
	app.get('/favicon.ico', sendBrandIcon);
	// The user guide (the project README) for the in-app Help viewer. It holds nothing secret (it is the public
	// documentation), so it is served here before the login gate and rendered client-side by the vendored markdown
	// library. One source: the same docs/README.md the project ships, so in-app Help can never drift from the docs.
	app.get('/readme.md', (req, res) => {
		res.type('text/markdown; charset=utf-8').setHeader('Cache-Control', 'no-store');
		res.sendFile(path.join(ROOT, '..', '..', 'docs', 'README.md'), { dotfiles: 'allow' }, (err) => { if (err && !res.headersSent) res.status(404).type('text').send('Help is unavailable.'); });
	});

	// ---- Mobile access (/m) -------------------------------------------------------------------------
	// A same-origin surface a phone reaches to pull ONE vault's CIPHERTEXT and decrypt it locally in the
	// browser. Mounted BEFORE the UI login gate, but NOT an un-gated hole: its data routes carry their own
	// mandatory bearer auth (a different credential than the desktop's session cookie); the static app shell
	// it also serves is client code only. Ciphertext is safe to expose and cache; plaintext never leaves the
	// phone's memory. The router is factored into mobileRoutes.js so a test drives the exact same code.
	app.use('/m', MobileRoutes.buildRouter({ mobileDir: path.join(ROOT, 'public', 'mobile'), isLoopbackAddr, exposed }));

	// Login gate. Always installed, but it NO-OPS when no password is set — every handler re-reads the live
	// auth state (currentUiAuth), so a password ADDED while the server is running takes effect immediately, with
	// no restart, and the loopback single-user default is unchanged (the gate simply waves requests through).
	// Static assets and the login endpoints stay open so the login page can style itself; everything else needs a
	// valid signed session cookie. A page request without one is redirected to the login form; an API request
	// gets a 401 the browser turns into a redirect.
	{
		// Throttle the login: verifying a password runs a memory-hard hash (Argon2id, ~64 MiB), so an
		// unthrottled /login would be both a DoS lever and an unbounded online-guessing oracle when the
		// interface is exposed. Cap concurrent verifications and back a client off after repeated failures.
		let loginInFlight = 0;
		const LOGIN_MAX_CONCURRENT = 4;
		const loginFails = Common.failureBackoff(); // per-IP online-guessing backoff, shared with the mobile /pair gate
		const clientIp = (req) => (req.socket && req.socket.remoteAddress) || 'unknown';
		app.get('/login', async (req, res) => {
			const a = await currentUiAuth();
			if (!a.enabled) return res.redirect('/');
			if (UiAuth.sessionFromRequest(req, a.secret)) return res.redirect('/');
			// The credential descriptors are not secret; the login page needs them to run the Touch ID / security-key
			// ceremony before the browser is signed in.
			res.render('login', { appName: Brand.name, error: null, webauthn: Vault.uiWebauthnDescriptors(a) });
		});
		app.post('/login', async (req, res) => {
			const a = await currentUiAuth();
			if (!a.enabled) return res.redirect('/');
			const ip = clientIp(req), now = Date.now();
			if (loginFails.blocked(ip, now)) return res.status(429).render('login', { appName: Brand.name, error: 'Too many attempts — wait a moment and try again.', webauthn: Vault.uiWebauthnDescriptors(a) });
			if (loginInFlight >= LOGIN_MAX_CONCURRENT) return res.status(429).render('login', { appName: Brand.name, error: 'The server is busy — try again in a moment.', webauthn: Vault.uiWebauthnDescriptors(a) });
			loginInFlight++;
			// Accept EITHER the password OR a security-key / Touch ID secret (the passwordless option). The
			// WebAuthn secret is the PRF value the authenticator released after its user check; it is verified
			// against the enrolled credentials' stored hashes, the same memory-hard check the password uses.
			let ok = false;
			try { const body = req.body || {}; ok = body.webauthnSecret ? await Vault.verifyUiWebauthn(body.webauthnSecret) : await UiAuth.verifyPassword(body.password || '', a.password); }
			finally { loginInFlight--; }
			if (!ok) {
				loginFails.fail(ip, now);
				return res.status(401).render('login', { appName: Brand.name, error: 'Sign-in failed. Check your password, or try your security key again.', webauthn: Vault.uiWebauthnDescriptors(a) });
			}
			loginFails.clear(ip);
			res.setHeader('Set-Cookie', UiAuth.setCookieHeader(UiAuth.signSession(a.secret), { secure }));
			res.redirect('/');
		});
		app.use(async (req, res, next) => {
			const a = await currentUiAuth();
			if (!a.enabled) return next(); // password cleared while running -> no login required
			// Exact asset prefixes (trailing slash), not startsWith('/js'), so no future route beginning with
			// those letters is accidentally exempted, and a non-normalized path can't slip past.
			if (req.path === '/login' || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/fonts/')) return next();
			if (UiAuth.sessionFromRequest(req, a.secret)) return next();
			if (req.path.startsWith('/api')) return res.status(401).json({ ok: false, error: 'Please sign in again.', login: true });
			return res.redirect('/login');
		});
	}

	// API guard. A custom header must be present — one no cross-origin page can set without a CORS
	// preflight this server never grants — which blocks CSRF (including bodyless POSTs). On the loopback
	// default the Host must also be loopback (blocks DNS-rebinding); when the interface is deliberately
	// exposed to the network, that check is dropped and the signed session cookie above is the guard.
	app.use('/api', (req, res, next) => {
		if (!exposed) {
			// Host without the port, via the shared bracket-aware splitter (handles "[::1]:7420", "host:port",
			// and a bare IPv6 literal correctly — a plain split would mangle the last two).
			const host = Common.splitHostPort(req.headers.host || '').host;
			// Reuse the loopback check the exposure decision itself uses, so this covers the WHOLE 127.0.0.0/8
			// range (a bind to 127.0.0.2 etc.) and ::1/localhost consistently — the old hardcoded trio wrongly
			// 403'd a non-.1 loopback bind. Still blocks DNS-rebinding (an external hostname is neither loopback
			// nor the exact bind address). A name-based loopback alias equal to the bind address is allowed too.
			if (!isLoopbackAddr(host) && host !== bindAddr) return res.status(403).json({ ok: false, error: 'forbidden' });
		}
		if (req.get('x-vdisk') !== '1') return res.status(403).json({ ok: false, error: 'forbidden' });
		next();
	});

	// End a session: clear the cookie AND rotate the server-side signing secret, so a captured token can't
	// outlive the logout (for a single-user product, invalidating every session on sign-out is the right call).
	// Behind the API guard, so it needs the custom header (CSRF-safe).
	app.post('/api/logout', async (req, res) => { res.setHeader('Set-Cookie', UiAuth.clearCookieHeader({ secure })); try { await Vault.rotateUiSecret(); } catch (_) {} invalidateUiAuthCache(); res.json({ ok: true }); }); // bust the auth cache so the just-revoked secret cannot validate a stolen cookie for another second
	// Passwordless sign-in (Touch ID / Windows Hello / a security key): list, enroll, and remove credentials. All
	// behind the login gate, so only a signed-in operator can manage them. Enrollment posts the PRF-derived secret
	// (the browser released it after the authenticator's user check); the server keeps only its hash.
	app.post('/api/webauthn-list', handle(async () => ({ credentials: Vault.listUiWebauthn(await currentUiAuth()) })));
	app.post('/api/webauthn-add', handle(async (req) => { const { secret, credentialId, prfSalt, label, password } = req.body || {}; return await Vault.addUiWebauthn({ secret, credentialId, prfSalt, label, password }); }));
	app.post('/api/webauthn-remove', handle(async (req) => await Vault.removeUiWebauthn((req.body || {}).id)));

	app.get('/', (req, res) => res.render('index', { appName: Brand.name, cli: Brand.cli, packExt: Brand.packExt, version: PKG.version, isMac: process.platform === 'darwin' }));

	app.get('/api/state', handle(async () => ({ state: await buildState() })));

	app.post('/api/create', handle(async (req) => {
		const { path: p, password, level, cloud, worm } = req.body || {};
		const res = await Vault.create(p, { password, level, cloud: cloud && cloud.remoteId ? cloud : undefined, worm: worm && worm.retainDays ? worm : undefined }); // names are always encrypted; level = KDF cost; cloud stores on a remote backend; worm = tamper-proof Object Lock
		return { vault: res.vault, identity: res.identity };
	}));
	// Cloud storage backends for cloud-backed vaults (parallel to the SFTP off-site destinations).
	app.post('/api/cloud-remotes', handle(async () => ({ remotes: await Vault.listCloudRemotes() })));
	app.post('/api/cloud-remote', handle(async (req) => { refuseOutboundIfExposed('a cloud storage remote'); return await Vault.saveCloudRemote((req.body || {}).remote || {}); }));
	app.post('/api/cloud-remote-remove', handle(async (req) => await Vault.removeCloudRemote((req.body || {}).id)));
	// Connect a browser-OAuth account (Drive/Dropbox). Streams the consent URL for the client to open, then
	// stores the captured token. The engine opens its own loopback consent server; the client opens the URL.
	app.post('/api/cloud-connect', stream(async (req, onProgress) => {
		refuseOutboundIfExposed('a cloud account connection'); // starts an outbound OAuth flow — gate it like the other outbound routes
		const { type, label, clientId, clientSecret } = req.body || {};
		const res = await Vault.cloudAuthorize(type, { clientId, clientSecret, onUrl: (url) => { try { onProgress({ url, label: 'Waiting for you to authorize in the browser' }); } catch (_) {} } });
		return await Vault.saveCloudOAuth({ label, type, token: res.token, clientId, clientSecret });
	}));
	app.post('/api/cloud-test', handle(async (req) => { const { id, remotePath } = req.body || {}; return await Vault.testCloudRemote(id, remotePath || ''); }));
	app.post('/api/import', handle(async (req) => {
		refuseHostFsIfExposed('Importing a folder into a new vault'); // reads caller-named host files — loopback-only
		const { path: p, password, level, sourceDir } = req.body || {};
		return await Vault.importFolder(p, { password, level, sourceDir }); // creates a new vault from an existing folder
	}));

	app.post('/api/mount', handle(async (req) => {
		const { path: p, password, keyShares, readCap, memberKey, readOnly, workingDisk, streaming, fuseBackend, force,
			mountpoint, volname, cacheSizeMB, vfsCacheMode, cacheDir, allowOther, rememberPrefs } = req.body || {};
		// A threshold key: reconstruct the unlock secret from k shares in memory (never written to disk).
		const secret = (Array.isArray(keyShares) && keyShares.length) ? Vault.unlockSecretFromShares(keyShares) : password;
		// The extra pass-through options (mountpoint / volname / cache-* / allow-other) let the CLI drive this
		// owner with full parity when it routes a `vdisk mount` here; the browser simply omits them. Keep
		// workingDisk/streaming as a TRUE/FALSE/absent tri-state: an ABSENT toggle (a plain CLI mount) must stay
		// undefined so Vault.mount falls back to this vault's remembered preference — coercing it to false here
		// would silently ignore that preference.
		const r = await Vault.mount(p, { password: secret, readCap: readCap || undefined, memberKey: memberKey || undefined, readOnly: !!readOnly,
			workingDisk: workingDisk === undefined ? undefined : !!workingDisk, streaming: streaming === undefined ? undefined : !!streaming,
			fuseBackend: fuseBackend === 'smb' ? 'smb' : undefined, force: !!force,
			mountpoint: mountpoint || undefined, volname: volname || undefined, cacheSizeMB: cacheSizeMB || undefined, vfsCacheMode: vfsCacheMode || undefined, cacheDir: cacheDir || undefined, allowOther: !!allowOther, owner });
		ensureGuardian(); // make sure the crash-safety guardian is alive the instant a vault opens, not up to a health-tick later
		if (!r.redirected) startLeaseHeartbeat(r.vault || p, !!r.readOnly); // key on the RESOLVED vault path (r.vault) so it matches stopLeaseHeartbeat — a name-mounted vault would otherwise start under a cwd-relative key and never stop, leaking a stale write-lease. Gate on the EFFECTIVE read-only state so a reader never publishes a held write lease. Skip entirely on a decoy redirect: the mounted store is the decoy, so beating the PRESENTED vault would publish a spurious lease at the real vault's mirror.
		// Remember the chosen mode as this vault's favorite. The browser sends explicit toggles and no rememberPrefs,
		// so it records as before; a plain delegated `vdisk mount` sends rememberPrefs=false, so it never overwrites
		// a remembered choice (e.g. the macOS SMB backend) with the defaults.
		if (rememberPrefs !== false) await Vault.recordMountPrefs(p, { readOnly, workingDisk, streaming, fuseBackend });
		return { mountpoint: r.mountpoint, mode: r.cacheMode, inRam: !!r.inRam, ramDowngraded: !!r.ramDowngraded, tamper: r.tamper || null };
	}));

	app.post('/api/unmount', handle(async (req) => {
		const { target, wipeCache, force, recover } = req.body || {}; // `recover` (implies force) is the user-confirmed last resort for a wedged drive a plain force could not release
		const r = await Vault.unmount(target, { wipeCache: wipeCache !== false, force: !!force || !!recover, recover: !!recover });
		if (r && r.vault) { stopLeaseHeartbeat(r.vault); Mobile.stopByVaultPath(r.vault); } // no longer hold this mount — stop refreshing its lease, and end any phone/in-app viewer session so locking the vault really ends access
		// A clean unmount may have changed the vault — in the background, refresh its recovery data and
		// sync its mirror so both stay current. Skipped for a forced teardown (unflushed writes make
		// its state untrusted).
		if (r && r.ok && !r.forced && r.vault) schedulePostUnmount(r.vault);
		return r;
	}));

	// Cooperative stop channel. `vdisk stop` uses this to ask the running service to shut down GRACEFULLY — the same
	// drain-writes-and-lock-vaults path as a SIGTERM — over the loopback control API. It exists mainly for Windows,
	// where a headless service cannot be sent a catchable signal (a SIGTERM there is an uncatchable terminate that
	// skips the drain); on every platform it unifies the stop path so the flush always runs. Respond FIRST, then run
	// gracefulExit on the next tick so the reply reaches the caller before the process tears down. Loopback- and
	// CSRF-guarded like the rest of this API (and password-gated when network-exposed), so only the local owner can
	// trigger it. `force` is advisory only: gracefulExit drains and locks any open vault regardless, and the CLI does
	// the "refuse while vaults are open unless --force" check before calling, so the flag simply records intent.
	app.post('/api/service-stop', handle(async () => {
		setImmediate(() => { try { ProcRegistry.gracefulExit(0); } catch (_) { process.exit(0); } });
		return { stopping: true };
	}));

	// Manual self-heal override: release stale (crashed) mounts and clean up leftovers.
	app.post('/api/repair', handle(async () => { await Vault.sweep(); return { repaired: true }; }));

	// Start-at-login (autostart) control from the UI, so a user never needs the command line for it. Install adds the
	// login service AND a clickable launcher, and uninstall removes both — the same as the CLI 'autostart install'.
	// Changing it is refused over a network-exposed connection: a remote caller must never install a system login
	// service on the host. Status is a read and stays open. Both changes are confirmed in the UI before they fire.
	app.post('/api/autostart-status', handle(async () => await require('../Autostart').status()));
	app.post('/api/autostart-install', handle(async (req) => {
		if (exposed) throw new Error('Start-at-login can only be changed from the app on this computer, not over a network connection.');
		// An optional network bind makes the auto-started interface reachable from other devices (a phone on the same
		// network). Like a live `ui --bind`, that always requires a login, so refuse until a web password is set —
		// giving the same guidance rather than installing a service that would refuse to start. A missing/loopback
		// bind keeps the this-computer-only default. Validate a real bind before writing it into the service.
		const wantBind = req.body && req.body.bind ? String(req.body.bind).trim() : null;
		const network = !!(wantBind && !isLoopbackAddr(wantBind));
		if (network) {
			if (!net.isIP(wantBind)) throw new Error('That is not a valid network address to start on.');
			if (!(await Vault.getUiAuth()).enabled) throw new Error('Set a web login password first — a network-reachable interface always requires one.');
		}
		// deferStart: this running service is registering autostart for itself, so only write the login entry — do
		// not load/reload the job now, which would disturb or replace the very process handling this request. It takes
		// effect at the next login (the app is already running this session).
		const r = await require('../Autostart').install(port, { deferStart: true, bind: network ? wantBind : null });
		// A command-line install adds a clickable browser-launcher so daily use needs no terminal. The packaged
		// desktop app is ALREADY that clickable app, so adding one would put a second, conflicting icon of the same
		// name on the system — skip it here and install only the login service.
		if (!Common.isDesktopApp()) { try { await require('../Shortcut').create(); } catch (_) {} } // best-effort: a launcher hiccup must not fail the login-service install
		return { ok: true, platform: r.platform, bind: r.bind || null };
	}));
	app.post('/api/autostart-uninstall', handle(async () => {
		if (exposed) throw new Error('Start-at-login can only be changed from the app on this computer, not over a network connection.');
		// keepRunning: removing the login entry must not stop THIS service (which is serving the request) — otherwise
		// the response never returns and the app goes down mid-toggle. It just won't start at the next login.
		await require('../Autostart').uninstall({ keepRunning: true });
		try { await require('../Shortcut').remove(); } catch (_) {}
		return { ok: true };
	}));
	// Set (or change) the web login password from the app, so a user can turn on network-reachable start-at-login
	// without dropping to the command line. Reachable only from the app on this computer (loopback, where the caller
	// is the owner) or from an already-authenticated exposed session — the API guard and login gate above already
	// enforce that. Setting a password rotates the signing secret, which invalidates THIS browser's session, so we
	// immediately re-issue a fresh cookie for it; otherwise the very next request would bounce to the login screen
	// mid-flow. setUiPassword enforces the minimum length.
	app.post('/api/web-password-set', handle(async (req, res) => {
		await Vault.setUiPassword(req.body && req.body.password);
		invalidateUiAuthCache(); // the signing secret just rotated — drop the cache so every OTHER old cookie stops validating at once
		const a = await Vault.getUiAuth();
		res.setHeader('Set-Cookie', UiAuth.setCookieHeader(UiAuth.signSession(a.secret), { secure }));
		return { ok: true };
	}));

	// Panic lock: gently unmount every vault this UI opened.
	app.post('/api/lock-all', handle(async () => { stopAllLeaseHeartbeats(); Mobile.stopAll(); const r = await Vault.lockAll({ owner }); afterLock(r.vaults); return r; }));
	// Read or update the app-wide settings — auto-lock timeout, auto-timestamp, lock-on-sleep, the version-history
	// retention caps, and the sync bandwidth limit. Only the keys present in the body are changed.
	app.post('/api/settings', handle(async (req) => {
		const body = req.body || {};
		if (body.autoLockMinutes != null) {
			const min = Math.max(0, Math.floor(Number(body.autoLockMinutes) || 0));
			await Vault.setSettings({ autoLockMinutes: min });
		}
		if (body.autoAttest != null) await Vault.setSettings({ autoAttest: !!body.autoAttest }); // opt-in auto-timestamping of each new baseline
		if (body.lockOnSleep != null) await Vault.setSettings({ lockOnSleep: !!body.lockOnSleep }); // lock open vaults when the machine wakes from sleep
		if (body.autoUpdateCheck != null) await Vault.setSettings({ autoUpdateCheck: !!body.autoUpdateCheck }); // opt-in periodic update check; OFF by default (it makes an outbound network request)
		if (body.versionsKeep != null) await Vault.setSettings({ versionsKeep: Math.max(0, Math.floor(Number(body.versionsKeep) || 0)) }); // file version history: 0 = off, else keep N snapshots
		if (body.versionsMaxAgeDays != null) await Vault.setSettings({ versionsMaxAgeDays: Math.max(0, Math.floor(Number(body.versionsMaxAgeDays) || 0)) }); // optional cap: drop snapshots older than N days (0 = off)
		if (body.versionsMaxSizeMB != null) await Vault.setSettings({ versionsMaxSizeMB: Math.max(0, Math.floor(Number(body.versionsMaxSizeMB) || 0)) }); // optional cap: trim oldest until .versions fits N MB (0 = off)
		if (body.bwlimit != null) {
			// A sync bandwidth limit passed to the engine: a plain rate ("1M") or an off-peak timetable
			// ("08:00,512k 23:00,off"). Empty or an explicit off/none/unlimited/0 clears it; otherwise VALIDATE the
			// shape (shared with the CLI) so a bad rate is rejected here with an example, not opaquely at sync time.
			const raw = String(body.bwlimit).trim();
			const bw = (raw === '' || /^(off|none|unlimited|0)$/i.test(raw)) ? '' : Common.validateBwlimit(raw);
			await Vault.setSettings({ bwlimit: bw });
		}
		const s = await Vault.getSettings();
		return { settings: publicSettings(s) };
	}));

	// Manual "check for updates": the user explicitly asks, so the outbound request is made now. Read-only and
	// best-effort — it never downloads or installs, and a failed check returns { ok:false } rather than erroring.
	// On a successful check the result is remembered so the interface can keep showing an available-update banner
	// without re-fetching, and so it reflects live against the running version (see publicSettings).
	app.post('/api/update-check', handle(async () => {
		const r = await UpdateCheck.checkForUpdate();
		if (r.ok) { try { await Vault.setSettings({ lastUpdateCheck: { at: r.checkedAt, latest: r.latest } }); } catch (_) {} }
		return r;
	}));

	app.post('/api/change-password', handle(async (req) => {
		const { path: p, oldPassword, newPassword } = req.body || {};
		return await Vault.changePassword(p, { oldPassword, newPassword });
	}));

	app.post('/api/keys', handle(async (req) => await Vault.listKeys((req.body || {}).path)));
	app.post('/api/add-key', handle(async (req) => {
		const { path: p, password, newPassword, label } = req.body || {};
		return await Vault.addKey(p, { password, newPassword, label });
	}));
	app.post('/api/add-recovery', handle(async (req) => {
		const { path: p, password } = req.body || {};
		return await Vault.addRecoveryKey(p, { password });
	}));
	// Dual-key: add a read-only password, or mint a shareable read-only capability token.
	app.post('/api/add-readonly', handle(async (req) => {
		const { path: p, password, readOnlyPassword, label } = req.body || {};
		return await Vault.addReadOnlyKey(p, { password, readOnlyPassword, label });
	}));
	app.post('/api/read-cap', handle(async (req) => {
		const { path: p, password, label, expiryDays } = req.body || {};
		return await Vault.makeReadCap(p, { password, label, expiryDays });
	}));
	// Mobile access: start a session (returns a one-time pairing code the desktop shows as a QR + code), and
	// stop/list running sessions. The heavy material never leaves through here — the phone redeems the code.
	app.post('/api/mobile-start', handle(async (req) => {
		const { path: p, password, local } = req.body || {};
		// local:true is the in-app viewer opened in this machine's own browser — an ephemeral session that leaves no
		// entry in the vault's access roster. Without it (the phone flow) the grant is recorded and revocable.
		const s = await Mobile.start(p, { password, local: !!local });
		return { sessionId: s.sessionId, code: s.code, name: s.name, expiresAt: s.expiresAt, path: '/m/' };
	}));
	app.post('/api/mobile-stop', handle(async (req) => ({ stopped: Mobile.stop((req.body || {}).sessionId) })));
	app.post('/api/mobile-sessions', handle(async () => ({ sessions: Mobile.listSessions() })));
	// Emergency / inheritance dead-man's switch.
	app.post('/api/emergency-status', handle(async () => await Vault.emergencyStatus()));
	app.post('/api/emergency-keypair', handle(async () => Vault.emergencyKeypair()));
	app.post('/api/emergency-enroll', handle(async (req) => { const { contactPubKey, contactLabel, inactivityDays, graceDays } = req.body || {}; return await Vault.emergencyEnroll({ contactPubKey, contactLabel, inactivityDays, graceDays }); }));
	app.post('/api/emergency-arm', handle(async (req) => { const { path: p, password } = req.body || {}; return await Vault.emergencyArm(p, { password }); }));
	app.post('/api/emergency-checkin', handle(async () => await Vault.emergencyCheckIn()));
	app.post('/api/emergency-disarm', handle(async () => await Vault.emergencyDisarm()));
	// Travel mode: hide all vaults (and stop mobile/serve sessions) under a travel password, and restore them.
	app.post('/api/travel-status', handle(async () => Vault.travelStatus()));
	app.post('/api/travel-start', handle(async (req) => { stopAllLeaseHeartbeats(); Mobile.stopAll(); await stopAllServing(); return await Vault.travelEnable({ travelPassword: (req.body || {}).password, owner }); }));
	app.post('/api/travel-restore', handle(async (req) => await Vault.travelRestore({ travelPassword: (req.body || {}).password })));
	// Team / multi-user vaults: enable, list members, add, remove. member-remove HARD (rotate) streams progress.
	app.post('/api/team-enable', handle(async (req) => { const { path: p, password } = req.body || {}; return await Vault.enableTeam(p, { password }); }));
	app.post('/api/members', handle(async (req) => await Vault.listMembers((req.body || {}).path)));
	app.post('/api/member-add', handle(async (req) => { const { path: p, password, memberPub, role, label } = req.body || {}; return await Vault.addMember(p, { password, memberPub, role, label }); }));
	app.post('/api/member-remove', stream(async (req, onProgress) => { const { path: p, password, memberId, rotate } = req.body || {}; return await Vault.removeMember(p, { password, memberId, rotate: rotate !== false, onProgress }); }));
	app.post('/api/member-owner', handle(async (req) => { const { path: p, password, memberId, owner } = req.body || {}; return await Vault.setMemberOwner(p, { password, memberId, owner: !!owner }); }));
	app.post('/api/member-add-device', handle(async (req) => { const { path: p, password, memberId, devicePub, label } = req.body || {}; return await Vault.addDevice(p, { password, memberId, devicePub, label }); }));
	app.post('/api/member-remove-device', stream(async (req, onProgress) => { const { path: p, password, slotId, rotate } = req.body || {}; return await Vault.removeDevice(p, { password, slotId, rotate: rotate !== false, onProgress }); }));

	// The signed roster of who has access, and revoking a share.
	app.post('/api/shares', handle(async (req) => await Vault.listShares((req.body || {}).path)));
	app.post('/api/revoke-share', handle(async (req) => { const { path: p, password, sid } = req.body || {}; return await Vault.revokeShare(p, { password, sid }); }));
	app.post('/api/prune-shares', handle(async (req) => { const { path: p, password } = req.body || {}; return await Vault.pruneShares(p, { password }); }));
	// Rotate keys + re-encrypt the whole vault (true revocation). Streams progress; it can run for a while.
	app.post('/api/rotate', stream(async (req, onProgress) => { const { path: p, password, reason } = req.body || {}; return await Vault.rotate(p, { password, reason: reason || 'manual rotation', onProgress }); }));
	app.post('/api/remove-key', handle(async (req) => {
		const { path: p, password, slotId } = req.body || {};
		return await Vault.removeKey(p, { password, slotId });
	}));
	app.post('/api/add-device-key', handle(async (req) => {
		const { path: p, password, deviceKey, webauthn, label } = req.body || {};
		return await Vault.addDeviceKey(p, { password, deviceKey, webauthn, label });
	}));
	app.post('/api/add-keyfile', handle(async (req) => {
		// The browser hashes the chosen file locally and sends only its digest — the file never leaves
		// the user's machine, and the server stores just a slot plus a non-secret name hint.
		const { path: p, password, keyfileDigest, keyfileName } = req.body || {};
		return await Vault.addKeyfile(p, { password, keyfileDigest, keyfileName });
	}));

	app.post('/api/snapshot', handle(async (req) => {
		const { path: p, password, force } = req.body || {};
		return await Vault.snapshot(p, { password, force: !!force });
	}));
	app.post('/api/audit', handle(async (req) => {
		const { path: p, password } = req.body || {};
		return await Vault.audit(p, { password });
	}));
	app.post('/api/seal', handle(async (req) => {
		const { path: p, password, accept } = req.body || {};
		return await Vault.seal(p, { password, accept });
	}));
	app.post('/api/unseal', handle(async (req) => {
		const { path: p, password } = req.body || {};
		return await Vault.unseal(p, { password });
	}));
	app.post('/api/tamper-log', handle(async (req) => await Vault.tamperLog((req.body || {}).path)));

	// Self-healing (no password — parity is over the ciphertext; the vault must be unmounted).
	// protect and check-and-repair stream live progress so a long run always visibly shows it working.
	app.post('/api/protect', stream(async (req, onProgress) => {
		const { path: p, tier, thorough } = req.body || {};
		return await Vault.protect(p, { tier, thorough: !!thorough, onProgress });
	}));
	// One "Check & repair" pass: verify, then repair only if there is damage — both reported live.
	app.post('/api/heal', stream(async (req, onProgress) => {
		const p = (req.body || {}).path;
		const allowUnverified = !!(req.body || {}).allowUnverified; // the user's explicit "repair anyway" choice
		const verify = await Vault.verifyRecovery(p, { onProgress });
		if (!verify.protected || verify.clean) return { verify, heal: null };
		// Do not repair from recovery data whose signature is present but invalid (a possibly-forged index):
		// surface the refusal so the UI can explain it and offer an explicit override, instead of letting heal throw.
		if (verify.authenticity && verify.authenticity.state === 'tampered' && !allowUnverified) return { verify, heal: null, refused: 'authenticity' };
		const heal = await Vault.heal(p, { allowUnverified, onProgress });
		return { verify, heal };
	}));
	app.post('/api/unprotect', handle(async (req) => { const { path: p, password } = req.body || {}; return await Vault.unprotect(p, { password }); })); // removing recovery data needs the vault's read-write password (verified in unprotect), so a visible path alone can't strip a vault's self-healing

	// Tier-1 mirror: two-way, zero-knowledge sync of a vault's ciphertext to a folder or SFTP target.
	app.post('/api/mirror-set', handle(async (req) => { const { path: p, dest, password } = req.body || {}; await requireVaultReadIfExposed(p, password); return await Vault.setMirrorDest(p, dest); }));
	app.post('/api/mirror-sync', stream(async (req, onProgress) => { const { path: p, prime, password } = req.body || {}; await requireVaultReadIfExposed(p, password); return await oncePerVault(mirroringNow, p, 'mirror sync', () => Vault.syncMirror(p, { prime: !!prime, onProgress })); }));
	app.post('/api/mirror-remove', handle(async (req) => await Vault.removeMirror((req.body || {}).path)));

	// Act as a server: serve a vault's ciphertext so another machine can mirror to it (Tier 2 node).
	app.post('/api/serve-start', handle(async (req) => {
		const { path: p, bind, relayHost, relayToken, password } = req.body || {};
		await requireVaultReadIfExposed(p, password); // serving publishes the vault's ciphertext to the network — prove you can open it first
		const useRelay = bind === 'relay';
		if (relayHost) refuseOutboundIfExposed('a relay host'); // a caller-supplied relay is an outbound target too
		if (useRelay && relayHost) await Vault.setRelay({ host: relayHost, token: relayToken }); // remember it
		return await startServing(p, { bind, useRelay });
	}));
	app.post('/api/serve-stop', handle(async (req) => await stopServing((req.body || {}).path)));
	app.post('/api/serve-info', handle(async (req) => servingInfo(servedVaults.get(path.resolve((req.body || {}).path || '')))));
	app.post('/api/relay-config', handle(async () => await Vault.getRelay()));
	app.post('/api/fingerprint', handle(async (req) => await Vault.fingerprint((req.body || {}).path)));
	// Build a printable Recovery Kit (identity + fingerprint + restore steps, and — unless addKey is
	// false — a freshly generated recovery key). Returns the kit HTML for the browser to open and print;
	// the recovery key, if any, is inside that HTML and shown only here. Adding a key needs the password.
	app.post('/api/recovery-kit', handle(async (req) => {
		const { path: p, password, addKey } = req.body || {};
		return await Vault.recoveryKit(p, { password, addKey: addKey !== false });
	}));
	// Provable, timestamped attestation (RFC 3161). Create a proof of the vault's exact current state, or
	// list and verify the existing proofs. No password — nothing here is secret.
	app.post('/api/attest', handle(async (req) => {
		const { path: p, tsaUrl } = req.body || {};
		// A custom timestamp-authority URL would let a request from the network make this machine POST to an
		// arbitrary internal address (an SSRF / internal port probe). On an exposed bind, refuse it and use only
		// the vetted public authority; on loopback the caller is the operator's own machine, so it is allowed.
		if (tsaUrl && exposed) throw new Error('A custom timestamp-authority URL is not allowed over a network-exposed connection. Use the default authority, or set a custom one from the app on this computer.');
		return await Vault.attest(p, { tsaUrl: (tsaUrl && !exposed) ? tsaUrl : undefined });
	}));
	app.post('/api/attestations', handle(async (req) => await Vault.attestations((req.body || {}).path)));

	// Favorites: mark a vault to surface first with one-tap unlock.
	app.post('/api/favorite', handle(async (req) => { const { path: p, on } = req.body || {}; return await Vault.setFavorite(p, on !== false); }));

	// Per-vault decoy (duress) protection (advanced, opt-in): pair a real vault with a decoy vault, list the
	// pairings (manager password — the hidden management view), or remove one. The mount path resolves a decoy
	// automatically; there is nothing to "unlock" for a session.
	app.post('/api/decoy-set', handle(async (req) => { const { realVault, decoyVault, decoyPassword, managerPassword } = req.body || {}; return await Vault.decoySet({ realVault, decoyVault, decoyPassword, managerPassword }); }));
	app.post('/api/decoy-list', handle(async (req) => { const mappings = await Vault.decoyList((req.body || {}).managerPassword); if (mappings == null) throw new Error('The manager password is incorrect.'); return { mappings }; }));
	app.post('/api/decoy-remove', handle(async (req) => { const { realVault, managerPassword } = req.body || {}; return await Vault.decoyRemove({ realVault, managerPassword }); }));

	// Secure notes — encrypted notes/secrets kept as files inside a MOUNTED vault (the engine encrypts
	// them transparently; the vault must be open to read or write them).
	// Filename search — a mounted vault searches with no password; an unmounted one needs the password.
	app.post('/api/search-names', handle(async (req) => { const { path: p, query, password } = req.body || {}; return await Vault.searchNames(p, { query, password }); }));
	// Content search: search inside files via the in-vault index, and (re)build that index with progress.
	app.post('/api/content-search', handle(async (req) => { const { path: p, query } = req.body || {}; return await Vault.contentSearch(p, { query }); }));
	app.post('/api/content-status', handle(async (req) => await Vault.contentIndexStatus((req.body || {}).path)));
	app.post('/api/content-reindex', stream(async (req, onProgress) => { const p = (req.body || {}).path; return await oncePerVault(reindexingNow, p, 'content reindex', () => Vault.contentReindex(p, { onProgress })); }));

	app.post('/api/notes-list', handle(async (req) => await Vault.notesList((req.body || {}).path)));
	app.post('/api/note-get', handle(async (req) => { const { path: p, id } = req.body || {}; return { note: await Vault.noteGet(p, id) }; }));
	app.post('/api/note-save', handle(async (req) => { const { path: p, id, title, body } = req.body || {}; return await Vault.noteSave(p, { id, title, body }); }));
	app.post('/api/note-delete', handle(async (req) => { const { path: p, id } = req.body || {}; return await Vault.noteDelete(p, id); }));

	// Tier 3 — disperse across nodes + threshold key. The heavy encode/decode runs in the dispersal
	// worker (see Vault.disperse), so these are safe to drive from the long-running server. For rebuild
	// and repair the browser points at the folders holding the shards; Vault.collectShards gathers the
	// .vdshard files from each (top-level only, bounded) — the same collector the scheduled repair uses.
	const collectShards = Vault.collectShards;
	app.post('/api/disperse', stream(async (req, onProgress) => {
		refuseHostFsIfExposed('Splitting a vault into shard folders'); // writes the vault's ciphertext shards to caller-named host folders — loopback-only, like reconstruct
		const { path: p, k, dests, force, password } = req.body || {};
		await requireVaultReadIfExposed(p, password); // splitting writes the vault's ciphertext shards to chosen folders
		const folders = (Array.isArray(dests) ? dests : []).map(d => String(d || '').trim()).filter(Boolean);
		return await oncePerVault(dispersingNow, p, 'split', () => Vault.disperse(p, { n: folders.length, k: parseInt(k, 10), dests: folders, force: !!force, onProgress }));
	}));
	app.post('/api/shards-inspect', handle(async (req) => { refuseHostFsIfExposed('Inspecting shard folders'); return await Vault.inspectShards(await collectShards((req.body || {}).folders)); })); // reads/probes caller-named host folders — loopback-only
	app.post('/api/reconstruct', stream(async (req, onProgress) => {
		refuseHostFsIfExposed('Rebuilding a vault from shards'); // reads shard folders and writes the rebuilt vault to a caller-named host path — loopback-only
		const { folders, destDir } = req.body || {};
		const shards = await collectShards(folders);
		if (!shards.length) throw new Error('No shard files (.vdshard) were found in the folder(s) you chose.');
		return await Vault.reconstructFromShards(shards, destDir, { onProgress });
	}));
	app.post('/api/shards-repair', stream(async (req, onProgress) => {
		refuseHostFsIfExposed('Repairing shard folders'); // reads and writes reconstructed shards into caller-named host folders — loopback-only
		const folders = (req.body || {}).folders;
		if (!(await collectShards(folders)).length) throw new Error('No shard files (.vdshard) were found in the folder(s) you chose.');
		return await Vault.repairFolders(folders, { onProgress }); // re-creates even wholly-missing shards
	}));
	app.post('/api/threshold-key', handle(async (req) => {
		const { path: p, password, n, k, readOnly } = req.body || {};
		return await Vault.addThresholdKey(p, { password, n: parseInt(n, 10), k: parseInt(k, 10), readOnly: !!readOnly });
	}));
	// Scheduled shard repair: set/clear a schedule for a folder set, and read the current schedules.
	app.post('/api/repair-schedules', handle(async () => ({ schedules: await Vault.listRepairSchedules() })));
	app.post('/api/repair-schedule', handle(async (req) => {
		const b = req.body || {};
		return await Vault.saveRepairSchedule({ folders: b.folders, label: b.label, mode: b.mode, intervalHours: b.intervalHours, hour: b.hour, minute: b.minute });
	}));
	app.post('/api/repair-schedule-remove', handle(async (req) => await Vault.removeRepairSchedule((req.body || {}).id)));

	app.post('/api/backup', handle(async (req) => {
		const { path: p, dest, password } = req.body || {};
		await requireVaultReadIfExposed(p, password); // a backup copies the vault's ciphertext (and key slots) to the destination
		return await Vault.backup(p, dest);
	}));
	// Restorability check: confirm the backup destination holds a complete, matching copy of this vault.
	app.post('/api/verify-backup', handle(async (req) => { refuseHostFsIfExposed('Verifying a backup destination'); const { path: p, dest } = req.body || {}; return await Vault.verifyBackup(p, { dest }); })); // reads a caller-named host path — loopback-only
	// File version history (prior versions kept at the backup destination): browse and restore.
	app.post('/api/versions', handle(async (req) => { const { path: p, password } = req.body || {}; await Vault.assertReadable(p, password); return await Vault.listVersions(p, { password }); })); // require a credential that opens the vault, so snapshot metadata is not disclosed to a caller who cannot open it
	app.post('/api/restore-version', handle(async (req) => { const { path: p, password, origin, timestamp, file } = req.body || {}; return await Vault.restoreVersion(p, { password, origin, timestamp, file }); }));
	// Pack a vault into a single portable container file inside the chosen folder (used by the Share flow).
	// Streams progress so a large vault shows a live bar instead of appearing to hang.
	app.post('/api/pack', stream(async (req, onProgress) => {
		const { path: p, destFolder, overwrite, keepSlots, password } = req.body || {};
		await requireVaultReadIfExposed(p, password); // packing writes the vault's ciphertext (and key slots) into a portable file
		return await Vault.pack(p, null, { destFolder, overwrite: !!overwrite, keepSlots: Array.isArray(keepSlots) ? keepSlots : undefined, onProgress });
	}));
	// Import a shared packed file in one step: unpack it into the vaults folder (unless another is given) and
	// register it, so it appears in the list ready to open. Streams progress. Guarded per source file so a
	// double-click (or a disconnect-and-retry) can't run two extractions of the same archive into one target.
	app.post('/api/unpack', stream(async (req, onProgress) => {
		refuseHostFsIfExposed('Unpacking a shared vault file'); // reads a caller-named host file and writes the vault to a caller-named host folder — loopback-only
		const { file, destFolder } = req.body || {};
		return await oncePerVault(unpackingNow, file, 'import', () => Vault.unpack(file, destFolder || Vault.vaultsDir(), { onProgress }));
	}));
	app.post('/api/backup-schedule', handle(async (req) => {
		const { path: p, schedule } = req.body || {};
		return await Vault.setBackupSchedule(p, schedule || { mode: 'off' });
	}));
	// Scheduled integrity scrub: read the current schedule, or set a new one.
	app.post('/api/scrub-schedule', handle(async (req) => {
		const { path: p, schedule } = req.body || {};
		if (schedule) return await Vault.setScrubSchedule(p, schedule);
		return { schedule: await Vault.getScrubSchedule(p) };
	}));
	// Run one scrub now (the same password-less recovery-data check plus optional repair the schedule runs), so
	// the web interface has the CLI's on-demand `scrub` as well as the schedule.
	app.post('/api/scrub-now', handle(async (req) => await Vault.runScrub((req.body || {}).path)));
	app.post('/api/sftp-dests', handle(async () => ({ dests: await Vault.listSftpDests() })));
	app.post('/api/sftp-dest', handle(async (req) => { refuseOutboundIfExposed('an off-site backup destination'); return await Vault.saveSftpDest((req.body || {}).dest || {}); }));
	app.post('/api/sftp-dest-remove', handle(async (req) => await Vault.removeSftpDest((req.body || {}).id)));
	app.post('/api/sftp-test', handle(async (req) => await Vault.testSftpDest((req.body || {}).id)));

	// Tier-2 peer nodes (WebDAV) — the client side of "anywhere access".
	app.post('/api/peers', handle(async () => ({ peers: await Vault.listPeers() })));
	app.post('/api/peer', handle(async (req) => {
		refuseOutboundIfExposed('a peer connection');
		const peer = (req.body || {}).peer || {};
		// A pasted connection code carries the address, login, and pinned cert in one string.
		if (peer.code) { const parsed = Vault.parsePeerCode(peer.code); if (!parsed) throw new Error('That connection code is not valid — copy it again from the other machine.'); return await Vault.savePeer({ label: peer.label, url: parsed.url, user: parsed.user, password: parsed.password, ca: parsed.ca }); }
		return await Vault.savePeer(peer);
	}));
	app.post('/api/peer-remove', handle(async (req) => await Vault.removePeer((req.body || {}).id)));
	app.post('/api/peer-test', handle(async (req) => await Vault.testPeer((req.body || {}).id)));

	// Re-run the integrity self-check on demand (the vault list shows its summary).
	app.post('/api/selfcheck', handle(async () => ({ selfCheck: { at: new Date().toISOString(), findings: await SelfCheck.run({ label: 'on demand' }), total: SelfCheck.list().length } })));

	app.post('/api/install-driver', handle(async () => await require('../DriverInstall').install()));
	app.post('/api/add-vault', handle(async (req) => { const r = await Vault.addKnownVault((req.body || {}).path); SelfCheck.run({ label: 'after add-vault', fresh: true }).catch(() => {}); return r; })); // re-run the self-check so its cached findings (shown in the UI) reflect the new list
	app.post('/api/remove-vault', handle(async (req) => { const r = await Vault.removeKnownVault((req.body || {}).path); if (r && r.path) readVaultState.evict(r.path); SelfCheck.run({ label: 'after remove-vault', fresh: true }).catch(() => {}); return r; })); // evict the removed vault's poll-cache entry so the map can't retain it forever; re-run the self-check so a removed vault's "no longer exists" finding clears instead of lingering from the cached sweep
	// Permanent delete (crypto-erase): destroy the vault's keys so its encrypted data can never be opened
	// again, then remove the local folder. This is irreversible, so the caller must echo back the vault's
	// EXACT name — a request that does not carry the precise name is refused, a second guard behind the UI's
	// typed-name confirmation (so a stray or replayed request can never erase). The engine force-unmounts and
	// drops the RAM cache itself, and refuses to report success while any key file survives.
	app.post('/api/secure-remove', handle(async (req) => {
		const { path: p, confirmName, password } = req.body || {};
		if (!p) throw new Error('No vault was specified.');
		// Derive the expected name from the SAME resolved path that will be erased, not the raw input's basename —
		// otherwise a path with a trailing "." or similar could make the name check describe a different folder than
		// the one destroyed. secureRemove resolves the path the same way, so the two can never disagree.
		const abs = Vault.resolveVaultDir(p);
		const expected = Vault.displayName(abs);
		if (String(confirmName == null ? '' : confirmName).trim() !== expected) throw new Error('The typed name did not match "' + expected + '", so nothing was deleted.');
		// secureRemove itself verifies the password (a read-write credential that actually opens the vault) before it
		// destroys anything, so knowing the visible name is never enough to erase a vault.
		const r = await Vault.secureRemove(abs, { password });
		if (r && r.vault) readVaultState.evict(r.vault); // drop the erased vault's poll-cache entry so the map can't retain it forever
		SelfCheck.run({ label: 'after secure-remove', fresh: true }).catch(() => {}); // refresh cached findings so the gone vault clears from the list
		return r;
	}));
	app.post('/api/vault-size', handle(async (req) => await Vault.vaultSize((req.body || {}).path))); // on demand only (a full folder walk), never on the poll
	app.post('/api/reveal', handle(async (req) => {
		// Opening a location in the OS file manager makes sense only on the machine running the app, and must not let a
		// caller point the server's opener at an arbitrary path/app. Refuse over the network, and confine the target to
		// one of your own vault folders or a live mountpoint (which is all the UI ever reveals).
		if (exposed) throw new Error('Opening a location in the file manager works only on the computer running the app, not over a network connection.');
		// normalizeMountpoint (not raw path.resolve) so a Windows drive-letter mountpoint ("X:") maps to its root
		// ("X:\") consistently on BOTH sides of the check below — a bare drive letter otherwise resolves against the
		// current directory and would never match its own root. A no-op for ordinary paths and on other platforms.
		const abs = Vault.normalizeMountpoint(String((req.body || {}).path || ''));
		const roots = [...(await Vault.listKnownVaults().catch(() => [])), ...(await Vault.listMounts().catch(() => [])).map(m => m && m.mountpoint).filter(Boolean)].map(p => Vault.normalizeMountpoint(p));
		if (!roots.some(r => abs === r || Common.pathWithin(abs, r))) throw new Error('That location is not one of your vaults, so it was not opened.');
		return await Vault.reveal(abs);
	}));
	app.post('/api/browse', handle(async (req) => {
		refuseHostFsIfExposed('Browsing folders on this computer'); // enumerates host directories and volumes — loopback-only, matching the other host-filesystem routes; the folder picker is useless over an exposed bind anyway
		return await browseDir((req.body || {}).path, { includeFiles: !!(req.body || {}).includeFiles });
	}));
	// Add files to a MOUNTED vault by streaming them in (no OS copy call), so a large file lands
	// reliably even where the macOS Finder's copy hits the FUSE-T "-36" bug. Guarded per vault.
	app.post('/api/import-files', stream(async (req, onProgress) => {
		refuseHostFsIfExposed('Adding files from this computer'); // reads caller-named host files — loopback-only
		const { path: p, sources, force } = req.body || {};
		return await oncePerVault(importingNow, p, 'file import', () => Vault.importFiles(p, sources, { onProgress, force: !!force }));
	}));

	// Terminal error handler: return a clean JSON error with NO stack trace, so a malformed body (or any route
	// error) never leaks install paths or Node internals. This matters even before login, because the JSON body
	// parser runs ahead of the auth gate and a bad body would otherwise reach Express's default handler, which in
	// a desktop (non-production) environment includes the stack.
	app.use((err, req, res, next) => {
		if (res.headersSent) return next(err);
		const bad = err && (err.type === 'entity.parse.failed' || err.type === 'encoding.unsupported' || err instanceof SyntaxError);
		const tooBig = err && err.type === 'entity.too.large';
		try { Common.warn('[web] request error: ' + ((err && err.message) || err)); } catch (_) {}
		res.status(bad || tooBig ? 400 : 500).json({ ok: false, error: bad ? 'Malformed request.' : tooBig ? 'Request too large.' : 'Request failed.' });
	});

	// On the loopback default this is a plain HTTP server; when exposed to the network it is HTTPS with
	// the self-signed certificate made above, so the login and every request are encrypted.
	const server = tls ? https.createServer(tls, app) : http.createServer(app);
	// Bound the time a client may take to send its request headers/body, so a slow or stalled connection (an
	// accidental one, or a slow-loris when the interface is exposed) can't tie up a socket indefinitely. The
	// long-running STREAMING endpoints (protect/heal/pack) send their whole response over one connection, so the
	// per-response timeout is left at the Node default (0 = unlimited) — only the request-receipt phase is capped.
	server.headersTimeout = 30 * 1000;   // time to receive the complete request headers
	server.requestTimeout = 5 * 60 * 1000; // time to receive the complete request (body included)
	server.keepAliveTimeout = 30 * 1000; // idle keep-alive before the socket is closed
	return new Promise((resolve, reject) => {
		let settled = false;
		// Without this, a taken or unbindable port emits 'error' with no listener, which the resilient
		// top-level handler logs and swallows — so the listen callback never fires and start() would hang
		// forever with only a raw stack trace. Reject with a clear, actionable message instead.
		server.once('error', (e) => {
			if (settled) return; settled = true;
			const code = e && e.code;
			const hint = code === 'EADDRINUSE' ? ' — port ' + port + ' is already in use. If that is ' + Brand.name + ', run "' + Brand.cli + ' stop" to stop it (or "' + Brand.cli + ' open" to reach it); otherwise stop the other program or start with --port <number>.'
				: code === 'EACCES' ? ' — permission to use port ' + port + ' was denied. Ports below 1024 need elevated privileges on most systems; start with --port <number> and choose 1024 or above.'
				: code === 'EADDRNOTAVAIL' ? ' — the address ' + bindAddr + ' is not one this computer can bind to. Use --bind with a local address (for example 127.0.0.1 for this machine only, or 0.0.0.0 for all interfaces).'
				: (e && e.message ? ': ' + e.message : '.');
			reject(new Error('Could not start the ' + Brand.name + ' web server' + hint));
		});
		server.listen(port, bindAddr, () => {
			if (settled) return; settled = true;
			const scheme = secure ? 'https' : 'http';
			const shown = exposed ? bindAddr : 'localhost';
			Common.log(Brand.name + ' UI at ' + scheme + '://' + shown + ':' + port + (authEnabled ? '  (login required)' : ''));
			// Advertise this owner's loopback control URL so the CLI can route mount/unmount through the SAME
			// long-lived process (it holds the vault key in memory for the whole session and finalizes cleanly on
			// unmount). Loopback only — never an exposed/TLS bind, which the CLI must not drive — AND only when the
			// run directory is verifiably owner-only, so the CLI never posts the vault password to a pidfile another
			// local user could have planted. Best-effort and non-blocking; the CLI treats a missing url as "no
			// owner" and mounts directly instead.
			if (!exposed && runDirHardened) { Common.writeJsonAtomic(servicePidFile, { pid: process.pid, at: new Date().toISOString(), url: 'http://127.0.0.1:' + port }).catch(() => {}); }
			if (exposed) Common.log('Exposed to the network with a self-signed certificate — expect a browser trust prompt the first time.');
			// Fire the boot-time integrity self-check once the server is listening. Fire-and-forget and
			// warn-only, so it can never delay startup or disturb anything — it just records findings.
			SelfCheck.run({ label: 'startup' }).catch(() => {});
			// Start downloading the encryption engine in the background on a fresh first run, so the page is usable
			// (showing a "Setting up…" state) instead of blocked while a tens-of-MB engine downloads. Fire-and-forget;
			// the health tick retries this until it succeeds, and a real operation still waits on its own ensure().
			try { Vault.startEngineSetup(); } catch (_) {}
			resolve({ server, port });
		});
	});
}

module.exports = { start, buildState };
