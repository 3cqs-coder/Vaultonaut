'use strict';
// lib/SelfCheck.js — the boot-time self-policing integrity registry.
//
// One place that runs the tool's own invariant checks and reports anything wrong, so a broken
// assumption is caught the moment the program starts instead of being hunted down later. It is the
// counterpart to the runtime mount Watchdog (lib/Watchdog.js): the Watchdog watches live drives for
// wedging, while this sweeps the install's on-disk state (permissions, settings, engine, registered
// vaults) once at startup. Two different jobs; kept as two modules so neither complicates the other.
//
// Design rules, matching the rest of the tool:
//   • WARN-ONLY. A check never blocks startup, a mount, or anything else — it observes and reports.
//   • NEVER throws. A check that throws becomes its own finding; run() itself always resolves.
//   • Self-registering. A check is `register(name, fn)`, and run() executes every registered one, so
//     adding a safeguard later is a single register() call with no edit to the runner. Any subsystem
//     can register its own check in its own module.
//   • Self-explanatory. Every finding carries a plain-language message AND how to fix it, so the log
//     never leaves the reader decoding a machine code.
//
// A check is `fn(ctx) -> finding | finding[] | null` (sync or async), where
//   finding = { level: 'warn' | 'error', message, fix }
// and ctx = { Vault, doctor, isPosix, dataDir, label } (Common is used directly as the module-level require).

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const Common = require('./Common');

// Generous ceiling for reading the app's own JSON metadata (settings, mount state, integrity ledger, tamper log)
// on the periodic self-check, so a pathologically large file cannot stall the tick with a huge main-thread parse.
// These files are effectively bounded in practice (the tamper log is slice-capped per vault); this is a backstop.
const MAX_META_BYTES = 64 * 1024 * 1024;

// ── Registry ─────────────────────────────────────────────────────────────────
const checks = []; // { name, fn }

// Register a named check. Idempotent by name (re-registering replaces), so requiring this module
// twice never double-runs a check.
function register(name, fn) {
	if (!name || typeof fn !== 'function') return checks.length;
	const i = checks.findIndex(c => c.name === name);
	if (i >= 0) checks[i] = { name, fn }; else checks.push({ name, fn });
	return checks.length;
}
function list() { return checks.map(c => c.name); }

let lastResult = null; // { at, total, findings } — the most recent sweep, for the UI/API to surface
function last() { return lastResult; }

// Run every registered check. Never throws. Returns the flattened findings (empty when all clear) and
// records the sweep to lastResult and the log. `context` may carry a precomputed doctor snapshot to
// avoid a second probe.
let runInFlight = null; // the currently-running sweep, so overlapping callers coalesce onto it instead of stacking
async function run(context) {
	context = context || {};
	// A sweep walks every known vault with several bounded per-vault reads, so on many vaults over a slow drive one
	// pass can outlast the caller's fixed re-fire interval. Ordinary callers COALESCE onto the running sweep rather
	// than stacking a second that re-pins threads on the same reads. A FRESH caller (an explicit refresh right after
	// the vault list changed) must reflect the NEW state, so it does not coalesce — it CHAINS after whatever is
	// running, and ordinary callers then coalesce onto it. Two sweeps never overlap, so the recorded result never
	// regresses to a pre-change one.
	if (runInFlight && !context.fresh) return runInFlight;
	const sweep = () => (async () => {
		const Vault = require('./Vault'); // lazy: avoids any load-order coupling with the core module
		let doctor = context.doctor;
		if (!doctor) { try { doctor = await Vault.doctor(); } catch (_) { doctor = null; } }
		// The module-level Common is used directly everywhere; ctx carries only the genuine per-run context.
		const ctx = { Vault, doctor, isPosix: process.platform !== 'win32', dataDir: Common.dataDir(), label: context.label || '' };

		const findings = [];
		for (const c of checks) {
			try {
				const res = await Promise.resolve().then(() => c.fn(ctx));
				for (const f of [].concat(res || [])) {
					if (f && f.message) findings.push({ check: c.name, level: f.level || 'warn', message: f.message, fix: f.fix || '' });
				}
			} catch (e) {
				// A check that throws is itself a finding — never silently swallowed, and never fatal.
				findings.push({ check: c.name, level: 'warn', message: 'Integrity check "' + c.name + '" could not run: ' + (e && e.message ? e.message : String(e)), fix: '' });
			}
		}

		const label = ctx.label ? ' (' + ctx.label + ')' : '';
		try {
			if (context.quiet) { /* caller formats the output itself (e.g. the doctor command) */ }
			else if (findings.length) {
				const failed = new Set(findings.map(f => f.check)).size;
				Common.warn('Integrity self-check' + label + ': ' + checks.length + ' checks ran — ' + (checks.length - failed) + ' passed, ' + failed + ' with finding(s):');
				for (const f of findings) Common.warn('  [' + f.level + '] ' + f.message + (f.fix ? ' — ' + f.fix : ''));
			} else {
				Common.log('Integrity self-check' + label + ': all ' + checks.length + ' checks passed.');
			}
		} catch (_) {}

		lastResult = { at: new Date().toISOString(), total: checks.length, findings };
		return findings;
	})();
	const prev = runInFlight;
	const mine = prev ? prev.catch(() => {}).then(sweep) : sweep(); // fresh: chain after the running sweep; otherwise start now
	runInFlight = mine;
	try { return await mine; } finally { if (runInFlight === mine) runInFlight = null; }
}

// ── Small helpers shared by the built-in checks ───────────────────────────────
// Warn if a file that holds secrets is readable by group or others (POSIX only — Windows uses ACLs,
// where the mode bits do not carry this meaning).
async function checkPerms(file, human, isPosix) {
	if (!isPosix) return null;
	let st; try { st = await fsp.stat(file); } catch (_) { return null; } // absent is fine — nothing to protect yet
	if (st.mode & 0o077) return { level: 'warn', message: human + ' (' + file + ') is readable by other users on this computer.', fix: 'Restrict it with:  chmod 600 "' + file + '"' };
	return null;
}

// ── Built-in checks ───────────────────────────────────────────────────────────

// 1. The encryption engine must be present, or nothing can be created, mounted, or synced.
register('engine', (ctx) => {
	const engine = ctx.doctor && ctx.doctor.engine;
	if (engine && engine.ok) return null;
	// A fresh install downloads the engine in the background on first run. That is a normal not-ready-YET state, not
	// a failure — the environment banner already shows a "Setting up…" message — so don't also raise a scary red
	// error for it. Only report a hard error when the engine is genuinely unavailable (not currently downloading).
	if (engine && engine.downloading) return null;
	return { level: 'error', message: 'The encryption engine is not available.', fix: 'Run "' + require('./Brand').cli + ' setup" while online to download it.' };
});

// 1b. Engine binary integrity — the bundled crypt engine should still match the checksum recorded when it
// was downloaded and verified against the official release. A mismatch means the binary changed since
// (possibly swapped or tampered), which would undermine every vault, so it is surfaced. Warn-only: the
// engine is re-verified and, if needed, re-downloaded from the official source on the next mount. This is
// tamper EVIDENCE for the on-disk binary, not a guarantee against a running attacker.
register('engine_integrity', async () => {
	let status = 'ok';
	try { status = await require('./RcloneSetup').integrityStatus(); } catch (_) { return null; }
	if (status !== 'mismatch') return null; // 'ok'/'unrecorded'/'absent' are not tampering signals
	return { level: 'warn', message: 'The bundled encryption engine no longer matches the checksum recorded when it was verified against the official release — it may have been altered or replaced.', fix: 'It will be re-verified and, if needed, re-downloaded from the official source on the next mount. If this keeps happening, reinstall the tool from a trusted copy.' };
});

// 1c. Engine VERSION drift. The checksum check above proves the binary is the one that was recorded, but a very old
// install — or a deliberate "setup --latest" — can leave a version whose behavior differs from what this build was
// tested against. Some features carry a hard floor: the two-way mirror needs bisync's --backup-dir1/2 and the
// percentage --max-delete, which arrived in engine 1.66. Warn-only, best-effort, and silent on a newer-or-equal
// version (a newer engine is a fine deliberate choice), so it never nags — it only surfaces an OLD or too-old engine.
register('engine_version', async () => {
	const RS = require('./RcloneSetup');
	let installed; try { installed = await RS.installedVersion(); } catch (_) { return null; }
	if (!installed) return null; // could not determine (offline probe failed) — say nothing rather than guess
	const cmp = require('./UpdateCheck').compareVersions; // one canonical version comparator (handles a leading 'v', pre-release suffixes, and any segment count) instead of a second inline copy that could drift
	const cli = require('./Brand').cli;
	if (cmp(installed, 'v1.66.0') < 0) {
		return { level: 'warn', message: 'The encryption engine is version ' + installed + ', which is older than this app needs. Some features — the two-way mirror in particular — depend on a newer engine and may not work correctly.', fix: 'Run "' + cli + ' setup" while online to install the tested engine version.' };
	}
	if (cmp(installed, RS.PINNED_TAG) < 0) {
		return { level: 'warn', message: 'The encryption engine is version ' + installed + ', older than the version this app was tested against (' + RS.PINNED_TAG + '). It will usually still work, but some behavior can differ.', fix: 'If you did not deliberately keep an older engine, run "' + cli + ' setup" to restore the tested version.' };
	}
	return null; // same as, or newer than, the tested pin — nothing to flag
});

// 1d. Application self-integrity. Generalizes the engine checksum pin to the WHOLE program: at release time the
// maintainer signs a manifest of every shipped file's hash with an Ed25519 key, and this confirms the installed
// files still match, verified against the public key embedded in the build. Warn-only and best-effort: it is INERT
// on an unsigned source checkout (no manifest, or no embedded key), so it never nags during development, and it can
// only be tamper EVIDENCE — whoever modified the files could also patch out this check — so it complements, never
// replaces, verifying the download out of band against the maintainer's key (see the README's verify steps).
register('release_integrity', async () => {
	const Brand = require('./Brand');
	const RI = require('./ReleaseIntegrity');
	// On the MAINTAINER's own working copy (the private signing key is present), a hash mismatch is just their own
	// not-yet-signed edits — the separate release_signing_pending reminder covers that with the right wording. Skip
	// the end-user "this copy may be modified" alarm there so the maintainer is never falsely alarmed by their edits.
	try { if (await RI.signingPending() !== null) return null; } catch (_) {}
	let r; try { r = await RI.verifyInstallCached(); } catch (_) { return null; } // cached: the periodic sweep does not re-hash the whole install
	if (!r || !r.present || r.pubkey === false) return null; // unsigned build / no embedded key → nothing to assert
	if (!r.signatureValid) return { level: 'warn', message: 'This copy of ' + Brand.name + ' has a release manifest whose signature does not verify — the manifest or the embedded key was changed.', fix: 'Re-download ' + Brand.name + ' from the official source and verify it (see "Verifying your download" in the README).' };
	if (r.unknownFormat) return { level: 'warn', message: 'This copy of ' + Brand.name + ' has a signed release manifest in a newer format that this version does not understand, so its files cannot be checked here.', fix: 'Update ' + Brand.name + ' to the latest version, which can verify it.' }; // authentic but newer-format: "update the tool", never a tamper alarm
	// Warn only when a SIGNED file was actually modified or is missing — real tamper evidence. Do NOT warn merely
	// because extra, unlisted files are present: a from-source checkout legitimately carries development files (the
	// test tree, packaging scripts, repository assets) that the published `files` allowlist strips from the npm package
	// and desktop bundle, and an added file that no signed file references is inert. Flagging those here would raise a
	// false "this copy may be modified" alarm on every from-source install. The out-of-band verify.js still reports
	// extra files for a downloaded release, where the artifact contains only the published set.
	const modified = [...(r.mismatches || []), ...(r.missing || [])];
	if (modified.length) {
		const n = modified.length;
		return { level: 'warn', message: n + ' application file(s) do not match the signed release (' + modified.slice(0, 5).join(', ') + (n > 5 ? ', …' : '') + ') — this copy of ' + Brand.name + ' may have been modified.', fix: 'Re-download ' + Brand.name + ' from the official source and verify it before using it with real vaults.' };
	}
	return null;
});

// 1e. MAINTAINER reminder to re-sign a release. This is a no-op on end-user installs (it only activates where the
// private signing key is present), and it never uses git or npm hooks — the app simply notices, each time it runs,
// that the package.json version was bumped past the last signed release and reminds you to re-sign. Warn-only.
register('release_signing_pending', async () => {
	const Brand = require('./Brand');
	let r; try { r = await require('./ReleaseIntegrity').signingPending(); } catch (_) { return null; }
	if (!r || !r.pending) return null; // no key here (an end user), or already signed at the current version
	const msg = r.reason === 'version-changed'
		? Brand.name + ' is now version ' + (r.version || '?') + ' but the last signed release was ' + (r.signedVersion || '?') + '. Re-sign so downloads of this version can be verified.'
		: Brand.name + ' has a release-signing key but this version has not been signed yet.';
	return { level: 'warn', message: msg, fix: 'Run "npm run sign" to sign the current files, then publish. (Run "npm run sign:check" any time to see whether a re-sign is due.)' };
});

// 1f. MAINTAINER guard: the release-signing PRIVATE key must never be committed. This activates only where that key
// is present (so it never touches end users), and confirms .gitignore still keeps it out of version control — a
// guard against an edited or removed ignore rule silently exposing the key. Pure filesystem read, no git spawn.
register('release_key_exposed', async () => {
	const RI = require('./ReleaseIntegrity');
	const root = require('./Common').root();
	const keyFile = path.join(root, RI.KEY_NAME);
	try { await fsp.access(keyFile); } catch (_) { return null; } // no key here → not the maintainer's machine
	let ignored = false;
	try {
		const gi = await Common.readFileCapped(path.join(root, '.gitignore'), MAX_META_BYTES, 'utf8');
		ignored = String(gi || '').split(/\r?\n/).map(l => l.trim()).some(l => l === RI.KEY_NAME || l === '/' + RI.KEY_NAME);
	} catch (_) { ignored = false; }
	if (ignored) return null;
	return { level: 'warn', message: 'The release-signing private key (' + RI.KEY_NAME + ') is present but .gitignore does not list it, so it could be committed by accident.', fix: 'Add "' + RI.KEY_NAME + '" to .gitignore and keep the private key out of version control.' };
});

// 2. The mount driver — a vault can still be created and synced without it, but not mounted, so this
// is a warning, not an error. The driver report already carries its own fix text.
register('driver', (ctx) => {
	const d = ctx.doctor && ctx.doctor.driver;
	if (!d || d.ok) return d && d.warn ? { level: 'warn', message: d.warn, fix: d.install || '' } : null;
	return { level: 'warn', message: (d.detail || 'No mount driver is installed.') + ' Vaults can be created and synced, but not mounted, until one is present.', fix: d.install || '' };
});

// 3. The data directory must be writable, or settings, state, and saved logins cannot persist.
register('data_dir_writable', async (ctx) => {
	const probe = path.join(ctx.dataDir, '.selfcheck-' + process.pid);
	try { await fsp.mkdir(ctx.dataDir, { recursive: true }); await fsp.writeFile(probe, 'ok'); await fsp.unlink(probe); return null; }
	catch (e) { return { level: 'error', message: 'The data directory (' + ctx.dataDir + ') is not writable: ' + (e && e.code ? e.code : e.message) + '.', fix: 'Check the folder exists and that you have permission to write to it.' }; }
});

// 4. The settings file must be valid JSON — a hand-edit or a truncated copy that broke it would
// otherwise be discovered only on the next write (which then moves it aside).
register('settings_readable', async (ctx) => {
	const p = path.join(ctx.dataDir, 'settings.json');
	let raw; try { raw = await Common.readFileCapped(p, MAX_META_BYTES, 'utf8'); } catch (_) { return null; } // absent (or, rarely, over the cap) is skipped, matching the capped ledger reader below
	try { JSON.parse(raw); return null; }
	catch (_) { return { level: 'warn', message: 'The settings file (' + p + ') is not valid JSON.', fix: 'Fix the JSON, or move the file aside to start fresh — saved off-site logins, schedules, and the auto-lock timeout would then need re-entering.' }; }
});

register('state_readable', async (ctx) => {
	const p = path.join(ctx.dataDir, 'state.json');
	let raw; try { raw = await Common.readFileCapped(p, MAX_META_BYTES, 'utf8'); } catch (_) { return null; } // absent (or, rarely, over the cap) is skipped, matching the capped ledger reader below
	try { JSON.parse(raw); return null; }
	catch (_) { return { level: 'warn', message: 'The mount-state file (' + p + ') is not valid JSON.', fix: 'It is moved aside and rebuilt automatically, but a vault that was mounted may need unmounting by hand, and the vault list is repopulated as vaults are opened.' }; }
});

// 5–7. Files that hold secrets must not be group/other-readable (POSIX). The settings file holds
// encrypted credentials; the credential key unwraps them; a TLS private key authenticates a served
// node. These are the paths a leak would matter for.
register('settings_perms', (ctx) => checkPerms(path.join(ctx.dataDir, 'settings.json'), 'The settings file', ctx.isPosix));
register('credkey_perms', (ctx) => checkPerms(path.join(ctx.dataDir, 'credkey'), 'The credential key', ctx.isPosix));
register('cert_key_perms', async (ctx) => {
	if (!ctx.isPosix) return null;
	const dir = path.join(ctx.dataDir, 'certs');
	let names; try { names = await fsp.readdir(dir); } catch (_) { return null; }
	const out = [];
	for (const n of names) if (n.endsWith('.key')) { const f = await checkPerms(path.join(dir, n), 'A TLS private key', ctx.isPosix); if (f) out.push(f); }
	return out;
});

// The run directory holds ephemeral engine configs and the service pidfile that the CLI trusts to route a mount
// (and its password) to a running owner. It is created 0700; warn if it became group/other-writable, because
// another local user could then plant runtime state — a fake owner endpoint included. Best-effort, POSIX only.
register('run_dir_perms', async (ctx) => {
	if (!ctx.isPosix) return null;
	const dir = Common.runDir();
	let st; try { st = await fsp.stat(dir); } catch (_) { return null; } // absent is fine — created on first use
	if (st.mode & 0o022) return { level: 'warn', message: 'The runtime directory (' + dir + ') is writable by other users on this computer.', fix: 'Restrict it with:  chmod 700 "' + dir + '"' };
	return null;
});

// The data directory now lives in the user's per-user application-data area, which on Linux is commonly
// world-readable by default. It holds the credential key, settings (with encrypted logins), the integrity
// ledgers, and the vault locks, so it must be owner-only. Startup hardens it to 0700; this warns if something
// loosened it (a manual chmod, a restrictive umask that predates the harden, a restored backup).
register('data_dir_perms', async (ctx) => {
	if (!ctx.isPosix) return null;
	let st; try { st = await fsp.stat(ctx.dataDir); } catch (_) { return null; } // absent is fine — created on first use
	if (st.mode & 0o077) return { level: 'warn', message: 'The data folder (' + ctx.dataDir + ') — which holds your credential key, settings, ledgers, and vault locks — is accessible to other users on this computer.', fix: 'Restrict it with:  chmod 700 "' + ctx.dataDir + '"' };
	return null;
});

// Data from an earlier version, when the data directory lived INSIDE the program folder, is silently ignored now
// that it lives in the per-user location — so a user upgrading in place could think their vaults, saved logins, or
// settings vanished. Notice a leftover in-tree data folder that differs from the active one, and guide the user to
// move it (never auto-move it — a mounted or in-use vault must not be relocated from under the user). Cheap: one
// bounded stat of a local path.
register('orphaned_legacy_data', async (ctx) => {
	const legacy = path.join(Common.root(), 'data');
	if (Common.samePath(legacy, ctx.dataDir)) return null; // the active dir already IS the in-tree one (a --data-dir override, or the test layout) — nothing orphaned
	if (!(await existsBounded(legacy))) return null;
	// Only flag it when it actually holds a previous install's data, not an empty or unrelated folder.
	const looksLikeData = (await Promise.all(['vaults', 'credkey', 'settings.json'].map(n => existsBounded(path.join(legacy, n))))).some(Boolean);
	if (!looksLikeData) return null;
	return { level: 'warn', message: 'Data from an earlier version was found inside the program folder (' + legacy + ') — vaults, saved logins, or settings this version no longer reads, because data now lives in ' + ctx.dataDir + '.', fix: 'Move that folder\'s contents into ' + ctx.dataDir + ' (or start with --data-dir "' + legacy + '" to keep using it), then remove the old copy once your vaults and logins are back. Do not delete it until then.' };
});

// A bounded existence probe. A registered vault can live in place on a wedged external/network mount, so a
// plain synchronous fs.existsSync would block the WHOLE event loop with no timeout — the one place that would
// violate the standing never-freeze invariant. Time-bounded so a hung mount degrades to "not present" instead.
const existsBounded = Common.pathExistsBounded; // single-sourced: bounded stat -> bool, safe on a wedged drive

// 8. Every registered vault should still exist and have a readable manifest — a moved or deleted
// vault leaves a dangling entry that clutters the list and fails confusingly on use.
register('known_vaults', async (ctx) => {
	let known; try { known = await ctx.Vault.listKnownVaults(); } catch (_) { return null; }
	const out = [];
	for (const entry of known) {
		const dir = entry && entry.path ? entry.path : entry;
		if (!dir) continue;
		if (!(await existsBounded(dir))) { out.push({ level: 'warn', message: 'A registered vault no longer exists at ' + dir + '.', fix: 'Remove it from the list, or reconnect the drive it lives on.' }); continue; }
		let m = null;
		try { m = await Common.withTimeout(ctx.Vault.readManifest(dir), 3000); }
		catch (e) {
			// A manifest from a NEWER build is a healthy vault this build simply cannot read yet — never tell the
			// user to remove it (that would throw away a good vault). Guide them to update instead. The readManifest
			// error already carries the newerFormat flag, so this costs no extra I/O.
			if (e && e.newerFormat) { out.push({ level: 'warn', message: 'The vault at ' + dir + ' was created by a newer version of the tool than this one, so its manifest cannot be read here.', fix: 'Update to the newer version to open it. Do not remove it from the list — the vault is fine.' }); continue; }
			out.push({ level: 'warn', message: 'The vault at ' + dir + ' is registered but its manifest could not be read.', fix: 'Check the folder is a complete vault, or remove it from the list.' }); continue;
		}
		// The manifest's own security seal must still match its key slots and settings. A mismatch means the
		// manifest was altered or a write was interrupted — surface it at startup, before the user opens the vault.
		// Reuses the manifest just read (no extra I/O) and the exact check the mount and audit paths use.
		try { const seal = ctx.Vault.checkManifestSeal(m); if (seal.sealed && !seal.ok) out.push({ level: 'warn', message: 'The manifest of the vault at ' + dir + ' no longer matches its own security seal — its key slots or settings may have been altered, or a write was interrupted.', fix: 'Open the vault and run a tamper check; if it confirms the manifest was altered, restore the vault from a backup.' }); } catch (_) {}
	}
	return out;
});

// A key rotation writes new key material to staged (.new) files and a journal, then commits atomically; a crash
// mid-commit leaves that staged state for resumeRekey to finish. resumeRekey runs on every mount and once at
// service start, so a journal that STILL exists when this boot check runs is one the automatic resume could not
// resolve — a wedged rotation the user would otherwise never see. Warn-only: opening the vault retries the resume.
register('stuck_rekey', async (ctx) => {
	let known; try { known = await ctx.Vault.listKnownVaults(); } catch (_) { return null; }
	const out = [];
	for (const entry of known) {
		const dir = entry && entry.path ? entry.path : entry;
		if (!dir) continue;
		if (!(await existsBounded(dir))) continue; // a vault on a disconnected/wedged drive is skipped with a BOUNDED stat, so this periodic check never blocks on it (the same guard known_vaults and disk_space use)
		let pending = false;
		try { pending = await ctx.Vault.rekeyPending(path.resolve(dir)); } catch (_) {}
		if (pending) out.push({ level: 'warn', message: 'The vault at ' + dir + ' has an unfinished key rotation (a staged key change from an interrupted operation).', fix: 'Open the vault — it finishes the rotation automatically on the next mount. If the warning persists after opening it, restore the vault from a backup.' });
	}
	return out;
});

// 8b. Surface a rolled-back membership roster or access list at boot. Both are protected by a monotonic epoch
// anchored locally; a rollback (a restored old manifest, or a sync-conflict copy that reverts a change) can make a
// removed member or a revoked read link reappear. This is otherwise noticed only lazily, when the user happens to
// open the team, access, or keys panel. `listMembers`/`listShares`/`listKeys` already compute `rolledBack` (the
// on-disk epoch is OLDER than the anchored one) and need no password; a benign add/remove advances the epoch and
// re-anchors it, so this never fires on ordinary use. Warn-only, bounded per vault, skips a wedged/disconnected drive.
register('roster_rollback', async (ctx) => {
	let known; try { known = await ctx.Vault.listKnownVaults(); } catch (_) { return null; }
	const out = [];
	for (const entry of known) {
		const dir = entry && entry.path ? entry.path : entry;
		if (!dir) continue;
		if (!(await existsBounded(dir))) continue; // bounded stat — never block on a disconnected/wedged drive
		const abs = path.resolve(dir);
		try {
			const mem = await Common.withTimeout(ctx.Vault.listMembers(abs), 3000);
			if (mem && mem.team && mem.rolledBack) out.push({ level: 'warn', message: 'The membership roster of the vault at ' + dir + ' is older than a change this computer already recorded — it may have been rolled back, so a removed member could reappear.', fix: 'Open the vault and re-check its members; if you did not expect this, restore from a trusted backup before relying on its access list.' });
		} catch (_) {}
		try {
			const sh = await Common.withTimeout(ctx.Vault.listShares(abs), 3000);
			if (sh && sh.rolledBack) out.push({ level: 'warn', message: 'The access list (read links) of the vault at ' + dir + ' is older than a change this computer already recorded — it may have been rolled back, so a revoked link could reappear.', fix: 'Open the vault and re-check who has access; rotate the vault\'s keys if a revoked link may have returned.' });
		} catch (_) {}
		try {
			const ks = await Common.withTimeout(ctx.Vault.listKeys(abs), 3000);
			if (ks && ks.rolledBack) out.push({ level: 'warn', message: 'The key slots of the vault at ' + dir + ' are older than a change this computer already recorded — it may have been rolled back, so a removed password, keyfile, or read-only key could reappear.', fix: 'Open the vault and re-check its keys; if a removed key may have returned, rotate the vault to truly revoke it.' });
			if (ks && ks.recoveryReminder) out.push({ level: 'warn', message: 'The vault at ' + dir + ' has no recovery key since it was last rotated — if you forget its password, there is no way back in.', fix: 'Open the vault\'s keys and add a recovery key (or set up owner recovery for a team vault), then store it somewhere safe.' });
		} catch (_) {}
	}
	return out;
});

// 9. Refuse to be surprised by a file from a newer build: warn if settings or state carry a higher
// schema version than this build understands (their unknown fields are preserved, never dropped).
register('schema_versions', async (ctx) => {
	const out = [];
	// The integrity ledger and the tamper log are SECURITY-bearing: they hold the anti-rollback high-water anchors
	// and the signed tamper checkpoint. A newer schema on those may re-encode fields this build reads under old
	// assumptions, so rollback/tamper detection cannot be fully trusted until the app is updated — a stronger warning
	// than the plain "you might lose a new setting" for the convenience files (settings, mount state).
	for (const [file, label, security] of [[path.join(ctx.dataDir, 'settings.json'), 'settings', false], [Common.statePath(), 'mount state', false], [path.join(ctx.dataDir, 'integrity.json'), 'tamper/rollback ledger', true], [path.join(ctx.dataDir, 'tamper-log.json'), 'tamper log', true]]) {
		// Read with a cap so a pathologically large ledger/log can't stall this periodic self-check with a huge
		// main-thread JSON.parse; over the cap it is skipped (warn-only degrades gracefully rather than freezing).
		let obj; try { obj = JSON.parse(await Common.readFileCapped(file, MAX_META_BYTES, 'utf8')); } catch (_) { continue; }
		if (obj && Number(obj.schemaVersion) > Common.SCHEMA_VERSION) {
			out.push(security
				? { level: 'warn', message: 'The ' + label + ' was written by a newer version of ' + Brand.name + ' (schema v' + obj.schemaVersion + '; this build understands v' + Common.SCHEMA_VERSION + '). It holds the rollback and tamper-detection records, so this older build may not evaluate them fully.', fix: 'Update ' + Brand.name + ' to the newer version so rollback and tamper protection are fully checked.' }
				: { level: 'warn', message: 'The ' + label + ' file was written by a newer version of ' + Brand.name + ' (schema v' + obj.schemaVersion + '; this build understands v' + Common.SCHEMA_VERSION + ').', fix: 'Update to the newer version to avoid losing settings it added.' });
		}
	}
	return out;
});


// 11. A nearly-full disk under the vault store is a real hazard: copying a large file into a mounted
// vault can fail or stall while the disk is almost full (on macOS the Finder surfaces this as a
// "-36" I/O error), because the write buffer cannot drain to the near-full backing store fast enough.
// Warn on the data directory's disk (where vaults live by default); best-effort and never blocking.
const LOW_DISK_PCT = 10, LOW_DISK_GIB = 5;
register('disk_space', async (ctx) => {
	// Vaults run IN PLACE wherever they live (external/removable drives included), not only under the data
	// directory — so check the data disk AND every registered vault's own volume. Dedupe by volume size so
	// several vaults on one disk warn once. Best-effort, warn-only.
	const out = [], seen = new Set();
	const macHint = process.platform === 'darwin'
		? ' On macOS this can appear as a Finder "-36" error; copying a very large file in from Terminal with "ditto <source> <vault>" is steadier than the Finder while space is tight.'
		: '';
	const consider = async (p, where) => {
		const info = await Common.diskFree(p);
		if (!info) return;
		const key = String(info.totalBytes); // volume size is a stable per-filesystem signature
		if (seen.has(key)) return;
		seen.add(key);
		const freeGiB = info.freeBytes / 1073741824;
		if (info.pctFree >= LOW_DISK_PCT && freeGiB >= LOW_DISK_GIB) return;
		out.push({
			level: 'warn',
			message: 'The disk ' + where + ' is nearly full (' + freeGiB.toFixed(1) + ' GiB, ' + info.pctFree.toFixed(0) + '% free). Copying a large file into a mounted vault can fail or stall while the disk is this full.' + macHint,
			fix: 'Free up space on this disk — aim for at least a few GiB and about 10% free.'
		});
	};
	await consider(ctx.dataDir, 'holding your vaults');
	let known = []; try { known = await ctx.Vault.listKnownVaults(); } catch (_) {}
	for (const entry of known) { const dir = entry && entry.path ? entry.path : entry; if (dir && (await existsBounded(dir))) await consider(dir, 'holding the vault at ' + dir); }
	return out;
});

// 12. Corrupt-copy accumulation. When a settings/state/ledger file is found unreadable it is moved aside as a
// ".corrupt-<timestamp>" copy (never deleted), so nothing is lost silently — but those copies can hold data
// and should not pile up unnoticed. Surface them so the user can review and clear them. Best-effort, warn-only.
register('corrupt_copies', async (ctx) => {
	let names; try { names = await fsp.readdir(ctx.dataDir); } catch (_) { return null; }
	const copies = names.filter(n => /\.corrupt-\d+$/.test(n));
	if (!copies.length) return null;
	return {
		level: 'warn',
		message: copies.length + ' set-aside "corrupt" copy file(s) are in the data folder (' + copies.slice(0, 4).join(', ') + (copies.length > 4 ? ', …' : '') + '). These are backups of files that were found unreadable and then rebuilt — normal after a bad shutdown, but they should not accumulate.',
		fix: 'Review them if you wish, then delete the ".corrupt-*" files under ' + ctx.dataDir + '.'
	};
});

// Every saved cloud remote's secrets must still decrypt with this machine's credential key — a replaced or
// restored credkey would otherwise surface only as an opaque "could not connect" when a cloud vault is opened.
register('cloud_credentials', async (ctx) => {
	let health; try { health = await ctx.Vault.checkCloudCreds(); } catch (_) { return null; }
	const bad = (health || []).filter(h => !h.ok);
	if (!bad.length) return null;
	return { level: 'warn', message: 'The saved login for ' + bad.length + ' cloud storage remote(s) (' + bad.map(b => b.label).slice(0, 3).join(', ') + ') can no longer be decrypted — this computer\'s credential key changed.', fix: 'Re-enter each cloud remote\'s credentials under Cloud storage.' };
});

// A cloud-backed vault that is currently MOUNTED depends on its remote being reachable — if the network is
// down or the sign-in expired, the drive will start returning errors. Probe only the remotes actually in use.
register('cloud_reachable', async (ctx) => {
	let inUse; try { inUse = await ctx.Vault.mountedCloudRemotes(); } catch (_) { return null; }
	if (!inUse || !inUse.length) return null;
	const seen = new Set(); const findings = [];
	for (const m of inUse.slice(0, 5)) {
		if (seen.has(m.remoteId)) continue; seen.add(m.remoteId);
		let r; try { r = await ctx.Vault.testCloudRemote(m.remoteId, m.remotePath); } catch (e) { r = { ok: false, detail: e && e.message || String(e) }; }
		if (!r.ok) {
			const auth = /401|403|unauthor|expired|token/i.test(String(r.detail || ''));
			findings.push({ level: 'warn', message: 'The cloud storage for the open vault "' + m.name + '" is ' + (auth ? 'refusing the saved sign-in (it may have expired)' : 'not reachable right now') + '.', fix: auth ? 'Re-enter the cloud remote\'s credentials under Cloud storage, then remount the vault.' : 'Check your network connection. The drive rides out brief outages automatically; unmount and remount if it stays unreachable.' });
		}
	}
	return findings.length ? findings : null;
});

// If the service is running but autostart is not installed, crash-restart is off — a hand-run `vdisk ui` has
// no net, so a crash would leave vaults unmanaged until the user starts it again.
register('restart_policy', async () => {
	let st; try { st = await require('./Autostart').status(); } catch (_) { return null; }
	if (!st || !st.supported || st.installed) return null;
	return { level: 'warn', message: 'Automatic restart is not set up, so if the background service crashes it will not come back on its own.', fix: 'Install the login/boot service (the app offers this on first run, or run "vdisk autostart install") so the service restarts itself after a crash.' };
});

// A network-reachable autostart entry (bind is a non-loopback address) must always have a web login password.
// Install-time enforces this, but nothing catches later DRIFT — e.g. the web password is cleared while a network
// autostart entry remains — which would bring the interface up exposed with NO password at the next login. Catch it.
register('exposed_no_password', async () => {
	let st; try { st = await require('./Autostart').status(); } catch (_) { return null; }
	if (!st || !st.installed || !st.bind) return null; // not installed, or loopback-only — nothing to expose
	let enabled = false; try { enabled = !!(await require('./Vault').getUiAuth()).enabled; } catch (_) { return null; } // can't tell -> stay quiet
	if (enabled) return null;
	return { level: 'warn', message: 'This computer is set to start ' + require('./Brand').name + ' at login on a network-reachable address (' + st.bind + '), but no web login password is set — at the next login the interface would come up exposed with no password.', fix: 'Set a web login password now, or make the auto-started interface this-computer-only by reinstalling autostart without a network address.' };
});

// The autostart entry should point at a launcher script that still exists. If the install was moved or removed, the
// service file's launch target can dangle and the service then silently fails to start at the next login. Warn while
// the running service is still up, so it can be fixed before the next restart. Fail-safe: an unparsed/absent target
// is skipped (never a false alarm), so only a definitively missing script trips this.
register('autostart_command_stale', async () => {
	let st; try { st = await require('./Autostart').status(); } catch (_) { return null; }
	if (!st || !st.installed || !st.script) return null;
	if (await existsBounded(st.script)) return null;
	return { level: 'warn', message: 'The start-at-login entry points at a launcher that no longer exists (' + st.script + '), so ' + require('./Brand').name + ' would fail to start automatically at the next login.', fix: 'Reinstall autostart from the current install (run "' + require('./Brand').cli + ' autostart install", or use the "Start at login" toggle) so the entry points at the right location.' };
});

// The system clock should not sit materially BEHIND files this tool has already written — a backward clock
// jump breaks lease timeouts, heartbeat-staleness, and tamper timestamps. A generous threshold avoids skew
// false positives; the point is to catch a clearly-wrong clock (e.g. a dead RTC resetting to an old date).
register('clock_sanity', async (ctx) => {
	let newest = 0;
	for (const f of ['state.json', 'settings.json']) { try { const s = await fsp.stat(path.join(ctx.dataDir, f)); newest = Math.max(newest, s.mtimeMs); } catch (_) {} }
	if (!newest) return null;
	const behindMs = newest - Date.now();
	if (behindMs <= 24 * 60 * 60 * 1000) return null; // within a day (or ahead) — fine
	return { level: 'warn', message: 'This computer\'s clock (' + new Date().toISOString().slice(0, 16) + ') is set earlier than files this tool last wrote (' + new Date(newest).toISOString().slice(0, 16) + ') — the clock may be wrong.', fix: 'Correct the system date and time. A wrong clock can disturb lease timeouts and the timestamps on tamper proofs.' };
});

// The crash-safety guardian (which locks open vaults if this service is killed) could not be started. While it is
// down, a force-quit could leave a vault mounted and readable. The web service records this when a launch fails and
// clears it when the guardian comes back; surface it for a day so the safety net being down is not invisible.
register('guardian_supervision', async (ctx) => {
	const p = path.join(ctx.dataDir, 'settings.json');
	let settings; try { settings = JSON.parse(await Common.readFileCapped(p, MAX_META_BYTES, 'utf8')); } catch (_) { return null; }
	const at = settings && settings.guardianDownAt ? Date.parse(settings.guardianDownAt) : NaN;
	if (isNaN(at) || (Date.now() - at) > 24 * 60 * 60 * 1000) return null; // only while recently down
	return { level: 'warn', message: 'The crash-safety guardian could not be started, so if ' + require('./Brand').name + ' is force-quit while a vault is open, that vault could stay mounted and readable until you lock it.', fix: 'Lock any vaults you are not using, and restart ' + require('./Brand').name + '. This notice clears on its own once the guardian is running again.' };
});

// A mount whose engine died without a clean unmount (a crash) is healed silently at startup — its record is
// released and its leftovers cleared. Surface that it happened, so a crash that occurred while the user was away
// does not go completely unnoticed. Recorded by pruneDeadMounts; cleared on its own after a day.
register('stale_mount_healed', async (ctx) => {
	const p = path.join(ctx.dataDir, 'settings.json');
	let settings; try { settings = JSON.parse(await Common.readFileCapped(p, MAX_META_BYTES, 'utf8')); } catch (_) { return null; }
	const at = settings && settings.staleMountAt ? Date.parse(settings.staleMountAt) : NaN;
	if (isNaN(at) || (Date.now() - at) > 24 * 60 * 60 * 1000) return null; // only a recent heal (last day)
	const n = settings.staleMountCount;
	return { level: 'warn', message: (Number.isFinite(n) && n > 0 ? n + ' vault drive(s) were' : 'A vault drive was') + ' found left over from an unclean shutdown and released at startup — ' + require('./Brand').name + ' likely crashed or was force-quit while a vault was open.', fix: 'Your vaults and data are safe; nothing to do. If this keeps happening, install the login/boot service so the app restarts itself after a crash. This notice clears on its own after a day.' };
});

// A large FORWARD clock jump WHILE the service was running is the other direction the mtime check above cannot see
// (a future time is indistinguishable from time simply passing). The health tick records one when it happens — it
// can tell a real jump from ordinary sleep by comparing wall time against the monotonic clock, which is suspended
// during sleep but not during a jump. Surface a recent one for a day so the user knows time-based safeguards may
// have been affected. It clears itself once the recorded time ages out.
register('clock_forward_jump', async (ctx) => {
	const p = path.join(ctx.dataDir, 'settings.json');
	let settings; try { settings = JSON.parse(await Common.readFileCapped(p, MAX_META_BYTES, 'utf8')); } catch (_) { return null; }
	const at = settings && settings.clockAnomalyAt ? Date.parse(settings.clockAnomalyAt) : NaN;
	if (isNaN(at) || (Date.now() - at) > 24 * 60 * 60 * 1000) return null; // only a jump within the last day
	const min = settings.clockAnomalyJumpMin;
	return { level: 'warn', message: 'The system clock jumped forward' + (Number.isFinite(min) && min > 0 ? ' by about ' + min + ' minute(s)' : '') + ' while ' + require('./Brand').name + ' was running — time-based safeguards (write leases, the dead-man timer, and tamper-proof timestamps) may have been affected.', fix: 'Check that the system date and time are correct. This notice clears on its own after a day.' };
});

// A scheduled backup that has stopped running is a silent data-safety hazard: the user believes an off-site copy
// is being kept current when it is not (the background service stopped, or the destination keeps failing). Warn
// when a schedule that HAS run before has gone more than two of its own intervals without running. A never-run
// schedule is skipped to avoid a false alarm on one just set up.
// The periodic self-maintaining schedules (backup, integrity scrub, shard repair), described ONCE so every check
// that reasons about them agrees on what each kind is, whether it is active, and how to name it. This single source
// is what keeps the overdue check and the last-error check below from drifting apart.
const scheduleIntervalHours = (s) => (s.mode === 'interval' ? s.intervalHours : 24);
const scheduleDay = (ms) => new Date(ms).toISOString().slice(0, 10);
const SCHEDULE_KINDS = [
	{ store: 'backupSchedules', noun: 'backup', active: (s) => !!s.dest, name: (id) => 'the vault at ' + id,
		overdueNote: 'the background service may have stopped, or the backups may be failing',
		fix: 'Make sure the background service is running (install autostart), confirm the destination is reachable and has space, then run it manually.' },
	{ store: 'scrubSchedules', noun: 'integrity check', active: () => true, name: (id) => 'the vault at ' + id,
		overdueNote: 'bit-rot in an idle vault could go unnoticed; the background service may have stopped, or the checks may be failing',
		fix: 'Make sure the background service is running (install autostart), and that the vault stays reachable and unmounted long enough for a check to run.' },
	{ store: 'repairSchedules', noun: 'shard repair', active: (s) => Array.isArray(s.folders) && s.folders.length > 0, name: (id, s) => '"' + (s.label || 'a dispersed vault') + '"',
		overdueNote: 'missing or damaged shards may be accumulating; the background service may have stopped, or the repair may be failing',
		fix: 'Make sure the background service is running (install autostart), and that the shard folders (drives or nodes) are connected and reachable.' },
];
// Walk every ACTIVE schedule across all three kinds, so the two checks below share one definition of "a schedule
// that should be running" and can never disagree about which schedules to judge.
function forEachActiveSchedule(settings, fn) {
	for (const k of SCHEDULE_KINDS) {
		for (const [id, s] of Object.entries((settings && settings[k.store]) || {})) {
			if (!s || s.mode === 'off' || !k.active(s)) continue;
			fn(k, id, s);
		}
	}
}

// A schedule is overdue when clearly more than two of its intervals — plus a generous grace — have passed since it
// last ran, which almost always means the background service stopped or the operation keeps failing. Warn-only.
register('schedule_health', async (ctx) => {
	let settings; try { settings = await ctx.Vault.getSettings(); } catch (_) { return null; }
	const now = Date.now(); const out = [];
	forEachActiveSchedule(settings, (k, id, s) => {
		const intervalMs = Math.max(1, Number(scheduleIntervalHours(s)) || 24) * 3600 * 1000;
		const last = s.lastRunAt ? new Date(s.lastRunAt).getTime() : 0;
		if (last && (now - last) > intervalMs * 2 + 6 * 3600 * 1000) out.push({ level: 'warn', message: 'The scheduled ' + k.noun + ' for ' + k.name(id, s) + ' last ran ' + scheduleDay(last) + ' and is overdue — ' + k.overdueNote + '.', fix: k.fix });
	});
	return out.length ? out : null;
});

// The overdue check only fires after two-plus intervals of silence, so a schedule that runs on time but FAILS every
// time would stay invisible for days. This surfaces the last recorded failure immediately, using data the tick
// already persists (lastResult / lastErrorAt), so a failing backup is caught on the next boot or sweep, not days later.
register('schedule_last_error', async (ctx) => {
	let settings; try { settings = await ctx.Vault.getSettings(); } catch (_) { return null; }
	const out = [];
	forEachActiveSchedule(settings, (k, id, s) => {
		if (typeof s.lastResult === 'string' && /^error/i.test(s.lastResult)) {
			out.push({ level: 'warn', message: 'The last scheduled ' + k.noun + ' for ' + k.name(id, s) + ' failed' + (s.lastErrorAt ? ' on ' + scheduleDay(new Date(s.lastErrorAt).getTime()) : '') + ' (' + s.lastResult + ').', fix: k.fix });
		}
	});
	return out.length ? out : null;
});

// Emergency (dead-man) access is armed per vault and holds a sealed read capability for a trusted contact. Two ways
// the arming can drift out from under the user, both warn-only (it never auto-disarms, because the arming is
// security-sensitive — it surfaces the drift and asks the user to re-check or disarm):
//   1. The vault it points at is no longer present — securely removed, or deleted outside the app. A later release
//      would hand the contact a grant for a vault that may be gone. A vault is "present" when its folder still holds
//      a readable manifest, so a folder whose keys were destroyed counts as gone.
//   2. The beneficiary the grant is sealed to is no longer enrolled. Removing a contact drops its own grants, but a
//      legacy grant, a hand-edited settings file, or a replaced contact map can leave a grant whose contactId points
//      at no enrolled contact. If that grant releases, no one can open it — silent, so it is surfaced here.
register('orphaned_emergency_arming', async (ctx) => {
	let settings; try { settings = await ctx.Vault.getSettings(); } catch (_) { return null; }
	const em = settings && settings.emergency;
	const armed = em && em.armed;
	if (!armed || typeof armed !== 'object') return null;
	// Enrolled beneficiary ids, via the SAME normalization the emergency code uses (handles the legacy single-contact
	// shape too), so this check can never disagree with what a real release would find enrolled.
	let enrolled; try { enrolled = new Set(Object.keys(ctx.Vault.emContacts(em) || {})); } catch (_) { enrolled = null; }
	const out = [];
	for (const rec of Object.values(armed)) {
		if (!rec || !rec.path) continue;
		let present = false;
		try { await ctx.Vault.readManifest(rec.path); present = true; } catch (_) { present = false; }
		if (!present) { out.push({ level: 'warn', message: 'Emergency access is still armed for “' + (rec.name || rec.path) + '”, a vault that is no longer present. If its dead-man switch fires, your trusted contact would receive access to a vault that may have been deleted.', fix: 'Open Emergency access to re-check, then disarm this vault if you removed it on purpose.' }); continue; }
		if (enrolled && enrolled.size) {
			let cid; try { cid = ctx.Vault.grantContactId(rec); } catch (_) { cid = null; }
			if (cid && !enrolled.has(cid)) out.push({ level: 'warn', message: 'Emergency access for “' + (rec.name || rec.path) + '” is armed to a trusted contact who is no longer enrolled. If its dead-man switch fires, no one would be able to open the released vault.', fix: 'Open Emergency access, then re-arm this vault to a current contact or disarm it.' });
		}
	}
	return out.length ? out : null;
});

// The tamper/rollback ledger and the tamper log are the records the integrity guarantees rest on. Settings and
// mount-state already get a proactive boot JSON-validity check; give these the same, so a corrupt one is caught and
// explained at startup rather than surfacing confusingly during a later tamper check. Absent is normal (fresh vault).
register('ledger_readable', async (ctx) => {
	const out = [];
	for (const [file, label] of [[path.join(ctx.dataDir, 'integrity.json'), 'tamper/rollback ledger'], [path.join(ctx.dataDir, 'tamper-log.json'), 'tamper log']]) {
		let raw; try { raw = await Common.readFileCapped(file, MAX_META_BYTES, 'utf8'); } catch (_) { continue; } // absent (or, rarely, over the size cap) is skipped — a corrupt normal-size file is still caught below
		try { JSON.parse(raw); }
		catch (_) { out.push({ level: 'warn', message: 'The ' + label + ' (' + file + ') is not valid JSON.', fix: 'It is moved aside and rebuilt automatically; recent rollback-protection history for open vaults may reset, so run a tamper check after reopening them.' }); }
	}
	return out.length ? out : null;
});

// A vault keeps decrypted data only in RAM, but on Linux the kernel can page RAM out to swap under memory
// pressure — and if that swap is not encrypted, decrypted content can persist on disk. Warn when active swap does
// not look encrypted. Advisory: a dm-crypt / mapper / zram device is treated as safe, a plain partition or file
// as risky (this cannot verify encryption with certainty, so it errs toward telling the user).
register('linux_swap_encrypted', async () => {
	if (process.platform !== 'linux') return null;
	let raw; try { raw = await fsp.readFile('/proc/swaps', 'utf8'); } catch (_) { return null; }
	// Flag only a raw swap PARTITION on a block device that does not look encrypted. A swap FILE (type "file")
	// lives on a filesystem that may itself be encrypted — a swapfile on a LUKS root is common and safe — so it
	// is not flagged, to avoid warning on a correctly-encrypted setup. A dm-crypt / mapper / zram device is safe.
	const risky = raw.split('\n').filter(l => l && !/^Filename/i.test(l)).map(l => l.split(/\s+/)).filter(c => c[1] === 'partition' && /^\/dev\//.test(c[0] || '') && !/dm-|mapper|zram|crypt/i.test(c[0])).map(c => c[0]);
	if (!risky.length) return null; // no swap, only a swapfile (fs-dependent), or all of it looks encrypted / RAM-backed
	return { level: 'warn', message: 'This computer has active swap that does not look encrypted (' + risky.slice(0, 2).join(', ') + '). A vault keeps decrypted data only in RAM, but under memory pressure the kernel can page RAM — including that data — out to unencrypted swap, where it could persist on disk.', fix: 'Use encrypted swap (a random-key dm-crypt swap) or turn swap off, so decrypted data can never reach the disk. Whole-disk encryption (LUKS) also covers this.' };
});

module.exports = { register, list, run, last };
