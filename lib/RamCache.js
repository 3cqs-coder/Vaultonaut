'use strict';
// lib/RamCache.js — a RAM-backed directory for the mount's write cache, so any decrypted data the
// engine buffers to support in-place writes lives ONLY in memory and never touches the persistent
// disk.
//
// Why this exists: a pure streaming mount keeps nothing on disk but cannot rewrite an existing file
// in place — which is what a database needs, and what the small sidecar files an OS writes when it
// opens media need. A working cache fixes that, but the engine's cache is plaintext, so we point it
// at RAM instead of the SSD. In the default "writes" cache mode only files opened FOR WRITING are
// cached (reads, including media playback, still stream and are never cached), so the footprint is
// small.
//
// One provider per platform. Every path is best-effort: provision() returns null when a RAM-backed
// directory cannot be created, so the caller falls back to streaming (which also writes nothing to
// disk — the guarantee holds either way). Nothing here throws to the caller.
//
//   provision(id, opts) -> { dir, device, kind } | null
//   release(handle)     -> Promise<void>
//   sweep(activeDirs)   -> Promise<void>   // free any of our RAM caches not currently in use
//
// Swap note: on macOS the OS encrypts swap by default, so RAM paged out stays ciphertext; on Linux
// tmpfs can page to (usually unencrypted) swap — documented; on Windows the physical-memory ImDisk
// allocation is locked in RAM and never paged.

const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const path = require('path');
const Common = require('./Common');
const Rclone = require('./Rclone');

const PREFIX = 'vdisk-ramcache-'; // volume / directory name prefix so we recognize and clean our own

// Windows only: a Windows RAM disk is an ImDisk unit at a drive letter, not a PREFIX-named folder the sweep can
// list like the macOS/Linux leftovers. So when one is allocated we drop a tiny marker file recording its letter,
// BEFORE the caller has a chance to record the handle in shared state. If the process then crashes before that
// handle is recorded, the marker still lets the next sweep free the orphaned disk with the SAME `imdisk -D`
// release used on a clean unmount — reclaiming the locked physical memory instead of leaking it until a reboot.
// Pure filesystem bookkeeping (no extra command); the marker is removed on a clean release.
function winMarkerDir() { return path.join(Common.dataDir(), 'ramdisk-pending'); }
function winMarkerPath(device) { return path.join(winMarkerDir(), String(device).replace(/[^A-Za-z]/g, '') + '.json'); }
async function writeWinMarker(handle) {
	try { await fsp.mkdir(winMarkerDir(), { recursive: true }); await Common.writeJsonAtomic(winMarkerPath(handle.device), { v: 1, device: handle.device, dir: handle.dir, at: Date.now() }); } catch (_) {}
}
async function removeWinMarker(device) { try { await fsp.rm(winMarkerPath(device), { force: true }); } catch (_) {} }

// The "writes" cache holds only files opened for writing (small: sidecars, an edited document), so a
// modest bound is ample; the engine evicts under pressure. Clamped to a sane range.
function sizeMB(opts) {
	const want = opts && Number(opts.cacheSizeMB) > 0 ? Number(opts.cacheSizeMB) : 2048;
	return Math.max(256, Math.min(Math.round(want), 8192));
}

// ── macOS: an hdiutil RAM disk (no admin, no install; macOS encrypts swap by default) ──────────
async function provisionDarwin(id, opts) {
	const mb = sizeMB(opts);
	// Mount the RAM disk INSIDE an owner-only directory rather than at /Volumes. macOS mounts a RAM
	// disk with ownership ignored (noowners), which makes every local user an "owner" and defeats
	// mode bits on the volume — so instead we gate access at the parent: the mount point lives under
	// runDir, hardened to 0700, which another local user cannot traverse. Being a separate volume,
	// it is also outside what per-volume backups (Time Machine) capture.
	const base = Common.runDir();
	await Common.hardenDir(base);
	const mp = path.join(base, PREFIX + id);
	await fsp.mkdir(mp, { recursive: true, mode: 0o700 });
	const attach = await Rclone.exec('hdiutil', ['attach', '-nobrowse', '-nomount', 'ram://' + (mb * 2048)], { timeoutMs: 15000 });
	if (attach.status !== 0) { try { await fsp.rmdir(mp); } catch (_) {} throw new Error('hdiutil attach failed: ' + (attach.stderr || attach.status)); }
	const device = String(attach.stdout || '').trim().split(/\s+/)[0];
	if (!/^\/dev\/disk\d+$/.test(device)) { try { await fsp.rmdir(mp); } catch (_) {} throw new Error('hdiutil returned no device'); }
	// From here the device is attached, so ANY failure (non-zero status OR a spawn rejection) must
	// detach it — otherwise a leaked /dev/diskN holds RAM until reboot.
	try {
		const fmt = await Rclone.exec('newfs_hfs', ['-v', PREFIX + id, device], { timeoutMs: 20000 });
		if (fmt.status !== 0) throw new Error('format failed: ' + (fmt.stderr || fmt.status));
		// `nobrowse` keeps this internal write-cache volume off the Desktop and out of the Finder
		// sidebar — it is an implementation detail, not a disk the user should see or open. (The
		// -nobrowse on the attach above only covers the raw device; the mount is where it takes
		// effect.) diskutil-mounting keeps the volume tracked by hdiutil so the detach on release and
		// the crash-sweep still clean it up.
		const mnt = await Rclone.exec('diskutil', ['mount', 'nobrowse', '-mountPoint', mp, device], { timeoutMs: 20000 });
		if (mnt.status !== 0) throw new Error('mount failed: ' + (mnt.stderr || mnt.status));
		return { dir: mp, device, kind: 'hdiutil', sizeMB: mb };
	} catch (e) {
		try { await Rclone.exec('hdiutil', ['detach', device, '-force'], { timeoutMs: 10000 }); } catch (_) {}
		try { await fsp.rmdir(mp); } catch (_) {}
		throw e;
	}
}

// ── Linux: a private mode-0700 subdir of /dev/shm (tmpfs, RAM-backed, needs no privilege) ──────
async function provisionLinux(id, opts) {
	// Only /dev/shm is guaranteed RAM-backed. Do NOT fall back to os.tmpdir(): on many systems /tmp
	// is disk-backed, which would silently write the decrypted cache to persistent storage while we
	// report it as "in RAM". If there is no /dev/shm, return null so the caller streams instead.
	if (!fs.existsSync('/dev/shm')) return null;
	// tmpfs is not a fixed-size device like the macOS/Windows RAM disks: /dev/shm reports whatever the
	// system caps it at, which containers routinely set to 64 MB. The engine's write-back cap is derived
	// from the size we advertise, so advertising more than /dev/shm can actually hold makes an in-place
	// write fail with ENOSPC while we report a healthy cache. Size to the REAL free space: fall back to
	// streaming when there is too little to be useful (streaming writes nothing to disk, so the guarantee
	// holds), and otherwise cap the cache to what will fit with headroom. A statfs failure keeps the prior
	// behavior, since virtually every non-container host has ample /dev/shm.
	let mb = sizeMB(opts);
	const df = await Common.diskFree('/dev/shm'); // shared bounded statfs + byte math (single-sourced); null if unavailable, in which case the prior size stands
	if (df && df.freeBytes != null) {
		const freeMB = Math.floor(df.freeBytes / (1024 * 1024));
		if (freeMB < 256) return null; // too small for even the minimum cache — stream instead
		mb = Math.min(mb, Math.floor(freeMB * 0.8)); // leave headroom; sizeMB()'s floor still applies below
		mb = Math.max(256, Math.min(mb, 8192));
	}
	const dir = path.join('/dev/shm', PREFIX + id);
	await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
	try { await fsp.chmod(dir, 0o700); } catch (_) {}
	return { dir, device: null, kind: 'shm', sizeMB: mb };
}

// ── Windows: an ImDisk RAM disk in PHYSICAL memory (locked in RAM, never paged) if present ─────
async function provisionWin(id, opts) {
	// Requires the ImDisk driver + imdisk.exe. The "awe" option allocates physical memory that is
	// never written to the pagefile. Absent the driver, imdisk errors and the caller falls back to
	// streaming. -a add, -s size, -m drive letter, -o awe physical memory, -p format switches.
	const mb = sizeMB(opts);
	const letter = await freeDriveLetterWin();
	if (!letter) throw new Error('no free drive letter for the RAM cache');
	const handle = { dir: letter + '\\', device: letter, kind: 'imdisk', sizeMB: mb };
	// Record the marker BEFORE allocating, so even a crash during `imdisk -a` leaves a trail to free the disk. A
	// marker for an allocation that then failed is harmless: a later sweep just runs `imdisk -D` on a unit that
	// isn't there (already wrapped so it can't throw), and removes the marker.
	await writeWinMarker(handle);
	const r = await Rclone.exec('imdisk', ['-a', '-s', mb + 'M', '-m', letter, '-o', 'awe', '-p', '/fs:ntfs /q /y'], { timeoutMs: 30000 });
	if (r.status !== 0) { await removeWinMarker(letter); throw new Error('imdisk failed (is the RAM-disk driver installed?): ' + (r.stderr || r.status)); }
	return handle;
}
async function freeDriveLetterWin() {
	for (const L of 'RSTUVWXYZQPONMLKJIHGFED') { // start high to avoid common letters
		const root = L + ':\\';
		// Probe with a bounded async access, never a synchronous existsSync: a drive letter mapped to a
		// disconnected network share blocks for the full SMB/redirector timeout (many seconds), which a
		// synchronous call would spend stalling the entire single-threaded service mid-mount. Only a clean
		// ENOENT means the letter is genuinely free; access succeeding means it is in use, and a timeout or
		// any other error means occupied-or-uncertain — in both of those cases skip on to the next letter.
		try {
			await Common.withTimeout(fsp.access(root), 1500);
			// access resolved -> the path exists -> the letter is taken; keep scanning.
		} catch (e) {
			if (e && e.code === 'ENOENT') return L + ':'; // nothing at this letter -> free
			// timeout / EPERM / disconnected mapped drive -> don't claim it; try the next.
		}
	}
	return null;
}

// Create a RAM-backed cache directory. Returns a handle, or null if none could be made.
async function provision(id, opts) {
	try {
		if (process.platform === 'darwin') return await provisionDarwin(id, opts);
		if (process.platform === 'linux') return await provisionLinux(id, opts);
		if (process.platform === 'win32') return await provisionWin(id, opts);
	} catch (e) {
		const msg = e && e.message ? e.message : String(e);
		// On Windows the RAM disk needs a third-party driver (ImDisk). When it is simply not installed, say so
		// plainly and point the way forward instead of surfacing a raw "spawn imdisk ENOENT".
		if (process.platform === 'win32' && /imdisk/i.test(msg) && /ENOENT/i.test(msg)) {
			Common.warn('No RAM disk on this PC (the ImDisk driver is not installed), so this vault mounted in streaming mode: files read and write normally, but in-place edits (databases, media) are not available. To enable them, install a RAM disk (see the Windows notes in the README), then remount.');
		} else {
			Common.warn('RAM cache unavailable (' + msg + '); falling back to streaming for this mount.');
		}
	}
	return null;
}

// Free a RAM cache created by provision(). Best-effort; never throws.
async function release(handle) {
	if (!handle) return;
	try {
		if (handle.kind === 'hdiutil' && handle.device) {
			await Rclone.exec('hdiutil', ['detach', handle.device, '-force'], { timeoutMs: 10000 }); // unmounts + frees the RAM device
			if (handle.dir) { try { await fsp.rmdir(handle.dir); } catch (_) {} } // remove the now-empty owner-only mount point
		} else if (handle.kind === 'shm' && handle.dir) await fsp.rm(handle.dir, { recursive: true, force: true });
		else if (handle.kind === 'imdisk' && handle.device) { await Rclone.exec('imdisk', ['-D', '-m', handle.device], { timeoutMs: 15000 }); await removeWinMarker(handle.device); }
	} catch (_) {}
}

// Remove any of our RAM caches that are NOT in the given set of in-use directories — cleaning up
// after a crash that could not run release(). RAM disks never survive a reboot, so this only has to
// catch same-session leaks. Best-effort; never throws.
// A very fresh cache is skipped: a mount in progress in ANOTHER OS process (e.g. a CLI `repair` running
// while the service mounts) has created its cache but not yet recorded it in the shared state, and this
// process can't see that other process's in-memory provisioning shield. The age gate protects that window
// across processes; a genuinely leaked cache is caught on a later sweep (and never survives a reboot).
const SWEEP_GRACE_MS = 60000;
async function tooFresh(dir) { try { return (Date.now() - (await fsp.stat(dir)).mtimeMs) < SWEEP_GRACE_MS; } catch (_) { return false; } }
async function sweep(activeDirs) {
	const active = new Set((activeDirs || []).filter(Boolean).map(d => path.resolve(d)));
	try {
		if (process.platform === 'darwin') {
			const base = Common.runDir();
			let names = [];
			try { names = (await fsp.readdir(base)).filter(n => n.startsWith(PREFIX)); } catch (_) {}
			for (const n of names) {
				const dir = path.join(base, n);
				if (active.has(path.resolve(dir)) || await tooFresh(dir)) continue;
				try { await Rclone.exec('hdiutil', ['detach', dir, '-force'], { timeoutMs: 10000 }); } catch (_) {} // unmounts + frees the RAM device (no-op on a bare leftover dir)
				try { await fsp.rmdir(dir); } catch (_) {}
			}
		} else if (process.platform === 'linux') {
			for (const base of ['/dev/shm', os.tmpdir()]) {
				let names = [];
				try { names = (await fsp.readdir(base)).filter(n => n.startsWith(PREFIX)); } catch (_) {}
				for (const n of names) {
					const dir = path.join(base, n);
					if (active.has(path.resolve(dir)) || await tooFresh(dir)) continue;
					try { await fsp.rm(dir, { recursive: true, force: true }); } catch (_) {}
				}
			}
		} else if (process.platform === 'win32') {
			// Free any ImDisk RAM disk whose marker is left over from a crash (its handle never reached shared
			// state) and that is not currently in use. Reuses the same `imdisk -D` release; the marker records the
			// drive letter, so no unit enumeration (an extra command) is needed.
			let markers = [];
			try { markers = (await fsp.readdir(winMarkerDir())).filter(n => n.endsWith('.json')); } catch (_) {}
			for (const n of markers) {
				let mk = null; try { mk = JSON.parse(await fsp.readFile(path.join(winMarkerDir(), n), 'utf8')); } catch (_) {}
				if (!mk || !mk.device || !mk.dir) { try { await fsp.rm(path.join(winMarkerDir(), n), { force: true }); } catch (_) {} continue; }
				// Skip a disk still in use, or one just provisioned (the marker's own timestamp is the provision time,
				// so a mount in progress in another process — which has a marker but no recorded handle yet — is not
				// swept out from under it). The grace window is the same one the other platforms use.
				if (active.has(path.resolve(mk.dir)) || (Date.now() - (mk.at || 0)) < SWEEP_GRACE_MS) continue;
				try { await Rclone.exec('imdisk', ['-D', '-m', mk.device], { timeoutMs: 15000 }); } catch (_) {}
				await removeWinMarker(mk.device);
			}
		}
	} catch (_) {}
}

module.exports = { provision, release, sweep };
