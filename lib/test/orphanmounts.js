'use strict';
// lib/test/orphanmounts.js — the startup reaper for FULLY-UNTRACKED orphan mounts (Vault.unmountUntrackedOrphans).
// A prior instance can leave a LIVE mount with no state row (an unmount that dropped the row without releasing the
// mount, or a crash mid-teardown); the tracked orphan sweep cannot see it, so the next mount picks a suffixed path and
// the orphans stack (six live NFS mounts of one vault were seen this way). This reaper clears them at startup. It is
// tested through the module's injectable deps, so the SELECTION logic — reap our untracked live mounts, never a tracked
// one, a foreign filesystem, or a non-mount — is verified deterministically with no real mount and without ever
// touching the real mount root. A source guard pins that it is actually wired into startup.
//
// Run:  node lib/test/orphanmounts.js

const path = require('path');
const fs = require('fs');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const CANARY_TOKEN = 'virtual-disk vault check v1\n'; // must match CANARY_TOKEN in lib/Vault.js (guarded below)

async function main() {
	const root = path.join(path.sep, 'fake', 'mount-root');
	const D = (name) => ({ name, isDirectory: () => true });
	const F = (name) => ({ name, isDirectory: () => false });
	const entries = [D('Untracked'), D('MissingCanary'), D('Tracked'), D('Foreign'), D('NotMounted'), F('afile.txt')];
	// Everything but NotMounted (and the plain file) reads as a live mount.
	const live = new Set(['Untracked', 'MissingCanary', 'Tracked', 'Foreign'].map((n) => path.join(root, n)));
	const canary = {
		[path.join(root, 'Untracked')]: CANARY_TOKEN,           // ours → reap
		[path.join(root, 'MissingCanary')]: null,               // live under our root but unreadable → reap (garbage)
		[path.join(root, 'Tracked')]: CANARY_TOKEN,             // ours but tracked → the owner-gated sweep handles it, skip here
		[path.join(root, 'Foreign')]: 'some other filesystem\n',// readable and NOT ours → never touch
	};
	const unmounted = [];
	const deps = {
		root,
		readdir: async () => entries,
		isMounted: async (mp) => live.has(mp),
		readAll: async () => [{ mountpoint: path.join(root, 'Tracked') }], // Tracked has a state row
		readCanary: async (mp) => canary[mp],
		unmount: async (mp) => { unmounted.push(mp); },
	};

	const r = await Vault.unmountUntrackedOrphans({ wipeCache: true }, deps);
	const has = (n) => unmounted.includes(path.join(root, n));

	ok('an untracked live mount carrying our canary is reaped', has('Untracked'));
	ok('an untracked live mount under our root we cannot read is reaped (garbage)', has('MissingCanary'));
	ok('a TRACKED live mount is left for the owner-gated sweep, not reaped here', !has('Tracked'));
	ok('a live mount with a foreign (non-vault) filesystem is never touched', !has('Foreign'));
	ok('a directory that is not a live mount is skipped', !has('NotMounted'));
	ok('a non-directory entry is skipped', !unmounted.some((m) => /afile\.txt$/.test(m)));
	ok('exactly the two safe-to-reap orphans were unmounted', r.count === 2 && unmounted.length === 2);

	// A missing root is a clean no-op (nothing mounted yet), never an error.
	const r2 = await Vault.unmountUntrackedOrphans({}, { root, readdir: async () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); }, readAll: async () => [] });
	ok('a missing mount root is a clean no-op', r2.count === 0);

	// Source guards: the canary token this test pins matches the module, and the reaper is actually wired into startup.
	const vaultSrc = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('the pinned canary token matches lib/Vault.js', vaultSrc.includes("CANARY_TOKEN = '" + CANARY_TOKEN.replace(/\n/g, '\\n') + "'"));
	const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the untracked-orphan reaper runs at service startup', /Vault\.unmountUntrackedOrphans\(\{ wipeCache: true \}\)/.test(serverSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ORPHAN-MOUNT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
