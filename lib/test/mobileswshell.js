'use strict';
// lib/test/mobileswshell.js — the mobile PWA's service worker precaches a fixed SHELL list so the viewer works
// offline. If a file the page loads at startup is MISSING from that list, the first offline load right after a
// version bump (when activate has deleted the old cache and only SHELL is precached) cache-misses and the viewer
// goes blank — this actually happened with the shared safe-text.js escaper. This pins the whole class: every local
// asset index.html loads must be in the SHELL, every SHELL entry must be a real file (a stale entry makes the atomic
// addAll install fail), and the cache-busting shell fingerprint must hash the shared directory the viewer caches.
// Pure static analysis — no engine, no browser, fast, cross-platform.
//
// Run:  node lib/test/mobileswshell.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const mobileDir = path.join(__dirname, '..', 'webserver', 'public', 'mobile');
const read = (p) => fs.readFileSync(path.join(mobileDir, p), 'utf8');

// Local assets the page pulls in at startup (skip absolute URLs and data: URIs).
const html = read('index.html');
const assets = new Set();
for (const m of html.matchAll(/(?:src|href)="([^"]+)"/g)) { const u = m[1]; if (!/^(https?:)?\/\//.test(u) && !/^data:/.test(u)) assets.add(u.replace(/^\.\//, '')); }
ok('index.html references a realistic set of startup assets', assets.size >= 8);

// The SHELL precache array from sw.js.
const sw = read('sw.js');
const shellMatch = sw.match(/var SHELL = \[([^\]]*)\]/);
ok('sw.js defines a SHELL precache array', !!shellMatch);
const shell = new Set((shellMatch ? shellMatch[1] : '').split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean));

// 1. Every startup asset the page loads must be precached (or the offline shell is incomplete).
for (const a of assets) ok('startup asset "' + a + '" is in the service-worker SHELL precache', shell.has(a));

// 2. Every SHELL entry must resolve to a real served asset, so the atomic addAll() at install time cannot fail on a
//    stale/renamed path. Some entries are served routes, not files under the mobile directory: 'shared/*' is served
//    from the common public/shared directory, and './', 'config', and 'manifest.webmanifest' are generated routes.
const sharedDir = path.join(__dirname, '..', 'webserver', 'public', 'shared');
const ROUTE_ENTRIES = new Set(['./', 'config', 'manifest.webmanifest']);
for (const s of shell) {
	if (ROUTE_ENTRIES.has(s)) continue;
	const onDisk = s.startsWith('shared/') ? path.join(sharedDir, s.slice('shared/'.length)) : path.join(mobileDir, s);
	ok('SHELL entry "' + s + '" resolves to a real served asset', fs.existsSync(onDisk));
}

// 3. The cache-busting fingerprint must hash the SHARED directory (not just one file in it), so editing any shared
//    module the viewer caches (safe-text.js, secret-schema.js) changes the served sw.js bytes and busts the cache.
const routes = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'mobileRoutes.js'), 'utf8');
ok('the shell fingerprint hashes the whole shared directory', /walk\(sharedDir\)/.test(routes));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-SW-SHELL CHECKS PASSED'));
process.exit(failures ? 1 : 0);
