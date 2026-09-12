'use strict';
// lib/test/enginebundledonly.js — a source-level drift guard for a hard product invariant: the app ONLY ever runs its
// bundled, checksum-verified rclone, NEVER a system rclone on PATH. A system engine could be any version with
// different crypt behavior or flags and could corrupt or misread a vault, so the resolver must derive the binary from
// the per-user bin dir and must never fall back to a PATH lookup. This pins that so a refactor can't quietly add a
// which/where/PATH fallback or spawn a bare "rclone".
//
// Run:  node lib/test/enginebundledonly.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return ''; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

const RS = read('lib/RcloneSetup.js');

// 1. The binary path is built from the per-user bin dir, not discovered on PATH.
const rp = (RS.split('\n').find(l => l.includes('function rclonePath(')) || '');
ok('rclonePath derives from Common.binDir() (the bundled location)', /Common\.binDir\(\)/.test(rp) && /exeName\('rclone'\)/.test(rp));

// 2. resolve() (the sync getter reached on hot/teardown paths) returns that bundled path and never does a PATH lookup.
const resolveBody = fnBody(RS, 'function resolve(');
ok('resolve() returns the bundled rclonePath()', /rclonePath\(\)/.test(resolveBody));
ok('resolve() never spawns or shells out (pure path getter)', !/spawn|exec|which|'where'/.test(resolveBody));

// 3. Nowhere in the engine setup is the binary located via PATH: no which/where lookup, no process.env.PATH probe.
const codeOnly = RS.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, ''); // strip comments (they discuss "NEVER a system rclone on PATH")
ok('RcloneSetup does not run a `which` lookup', !/\bwhich\b/.test(codeOnly));
ok('RcloneSetup does not run a `where` lookup', !/'where'|"where"/.test(codeOnly));
ok('RcloneSetup does not probe process.env.PATH to find the engine', !/process\.env\.PATH/.test(codeOnly));

// 4. The engine is always spawned by an explicit bin PATH argument — never as a bare "rclone" command name that the
//    OS would resolve through PATH.
const RC = read('lib/Rclone.js').replace(/\/\/.*$/gm, '');
ok('Rclone never spawns a bare "rclone" command (PATH resolution)', !/spawn(Sync)?\(\s*['"]rclone['"]/.test(RC) && !/spawnP\(\s*['"]rclone['"]/.test(RC));

// 5. The `verify` integrity command must hash-check the engine like every other standalone operation: it runs through
//    ensureEngine() (which verifies the pinned checksum and fails closed), never the bare resolve() path getter. It is
//    the command a user reaches for when they suspect tampering, so running an unverified or swapped binary there would
//    let the very check meant to catch a swap be performed by the swapped engine.
const V = read('lib/Vault.js');
const verifyBody = fnBody(V, 'async function verify(vaultDir');
ok('verify() obtains the engine via ensureEngine() (checksum-verified), not the bare resolve() getter', /ensureEngine\(\)/.test(verifyBody) && !/RcloneSetup\.resolve\(\)/.test(verifyBody));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-BUNDLED-ONLY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
