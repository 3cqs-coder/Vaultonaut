'use strict';
// lib/test/unmountladder.js — a source-level drift guard over Rclone.unmount, the function that guarantees an
// unmount always completes (a per-OS graceful -> forced/lazy ladder) AND that auto-lock / panic-lock never
// force-detaches a busy vault (the `gracefulOnly` mode). Two hard invariants ride on it: never wedge a mount into a
// reboot (the forced/lazy fallback must stay), and never lose data (auto-lock must never sever active writes with a
// forced unmount). spawnP is not exported, so this is enforced at the source level like the other *drift guards.
//
// Run:  node lib/test/unmountladder.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return ''; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

const U = fnBody(read('lib/Rclone.js'), 'async function unmount(');
ok('Rclone.unmount is present', U.length > 0);

// The three modes select the attempt order correctly: gracefulOnly uses ONLY the graceful list (no forced/lazy
// commands), force tries the forced list first, and the default tries graceful first then forced.
ok('gracefulOnly uses ONLY the graceful ladder', /gracefulOnly\s*\?\s*graceful\s*:/.test(U));
ok('force tries the forced/lazy ladder first', /force\s*\?\s*\[\s*\.\.\.forced\s*,\s*\.\.\.graceful\s*\]/.test(U));
ok('the default tries graceful first, then forced', /\[\s*\.\.\.graceful\s*,\s*\.\.\.forced\s*\]/.test(U));

// The graceful commands must contain NO forced/lazy flags (so gracefulOnly can never sever an active mount), and the
// forced commands MUST contain them (so a wedged mount is always recoverable). Check each push line.
const FORCED_TOKENS = /-uz|-l\b|-f\b|'force'/;
const gracefulLines = U.split('\n').filter(l => l.includes('graceful.push('));
const forcedLines = U.split('\n').filter(l => l.includes('forced.push('));
ok('there is a graceful ladder for macOS and Linux', gracefulLines.length >= 2);
ok('there is a forced ladder for macOS and Linux', forcedLines.length >= 2);
ok('no graceful command carries a forced/lazy flag (-uz/-l/-f/force)', gracefulLines.every(l => !FORCED_TOKENS.test(l)));
ok('every forced ladder actually uses a forced or lazy flag', forcedLines.every(l => FORCED_TOKENS.test(l)));

// The macOS and Linux ladders name the expected per-OS tools.
ok('the macOS ladder uses umount and diskutil', /umount/.test(U) && /diskutil/.test(U));
ok('the Linux ladder uses fusermount3, fusermount, and umount, with a lazy detach', /fusermount3/.test(U) && /fusermount'/.test(U) && /umount/.test(U) && /-l\b/.test(U));

// Every attempt is bounded, so a wedged unmount command can never hang the caller.
ok('every unmount attempt is time-bounded (timeoutMs)', /spawnP\([^)]*timeoutMs:\s*\d+/.test(U) || /timeoutMs:\s*6000/.test(U));

// The auto-lock / panic-lock (gentle) path must ask for a graceful-ONLY unmount and NEVER force — a forced detach
// there would sever an open file's writes (data loss). It leaves a busy vault mounted to retry, rather than forcing.
const V = read('lib/Vault.js');
const gentleIdx = V.indexOf('else if (opts.gentle) {'); // the macOS/Linux gentle branch specifically (not the win32 one above it)
const gentleSlice = gentleIdx >= 0 ? V.slice(gentleIdx, gentleIdx + 1500).replace(/\/\/.*$/gm, '') : '';
ok('the gentle auto-lock path calls unmount with gracefulOnly: true', /Rclone\.unmount\([^)]*gracefulOnly:\s*true/.test(gentleSlice));
ok('the gentle auto-lock path never passes force: true', !/force:\s*true/.test(gentleSlice));

// The dead-mount reaper (pruneDeadMounts) force-releases a stale mount and removes its state row BY MOUNTPOINT. If it
// could overlap a concurrent mount of the same vault, it would delete or force-unmount a freshly re-mounted LIVE row
// at that path — leaving a decrypted mount untracked (never auto-locked) or severing fresh writes. It must therefore
// run while HOLDING the mount serial queue (withMountLock), so a reap and a mount can never interleave. Pin that the
// reaper self-serializes when not already locked, and that the one in-queue caller (mountImpl) passes locked:true so
// it runs the body directly instead of deadlocking by re-acquiring the same queue.
ok('pruneDeadMounts serializes against mounts via withMountLock', /async function pruneDeadMounts\(\{ locked = false \} = \{\}\) \{[\s\S]{0,900}if \(!locked\) return withMountLock\(\(\) => pruneDeadMounts\(\{ locked: true \}\)\)/.test(V));
ok('the in-queue caller (mountImpl) passes locked:true to avoid a re-entrant deadlock', /await pruneDeadMounts\(\{ locked: true \}\)/.test(V));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UNMOUNT-LADDER CHECKS PASSED'));
process.exit(failures ? 1 : 0);
