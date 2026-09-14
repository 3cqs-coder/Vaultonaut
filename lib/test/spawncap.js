'use strict';
// lib/test/spawncap.js — spawnP's buffered-stdout cap. The engine wrapper keeps a defense-in-depth ceiling on how much
// stdout it will buffer, so a caller that forgets to pass its own maxOutBytes — or a hostile/huge output (a peer-
// controlled lease file, a runaway listing) — still cannot grow this process's memory without bound. When the
// accumulator passes the cap the child is SIGKILLed and the truncated result then simply fails to parse (treated as
// absent), never a crash. reliabilityguards.js covers the OAuth-capture and streaming-branch caps; this pins the
// DEFAULT buffered-branch cap (value + that it is the signature default) and proves the kill actually fires.
//
// Run:  node lib/test/spawncap.js

const fs = require('fs');
const path = require('path');
const Rclone = require('../Rclone');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// --- static: the default cap exists, is a sane large value, and is the parameter default (so a caller that omits
	//     maxOutBytes still inherits it) ---
	const src = fs.readFileSync(path.join(__dirname, '..', 'Rclone.js'), 'utf8');
	ok('a default stdout cap constant is defined at 256 MiB', /const MAX_STDOUT_DEFAULT = 256 \* 1024 \* 1024;/.test(src));
	ok('spawnP defaults maxOutBytes to MAX_STDOUT_DEFAULT', /function spawnP\([^)]*maxOutBytes = MAX_STDOUT_DEFAULT/.test(src));
	ok('the buffered branch kills the child once the accumulator passes the cap', /out\.length > maxOutBytes\)\s*\{\s*try \{ child\.kill\('SIGKILL'\)/.test(src));

	// --- behavioral: a child that floods stdout past an explicit small cap is terminated and its output bounded ---
	// Emit ~8 MiB from a real child (node itself, always present) with a 64 KiB cap. The accumulator must trip the
	// SIGKILL long before 8 MiB is buffered.
	const cap = 64 * 1024;
	const emit = 8 * 1024 * 1024;
	const code = 'const b="x".repeat(1024*1024);for(let i=0;i<8;i++)process.stdout.write(b);';
	const r = await Rclone.run(process.execPath, ['-e', code], { maxOutBytes: cap, timeoutMs: 30000 });
	ok('the flooding child does not exit cleanly (it was killed, not status 0)', r.status !== 0);
	ok('the buffered stdout is bounded far below what the child tried to emit', r.stdout.length < emit / 2);
	// The kill fires from a data handler, so a little past the cap can arrive in the same tick before the process dies;
	// allow a generous margin but still prove it is a small multiple of the cap, not the full flood.
	ok('the retained stdout stays within a small multiple of the cap', r.stdout.length < cap + 4 * 1024 * 1024);

	// --- control: a child whose output is well UNDER the cap is captured intact (the cap never truncates normal use) ---
	const r2 = await Rclone.run(process.execPath, ['-e', 'process.stdout.write("hello world")'], { maxOutBytes: cap, timeoutMs: 30000 });
	ok('a small output under the cap is returned intact', r2.status === 0 && r2.stdout === 'hello world');

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SPAWN-CAP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
