'use strict';
// lib/test/vaultnameportable.js — a vault is a folder on disk, and a vault made on one operating system must open and
// mount on every other. Windows is the strictest, so Common.assertPortableVaultName rejects, on EVERY platform at
// creation, any name that would be invalid or silently altered as a Windows folder: a reserved device name, an illegal
// character, or a leading/trailing space or period. This pins that rule so a future edit cannot quietly loosen it and
// let an unportable vault be created. Pure — no engine.
//
// Run:  node lib/test/vaultnameportable.js

const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function rejects(name) { try { Common.assertPortableVaultName(name); return false; } catch (_) { return true; } }
function accepts(name) { try { Common.assertPortableVaultName(name); return true; } catch (_) { return false; } }

// --- valid names are accepted (no false rejections) ---
// COM0/LPT0 are NOT reserved on Windows (only COM1-9 / LPT1-9), so they must be ACCEPTED — over-rejecting them was a bug.
for (const good of ['MyVault', 'work-vault_2', 'café', 'Vault 2024', 'com', 'lpt', 'COM0', 'LPT0', 'CONtact', 'report.final', '日本語', 'a']) {
	ok('accepts a valid name: "' + good + '"', accepts(good));
}

// --- Windows reserved device names are rejected, case-insensitively and even with an extension ---
// Includes CLOCK$ (a legacy reserved DOS device) and the superscript COM¹/LPT² forms Win32 also maps.
for (const bad of ['CON', 'con', 'Con', 'PRN', 'AUX', 'NUL', 'COM1', 'COM9', 'LPT1', 'LPT9', 'CON.vault', 'nul.txt', 'CLOCK$', 'clock$', 'COM¹', 'LPT²']) {
	ok('rejects the reserved device name: "' + bad + '"', rejects(bad));
}

// --- illegal characters (reserved on Windows / unportable) are rejected ---
for (const ch of ['<', '>', ':', '"', '/', '\\', '|', '?', '*']) {
	ok('rejects a name containing "' + ch + '"', rejects('my' + ch + 'vault'));
}
ok('rejects a control character in the name', rejects('my\x01vault'));

// --- a leading/trailing space or period is rejected (Windows silently drops it) ---
for (const bad of [' lead', 'trail ', '.lead', 'trail.', ' ', '.', '..']) {
	ok('rejects a leading/trailing space or period: "' + bad + '"', rejects(bad));
}

// --- empty and over-long names are rejected ---
ok('rejects an empty name', rejects('') && rejects(null) && rejects('   '));
// The cap is 64 so the whole vault PATH stays within the Windows MAX_PATH (260) budget, not just the name component.
ok('rejects a name over 64 characters (Windows path-length safety)', rejects('x'.repeat(65)));
ok('accepts a name at the 64-character limit', accepts('x'.repeat(64)));
ok('accepts a normal short name', accepts('x'.repeat(40)));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-NAME-PORTABLE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
