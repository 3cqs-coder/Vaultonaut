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
for (const good of ['MyVault', 'work-vault_2', 'café', 'Vault 2024', 'com', 'lpt', 'CONtact', 'report.final', '日本語', 'a']) {
	ok('accepts a valid name: "' + good + '"', accepts(good));
}

// --- Windows reserved device names are rejected, case-insensitively and even with an extension ---
for (const bad of ['CON', 'con', 'Con', 'PRN', 'AUX', 'NUL', 'COM1', 'COM9', 'LPT1', 'LPT9', 'CON.vault', 'nul.txt']) {
	ok('rejects the reserved device name: "' + bad + '"', rejects(bad));
}

// --- illegal characters (reserved on Windows / unportable) are rejected ---
for (const ch of ['<', '>', ':', '"', '/', '\\', '|', '?', '*']) {
	ok('rejects a name containing "' + ch + '"', rejects('my' + ch + 'vault'));
}
ok('rejects a control character in the name', rejects('myvault'));

// --- a leading/trailing space or period is rejected (Windows silently drops it) ---
for (const bad of [' lead', 'trail ', '.lead', 'trail.', ' ', '.', '..']) {
	ok('rejects a leading/trailing space or period: "' + bad + '"', rejects(bad));
}

// --- empty and over-long names are rejected ---
ok('rejects an empty name', rejects('') && rejects(null) && rejects('   '));
ok('rejects a name over 200 characters', rejects('x'.repeat(201)));
ok('accepts a name at a sane length', accepts('x'.repeat(180)));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-NAME-PORTABLE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
