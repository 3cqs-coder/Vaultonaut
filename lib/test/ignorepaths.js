'use strict';
// lib/test/ignorepaths.js — the tamper scan must ignore EXACTLY the tool's own metadata blobs (and OS
// noise), and NOTHING else. A prefix match would let a holder of the read key plant a tamper-invisible
// file whose name merely starts with ".vaultsnapshot"/".vaultsession", which would defeat the tamper
// check (the file would never register as added, even on a sealed vault). This guards the exact-match rule.
//
// Run:  node lib/test/ignorepaths.js

const Vault = require('../Vault');
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ig = Vault.isIgnoredVaultPath;

console.log('[the tool/OS control files ARE ignored]');
for (const n of ['.vaultsnapshot', '.vaultsnapshot.new', '.vaultsession', '.vaultsession.new', '.vaultcheck', '.DS_Store', '._resourcefork', '.metadata_never_index'])
	ok('ignores "' + n + '" (exact metadata blob or OS noise)', ig(n) && ig('sub/dir/' + n));

console.log('[look-alikes a read-key holder could plant are NOT ignored]');
for (const n of ['.vaultsnapshot-payload', '.vaultsnapshots', '.vaultsnapshot.evil', '.vaultsession_backdoor', '.vaultsessionx', 'vaultsnapshot', 'notes.txt'])
	ok('does NOT ignore look-alike "' + n + '" (would be a tamper-invisible plant)', !ig(n) && !ig('a/b/' + n));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL IGNORE-PATH CHECKS PASSED'));
process.exitCode = failures ? 1 : 0;
