'use strict';
// lib/test/internalnamesdrift.js — the set of "the tool's own metadata files, plus OS-noise files" is defined
// canonically in lib/Vault.js (INTERNAL_VAULT_OBJECTS for the control files, and the isIgnoredVaultPath predicate over
// OS_JUNK_COMMON + a few patterns for the OS noise). By necessity that set is copied into two other places that cannot
// require Vault: the content-search worker (which must never INDEX these) and the mobile client (which must never SHOW
// them as the user's files). If a copy drifts — a renamed control file, a new OS-junk name — an internal blob would
// silently leak into the search index or the phone's file browser. This guard binds all three to the canonical source
// by BEHAVIOR (not exact regex text, so cosmetic ordering differences don't matter), so changing one without the
// others fails the suite.
//
// Run:  node lib/test/internalnamesdrift.js

const fs = require('fs');
const path = require('path');
const Vault = require('../Vault');
const SearchWorker = require('../SearchWorker');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const setsEqual = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

const canonical = Vault.INTERNAL_VAULT_OBJECTS; // Set of the control-file basenames

// 1. The search worker's exclude set must equal the canonical control-file set exactly.
ok('SearchWorker.INTERNAL equals Vault.INTERNAL_VAULT_OBJECTS', setsEqual(SearchWorker.INTERNAL, canonical));
ok('every canonical control name is treated as an ignored vault path', [...canonical].every((n) => Vault.isIgnoredVaultPath(n)));

// 1b. The self-heal parity must EXCLUDE the same control files (by their encrypted names, cached at mount). The
//     recovery exclude list is a SUPERSET of the control set — it also carries OS-junk names. If a new control file
//     were added to INTERNAL_VAULT_OBJECTS but not to RECOVERY_EXCLUDE_NAMES, self-heal would cover it and "repair"
//     (revert) it every mount/unmount cycle, exactly the class of bug this binding prevents.
const recoveryExclude = new Set(Vault.RECOVERY_EXCLUDE_NAMES);
ok('every canonical control name is in the self-heal exclude list (RECOVERY_EXCLUDE_NAMES)', [...canonical].every((n) => recoveryExclude.has(n)));

// 2. The mobile client's isInternalName must classify the SAME names. Extract its control-name checks and its OS-junk
//    regex from the source (scoped to the function body), then compare BEHAVIOR against the canonical predicate.
const mobileSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'mobile', 'app.js'), 'utf8');
const fnBody = (mobileSrc.match(/function isInternalName\(p\)\s*\{([\s\S]*?)\n\t\}/) || [])[1] || '';
ok('found the mobile isInternalName function', fnBody.length > 0);

const mobileControl = new Set((fnBody.match(/base === '([^']+)'/g) || []).map((m) => m.replace(/^base === '/, '').replace(/'$/, '')));
ok('mobile control names equal the canonical control set', setsEqual(mobileControl, canonical));

const reMatch = fnBody.match(/\/\^\((.*?)\)\$\/\.test\(base\)/);
ok('mobile OS-junk regex is present', !!reMatch);
if (reMatch) {
	const mobileJunkRe = new RegExp('^(' + reMatch[1] + ')$');
	// A representative junk set: every canonical OS_JUNK_COMMON literal (so a name added there but missed by mobile
	// fails here) plus one example per wildcard pattern family. For each, the mobile regex must agree with the
	// canonical predicate; and a handful of real user files must be internal in neither.
	const junkExamples = [...(Vault.OS_JUNK_COMMON || []), '._hiddenfork', '.metadata_never_index', '.TemporaryItems', '.DocumentRevisions-V100', '.apDisk', '.fuse_hidden0001', '.nfs0002', '.Spotlight-V100', '.Trashes', '.fseventsd'];
	for (const n of junkExamples) {
		ok('mobile regex matches "' + n + '" iff the canonical predicate does', mobileJunkRe.test(n) === Vault.isIgnoredVaultPath(n));
	}
	for (const n of ['report.pdf', 'photo.jpg', 'notes.txt', 'Budget-2026.xlsx']) {
		ok('user file "' + n + '" is internal by neither the mobile matcher nor the canonical predicate', !mobileJunkRe.test(n) && !mobileControl.has(n) && !Vault.isIgnoredVaultPath(n));
	}
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL INTERNAL-NAME DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
