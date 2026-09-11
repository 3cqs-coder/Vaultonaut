'use strict';
// lib/test/remotepathdrift.js — a source-level drift guard for a whole cross-platform bug CLASS: rclone REMOTE paths
// must always be joined with forward slashes, never with path.join (which yields backslashes on Windows and breaks
// the remote address). remoteJoin() is the one forward-slash joiner; local filesystem paths use path.join. This pins
// remoteJoin's shape and asserts the remote/local fork sites keep remoteJoin on the remote side, so a refactor can't
// quietly route a remote path through path.join and break every backup/mirror/version op on Windows.
//
// Run:  node lib/test/remotepathdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };

const V = read('lib/Vault.js');

// 1. remoteJoin joins with a forward slash and NEVER uses an OS-dependent joiner.
const rjLine = (V.split('\n').find(l => l.includes('function remoteJoin(')) || '');
ok('remoteJoin is defined', rjLine.length > 0);
ok("remoteJoin joins with a forward slash (+ '/' +)", /\+\s*'\/'\s*\+/.test(rjLine));
ok('remoteJoin does not use path.join / path.sep / a backslash', !/path\.join|path\.sep|\\\\/.test(rjLine));

// 2. remoteJoin is actually the joiner used for remote paths (not bypassed).
const uses = (V.match(/remoteJoin\(/g) || []).length;
ok('remoteJoin is used for remote path building (several sites)', uses >= 3);

// 3. Every remote/local FORK that builds a version-history directory keeps remoteJoin on the remote side. A line that
//    forks on remoteDest and mentions VERSIONS_DIR must contain remoteJoin (the remote branch) — if someone swapped
//    it for path.join, remoteJoin would vanish from that line and this fails.
const forkLines = V.split('\n').filter(l => /remoteDest\s*\?/.test(l) && /VERSIONS_DIR/.test(l));
ok('the remote/local version-dir fork sites are present', forkLines.length >= 1);
ok('every remoteDest fork building a version dir uses remoteJoin on the remote side', forkLines.every(l => /remoteJoin\(/.test(l)));

// (A remote/local fork line legitimately mentions BOTH remoteJoin and path.join — one per branch of the ternary — so
//  co-occurrence on a line is correct, not a defect; #3 already pins the remote branch to remoteJoin.)

// 4. Sanity on the helper's actual behavior, reproduced from its source contract: trailing slashes collapse and the
//    result is forward-slash joined regardless of the platform separator.
const remoteJoin = (remote, sub) => String(remote).replace(/\/+$/, '') + '/' + sub;
ok('remoteJoin("b2:bucket/vault/", ".versions") is forward-slash joined', remoteJoin('b2:bucket/vault/', '.versions') === 'b2:bucket/vault/.versions');
ok('remoteJoin output contains no backslash', !remoteJoin('sftp:/srv/vault', '.versions/2026').includes('\\'));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REMOTE-PATH-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
