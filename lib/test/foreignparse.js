'use strict';
// lib/test/foreignparse.js — the tamper scan decides "foreign/undecryptable entry = suspicious" vs "benign notice" and
// "real content integrity failure = tampering" vs "any line that merely says error" by parsing the engine's stderr.
// Those two parsers (foreignCipherNames, integrityFailureLines) are the same safety-critical classification class as the
// hashsum damage parser, so they get the same offline, engine-free unit test that runs on every platform and CI runner
// (the end-to-end path, foreign.js, skips on a driverless/engine-less runner — exactly where a source-level guard is
// needed). The stderr shapes below are the real output of the bundled rclone, plus the edge cases the parser must nail.
//
// Run:  node lib/test/foreignparse.js

const { foreignCipherNames, integrityFailureLines } = require('../Vault')._foreignParse;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// A foreign FILE dropped into the encrypted store by someone without the key: rclone cannot decode its name and skips it
// with a NOTICE. The parser must keep the encrypted name verbatim (it is the only handle the user has to find and remove
// the offender), stripping only the timestamp + level prefix.
const foreignFile = [
	'2026/09/11 11:57:45 NOTICE: v3kq9m2p8: Skipping undecryptable file name: no space left after decode',
].join('\n');
ok('captures a foreign file name (name kept, prefix stripped)', JSON.stringify(foreignCipherNames(foreignFile)) === JSON.stringify(['v3kq9m2p8']));

// The DIR-name variant is equally a foreign entry and must be captured the same way.
const foreignDir = [
	'2026/09/11 11:57:45 NOTICE: a1b2c3d4: Skipping undecryptable dir name: illegal base32 data at input byte 3',
].join('\n');
ok('captures a foreign dir name (the "dir name" variant)', JSON.stringify(foreignCipherNames(foreignDir)) === JSON.stringify(['a1b2c3d4']));

// An encrypted name that itself contains spaces and ": " must be kept WHOLE — the name is sliced off at the stable
// " : Skipping undecryptable " keyword, not at the first colon.
const spacedName = [
	'2026/01/01 00:00:00 NOTICE: weird name: with colon: Skipping undecryptable file name: bad decode',
].join('\n');
ok('a foreign name containing spaces and ": " is kept whole', JSON.stringify(foreignCipherNames(spacedName)) === JSON.stringify(['weird name: with colon']));

// CRLF (a Windows engine) parses identically.
ok('CRLF stderr parses the same', JSON.stringify(foreignCipherNames(foreignFile.replace(/\n/g, '\r\n'))) === JSON.stringify(['v3kq9m2p8']));

// Multiple foreign entries all appear, in order.
const manyForeign = [
	'2026/01/01 00:00:00 NOTICE: aaa: Skipping undecryptable file name: x',
	'2026/01/01 00:00:00 NOTICE: bbb: Skipping undecryptable dir name: y',
].join('\n');
ok('multiple foreign entries are all listed', JSON.stringify(foreignCipherNames(manyForeign)) === JSON.stringify(['aaa', 'bbb']));

// A clean run has none.
ok('a clean stderr yields no foreign entries', foreignCipherNames('2026/01/01 00:00:00 INFO  : done\n').length === 0);
ok('empty stderr yields no foreign entries', foreignCipherNames('').length === 0);

// --- integrityFailureLines: a REAL content-integrity failure vs. the benign "undecryptable name" notice ---------------

// The crux, and the exact bug the code comment warns about: the benign "Skipping undecryptable …" notice contains the
// substring "decrypt", which the INTEGRITY_FAIL pattern also matches — so BENIGN_SKIP must be checked FIRST and win.
// A foreign-NAME notice is NOT a content integrity failure and must never read as one.
ok('the benign undecryptable-NAME notice is NOT an integrity failure (contains "decrypt" but is benign)', integrityFailureLines(foreignFile).length === 0);
ok('the benign undecryptable-DIR notice is NOT an integrity failure', integrityFailureLines(foreignDir).length === 0);

// A genuine content failure — the AEAD tag did not verify — IS an integrity failure and must be surfaced.
const realFail = [
	'2026/01/01 00:00:00 ERROR : photo.jpg: failed to authenticate decrypted block - bad password?',
].join('\n');
ok('a real block-auth failure IS an integrity failure', integrityFailureLines(realFail).length === 1);

// A "bad password" line (a wrong key against real ciphertext) is an integrity failure.
ok('a bad-password line is an integrity failure', integrityFailureLines('2026/01/01 00:00:00 ERROR : could not decrypt: bad password\n').length === 1);

// A benign notice AND a real failure in the same stderr: only the real one is returned (the benign line is filtered out
// even though it, too, contains "decrypt").
const mixed = [foreignFile, realFail].join('\n');
ok('a mix returns only the real failure, never the benign notice', integrityFailureLines(mixed).length === 1 && /failed to authenticate/.test(integrityFailureLines(mixed)[0]));

// A line that merely contains the word "error" but no integrity phrase is NOT an integrity failure (the reason the
// pattern is specific rather than matching "error").
ok('a generic "error" line without an integrity phrase is not an integrity failure', integrityFailureLines('2026/01/01 00:00:00 ERROR : Failed to copy: quota exceeded\n').length === 0);

// CRLF parses identically here too.
ok('CRLF integrity stderr parses the same', integrityFailureLines(realFail.replace(/\n/g, '\r\n')).length === 1);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FOREIGN-PARSE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
