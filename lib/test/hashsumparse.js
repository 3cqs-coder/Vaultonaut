'use strict';
// lib/test/hashsumparse.js — the tamper scan's decision to REPORT a damaged file vs. ABORT the whole check rests on
// parsing the engine's `hashsum --download` stderr. This pins that parser (Vault._hashsumParse). It is pure and
// offline (no engine, no mount), so it runs on every platform and CI runner. The stderr shapes below are the real
// output of the bundled rclone (reproduced against it), plus the edge cases the parser must get right.
//
// Run:  node lib/test/hashsumparse.js

const { hashsumDamagedFiles, hashsumErrorsAllPerFile } = require('../Vault')._hashsumParse;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Real bundled-rclone (1.75.1) output for one HEADER-corrupt file: a per-file "failed to open file" line, then the
// two-or-more-errors summary ("with N errors" — rclone counts the internal retries as 2).
const oneBad = [
	'2026/09/11 11:57:45 ERROR : big.bin: failed to open file big.bin: not an encrypted file - bad magic string',
	'2026/09/11 11:57:45 NOTICE: Failed to hashsum with 2 errors: last error was: failed to open file big.bin: not an encrypted file - bad magic string',
].join('\n');

ok('captures the damaged file path from a bad-magic (header) line', JSON.stringify(hashsumDamagedFiles(oneBad)) === JSON.stringify(['big.bin']));
ok('a bad-magic run is recognized as all-per-file (report, do not abort)', hashsumErrorsAllPerFile(oneBad) === true);

// Real bundled-rclone output for a SINGLE BODY-corrupt (or partially-healed) file: a block-auth failure, whose message
// itself repeats ": " ("failed to copy file to hasher: failed to authenticate …"), and — the crux — a SINGLE-error
// summary "Failed to hashsum:" with NO count. The path must still be captured whole ("big.jpg", not the message), and
// this must be recognized as all-per-file (the regression this test locks — the counted-summary requirement aborted it).
const bodyBad = [
	'2026/09/11 12:14:15 ERROR : big.jpg: failed to copy file to hasher: failed to authenticate decrypted block - bad password?',
	'2026/09/11 12:14:15 NOTICE: Failed to hashsum: failed to copy file to hasher: failed to authenticate decrypted block - bad password?',
].join('\n');
ok('captures just the path from a block-auth line (message repeats ": ")', JSON.stringify(hashsumDamagedFiles(bodyBad)) === JSON.stringify(['big.jpg']));
ok('a SINGLE block-auth failure is all-per-file (the single-error "Failed to hashsum:" summary is accepted)', hashsumErrorsAllPerFile(bodyBad) === true);

// A path that itself contains ": " must be kept WHOLE (anchor on ": failed to").
const colonName = [
	'2026/01/01 00:00:00 ERROR : weird: name.bin: failed to open file weird: name.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum: failed to open file weird: name.bin: not an encrypted file',
].join('\n');
ok('a path containing ": " is captured whole', hashsumDamagedFiles(colonName).includes('weird: name.bin'));

// A filename with spaces (and a leading space) is preserved (trimmed of the surrounding whitespace).
const spaced = [
	'2026/01/01 00:00:00 ERROR :  my photo 2.jpg: failed to open file  my photo 2.jpg: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum: failed to open file  my photo 2.jpg',
].join('\n');
ok('a filename with spaces is captured', hashsumDamagedFiles(spaced).includes('my photo 2.jpg'));

// CRLF line endings (a Windows engine) are handled.
const crlf = oneBad.replace(/\n/g, '\r\n');
ok('CRLF stderr parses the same', JSON.stringify(hashsumDamagedFiles(crlf)) === JSON.stringify(['big.bin']) && hashsumErrorsAllPerFile(crlf) === true);

// Multiple damaged files dedupe and all appear.
const many = [
	'2026/01/01 00:00:00 ERROR : a.bin: failed to open file a.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 ERROR : b.bin: failed to open file b.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 ERROR : a.bin: failed to open file a.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum with 3 errors',
].join('\n');
ok('multiple damaged files are listed and deduped', JSON.stringify(hashsumDamagedFiles(many).sort()) === JSON.stringify(['a.bin', 'b.bin']));

// A TRANSIENT read error (an i/o timeout / reset over a cloud or SFTP backend) on a HEALTHY file must NOT be classified
// as damage — reporting it would false-alarm on a good file and could prompt the user to delete it. It has no
// deterministic damage phrase, so it is not damaged and the run is inconclusive (abort/retry), never clean-but-for-N.
const transient = [
	'2026/01/01 00:00:00 ERROR : big.bin: failed to open file big.bin: Get "https://s3.example.com/...": dial tcp: i/o timeout',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum: failed to open file big.bin: i/o timeout',
].join('\n');
ok('a transient read error is NOT classified as a damaged file', hashsumDamagedFiles(transient).length === 0);
ok('a transient read error is NOT all-per-file damage (inconclusive -> abort)', hashsumErrorsAllPerFile(transient) === false);
ok('a mix of real damage AND a transient read error aborts (inconclusive, retryable), not partial damage', hashsumErrorsAllPerFile([
	'2026/01/01 00:00:00 ERROR : a.bin: failed to authenticate decrypted block - bad password?',
	'2026/01/01 00:00:00 ERROR : b.bin: failed to open file b.bin: connection reset by peer',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum with 2 errors',
].join('\n')) === false);

// FAIL-CLOSED cases — these must NOT be treated as all-per-file, so the scan aborts rather than passing as clean-but-N.
ok('a fatal/global error line is NOT all-per-file (abort)', hashsumErrorsAllPerFile([
	'2026/01/01 00:00:00 ERROR : failed to create file system for "vault:": permission denied',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum with 1 errors',
].join('\n')) === false);
ok('a mix of per-file and a fatal ERROR is NOT all-per-file (abort)', hashsumErrorsAllPerFile([
	'2026/01/01 00:00:00 ERROR : a.bin: failed to open file a.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 ERROR : the vault could not be read: input/output error',
	'2026/01/01 00:00:00 NOTICE: Failed to hashsum with 2 errors',
].join('\n')) === false);
ok('per-file errors with the summary TRUNCATED away are NOT trusted (abort)', hashsumErrorsAllPerFile([
	'2026/01/01 00:00:00 ERROR : a.bin: failed to open file a.bin: not an encrypted file - bad magic string',
	'2026/01/01 00:00:00 ERROR : b.bin: failed to open file b.bin: not an encrypted file - bad magic string',
].join('\n')) === false);
ok('empty stderr is not all-per-file', hashsumErrorsAllPerFile('') === false);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HASHSUM-PARSE CHECKS PASSED'));
process.exit(failures ? 1 : 0);
