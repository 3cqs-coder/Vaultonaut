'use strict';
// lib/test/notesdurability.js — a source-level DRIFT GUARD that locks secure-note I/O to the mount filesystem through
// a single shared, atomic, durable writer. It is engine-free (it only reads source), so it runs on EVERY platform and
// CI runner, including the driverless ones where notes.js skips all of its mounted checks — the exact runners on which
// a note-I/O regression would otherwise slip through unnoticed.
//
// WHY THIS EXISTS: notes require the vault to be OPEN (mounted), so each decrypted note file sits on the mountpoint and
// is read and written through the mount filesystem — one fs call, never a spawned engine process per note. That makes
// opening the Notes view and the password audit fast on a store with hundreds of logins. Durability across an unmount
// is preserved WITHOUT a store-direct path: mounts run with --vfs-write-back 0s, every note write fsyncs before its
// atomic rename, and the unmount DRAINS both the write-back queue and active transfers (treating an unreachable channel
// as busy) and DEFERS rather than tearing down on unflushed data. The runtime proof lives in notes.js — the
// "DURABLE DELETE ACROSS UNMOUNT" and "ROTATION SURVIVAL" cases running on the Windows and Linux CI runners, where the
// original write-back loss was worst. These source assertions fail the build if any of the write-side invariants below
// quietly revert (a note write must stay unique-temp + fsync + renameWithRetry, serialized, bounded, and cleaned up).
//
// Run:  node -r ./lib/test/_setup.js lib/test/notesdurability.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
// The body of a named function, from its declaration to the next top-level `\n}` (a `}` at column 0, which for a
// top-level function is its own end), with line comments stripped so a keyword named in a comment is never mistaken
// for the code doing it. Same helper the other *drift.js guards use.
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return null; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

const V = read('lib/Vault.js');

// The note functions and the shared mount-fs primitives must all exist (a rename would break these guards silently, so
// prove each body was actually found before asserting over it).
const WRITE_HELPERS = ['async function noteSave(', 'async function noteRecordRawWrite('];
const READ_HELPERS = ['async function readNoteFile(', 'async function listNoteFiles(', 'async function noteDelete(', 'async function noteGet(', 'async function noteRecordRaw(', 'async function notesList(', 'async function notesHealth('];
const PRIMITIVES = ['async function readNoteFile(', 'async function listNoteFiles(', 'async function writeNoteFileAtomic(', 'async function deleteNoteFile('];
const ALL = [...new Set([...WRITE_HELPERS, ...READ_HELPERS, ...PRIMITIVES])];
for (const decl of ALL) ok('note function is present: ' + decl.replace('async function ', '').replace('(', ''), fnBody(V, decl) !== null);

// 1. WRITES go through the ONE shared mount-fs atomic writer, never straight through the store or a bare fs write. A
//    note write must call writeNoteFileAtomic and must NOT reach for the store-direct writer (writeVaultObjectAtomic)
//    or an unmanaged fs write/rename of its own — the whole point is a single, durable, atomic write path.
for (const decl of WRITE_HELPERS) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' writes via writeNoteFileAtomic (the one shared atomic mount-fs writer)', /writeNoteFileAtomic\(/.test(b));
	ok(name + ' does NOT write a note straight to the store (no writeVaultObjectAtomic) or with a bare fs write/rename', !/writeVaultObjectAtomic|fsp?\.writeFile|\bwriteFileSync|\.rename\(|writeJsonAtomic/.test(b));
}

// 2. READS, LIST, and DELETE go through the mount-fs primitives, never a store-direct engine call (Rclone.run) and
//    never a fs write. A note read/list/delete must not shell out to the engine (which was the slow per-note spawn).
for (const decl of READ_HELPERS) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' does NOT shell out to the engine per note (no Rclone.run / ephemeral config)', !/Rclone\.run\(|withEphemeralConfig|writeEphemeralConfig|notesEngine\(/.test(b));
}

// 3. The mount-fs primitives are the ONLY note store-touch points, and each does exactly what durability needs.
{
	const rf = fnBody(V, 'async function readNoteFile(') || '';
	ok('readNoteFile reads through the mount filesystem, size-capped and bounded', /readFileCapped\(/.test(rf) && /withTimeout\(/.test(rf) && !/Rclone\.run\(/.test(rf));
	const lf = fnBody(V, 'async function listNoteFiles(') || '';
	ok('listNoteFiles lists through the mount filesystem, bounded, and keeps only .json', /fsp?\.readdir\(/.test(lf) && /withTimeout\(/.test(lf) && /\.json'\)/.test(lf) && !/Rclone\.run\(/.test(lf));
	const df = fnBody(V, 'async function deleteNoteFile(') || '';
	ok('deleteNoteFile removes through the mount filesystem, idempotent and bounded', /fsp?\.rm\(/.test(df) && /force: true/.test(df) && /withTimeout\(/.test(df) && !/Rclone\.run\(/.test(df));
}

// 4. writeNoteFileAtomic is durable AND atomic: a UNIQUE temp (so two writers never share one), an fsync of the bytes
//    BEFORE the rename (flushes toward the store on close — on top of --vfs-write-back 0s and the unmount drain), an
//    atomic renameWithRetry (rides out the Windows lock), the temp cleaned up on failure, and every op bounded.
{
	const w = fnBody(V, 'async function writeNoteFileAtomic(') || '';
	ok('writeNoteFileAtomic uses a UNIQUE temp (concurrent writers never collide)', /uniqueTempPath\(/.test(w));
	ok('writeNoteFileAtomic fsyncs the file before the rename (durable on close)', /\.sync\(\)/.test(w) && w.indexOf('.sync()') < w.indexOf('renameWithRetry('));
	ok('writeNoteFileAtomic renames atomically with the Windows-lock retry', /renameWithRetry\(/.test(w));
	ok('writeNoteFileAtomic cleans up its temp on failure', /fsp?\.rm\(tmp/.test(w));
	ok('writeNoteFileAtomic bounds every filesystem op', /withTimeout\(/.test(w));
}

// 5. The note store-direct engine path is fully gone: Vault.js no longer defines notesEngine or readNoteObject, and no
//    note function shells out per note. (The store-direct writeVaultObjectAtomic stays ONLY for the non-note records
//    guarded in section 6.)
ok('the per-note engine helpers are gone (no notesEngine / readNoteObject in Vault.js)', !/function notesEngine\(|function readNoteObject\(/.test(V));

// 6. CLASS INVARIANT: the OTHER durable in-store records — the tamper baseline, its version upgrade, and the session
//    marker — still write through the store-direct writeVaultObjectAtomic. Notes moved to the mount; these did not, so
//    the store-direct temp-then-rename must remain intact for them and cannot silently drift onto the mount.
for (const decl of ['async function writeSnapshot(', 'async function resignBaselineV4(', 'async function writeSessionMarker(']) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' routes its durable write through writeVaultObjectAtomic (store-direct, unchanged)', /writeVaultObjectAtomic\(/.test(b));
}
{
	const wvoa = fnBody(V, 'async function writeVaultObjectAtomic(') || '';
	ok('writeVaultObjectAtomic still does temp-then-rename straight to the crypt remote (rcat then moveto)', /'rcat'/.test(wvoa) && /'moveto'/.test(wvoa));
	// The temp name stays FIXED ("<name>.new"): INTERNAL_VAULT_OBJECTS and RECOVERY_EXCLUDE_NAMES list those exact temp
	// names to skip them, so a randomized temp would resurface as a phantom foreign/protectable file. Guard that intent.
	ok('writeVaultObjectAtomic uses the fixed "<name>.new" temp (the exclusion lists depend on it)', /name \+ '\.new'/.test(wvoa));
}
// The corrupt-file aside (the one local, non-vault rename Vault.js used to do, quarantining an unreadable settings
// file) lives in the shared Common.preserveCorruptFile, and the only remaining raw rename is the note writer's atomic
// renameWithRetry. A `.rename(` on the store-direct path would be a durable write sneaking off the crypt remote.
// (renameWithRetry does not match — it is a `.renameWithRetry(` call, not `.rename(`.)
{
	const renameLines = V.split('\n').filter(l => /\.rename\(/.test(l) && !/^\s*\/\//.test(l));
	ok('Vault.js does no raw fs rename (note writes use renameWithRetry; the corrupt-file aside moved to Common)', renameLines.length === 0);
}

// 7. Note WRITES are serialized per vault, so a same-id save can never interleave another (the atomic rename makes it
//    last-write-wins), an edit's read-then-write of createdAt cannot interleave, and a delete cannot land mid-save.
for (const decl of ['async function noteSave(', 'async function noteDelete(', 'async function noteRecordRawWrite(']) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' is serialized per vault (serializeNoteWrite)', /serializeNoteWrite\(/.test(b));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTES-DURABILITY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
