'use strict';
// lib/test/notesdurability.js — a source-level DRIFT GUARD that locks secure-note I/O to the encrypted store and the
// temp-then-rename write to a single, shared, atomic primitive. It is engine-free (it only reads source), so it runs
// on EVERY platform and CI runner, including the driverless ones where notes.js skips all of its mounted checks — the
// exact runners on which a mount-filesystem regression would otherwise slip through unnoticed.
//
// WHY THIS EXISTS: a rclone mount's VFS write-back cache can silently drop an atomic temp-then-rename save when the
// vault is unmounted before the cache flushes (a documented rclone behavior, worst on Linux fuse). That lost a note
// edit made just before an unmount and broke a key rotation right after. The fix routes every note read and write
// DIRECTLY to the crypt remote (cat/lsf/deletefile and writeVaultObjectAtomic's rcat+moveto), never through the
// mounted filesystem. These assertions fail the build if any of that quietly reverts.
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

// The note functions and the shared atomic writer must all exist (a rename would break these guards silently, so
// prove each body was actually found before asserting over it).
const WRITE_HELPERS = ['async function noteSave(', 'async function noteRecordRawWrite('];
const READ_HELPERS = ['async function readNoteObject(', 'async function listNoteFiles(', 'async function noteDelete(', 'async function noteGet(', 'async function noteRecordRaw(', 'async function notesList(', 'async function notesHealth('];
const DIRECT_IO = ['async function readNoteObject(', 'async function listNoteFiles(', 'async function noteDelete('];
const ALL = [...new Set([...WRITE_HELPERS, ...READ_HELPERS])];
for (const decl of ALL) ok('note function is present: ' + decl.replace('async function ', '').replace('(', ''), fnBody(V, decl) !== null);

// 1. WRITES go through the shared atomic store primitive, never the mount filesystem. writeVaultObjectAtomic is the
//    one place the rcat→moveto temp-then-rename lives; a note write must use it and must NOT write or rename a file
//    through fs (which would put the durable path back on the mount's write-back cache).
for (const decl of WRITE_HELPERS) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' writes via writeVaultObjectAtomic (shared atomic store write)', /writeVaultObjectAtomic\(/.test(b));
	ok(name + ' does NOT write a note through the mount filesystem (no fs writeFile/rename/writeJsonAtomic)', !/fsp?\.writeFile|\bwriteFileSync|fsp?\.rename|\.rename\(|writeJsonAtomic/.test(b));
}

// 2. READS, LIST, and DELETE go through the crypt remote, never the mount filesystem. No note function may read a note
//    with fs (readFile/readdir/readJsonCorruptAside/readFileCapped) or delete one with fs (rm/unlink).
for (const decl of READ_HELPERS) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' does NOT read/delete a note through the mount filesystem', !/fsp?\.readFile|fsp?\.readdir|fsp?\.rm\(|fsp?\.unlink\(|readJsonCorruptAside|readFileCapped/.test(b));
}
// The three primitives that actually touch the store do so through the crypt remote (Rclone.run on a vault: path).
for (const decl of DIRECT_IO) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' reaches the store through the crypt remote (Rclone.run on vault:)', /Rclone\.run\(/.test(b) && /'vault:'/.test(b));
	// A wedged store must fail fast: the child is killed at the mount timeout, not left to spawnP's 60s default.
	ok(name + ' passes an explicit timeoutMs so a wedged store child is killed, not orphaned', /timeoutMs/.test(b));
}

// 3. No note I/O helper builds a filesystem path from the mountpoint (that is exactly the pattern that put note I/O on
//    the mount VFS). notesEngine legitimately DERIVES the session from the mountpoint, so it is not included here.
for (const decl of ALL) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' builds no filesystem path (no path.join in the note I/O path)', !/path\.join\(/.test(b));
}

// 4. CLASS INVARIANT: every durable in-store record — the tamper baseline, its version upgrade, the session marker,
//    and notes — writes through writeVaultObjectAtomic, so the temp-then-rename lives in exactly one place and cannot
//    drift back to a mount-filesystem save for any one of them.
for (const decl of ['async function writeSnapshot(', 'async function resignBaselineV4(', 'async function writeSessionMarker(']) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' routes its durable write through writeVaultObjectAtomic', /writeVaultObjectAtomic\(/.test(b));
}
{
	const wvoa = fnBody(V, 'async function writeVaultObjectAtomic(') || '';
	ok('writeVaultObjectAtomic still does temp-then-rename straight to the crypt remote (rcat then moveto)', /'rcat'/.test(wvoa) && /'moveto'/.test(wvoa));
	// The temp name stays FIXED ("<name>.new"): INTERNAL_VAULT_OBJECTS and RECOVERY_EXCLUDE_NAMES list those exact temp
	// names to skip them, so a randomized temp would resurface as a phantom foreign/protectable file. Guard that intent.
	ok('writeVaultObjectAtomic uses the fixed "<name>.new" temp (the exclusion lists depend on it)', /name \+ '\.new'/.test(wvoa));
}
// The corrupt-file aside (the one local, non-vault rename Vault.js used to do, quarantining an unreadable settings
// file) now lives in the shared Common.preserveCorruptFile, so Vault.js should contain NO raw fs rename at all. Any
// `.rename(` here would be a durable vault write sneaking back onto the filesystem instead of going through the crypt
// remote. (renameWithRetry does not match — it is a `.renameWithRetry(` call, not `.rename(`.)
{
	const renameLines = V.split('\n').filter(l => /\.rename\(/.test(l) && !/^\s*\/\//.test(l));
	ok('Vault.js does no raw fs rename (the corrupt-file aside moved to the shared Common.preserveCorruptFile)', renameLines.length === 0);
}

// 5. Note WRITES are serialized per vault, so two concurrent saves to the same id can never share the fixed temp
//    mid-flight (a torn write) and an edit's read-then-write of createdAt cannot interleave.
for (const decl of ['async function noteSave(', 'async function noteDelete(', 'async function noteRecordRawWrite(']) {
	const b = fnBody(V, decl) || '';
	const name = decl.replace('async function ', '').replace('(', '');
	ok(name + ' is serialized per vault (serializeNoteWrite)', /serializeNoteWrite\(/.test(b));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NOTES-DURABILITY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
