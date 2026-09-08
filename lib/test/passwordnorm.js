'use strict';
// lib/test/passwordnorm.js — a non-ASCII vault password must unlock regardless of the Unicode FORM the OS or
// keyboard produced. macOS input can arrive decomposed (NFD) while Linux/Windows produce composed (NFC), so a
// vault created with, say, "páss🔒word" on one platform used to fail to unlock on another because the raw bytes
// differed. New slots are now written from the canonical NFC form, and unlock tries NFC/NFD/raw, so the same
// password opens the vault everywhere. This is verified through changePassword (which authenticates the old
// password via the same slot-unlock path) so it needs no mount driver — only the bundled engine to create.
//
// Run:  node lib/test/passwordnorm.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const fs = require('fs');
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function refused(fn) { try { await fn(); return false; } catch (_) { return true; } }

let workspace = null;
async function main() {
	if (!(await vdisk.doctor()).engine.ok) { console.log('Engine missing — skipping.'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-pwnorm-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'doc.txt'), 'hello ' + crypto.randomBytes(4).toString('hex'));

	// The SAME password in two Unicode forms: composed (NFC, U+00E1) and decomposed (NFD, "a" + U+0301).
	const nfc = 'p\u00e1ss\u{1F512}word';    // "pass-lock-word" with a as ONE composed code point (U+00E1)
	const nfd = 'pa\u0301ss\u{1F512}word';   // same characters, DECOMPOSED: "a" + combining acute (U+0301)
	ok('the two forms really are different byte sequences', nfc !== nfd);
	ok('but they share one canonical NFC form', nfc.normalize('NFC') === nfd.normalize('NFC'));

	const v = path.join(tmp, 'N.vault');
	await vdisk.importFolder(v, { password: nfc, sourceDir: src });

	// Unlock (authenticate) with the OTHER form — this is the cross-platform case. changePassword verifies the
	// old password through the slot-unlock path, so a success here proves the decomposed input opened the
	// NFC-created vault.
	let crossFormOk = true;
	try { await vdisk.changePassword(v, { oldPassword: nfd, newPassword: 'interim-ascii' }); } catch (_) { crossFormOk = false; }
	ok('a non-ASCII password unlocks in a different Unicode form (NFC vault, NFD input)', crossFormOk);

	// A genuinely wrong password is still refused — the extra forms must not weaken rejection.
	ok('a genuinely wrong password is still refused', await refused(() => vdisk.changePassword(v, { oldPassword: 'not-the-password', newPassword: 'x' })));

	// Round-trip back to a non-ASCII password and confirm it still opens (now via NFC directly).
	await vdisk.changePassword(v, { oldPassword: 'interim-ascii', newPassword: nfc });
	let backOk = true;
	try { await vdisk.changePassword(v, { oldPassword: nfc, newPassword: nfc }); } catch (_) { backOk = false; }
	ok('a non-ASCII password set now opens with its own (NFC) form', backOk);

	// An ordinary ASCII password is completely unaffected (the common case, a no-op for normalization).
	const a = path.join(tmp, 'A.vault');
	await vdisk.importFolder(a, { password: 'plain-ascii-pass', sourceDir: src });
	let asciiOk = true;
	try { await vdisk.changePassword(a, { oldPassword: 'plain-ascii-pass', newPassword: 'plain-ascii-2' }); } catch (_) { asciiOk = false; }
	ok('an ASCII password behaves exactly as before', asciiOk);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PASSWORD-NORMALIZATION CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(() => { if (workspace) try { fs.rmSync(workspace, { recursive: true, force: true }); } catch (_) {} });
