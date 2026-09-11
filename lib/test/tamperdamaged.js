'use strict';
// lib/test/tamperdamaged.js — a single unreadable blob must not abort the whole tamper check. When one file's
// encrypted CONTENT is damaged (a "bad magic" header, a failed block authentication — e.g. the residue of a loss too
// large for self-healing to fully rebuild), the engine's `hashsum --download` exits non-zero but STILL hashes every
// other file. The audit must REPORT that one file as damaged and check the rest, not throw a mysterious
// "Could not scan the vault" that hides the real, actionable result. Needs the bundled engine; no mount driver (the
// audit runs on the unmounted store, and the damage is applied to the ciphertext directly).
//
// Run:  node lib/test/tamperdamaged.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const vdisk = require('../index');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function blobs(dir) {
	const out = [];
	async function walk(d) { for (const e of await fsp.readdir(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) await walk(p); else { out.push({ p, size: (await fsp.stat(p)).size }); } } }
	await walk(dir);
	return out;
}

let workspace = null;
async function main() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-tamperdamaged-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	// One biggish file to damage, plus several others that must stay verifiably intact through the scan.
	await fsp.writeFile(path.join(src, 'big.bin'), crypto.randomBytes(200 * 1024));
	for (let i = 0; i < 5; i++) await fsp.writeFile(path.join(src, 'ok' + i + '.bin'), crypto.randomBytes(20 * 1024));
	const v = path.join(tmp, 'TamperDamaged.vault');
	await vdisk.importFolder(v, { password: 'pw', sourceDir: src });

	// A deep snapshot records every file's content hash — the baseline the audit compares against.
	await vdisk.snapshot(v, { password: 'pw', deep: true });
	let clean;
	try { clean = await vdisk.audit(v, { password: 'pw', deep: true }); } catch (e) { clean = { threw: e.message }; }
	ok('a fresh deep audit is clean before any damage', clean && clean.clean === true && !clean.threw);

	// Corrupt ONE file's ciphertext BODY (a byte well past the 32-byte header, so the header still reads but a data
	// block fails authentication). This is the harder, real case a partially-healed file leaves, and — crucially — it
	// makes the engine print a SINGLE-error summary ("Failed to hashsum:" with no count), the exact shape a regression
	// once mis-read as a fatal error and aborted on. The blob keeps its size and valid encrypted NAME, so it still lists
	// and decodes its name; only its content can no longer be read.
	const cipherDir = path.join(v, 'data');
	const biggest = (await blobs(cipherDir)).sort((a, b) => b.size - a.size)[0];
	const fh = await fsp.open(biggest.p, 'r+'); await fh.write(Buffer.from('ZZZZZZZZ'), 0, 8, 40000); await fh.close();

	// The audit must NOT throw; it must complete and REPORT the damaged file.
	let rep, threw = null;
	try { rep = await vdisk.audit(v, { password: 'pw', deep: true }); } catch (e) { threw = e.message; }
	ok('the audit does not abort the whole scan on one unreadable file', threw === null);
	ok('the audit did not surface the old "Could not scan the vault" error', !(threw && /could not scan the vault/i.test(threw)));
	if (rep) {
		ok('the audit reports exactly one damaged file', Array.isArray(rep.damaged) && rep.damaged.length === 1);
		ok('the damaged file is named as its decrypted path', rep.damaged.length === 1 && rep.damaged[0] === 'big.bin');
		// Damage makes the result not-clean and is its OWN finding — it must NOT be filed under tampering (corruption is
		// not an attack), so report.damaged carries it while report.tamper stays empty (no false tamper alarm).
		ok('the damaged file makes the result not-clean without a false tamper alarm', rep.clean === false && rep.damaged.length === 1 && rep.tamper.length === 0);
		// The intact files must not be mis-reported: a damaged blob keeps its size, so it must NOT read as removed, and
		// the other files stay clean (not falsely modified/removed by an aborted-then-partial scan).
		ok('the damaged file is not mis-reported as removed (its size is unchanged)', !rep.removed.includes('big.bin'));
		ok('the intact files are not falsely flagged (no spurious removed/added)', rep.removed.length === 0 && rep.added.length === 0);
	}

	// A deep snapshot must REFUSE over the damaged vault, so damage is never recorded as the new trusted state. It must
	// say so clearly and carry e.damaged. (A structural, deep:false snapshot never reads content, so it is not gated.)
	let snapThrew = null, snapDamaged = null;
	try { await vdisk.snapshot(v, { password: 'pw', deep: true }); } catch (e) { snapThrew = e.message; snapDamaged = e.damaged; }
	ok('a deep snapshot refuses over a damaged vault', snapThrew !== null && /refused/i.test(snapThrew));
	ok('the refusal names the damaged file and carries e.damaged', Array.isArray(snapDamaged) && snapDamaged.includes('big.bin'));

	await vdisk.removeKnownVault(v).catch(() => {});
	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TAMPER-DAMAGED CHECKS PASSED'));
	return cleanup().then(() => process.exit(failures ? 1 : 0));
}
async function cleanup() { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }

main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
