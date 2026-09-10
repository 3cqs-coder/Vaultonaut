'use strict';
// lib/test/fileproof.js — the single-file proof. Two layers:
//   1) the Merkle INCLUSION-PROOF primitives (Integrity.merkleProof / verifyMerkleProof) over every tree shape,
//      including the odd-node-promoted cases, proving each leaf reaches the same root merkleRoot() signs, and that
//      a tampered leaf, sibling, or root fails closed;
//   2) end to end through a real vault: fileProof builds a shareable proof, verifyFileProof re-checks it OFFLINE
//      with no password (GENUINE), a flipped content hash or wrong expected identity reads TAMPERED, and the
//      SELF-CONTAINED verify.js (stock Node) agrees.
// Needs the engine for layer 2 (no mount driver; no network). Layer 1 is pure and always runs.
//
// Run:  node lib/test/fileproof.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function primitives() {
	// Every tree size from 1..9 exercises balanced and odd-node-promoted shapes. Each file must produce a proof that
	// reproduces the exact root merkleRoot() computes, and the recomputed leaf must bind the real file fields.
	let allOk = true, tamperCaught = true, absentNull = true;
	for (let n = 1; n <= 9; n++) {
		const files = [];
		for (let i = 0; i < n; i++) files.push({ path: 'dir/f' + i + '.txt', size: i * 100, hash: (i + 1).toString(16).repeat(8) });
		const root = await Integrity.merkleRoot(files);
		for (const f of files) {
			const pr = await Integrity.merkleProof(files, f.path);
			if (!pr || pr.root !== root) { allOk = false; continue; }
			const leaf = Integrity.fileLeafHex({ path: pr.path, size: pr.size, hash: pr.hash });
			if (!Integrity.verifyMerkleProof(leaf, pr.proof, root)) allOk = false;
			// A flipped leaf field must NOT verify to the same root.
			const badLeaf = Integrity.fileLeafHex({ path: pr.path, size: (pr.size || 0) + 1, hash: pr.hash });
			if (Integrity.verifyMerkleProof(badLeaf, pr.proof, root)) tamperCaught = false;
			// A flipped sibling or root must fail.
			if (pr.proof.length) { const bent = pr.proof.map((s, i) => i === 0 ? { side: s.side, hash: 'ff'.repeat(32) } : s); if (Integrity.verifyMerkleProof(leaf, bent, root)) tamperCaught = false; }
			if (Integrity.verifyMerkleProof(leaf, pr.proof, 'ab'.repeat(32))) tamperCaught = false;
		}
		if (await Integrity.merkleProof(files, 'dir/does-not-exist') !== null) absentNull = false;
	}
	ok('every leaf, across balanced and odd tree shapes (n=1..9), proves inclusion to the signed root', allOk);
	ok('a tampered leaf, sibling, or root fails the inclusion check', tamperCaught);
	ok('a proof for an absent file is null', absentNull);
}

async function endToEnd() {
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the end-to-end file-proof checks.'); return; }
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'contract.txt'), 'the signed agreement, verbatim');
	await fsp.writeFile(path.join(src, 'photo.bin'), Buffer.alloc(2048, 7));
	const v = path.join(tmp, 'Case.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw1', deep: true }); // deep so the proof binds the plaintext content hash

	const proof = await vdisk.fileProof(v, { password: 'pw1', path: 'contract.txt' });
	ok('a file proof is produced with the file, a signed baseline, and an inclusion path', !!(proof.file && proof.file.path === 'contract.txt' && proof.baseline && proof.baseline.sig && Array.isArray(proof.proof)));
	ok('the proof binds the plaintext content hash (deep snapshot)', proof.hasContentHash && !!proof.file.hash);
	ok('the proof carries the vault identity and origin identity', !!proof.identity && !!proof.originIdentity);
	ok('the proof carries no file contents', !JSON.stringify(proof).includes('the signed agreement'));

	// Verify OFFLINE with no password.
	const good = vdisk.verifyFileProof(proof);
	ok('a pristine file proof verifies as GENUINE', good.verdict === 'GENUINE' && good.checks.every(c => c.ok));
	ok('the origin-identity check passes when the expected identity matches', vdisk.verifyFileProof(proof, { expectIdentity: proof.originIdentity }).verdict === 'GENUINE');
	ok('a wrong expected identity is reported, not passed off as genuine', vdisk.verifyFileProof(proof, { expectIdentity: 'AAAAA-BBBBB-CCCCC' }).verdict === 'TAMPERED');

	// Tamper: a flipped content hash must break inclusion (the file was altered) -> TAMPERED.
	const bent = JSON.parse(JSON.stringify(proof)); bent.file.hash = 'deadbeef'.repeat(8);
	ok('a proof whose file hash was altered is TAMPERED', vdisk.verifyFileProof(bent).verdict === 'TAMPERED');
	// Tamper: a forged baseline signature -> TAMPERED.
	const bent2 = JSON.parse(JSON.stringify(proof)); bent2.baseline.seq = (bent2.baseline.seq || 0) + 99;
	ok('a proof with an altered signed header is TAMPERED', vdisk.verifyFileProof(bent2).verdict === 'TAMPERED');

	// The SELF-CONTAINED verifier (stock Node) agrees on a pristine proof and on a tampered one.
	const standalone = require('../verify-bundle');
	ok('the standalone verifier agrees a pristine file proof is GENUINE', standalone.verifyFileProof(proof).verdict === 'GENUINE');
	ok('the standalone verifier also reports TAMPERED for the altered proof', standalone.verifyFileProof(bent).verdict === 'TAMPERED');

	let absent = false; try { await vdisk.fileProof(v, { password: 'pw1', path: 'nope.txt' }); } catch (_) { absent = true; }
	ok('proving a file that is not in the snapshot is refused', absent);
	await vdisk.removeKnownVault(v).catch(() => {});
}

async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-fileproof-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	await primitives();
	await endToEnd();
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FILE-PROOF CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}
main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
