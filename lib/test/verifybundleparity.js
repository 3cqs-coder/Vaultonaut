'use strict';
// lib/test/verifybundleparity.js — the standalone, dependency-free verify-bundle.js re-vendors several cryptographic
// primitives from Integrity.js (on purpose, so it can be pasted anywhere and still verify a bundle years later). If
// one copy ever drifts from the other, the standalone verifier could return GENUINE where the main tool returns
// TAMPERED (or vice versa). The end-to-end bundle test guards the verdicts; this guards the PRIMITIVES directly, so a
// future edit to merkleRoot / identity / fingerprint / signingInput on one side that is not mirrored on the other is
// caught immediately. Pure, no engine.
//
// Run:  node lib/test/verifybundleparity.js

const crypto = require('crypto');
const Integrity = require('../Integrity');
const Kdf = require('../Kdf');
const { _primitives: vb } = require('../verify-bundle');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// merkleRoot over random file sets (varied sizes, unicode paths, missing size/hash, duplicates by path).
	for (let t = 0; t < 40; t++) {
		const n = Math.floor(Math.random() * 12);
		const files = [];
		for (let i = 0; i < n; i++) {
			files.push({
				path: 'dir/' + crypto.randomBytes(3).toString('hex') + (Math.random() < 0.3 ? '/ünîçødé' : '') + '.bin',
				size: Math.random() < 0.2 ? null : Math.floor(Math.random() * 1e9),
				hash: Math.random() < 0.2 ? null : crypto.randomBytes(32).toString('hex'),
			});
		}
		const a = await Integrity.merkleRoot(files);
		const b = vb.merkleRoot(files);
		if (a !== b) { ok('merkleRoot parity (iteration ' + t + ')', false); break; }
	}
	if (!failures) ok('merkleRoot is byte-identical across the two implementations (40 random sets)', true);
	ok('merkleRoot parity on the empty set', (await Integrity.merkleRoot([])) === vb.merkleRoot([]));

	// A single-file proof is BUILT only by the main tool (Integrity.merkleProof) but must VERIFY on the standalone
	// side (vb.verifyMerkleProof) exactly as it does in the tool — otherwise a shareable file proof could read GENUINE
	// on one and TAMPERED on the other. Build a proof for every file across several tree shapes and confirm both the
	// tool's and the vendored verifier accept it, and that the vendored fileLeafHex matches the tool's.
	let mpOk = true;
	for (let n = 1; n <= 9 && mpOk; n++) {
		const files = [];
		for (let i = 0; i < n; i++) files.push({ path: 'd/f' + i, size: i * 7, hash: crypto.randomBytes(32).toString('hex') });
		const root = await Integrity.merkleRoot(files);
		for (const f of files) {
			const pr = await Integrity.merkleProof(files, f.path);
			const leafI = Integrity.fileLeafHex(f), leafV = vb.fileLeafHex(f);
			if (leafI !== leafV) { mpOk = false; break; }
			if (!pr || pr.root !== root) { mpOk = false; break; }
			if (!Integrity.verifyMerkleProof(leafI, pr.proof, root) || !vb.verifyMerkleProof(leafV, pr.proof, root)) { mpOk = false; break; }
			// A bent root must fail on BOTH.
			if (Integrity.verifyMerkleProof(leafI, pr.proof, 'ab'.repeat(32)) || vb.verifyMerkleProof(leafV, pr.proof, 'ab'.repeat(32))) { mpOk = false; break; }
		}
	}
	ok('fileLeafHex + Merkle inclusion proofs verify byte-identically on both implementations', mpOk);

	// identity and fingerprint over random public keys / roots.
	let idOk = true, fpOk = true;
	for (let t = 0; t < 50; t++) {
		const pub = crypto.randomBytes(32).toString('hex');
		if (Integrity.identity(pub) !== vb.identity(pub)) { idOk = false; break; }
		const root = crypto.randomBytes(32).toString('hex');
		if (Integrity.fingerprint(root) !== vb.fingerprint(root)) { fpOk = false; break; }
	}
	ok('identity is byte-identical across the two implementations', idOk);
	ok('fingerprint is byte-identical across the two implementations', fpOk);
	ok('identity of a null key matches (both null)', Integrity.identity(null) === vb.identity(null));

	// signingInput for both v3 (no seal/deep binding) and v4+ (seal/deep bound) records.
	let siOk = true;
	for (let t = 0; t < 50; t++) {
		const f = {
			scheme: Integrity.SCHEME, root: crypto.randomBytes(32).toString('hex'), seq: Math.floor(Math.random() * 1000),
			prevRoot: Math.random() < 0.5 ? crypto.randomBytes(32).toString('hex') : null, count: Math.floor(Math.random() * 500),
			createdAt: new Date(Math.floor(Math.random() * 2e12)).toISOString(), version: Math.random() < 0.5 ? 3 : 4,
			sealed: Math.random() < 0.5, deep: Math.random() < 0.5,
		};
		if (Integrity.signingInput(f) !== vb.signingInput(f)) { siOk = false; break; }
	}
	ok('signingInput is byte-identical across the two implementations (v3 and v4)', siOk);

	// levelOf governs the LEGACY (v1) manifest-seal input. It must be byte-identical to Kdf.levelOf, or the standalone
	// verifier could report GENUINE where the main tool reports TAMPERED on a mutated-KDF-param manifest. Cover the
	// genuine presets, the exact drift case (a preset's iterations/parallelism lowered while the label + memKiB are
	// kept — must resolve to 'custom', NOT the label), and random params.
	let levOk = true;
	const presets = Object.entries(Kdf.LEVELS);
	for (const [name, p] of presets) {
		const genuine = { ...p, level: name, salt: 'x' };
		if (Kdf.levelOf(genuine) !== name || vb.levelOf(genuine) !== name || Kdf.levelOf(genuine) !== vb.levelOf(genuine)) { levOk = false; break; }
		// The mutation the parity guard exists to catch: keep the label + memKiB, lower iterations.
		const mutated = { ...p, iterations: p.iterations + 1, level: name, salt: 'x' };
		if (Kdf.levelOf(mutated) !== 'custom' || vb.levelOf(mutated) !== 'custom') { levOk = false; break; }
	}
	for (let t = 0; t < 60 && levOk; t++) {
		const params = { memKiB: [65536, 262144, 524288, 40000][Math.floor(Math.random() * 4)], iterations: 1 + Math.floor(Math.random() * 5), parallelism: 1 + Math.floor(Math.random() * 5), level: ['standard', 'high', 'max', 'custom', undefined][Math.floor(Math.random() * 5)] };
		if (Kdf.levelOf(params) !== vb.levelOf(params)) { levOk = false; }
	}
	ok('levelOf is byte-identical to Kdf.levelOf (presets, the mutated-param drift case, and random params)', levOk);
	ok('levelOf ignores the label and matches by all three cost params', vb.levelOf({ memKiB: 65536, iterations: 1, parallelism: 4, level: 'standard' }) === 'custom');

	// sealTag governs the current (v3) manifest-seal input; it must be byte-identical to Kdf.sealTag over all fields.
	let stOk = true;
	for (let t = 0; t < 60; t++) {
		const p = { algo: Math.random() < 0.5 ? 'argon2id' : undefined, v: 1, memKiB: Math.floor(Math.random() * 600000), iterations: 1 + Math.floor(Math.random() * 6), parallelism: 1 + Math.floor(Math.random() * 6), hashLen: 32, salt: crypto.randomBytes(8).toString('base64') };
		if (Kdf.sealTag(p) !== vb.sealTag(p)) { stOk = false; break; }
	}
	ok('sealTag is byte-identical to Kdf.sealTag', stOk && Kdf.sealTag(undefined) === vb.sealTag(undefined));

	// keySlotsOf must read both shapes the manifest can take (an array of slots, or the single-slot wrappedKey/kdf
	// form) identically to how the writer produced them, so the composed manifest-seal input can never diverge.
	const arrCrypt = { keySlots: [{ id: 'a', kdf: { memKiB: 65536 }, wrappedKey: 'AA' }] };
	const singleCrypt = { wrappedKey: 'BB', kdf: { memKiB: 65536 } };
	ok('keySlotsOf reads an explicit slot array', vb.keySlotsOf(arrCrypt).length === 1 && vb.keySlotsOf(arrCrypt)[0].id === 'a');
	ok('keySlotsOf reads the single-slot shape', vb.keySlotsOf(singleCrypt).length === 1 && vb.keySlotsOf(singleCrypt)[0].id === 'primary');
	ok('keySlotsOf returns nothing for an empty crypt', vb.keySlotsOf({}).length === 0);

	// The standalone verifier ALSO re-vendors the seal / succession / attestation input-builders and the Ed25519
	// verify — the functions that actually decide the GENUINE/TAMPERED verdict on a bundle. A drift in any of them is
	// exactly what this guard exists to catch, yet they were previously exercised only by the engine-gated end-to-end
	// bundle test. Assert byte-parity against the canonical Vault.js copies (exposed via Vault._sealParity).
	const V = require('../Vault')._sealParity;
	const vp = require('../verify-bundle')._sealParity;

	let succOk = true;
	for (let t = 0; t < 30; t++) {
		const b = { v: 1, alg: 'ed25519', prev: Math.random() < 0.5 ? crypto.randomBytes(16).toString('hex') : null, oldIdentity: crypto.randomBytes(8).toString('hex'), oldPubkey: crypto.randomBytes(32).toString('hex'), newIdentity: crypto.randomBytes(8).toString('hex'), newPubkey: crypto.randomBytes(32).toString('hex'), timestamp: new Date(Math.floor(Math.random() * 2e12)).toISOString(), reason: Math.random() < 0.5 ? 'rotation' : '' };
		if (V.successionInput(b) !== vp.successionInput(b)) { succOk = false; break; }
	}
	ok('successionInput is byte-identical across the two implementations', succOk);

	let attOk = true;
	for (let t = 0; t < 30; t++) {
		const id = crypto.randomBytes(8).toString('hex'), root = crypto.randomBytes(32).toString('hex'), seq = Math.floor(Math.random() * 1000), b64 = crypto.randomBytes(20).toString('base64');
		// Compare at the HEX level that lands on disk / in the chain: Vault.attestDigest returns raw bytes (its caller
		// hexes them) while the standalone copy returns hex directly, and Vault.tokenHashOf takes raw bytes while the
		// standalone takes base64 — so normalize the inputs, then the produced hex must be byte-identical.
		const digHex = V.attestDigest(id, root, seq).toString('hex');
		const tHash = V.tokenHashOf(Buffer.from(b64, 'base64'));
		const prev = Math.random() < 0.5 ? crypto.randomBytes(32).toString('hex') : null;
		if (V.attestGenesis(id) !== vp.attestGenesis(id) || digHex !== vp.attestDigest(id, root, seq)
			|| tHash !== vp.tokenHashOf(b64)
			|| V.attestChainHash(prev, digHex, tHash) !== vp.attestChainHash(prev, digHex, tHash)) { attOk = false; break; }
	}
	ok('attestGenesis / attestDigest / attestChainHash / tokenHashOf are byte-identical (at the on-disk hex level)', attOk);

	// manifestSealInput (the single current v3 form) over representative manifests, including a MEMBER slot (which must
	// be excluded from the seal) alongside passphrase-family slots with varied KDF params and recoveryVersion values.
	const keypair = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));
	let mseOk = true;
	for (let t = 0; t < 20; t++) {
		const kdf = () => ({ algo: 'argon2id', v: 1, memKiB: [65536, 262144][t % 2], iterations: 1 + (t % 4), parallelism: 1 + (t % 3), hashLen: 32, salt: crypto.randomBytes(12).toString('base64') });
		// Vary recoveryVersion too, since it is now folded into the seal input — the two implementations must agree on it.
		const manifest = { recoveryVersion: t % 3 === 0 ? undefined : t, integrity: { scheme: Integrity.SCHEME, pubkey: keypair.pub }, crypt: { salt: crypto.randomBytes(16).toString('base64'), keySlots: [
			{ id: 'primary', kind: 'password', wrappedKey: crypto.randomBytes(48).toString('base64'), kdf: kdf() },
			{ id: 'reader', kind: 'readonly', wrappedKey: crypto.randomBytes(48).toString('base64'), kdf: kdf() },
			{ id: 'dev1', kind: 'member', wrappedKey: crypto.randomBytes(48).toString('base64'), kdf: kdf() } ] } };
		if (V.manifestSealInput(manifest) !== vp.manifestSealInput(manifest)) { mseOk = false; break; }
	}
	ok('manifestSealInput (v3, incl. recoveryVersion) is byte-identical across both implementations', mseOk);

	// verify (Ed25519) + manifestSealVerifies end-to-end: a genuine seal verifies on both, a tampered one fails on both.
	{
		const manifest = { integrity: { scheme: Integrity.SCHEME, pubkey: keypair.pub }, crypt: { salt: 'S', keySlots: [{ id: 'primary', kind: 'password', wrappedKey: 'AA', kdf: { algo: 'argon2id', v: 1, memKiB: 65536, iterations: 3, parallelism: 4, hashLen: 32, salt: 's' } }] } };
		const sig = Integrity.sign(keypair.priv, V.manifestSealInput(manifest));
		ok('a genuine seal verifies on both, and verify rejects a wrong payload on both', V.manifestSealVerifies(manifest, keypair.pub, sig) === true && vp.manifestSealVerifies(manifest, keypair.pub, sig) === true && Integrity.verify(keypair.pub, 'x', sig) === false && vp.verify(keypair.pub, 'x', sig) === false);
		const tampered = JSON.parse(JSON.stringify(manifest)); tampered.crypt.salt = 'S2';
		ok('a tampered manifest fails the seal on both implementations', V.manifestSealVerifies(tampered, keypair.pub, sig) === false && vp.manifestSealVerifies(tampered, keypair.pub, sig) === false);
	}

	// rosterSealInput (the owner-key seal over the membership roster) must be byte-identical too — member slots are
	// excluded from the manifest seal because THIS signature covers them, so the two verifiers must agree on it or a
	// team vault's bundle could read GENUINE on one and TAMPERED on the other.
	{
		let rsOk = true;
		for (let t = 0; t < 12; t++) {
			const manifest = { members: { epoch: t, keyGeneration: t % 3, ownerPubKey: keypair.pub, recovery: t % 2 ? { k: 2, n: 3, trustees: [{ fp: 'fp' + t, sealed: 'sealed' + t }, { fp: 'fp' + (t + 1), sealed: 's' + t }] } : undefined },
				crypt: { keySlots: [
					{ id: 'm1', kind: 'member', role: 'read', owner: t % 2 === 0, pubFp: 'p' + t, sealed: 'S' + t },
					{ id: 'm2', kind: 'member', role: 'write', pubFp: 'q' + t, sealed: 'T' + t },
					{ id: 'primary', kind: 'password', wrappedKey: 'AA' } ] } };
			if (V.rosterSealInput(manifest) !== vp.rosterSealInput(manifest)) { rsOk = false; break; }
		}
		ok('rosterSealInput is byte-identical across both implementations', rsOk);
		// End-to-end: a genuine owner-signed roster verifies on both; adding a member slot breaks it on both.
		const roster = { members: { epoch: 4, keyGeneration: 1, ownerPubKey: keypair.pub }, crypt: { keySlots: [{ id: 'm1', kind: 'member', role: 'read', owner: true, pubFp: 'p', sealed: 'S' }] } };
		roster.members.sig = Integrity.sign(keypair.priv, V.rosterSealInput(roster));
		ok('a genuine roster verifies on both implementations', V.verifyRoster(roster) === true && vp.rosterVerifies(roster) === true);
		const forged = JSON.parse(JSON.stringify(roster)); forged.crypt.keySlots.push({ id: 'evil', kind: 'member', role: 'write', pubFp: 'x', sealed: 'X' });
		ok('a forged extra member slot fails the roster on both implementations', V.verifyRoster(forged) === false && vp.rosterVerifies(forged) === false);
		// A vault with no members section is not a failure on either (rosterVerifies returns true; verifyRoster returns
		// false only because there is nothing to verify — the bundle verifiers gate on presence, so this is consistent).
		ok('an absent roster is treated as no-failure by the standalone verifier', vp.rosterVerifies({}) === true);
	}

	// The refuse-forward version constants and integrity scheme must match between the tool and the standalone verifier.
	// A drift here (e.g. bumping SEAL_VERSION in one file only) would make the shipped verifier false-alarm UNVERIFIED on
	// a genuine current bundle. This is the fast static guard the end-to-end bundle test (engine-gated) cannot be.
	{
		const A = require('../Vault')._bundleVersions, B = require('../verify-bundle')._bundleVersions;
		let vOk = true; const keys = ['BASELINE_VERSION', 'SEAL_VERSION', 'ATTEST_VERSION', 'SUCCESSION_VERSION', 'GENESIS_VERSION', 'FILE_PROOF_VERSION', 'SCHEME'];
		for (const k of keys) { if (A[k] !== B[k]) { vOk = false; console.log('    drift: ' + k + ' Vault=' + A[k] + ' standalone=' + B[k]); } }
		ok('the refuse-forward version constants and scheme match the standalone verifier', vOk);
	}

	// The COMPOSED single-file-proof verdict (verifyFileProof) is hand-duplicated in Vault.js and verify-bundle.js; the
	// end-to-end fileproof test cross-checks them only WITH an engine. Guard the verdict composition itself here, with
	// no engine: craft a fully-signed proof from Integrity alone (a one-file set, so the Merkle root IS the leaf and
	// the inclusion path is empty), then assert both verifiers agree across GENUINE, tampered content, forward-version
	// (UNVERIFIED — the refuse-forward gate), and a wrong expected origin (TAMPERED).
	{
		const Vf = require('../Vault').verifyFileProof, Bf = require('../verify-bundle').verifyFileProof;
		const seed = crypto.randomBytes(32).toString('base64');
		const kp = Integrity.signKeysFromSeed(seed);
		const file = { path: 'doc.txt', size: 123, hash: crypto.randomBytes(32).toString('hex') };
		const leaf = Integrity.fileLeafHex(file);
		const root = await Integrity.merkleRoot([file]); // single leaf: root === leaf
		const header = { scheme: Integrity.SCHEME, root, seq: 7, prevRoot: null, count: 1, createdAt: new Date().toISOString(), version: 4, sealed: false, deep: true };
		const sig = Integrity.sign(kp.priv, Integrity.signingInput(header));
		const id = Integrity.identity(kp.pub);
		const proof = { v: 1, kind: 'file-proof', pubkey: kp.pub, identity: id, originIdentity: id, file, hasContentHash: true, baseline: Object.assign({ sig }, header), proof: [], at: header.createdAt };
		const agree = (label, mutate, expect, expectFlag) => {
			const p = mutate ? mutate(JSON.parse(JSON.stringify(proof))) : proof;
			const rv = Vf(p, expectFlag), rb = Bf(p, expectFlag && expectFlag.expectIdentity); // Vault takes {expectIdentity}; standalone takes the bare id
			ok('verifyFileProof parity — ' + label, rv.verdict === expect && rb.verdict === expect && rv.verdict === rb.verdict);
		};
		agree('a genuine proof is GENUINE on both', null, 'GENUINE');
		agree('a tampered content hash is TAMPERED on both', (p) => { p.file.hash = 'deadbeef'.repeat(8); return p; }, 'TAMPERED');
		agree('a newer format version is UNVERIFIED on both (refuse-forward)', (p) => { p.v = 2; return p; }, 'UNVERIFIED');
		agree('a wrong expected origin is TAMPERED on both', null, 'TAMPERED', { expectIdentity: 'ZZZZZ-ZZZZZ-ZZZZZ' });
		ok('the crafted proof binds content (hasContentHash) on both verifiers', Vf(proof).hasContentHash === true && Bf(proof).hasContentHash === true);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VERIFY-BUNDLE-PARITY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
