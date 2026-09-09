'use strict';
// lib/test/bundle.js — portable, third-party-verifiable proof bundles. make-bundle packages a hash-only proof
// (manifest + signed baseline + succession + attestations + genesis anchor); verify-bundle re-checks it OFFLINE
// with no vault and no password and returns GENUINE / TAMPERED / ROLLED-BACK. Needs the engine (no mount
// driver; no network — attestation is not exercised here).
//
// Run:  node lib/test/bundle.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-bundle-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;                       // isolate the rollback ledger
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'contract.txt'), 'the agreement');
	const v = path.join(tmp, 'Case.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	await vdisk.snapshot(v, { password: 'pw1' });

	const out = path.join(tmp, 'proof');
	const b = await vdisk.makeBundle(v, { password: 'pw1', outDir: out });
	ok('a bundle is written with an identity and fingerprint', !!(b.identity && b.fingerprint));
	ok('the bundle carries the hash-only proof files', ['manifest.json', 'baseline.json', 'succession.json', 'attestations.json', 'genesis.json'].every(f => fs.existsSync(path.join(out, f))));

	// A pristine bundle verifies as GENUINE, offline, with no password.
	const good = await vdisk.verifyBundle(out);
	ok('a pristine bundle verifies as GENUINE', good.verdict === 'GENUINE');
	ok('the structural checks all pass', good.checks.every(c => c.ok));

	// The SELF-CONTAINED verifier (stock Node, no install) agrees, and is copied into the bundle.
	const standalone = require('../verify-bundle');
	ok('a stock-Node verify.js was copied into the bundle', fs.existsSync(path.join(out, 'verify.js')));
	ok('the standalone verifier agrees the pristine bundle is GENUINE', standalone.verifyBundle(out).verdict === 'GENUINE');
	const { execFileSync } = require('child_process');
	let cliVerdict = ''; try { cliVerdict = execFileSync(process.execPath, [path.join(out, 'verify.js'), out], { encoding: 'utf8' }); } catch (e) { cliVerdict = (e.stdout || '') + (e.message || ''); }
	ok('running "node verify.js <bundle>" prints GENUINE', /Verdict:\s*GENUINE/.test(cliVerdict));

	// Tampering the recorded file set breaks the signed Merkle root -> TAMPERED.
	const baseline = JSON.parse(await fsp.readFile(path.join(out, 'baseline.json'), 'utf8'));
	const orig = JSON.stringify(baseline);
	if (baseline.files && baseline.files[0]) baseline.files[0].hash = 'deadbeef'.repeat(8);
	await fsp.writeFile(path.join(out, 'baseline.json'), JSON.stringify(baseline));
	const tampered = await vdisk.verifyBundle(out);
	ok('a bundle with an altered file set is TAMPERED', tampered.verdict === 'TAMPERED' && tampered.checks.some(c => c.name === 'content-root' && !c.ok));
	ok('the standalone verifier also reports TAMPERED', require('../verify-bundle').verifyBundle(out).verdict === 'TAMPERED');
	await fsp.writeFile(path.join(out, 'baseline.json'), orig); // restore

	// Substituting the published verify key breaks the baseline signature -> TAMPERED.
	const manifest = JSON.parse(await fsp.readFile(path.join(out, 'manifest.json'), 'utf8'));
	const mOrig = JSON.stringify(manifest);
	manifest.integrity.pubkey = require('crypto').randomBytes(32).toString('hex');
	await fsp.writeFile(path.join(out, 'manifest.json'), JSON.stringify(manifest));
	const sub = await vdisk.verifyBundle(out);
	ok('a bundle with a substituted verify key is TAMPERED', sub.verdict === 'TAMPERED');
	await fsp.writeFile(path.join(out, 'manifest.json'), mOrig); // restore
	ok('the restored bundle verifies GENUINE again', (await vdisk.verifyBundle(out)).verdict === 'GENUINE');

	// REFUSE FORWARD: a bundle whose baseline was written by a NEWER version binds fields this verifier does not know,
	// so a naive check would fail the signature and wrongly print TAMPERED. Both verifiers must instead say UNVERIFIED
	// ("made by a newer version — update"), so a legitimate newer bundle is never branded as tampered.
	const nb = JSON.parse(await fsp.readFile(path.join(out, 'baseline.json'), 'utf8'));
	await fsp.writeFile(path.join(out, 'baseline.json'), JSON.stringify({ ...nb, version: (nb.version || 4) + 1 }));
	const newerMain = await vdisk.verifyBundle(out);
	ok('a newer-version bundle is UNVERIFIED, not TAMPERED (main verifier)', newerMain.verdict === 'UNVERIFIED' && newerMain.checks.some(c => c.name === 'bundle-format' && !c.ok));
	ok('the standalone verifier also reports UNVERIFIED for a newer-version bundle', require('../verify-bundle').verifyBundle(out).verdict === 'UNVERIFIED');
	await fsp.writeFile(path.join(out, 'baseline.json'), orig); // restore
	ok('the restored bundle verifies GENUINE again after the newer-version check', (await vdisk.verifyBundle(out)).verdict === 'GENUINE');

	// REFUSE FORWARD, part 2: the manifest seal, the attestation and succession stores, and the genesis anchor each
	// carry their OWN format version, bumpable independently of the baseline version. A newer one binds under rules
	// this build does not know, so both verifiers must report UNVERIFIED — never a false TAMPERED — and never silently
	// GENUINE. This future-proofs the portable trust tool: a later build can evolve any one of these structures without
	// the shipped verifier branding a legitimate newer bundle as tampered.
	const std = require('../verify-bundle');
	const bumpField = async (file, mutate) => {
		const p = path.join(out, file); const before = await fsp.readFile(p, 'utf8');
		const obj = JSON.parse(before); mutate(obj); await fsp.writeFile(p, JSON.stringify(obj));
		const main = await vdisk.verifyBundle(out); const alone = std.verifyBundle(out);
		await fsp.writeFile(p, before); // restore
		return { main, alone };
	};
	for (const [label, file, mutate] of [
		['manifest seal', 'manifest.json', (o) => { o.integrity.sealVersion = 99; }],
		['attestation store', 'attestations.json', (o) => { o.version = 99; }],
		['succession store', 'succession.json', (o) => { o.version = 99; }],
		['genesis anchor', 'genesis.json', (o) => { o.v = 99; }],
	]) {
		const r = await bumpField(file, mutate);
		ok('a newer ' + label + ' is UNVERIFIED, not TAMPERED (main verifier)', r.main.verdict === 'UNVERIFIED' && r.main.checks.some(c => c.name === 'bundle-format' && !c.ok));
		ok('a newer ' + label + ' is UNVERIFIED in the standalone verifier too', r.alone.verdict === 'UNVERIFIED');
	}
	ok('the bundle verifies GENUINE again after the per-structure newer-version checks', (await vdisk.verifyBundle(out)).verdict === 'GENUINE');

	// After a rotation, the bundle's succession still anchors the new identity to the original -> GENUINE.
	await vdisk.rotate(v, { password: 'pw1', reason: 'test' });
	const out2 = path.join(tmp, 'proof2');
	await vdisk.makeBundle(v, { password: 'pw1', outDir: out2 });
	const rotated = await vdisk.verifyBundle(out2);
	ok('a bundle from a rotated vault verifies GENUINE (succession anchored to the original identity)', rotated.verdict === 'GENUINE' && rotated.checks.some(c => c.name === 'identity-succession' && c.ok));
	ok('the rotated bundle reports the ORIGINAL identity as its origin', rotated.originIdentity === b.identity);

	// Origin anchor: the recorded original identity (from before the rotation) must be in the verified lineage.
	const okOrigin = await vdisk.verifyBundle(out2, { expectIdentity: b.identity });
	ok('verifying with the correct recorded origin identity is GENUINE', okOrigin.verdict === 'GENUINE' && okOrigin.checks.some(c => c.name === 'origin-identity' && c.ok));
	const wrongOrigin = await vdisk.verifyBundle(out2, { expectIdentity: 'AAAAA-BBBBB-CCCCC-DDDDD' });
	ok('a WRONG recorded origin identity fails (a different vault or a fabricated lineage)', wrongOrigin.verdict === 'TAMPERED' && wrongOrigin.checks.some(c => c.name === 'origin-identity' && !c.ok));
	// The standalone verifier takes the same origin argument.
	ok('the standalone verifier accepts the origin identity and agrees GENUINE', require('../verify-bundle').verifyBundle(out2, b.identity).verdict === 'GENUINE');
	ok('the standalone verifier rejects a wrong origin identity', require('../verify-bundle').verifyBundle(out2, 'AAAAA-BBBBB-CCCCC-DDDDD').verdict === 'TAMPERED');

	// Regression: an attestation FIRST made after a key rotation is anchored to the identity it was made under
	// (not the vault's original genesis identity). Both verifiers must accept such a chain as GENUINE. Anchoring
	// to the genesis identity instead wrongly read the chain as TAMPERED. We synthesize the chain structurally
	// (the token bytes only feed the chain hash; their trusted-time signature is checked separately and is
	// irrelevant to the chain linkage this regresses).
	const sha = (...parts) => { const h = require('crypto').createHash('sha256'); for (const p of parts) h.update(p); return h.digest('hex'); };
	const attGenesis = (id) => sha('vault-attest-genesis-v1\n', String(id));
	const attDigest = (id, root, seq) => sha('vault-attest-v1\n', String(id) + '\n' + String(root) + '\n' + String(seq));
	const attChain = (prev, dHex, tHex) => sha('vault-attest-chain-v1\n', String(prev) + '\n' + String(dHex) + '\n' + String(tHex));
	const bl2 = JSON.parse(await fsp.readFile(path.join(out2, 'baseline.json'), 'utf8'));
	const man2 = JSON.parse(await fsp.readFile(path.join(out2, 'manifest.json'), 'utf8'));
	const idNew = require('../Integrity').identity(man2.integrity.pubkey); // the ROTATED (current) identity — differs from genesis
	const token = Buffer.from('not-a-real-token-just-bytes').toString('base64');
	const tHash = sha(Buffer.from(token, 'base64'));
	const dHex = attDigest(idNew, bl2.merkleRoot, bl2.seq);
	const prev0 = attGenesis(idNew);
	const attStore = { items: [{ at: new Date().toISOString(), identity: idNew, root: bl2.merkleRoot, seq: bl2.seq, digest: dHex, prev: prev0, chain: attChain(prev0, dHex, tHash), token }] };
	await fsp.writeFile(path.join(out2, 'attestations.json'), JSON.stringify(attStore));
	const anchored = await vdisk.verifyBundle(out2, { expectIdentity: b.identity });
	ok('an attestation first made after a rotation keeps the chain intact (in-repo verifier)', anchored.checks.some(c => c.name === 'attestation-chain' && c.ok) && anchored.verdict === 'GENUINE');
	const anchoredStd = require('../verify-bundle').verifyBundle(out2, b.identity);
	ok('the standalone verifier accepts the same post-rotation attestation chain', anchoredStd.checks.some(c => c.name === 'attestation-chain' && c.ok) && anchoredStd.verdict === 'GENUINE');

	// Regression: the succession record's signature algorithm is part of the signed input, so swapping `alg`
	// (an algorithm-substitution attempt) breaks the signature and the bundle reads as TAMPERED, not GENUINE.
	const succPath = path.join(out2, 'succession.json');
	const succ = JSON.parse(await fsp.readFile(succPath, 'utf8'));
	succ.items[0].alg = 'rsa'; // was 'ed25519' — a downgrade an attacker might attempt
	await fsp.writeFile(succPath, JSON.stringify(succ));
	ok('swapping the succession signature algorithm is rejected (alg is signed)', (await vdisk.verifyBundle(out2, { expectIdentity: b.identity })).checks.some(c => c.name === 'identity-succession' && !c.ok));
	ok('the standalone verifier also rejects a swapped succession algorithm', require('../verify-bundle').verifyBundle(out2, b.identity).checks.some(c => c.name === 'identity-succession' && !c.ok));

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BUNDLE CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
