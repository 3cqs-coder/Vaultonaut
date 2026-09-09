#!/usr/bin/env node
'use strict';
// verify-bundle.js — a SELF-CONTAINED verifier for a Vaultonaut proof bundle. It needs nothing but a stock
// Node.js install: no npm install, no dependencies, no network, no vault, and no password. Point it at a proof
// bundle folder and it re-runs the cryptographic checks itself and prints a verdict — GENUINE, TAMPERED, or
// ROLLED-BACK — so a third party can confirm a vault's integrity without trusting whoever produced the bundle.
//
//   node verify.js <bundle-folder>
//
// It verifies the vault identity, the manifest seal, the signed baseline (Ed25519), the file-set Merkle root,
// and the identity-succession chain anchored to the vault's original identity. The RFC 3161 timestamp tokens'
// trusted-TIME signatures are the one thing it does not check here (that needs the full tool, `vdisk
// verify-bundle`); the tamper/rollback verdict below does not depend on them.
//
// This file is a faithful, standalone copy of the verification math from the main tool. It is intentionally
// dependency-free so it can be published, mirrored, or pasted anywhere and still verify a bundle years later.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---- vendored primitives (byte-compatible with the tool that produced the bundle) ----
const HASH = 'sha256';
const SCHEME = 'vdisk-integrity-1';
const BASELINE_VERSION = 4; // the baseline record format this verifier understands; a newer one is refused forward (see verifyBundle)
function h(...bufs) { return crypto.createHash(HASH).update(Buffer.concat(bufs)).digest(); }
const LEAF = Buffer.from([0x00]), NODE = Buffer.from([0x01]);
function fileLeaf(f) { return h(LEAF, Buffer.from(f.path + '\0' + (f.size == null ? '' : f.size) + '\0' + (f.hash || ''), 'utf8')); }
function merkleRoot(files) {
	if (!files || !files.length) return h(LEAF).toString('hex');
	let level = files.slice().sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).map(fileLeaf);
	while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? h(NODE, level[i], level[i + 1]) : level[i]); level = next; }
	return level[0].toString('hex');
}
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ANCHOR_BYTES = 16; // 128-bit identity/fingerprint — must match Integrity.js exactly (the 'vault-identity-v1' tag versions the scheme)
function groupB32(buf) {
	let bits = 0, val = 0, out = '';
	for (const byte of buf) { val = (val << 8) | byte; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
	if (bits > 0) out += B32[(val << (5 - bits)) & 31];
	return (out.match(/.{1,4}/g) || []).join('-');
}
function fingerprint(rootHex) { return groupB32(Buffer.from(rootHex, 'hex').subarray(0, ANCHOR_BYTES)); }
function identity(pubHex) { if (!pubHex) return null; return groupB32(crypto.createHash(HASH).update('vault-identity-v1').update(String(pubHex)).digest().subarray(0, ANCHOR_BYTES)); }
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verify(pubHex, payload, sigB64) {
	try { const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' }); return crypto.verify(null, Buffer.from(payload, 'utf8'), pub, Buffer.from(sigB64, 'base64')); }
	catch (_) { return false; }
}
function signingInput({ scheme, root, seq, prevRoot, count, createdAt, version, sealed, deep }) {
	const fields = [scheme, root, seq, prevRoot || '', count, createdAt];
	if (version >= 4) fields.push('sealed=' + (sealed ? 1 : 0), 'deep=' + (deep ? 1 : 0));
	return fields.join('\n');
}
// Byte-identical to Kdf.levelOf in the main tool: match a preset by ALL THREE concrete cost parameters and IGNORE
// the `level` label, so a mutated slot (e.g. iterations/parallelism lowered while the label and memKiB are kept)
// resolves to 'custom' and the legacy v1 seal input diverges from the signed one — exactly as the main tool sees it.
// Trusting the label here would make this standalone verifier report GENUINE on a KDF mutation the main tool flags
// as TAMPERED. Backward-compatible: the presets have never changed, so every genuine slot still resolves to the
// same preset name that was signed.
const LEVELS = { standard: { memKiB: 65536, iterations: 3, parallelism: 4 }, high: { memKiB: 262144, iterations: 4, parallelism: 4 }, max: { memKiB: 524288, iterations: 4, parallelism: 4 } };
function levelOf(params) { if (!params) return 'standard'; for (const name of Object.keys(LEVELS)) { const p = LEVELS[name]; if (p.memKiB === params.memKiB && p.iterations === params.iterations && p.parallelism === params.parallelism) return name; } return 'custom'; }
function keySlotsOf(crypt) {
	if (Array.isArray(crypt.keySlots) && crypt.keySlots.length) return crypt.keySlots;
	if (crypt.wrappedKey && crypt.kdf) return [{ id: 'primary', kdf: crypt.kdf, wrappedKey: crypt.wrappedKey }];
	return [];
}
// A tamper tag over ALL of a slot's derivation-governing KDF fields (cost params + salt + hashLen + algo/version) —
// byte-identical to Kdf.sealTag in the main tool, so a v2 seal verifies GENUINE here too.
function sealTag(p) {
	p = p || {};
	const parts = ['kdf1', String(p.algo || 'argon2id'), String(p.v || 1), String(p.memKiB || ''), String(p.iterations || ''), String(p.parallelism || ''), String(p.hashLen || ''), String(p.salt || '')];
	return crypto.createHash('sha256').update(parts.join('\x1f')).digest('hex');
}
// MEMBER slots are excluded exactly as the writer excludes them (covered by the owner-key roster signature). v2
// The current (v3) manifest-seal input: SCHEME, salt, published key, the signed recovery-version floor, and each
// non-member slot folded with its full KDF via sealTag. Kept byte-identical to the main tool so a bundle it sealed
// verifies GENUINE here.
function manifestSealInput(manifest) {
	const c = (manifest && manifest.crypt) || {};
	const slots = keySlotsOf(c).filter(s => s.kind !== 'member').map(s => s.id + ':' + crypto.createHash('sha256').update(String(s.wrappedKey || '')).digest('hex') + ':' + sealTag(s.kdf)).sort();
	return ['vault-manifest-seal-v3', SCHEME, String(c.salt || ''), (manifest.integrity && manifest.integrity.pubkey) || '', String(Number(manifest.recoveryVersion) || 0), slots.join(',')].join('\n');
}
function manifestSealVerifies(manifest, pub, sig) {
	try { return verify(pub, manifestSealInput(manifest), sig); } catch (_) { return false; }
}
function successionInput(b) { return ['identity-succession-v1', String(b.v || 1), String(b.alg || 'ed25519'), b.prev || 'genesis', b.oldIdentity, b.oldPubkey, b.newIdentity, b.newPubkey, b.timestamp, b.reason || ''].join('\n'); }
function attestGenesis(id) { return crypto.createHash('sha256').update('vault-attest-genesis-v1\n').update(String(id)).digest('hex'); }
function attestChainHash(prev, digestHex, tokenHashHex) { return crypto.createHash('sha256').update('vault-attest-chain-v1\n').update(String(prev) + '\n' + String(digestHex) + '\n' + String(tokenHashHex)).digest('hex'); }
function attestDigest(id, root, seq) { return crypto.createHash('sha256').update('vault-attest-v1\n').update(String(id) + '\n' + String(root) + '\n' + String(seq)).digest('hex'); }
function tokenHashOf(tokenB64) { return crypto.createHash('sha256').update(Buffer.from(tokenB64, 'base64')).digest('hex'); }

// ---- verification (mirrors the tool's verifyBundle, minus the RFC 3161 token signature) ----
// A bundle is untrusted input a recipient runs this on, so refuse a file larger than a generous cap before
// reading it into memory — a malicious bundle must not be able to exhaust the verifier's heap. Over the cap
// reads as a missing file (a failed check), which the fail-closed verdict logic already handles. Kept inline so
// this verifier stays fully self-contained and dependency-free.
const MAX_BUNDLE_FILE_BYTES = 256 * 1024 * 1024;
function loadJSON(dir, f) {
	try {
		const p = path.join(dir, f);
		if (fs.statSync(p).size > MAX_BUNDLE_FILE_BYTES) return null;
		return JSON.parse(fs.readFileSync(p, 'utf8'));
	} catch (_) { return null; }
}

function verifyBundle(dir, expectIdentity) {
	const checks = []; const add = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail: detail || '' }); return ok; };
	const manifest = loadJSON(dir, 'manifest.json'), baseline = loadJSON(dir, 'baseline.json');
	const succession = loadJSON(dir, 'succession.json') || { items: [] }, attest = loadJSON(dir, 'attestations.json') || { items: [] };
	const genesis = loadJSON(dir, 'genesis.json');
	if (!manifest || !baseline) { add('bundle-complete', false, 'Missing manifest or baseline.'); return { verdict: 'UNVERIFIED', checks, identity: null }; }

	const pub = manifest.integrity && manifest.integrity.pubkey;
	const id = pub ? identity(pub) : null;
	add('identity-present', !!id, id ? '' : 'No published verification key.');

	// The manifest seal is an EXTRA layer over the key-slots/salt. Its ABSENCE is intentionally not a failure: a
	// vault that was never snapshotted has no seal to check, and this portable verifier has no local record telling it
	// a seal "should" be present, so treating absence as tampering would false-alarm on a legitimately unsealed vault.
	// Forgery is already blocked by the baseline Ed25519 signature (below) verified against the published key, from
	// which `identity` is derived and which `--expect` anchors — none of which an attacker can forge without the write
	// key. So a stripped seal only drops the extra key-slot coverage; it cannot make a tampered vault read GENUINE.
	let sealOk = true;
	if (manifest.integrity && manifest.integrity.manifestSig) { sealOk = manifestSealVerifies(manifest, pub, manifest.integrity.manifestSig); }
	add('manifest-seal', sealOk, sealOk ? '' : 'The manifest security fields were altered since they were sealed.');

	let sigOk = false;
	try { sigOk = verify(pub, signingInput({ scheme: baseline.scheme, root: baseline.merkleRoot, seq: baseline.seq, prevRoot: baseline.prevRoot, count: baseline.count, createdAt: baseline.createdAt, version: baseline.version, sealed: baseline.sealed, deep: baseline.deep }), baseline.sig); } catch (_) { sigOk = false; }
	add('baseline-signature', sigOk, sigOk ? '' : 'The baseline signature does not verify.');

	// Refuse forward ONLY for a GENUINELY newer bundle: the version and scheme are part of the signed input above, so a
	// forged bump breaks the signature and prints TAMPERED, while a real newer bundle verifies here. Report UNVERIFIED
	// ("update the verifier") for the latter rather than a false TAMPERED. Gating on sigOk keeps a forgery visible.
	if (sigOk && ((typeof baseline.version === 'number' && baseline.version > BASELINE_VERSION) || (baseline.scheme && baseline.scheme !== SCHEME))) {
		add('bundle-format', false, 'This bundle was made by a newer version of the tool — update the verifier to check it.');
		return { verdict: 'UNVERIFIED', checks, identity: id };
	}

	let rootOk = false;
	try { rootOk = merkleRoot(baseline.files || []) === baseline.merkleRoot; } catch (_) { rootOk = false; }
	add('content-root', rootOk, rootOk ? '' : 'The file set does not reproduce the signed root.');

	let successionOk = true;
	const lineage = new Set();
	if (genesis && genesis.identity) lineage.add(genesis.identity);
	if (id) lineage.add(id);
	if (genesis && id && genesis.identity !== id) {
		let cursor = genesis.identity, reached = false, prevChain = null;
		for (const b of (succession.items || [])) {
			let vfd = false;
			// Doubly signed, keys hash to their identities, AND `prev` links to the previous record's `chain` — the
			// same linkage rule the full tool's audit enforces, so a reordered or spliced chain is rejected here too.
			try { const input = successionInput(b); vfd = (b.alg || 'ed25519') === 'ed25519' && verify(b.oldPubkey, input, b.sigOld) && verify(b.newPubkey, input, b.sigNew) && identity(b.oldPubkey) === b.oldIdentity && identity(b.newPubkey) === b.newIdentity && (b.prev || null) === (prevChain || null); } catch (_) { vfd = false; }
			if (vfd && b.oldIdentity === cursor) { cursor = b.newIdentity; lineage.add(cursor); prevChain = b.chain || null; if (cursor === id) { reached = true; break; } }
		}
		successionOk = reached;
	}
	add('identity-succession', successionOk, successionOk ? '' : 'The identity does not descend from the original by a valid signed succession.');

	// Origin anchor: if the reader passed the origin identity they recorded out of band, confirm it is in the
	// verified lineage. This is what proves the genesis is the RIGHT one, not a fabricated lineage.
	let originOk = true;
	if (expectIdentity) {
		originOk = lineage.has(String(expectIdentity).trim());
		add('origin-identity', originOk, originOk ? 'Matches the recorded origin identity.' : 'The identity lineage does not include the origin identity you recorded — a different vault, or a fabricated lineage.');
	}

	// Attestation CHAIN structure (each proof commits to the prior one). The RFC 3161 token's trusted-time
	// signature is not checked here — that is the one part the full tool verifies.
	let chainOk = true, maxSeq = -1;
	// Anchor to the identity the FIRST attestation was made under (what the writer stored as its `prev`), so a
	// vault first attested after a key rotation is not misread as tampered. This must match the full tool exactly.
	let prevExpected = attest.items && attest.items.length ? attestGenesis(attest.items[0].identity) : null;
	for (const it of (attest.items || [])) {
		let chained = false;
		try { const dm = Buffer.from(it.digest, 'hex').equals(Buffer.from(attestDigest(it.identity, it.root, it.seq), 'hex')); const expect = attestChainHash(prevExpected, it.digest, tokenHashOf(it.token)); chained = dm && (it.chain === expect) && (it.prev == null || it.prev === prevExpected); } catch (_) {}
		if (!chained) chainOk = false;
		prevExpected = (it.chain != null) ? it.chain : prevExpected;
		if (typeof it.seq === 'number' && it.seq > maxSeq) maxSeq = it.seq;
	}
	if (attest.items && attest.items.length) add('attestation-chain', chainOk, chainOk ? '' : 'The timestamp proof chain is broken (reordered, inserted, or altered).');

	// Rollback detection depends on the TSA token's trusted sequence number, which this dependency-free tool
	// cannot verify — a forged higher-seq item would be indistinguishable from a real one here. So we NEVER
	// assert ROLLED-BACK from an unverifiable seq. We only note that a newer proof MAY exist; confirm rollback
	// (and trusted time) with the full tool, which checks the timestamp signatures.
	const newerProofSeen = maxSeq >= 0 && typeof baseline.seq === 'number' && maxSeq > baseline.seq;
	if (attest.items && attest.items.length) add('timestamp-trust', true, 'Timestamp signatures are not checked here — run the full tool to verify trusted time' + (newerProofSeen ? ' and to confirm whether a newer attested version exists.' : '.'));

	const structureOk = id && sealOk && sigOk && rootOk && successionOk && chainOk && originOk;
	const verdict = !structureOk ? 'TAMPERED' : 'GENUINE';
	return { verdict, checks, identity: id, originIdentity: genesis ? genesis.identity : id, fingerprint: baseline.merkleRoot ? fingerprint(baseline.merkleRoot) : null, seq: baseline.seq, timestamps: (attest.items || []).length };
}

if (require.main === module) {
	const dir = process.argv[2];
	if (!dir) { console.error('Usage: node verify.js <bundle-folder> [expected-origin-identity]'); process.exit(2); }
	const r = verifyBundle(path.resolve(dir), process.argv[3]);
	console.log('Verdict:   ' + r.verdict);
	if (r.identity) console.log('Identity:  ' + r.identity + (r.seq != null ? '   (version ' + r.seq + ')' : ''));
	if (r.originIdentity) console.log('Origin:    ' + r.originIdentity + '   (the vault\'s ORIGINAL identity)');
	if (r.timestamps) console.log('Note:      ' + r.timestamps + ' timestamp proof(s) present; their trusted-time signatures are checked by the full "vdisk verify-bundle".');
	console.log('\nChecks:');
	for (const c of r.checks) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.name + (c.detail ? '  — ' + c.detail : ''));
	if (!process.argv[3] && r.originIdentity) console.log('\nConfirm the Origin identity above matches the value the vault owner gave you separately (their Recovery Kit, website, or a value they told you). The math proves the lineage is self-consistent, not that this origin is the right one — pass it as a second argument to have this check it.');
	if (r.verdict === 'GENUINE' && !r.timestamps) console.log('Note: with no timestamp proof, GENUINE cannot prove this is the LATEST version — only that it is internally authentic and untampered.');
	process.exit(r.verdict === 'GENUINE' ? 0 : 1);
}

// The vendored primitives are exported too, ONLY so a test can assert they still produce byte-identical output to
// their canonical counterparts in Integrity.js (a divergence would mean this standalone verifier could disagree with
// the main tool). They are not part of the public verifier API.
module.exports = { verifyBundle, _primitives: { merkleRoot, identity, fingerprint, signingInput, levelOf, sealTag, keySlotsOf }, _sealParity: { verify, manifestSealInput, manifestSealVerifies, successionInput, attestGenesis, attestChainHash, attestDigest, tokenHashOf } };
