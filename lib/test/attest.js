'use strict';
// lib/test/attest.js — provable, timestamped attestation (RFC 3161). The DER request/response encoding
// and the token binding check are exercised offline against a synthetic token we build here, so the
// parser is covered deterministically with no network. A live check against a public TSA runs when the
// network is reachable and is skipped (not failed) otherwise, and the same for the end-to-end vault
// attestation, which also needs the bundled engine.
//
// Run:  node lib/test/attest.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const Attest = require('../Attest');
const Common = require('../Common');
const vdisk = require('../index');
const D = Attest._der;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Build a synthetic RFC 3161 TimeStampToken (CMS SignedData wrapping a TSTInfo) that certifies `digest`
// at `genTimeStr`. Only the fields readToken needs are populated — enough to test the parser end to end.
function fakeToken(digest, genTimeStr) {
	const SHA256 = Attest.SHA256_OID;
	const algId = D.encSeq(D.encOid(SHA256), D.encNull());
	const messageImprint = D.encSeq(algId, D.encOctet(digest));
	const genTime = D.tlv(0x18, Buffer.from(genTimeStr, 'latin1')); // GeneralizedTime
	const tstInfo = D.encSeq(
		D.encInt(1),                       // version
		D.encOid('1.2.3.4.1'),             // policy
		messageImprint,
		D.encInt(Buffer.from([0x2a])),     // serial
		genTime,
	);
	const eContent = D.encOctet(tstInfo);
	const encap = D.encSeq(D.encOid('1.2.840.113549.1.9.16.1.4'), D.tlv(0xA0, eContent)); // id-ct-TSTInfo, [0] eContent
	const signedData = D.encSeq(D.encInt(3), D.tlv(0x31, algId), encap);                  // version, digestAlgorithms SET, encapContentInfo
	return D.encSeq(D.encOid('1.2.840.113549.1.7.2'), D.tlv(0xA0, signedData));           // ContentInfo { signedData, [0] SignedData }
}

let workspace = null;
let isoData = null;
async function main() {
	// Isolate the global data dir (settings, rollback ledger, known-vaults state) into a throwaway dir so the
	// test is hermetic — in particular it must not pick up the machine's own `autoAttest` setting, which would
	// fire background auto-attestations and change the proof count. binDir() is ROOT-based, so the engine still
	// resolves after this redirect.
	isoData = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-attest-data-'));
	Common.dataDir = () => isoData;
	Common.statePath = () => path.join(isoData, 'state.json');

	// --- Request encoding round-trips (offline) ---
	const digest = crypto.createHash('sha256').update('hello vault').digest();
	const reqDer = Attest.buildRequest(digest, { nonce: Buffer.from('0123456789abcdef', 'hex') });
	const root = D.readTLV(reqDer, 0);
	const kids = D.children(reqDer, root.start, root.end);
	ok('request is a SEQUENCE', root.tag === 0x30);
	ok('request version is 1', reqDer[kids[0].start] === 1);
	const mi = D.children(reqDer, kids[1].start, kids[1].end); // messageImprint
	const alg = D.children(reqDer, mi[0].start, mi[0].end);
	ok('request names SHA-256', D.decodeOid(reqDer.subarray(alg[0].start, alg[0].end)) === Attest.SHA256_OID);
	ok('request carries our exact digest', reqDer.subarray(mi[1].start, mi[1].end).equals(digest));

	// --- Token parsing + binding (offline, synthetic token) ---
	const tok = fakeToken(digest, '20260901120000Z');
	const info = Attest.readToken(tok);
	ok('a token is readable', !!info);
	ok('the certified imprint matches our digest', info && info.imprintHex === digest.toString('hex'));
	ok('the certified time is parsed', info && info.genTime && info.genTime.toISOString() === '2026-09-01T12:00:00.000Z');
	const good = Attest.verifyBinding(tok, digest);
	ok('verifyBinding accepts a matching digest', good.ok === true);
	const bad = Attest.verifyBinding(tok, crypto.createHash('sha256').update('other').digest());
	ok('verifyBinding rejects a different digest', bad.ok === false && bad.reason === 'imprint-mismatch');
	const garbage = Attest.verifyBinding(Buffer.from('not der', 'utf8'), digest);
	ok('verifyBinding fails closed on garbage', garbage.ok === false);

	// --- Live TSA + FULL verification (skipped when offline) ---
	let liveToken = null;
	try {
		const r = await Attest.timestamp(digest, { timeoutMs: 20000 });
		liveToken = r.token;
		ok('a live TSA returns a token certifying our digest', Attest.verifyBinding(r.token, digest).ok === true);
		ok('a live TSA returns a real signed time', r.genTime instanceof Date && !isNaN(r.genTime));
		// Full authenticity: signature + timestamping-EKU + ESSCertID + chain to a trusted root.
		const full = Attest.verifyToken(r.token, { digest });
		ok('the default authority token FULLY verifies (chain to a trusted root)', full.ok === true);
		// Tamper the signed content -> must fail (the signature no longer covers it).
		const t1 = Buffer.from(r.token); t1[Math.floor(t1.length * 0.05)] ^= 1;
		ok('a token with tampered content fails full verification', Attest.verifyToken(t1, { digest }).ok === false);
		// A different digest -> imprint mismatch.
		ok('full verification rejects a different digest', Attest.verifyToken(r.token, { digest: crypto.createHash('sha256').update('x').digest() }).ok === false);
	} catch (e) { console.log('  skip  live TSA check (' + (e && e.message || e) + ')'); }

	// A validly-SIGNED token whose root is NOT publicly trusted must be REJECTED (this is the forgery
	// defense: an attacker's self-minted timestamping cert never chains to a trusted root). We use a real
	// TSA whose root is not in the platform bundle; if unreachable, the check is skipped.
	try {
		const fr = await Attest.timestamp(digest, { tsaUrl: 'https://freetsa.org/tsr', timeoutMs: 20000 });
		const untrusted = Attest.verifyToken(fr.token, { digest });
		ok('an untrusted-root token is rejected (forgery defense)', untrusted.ok === false && untrusted.reason === 'untrusted-chain');
	} catch (e) { console.log('  skip  untrusted-root check (' + (e && e.message || e) + ')'); }

	// Multi-authority fallback: the built-in list is tried in order so one unreachable authority doesn't fail an
	// attestation. These checks need no network — they pin the list shape and that a CUSTOM authority is used
	// alone (no silent fallback to the defaults), failing fast with the connection error instead.
	ok('there is more than one default authority (a single point of failure was removed)', Array.isArray(Attest.DEFAULT_TSAS) && Attest.DEFAULT_TSAS.length >= 2);
	ok('the primary default is the first of the list', Attest.DEFAULT_TSA === Attest.DEFAULT_TSAS[0]);
	ok('the default authorities are distinct', new Set(Attest.DEFAULT_TSAS).size === Attest.DEFAULT_TSAS.length);
	let customErr = null;
	try { await Attest.timestamp(digest, { tsaUrl: 'http://127.0.0.1:1/tsr', timeoutMs: 4000 }); } catch (e) { customErr = e && e.message || String(e); }
	ok('a custom unreachable authority fails without falling back to the defaults', !!customErr && !/any timestamp authority/i.test(customErr));

	// --- End-to-end vault attestation (needs the engine; live part needs network) ---
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('  skip  vault attestation (engine missing)'); }
	else {
		const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-attest-')); workspace = tmp;
		const src = path.join(tmp, 'src'); await fsp.mkdir(src);
		await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(1024));
		const v = path.join(tmp, 'Att.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

		// Attesting before a baseline exists must refuse (nothing fixed to prove).
		let refusedNoBaseline = false;
		try { await vdisk.attest(v, { timeoutMs: 15000 }); } catch (_) { refusedNoBaseline = true; }
		ok('attest refuses before a snapshot exists', refusedNoBaseline);

		await vdisk.snapshot(v, { password: 'pw1' });
		if (liveToken) { // only attempt the network attestation if the live TSA was reachable above
			await vdisk.attest(v, { timeoutMs: 15000 });
			const list = await vdisk.attestations(v);
			ok('the attestation is stored and verifies', list.items.length === 1 && list.items[0].verified === true);
			ok('the stored proof matches the current state', list.items[0].matchesCurrent === true);
			ok('the sidecar travels beside the vault', await fsp.stat(path.join(v, 'attestations.json')).then(() => true).catch(() => false));

			// A new snapshot advances the state; the old proof stays valid but no longer matches "current".
			await fsp.writeFile(path.join(src, 'b.txt'), crypto.randomBytes(512));
			await vdisk.importFiles(v, [path.join(src, 'b.txt')]).catch(() => {}); // best-effort; if it needs a mount, fall back below
			await vdisk.snapshot(v, { password: 'pw1' });
			// A second attestation chains onto the first.
			await vdisk.attest(v, { timeoutMs: 15000 });
			const list2 = await vdisk.attestations(v);
			ok('an older proof still verifies after the state changes', list2.items[0].verified === true);
			ok('an older proof no longer matches the new current state', list2.items[0].matchesCurrent === false);
			ok('two proofs form an intact tamper-evident chain', list2.items.length === 2 && list2.chainOk === true && list2.items.every(i => i.chained));
			ok('the chain head is exposed for out-of-band pinning', !!(list2.head && list2.head.chain && list2.head.seq === list2.currentSeq));
			ok('the newest proof matches the current state', list2.items[1].matchesCurrent === true);
			ok('an up-to-date vault is not flagged as rolled back', list2.rolledBack === false);

			// Tamper the sidecar: reorder the two proofs — the hash chain must break.
			const sidecar = path.join(v, 'attestations.json');
			const store = JSON.parse(await fsp.readFile(sidecar, 'utf8'));
			const reordered = { ...store, items: [store.items[1], store.items[0]] };
			await fsp.writeFile(sidecar, JSON.stringify(reordered));
			ok('reordering proofs breaks the chain', (await vdisk.attestations(v)).chainOk === false);
			await fsp.writeFile(sidecar, JSON.stringify(store)); // restore

			// A local rollback signal: drop the vault's baseline back below the highest attested version.
			// (Simulated by lowering the recorded snapshot seq; the sidecar still holds the newer proof.)
			const Vault = require('../Vault');
			const mBefore = await Vault.readManifest(v);
			const rolled = JSON.parse(JSON.stringify(mBefore));
			rolled.snapshot.seq = 1; // older than the highest attested seq
			await require('fs').promises.writeFile(path.join(v, 'vault.json'), JSON.stringify(rolled, null, 2));
			ok('a vault older than its attested history is flagged as rolled back', (await vdisk.attestations(v)).rolledBack === true);
			await require('fs').promises.writeFile(path.join(v, 'vault.json'), JSON.stringify(mBefore, null, 2)); // restore
		} else { console.log('  skip  live vault attestation (TSA unreachable)'); }

		await vdisk.removeKnownVault(v).catch(() => {});
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ATTESTATION CHECKS PASSED'));
	await cleanup();
	process.exit(failures ? 1 : 0);
}

async function cleanup() {
	if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {});
	if (isoData) await fsp.rm(isoData, { recursive: true, force: true }).catch(() => {});
}

main().catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
