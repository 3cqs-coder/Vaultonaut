'use strict';
// lib/test/tamperchain.js — the tamper-log hash chain. Each entry commits to the previous one
// (a blockchain-style prev-hash linkage), the first entry is bound to a vault-identity genesis, and both
// ends of the retained window are anchored in the ledger (head + eviction watermark). A read-write session
// co-signs the head (a Rekor-style signed checkpoint). This verifies that a clean or legitimately-evicted log
// passes, while an edit, a reorder, a newest-truncation, an oldest-deletion, a corrupted genesis, a forged
// checkpoint, and a rollback below a signed checkpoint are each detected with the right reason.
//
// Pure unit test over Integrity — no engine needed. It runs against its OWN throwaway data directory (not the
// shared .test-data the preload points at), so the tamper log and rollback ledger it writes are isolated: state
// that other suites accumulate in the shared ledger across repeated runs can never grow the shared files enough
// to perturb this one.  Run:  node lib/test/tamperchain.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const Common = require('../Common');
// Redirect the data dir to a private temp dir BEFORE requiring Integrity (which resolves the ledger/log paths from
// Common.dataDir()) and before computing LOG/LEDGER below, so every read and write here stays inside this test's
// own directory rather than the shared .test-data.
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'vdtamperchain-'));
Common.setDataDir(DATA_DIR);
const Integrity = require('../Integrity');

const LOG = path.join(Common.dataDir(), 'tamper-log.json');
const LEDGER = path.join(Common.dataDir(), 'integrity.json');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
async function readJson(p) { try { return JSON.parse(await fsp.readFile(p, 'utf8')); } catch (_) { return {}; } }
async function writeJson(p, o) { await fsp.writeFile(p, JSON.stringify(o)); }
async function setEvents(vid, arr) { const l = await readJson(LOG); l[vid] = arr; await writeJson(LOG, l); }
async function getEvents(vid) { return (await readJson(LOG))[vid] || []; }
async function setAnchor(vid, head) { const g = await readJson(LEDGER); g.tamperHeads = g.tamperHeads || {}; g.tamperHeads[vid] = head; await writeJson(LEDGER, g); }
async function getAnchor(vid) { return ((await readJson(LEDGER)).tamperHeads || {})[vid] || null; }

const vids = [];
function freshVid() { const v = crypto.randomBytes(16).toString('hex'); vids.push(v); return v; }

async function reason(vid, pub) { return (await Integrity.verifyTamperLog(vid, pub)).reason; }

async function main() {
	const kp = Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64'));

	// --- a clean chain verifies, and reports whether it is signed ---
	let vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k, notes: [k] });
	let v = await Integrity.verifyTamperLog(vid, kp.pub);
	ok('a clean 3-entry chain verifies', v.ok === true);
	ok('an unsigned chain reports signed:false', v.signed !== true);
	await Integrity.signTamperHead(vid, kp.priv);
	v = await Integrity.verifyTamperLog(vid, kp.pub);
	ok('after a write-key checkpoint the chain reports signed:true', v.ok === true && v.signed === true);
	ok('a checkpoint verified against the WRONG key is rejected', (await reason(vid, Integrity.signKeysFromSeed(crypto.randomBytes(32).toString('base64')).pub)) === 'checkpoint-forged');

	// --- REGRESSION: production events carry own keys with UNDEFINED values (the Vault wrapper builds
	// e.added = cap(undefined) etc.), which JSON drops on disk. The write-time hash must match the recompute
	// from disk, or every real log would falsely read as 'edited'. ---
	vid = freshVid();
	await Integrity.logTamper(vid, { kind: 'baseline-altered', added: undefined, removed: undefined, modified: undefined, foreign: undefined, notes: ['seal removed'] });
	await Integrity.logTamper(vid, { kind: 'changed-while-unmounted', added: undefined, removed: undefined, modified: ['a.txt'], foreign: undefined, notes: undefined });
	ok('a log of production-shaped events (undefined fields) verifies', (await Integrity.verifyTamperLog(vid)).ok === true);

	// --- editing an entry breaks its chain hash ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	let e = await getEvents(vid); e[1] = { ...e[1], notes: ['tampered'] }; await setEvents(vid, e);
	ok('editing an entry is detected', (await reason(vid)) === 'edited');

	// --- reordering entries breaks the prev-hash links ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	e = await getEvents(vid); [e[0], e[1]] = [e[1], e[0]]; await setEvents(vid, e);
	ok('reordering entries is detected', (await reason(vid)) === 'reordered');

	// --- removing the NEWEST entries disagrees with the head anchor ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	e = await getEvents(vid); await setEvents(vid, e.slice(1)); // drop the newest
	ok('removing the newest entries is detected (head anchor)', (await reason(vid)) === 'truncated');

	// --- BENIGN interrupted append: a crash BETWEEN the tamper-log write and the ledger-anchor write leaves the
	// anchor exactly one entry behind a correctly-chained head. That must NOT read as tampering (it self-heals on
	// the next append), while a head two-or-more ahead — or one that doesn't link to the anchor — still must. ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	e = await getEvents(vid); // e[0] = head (n=3), e[1] = n=2, e[2] = n=1
	await setAnchor(vid, { n: e[1].n, hash: e[1].hash, evicted: 0 }); // anchor lags one behind; the head links to it
	ok('a one-behind ledger anchor (interrupted append) is NOT reported as tampering', (await Integrity.verifyTamperLog(vid)).ok === true);
	await setAnchor(vid, { n: e[2].n, hash: e[2].hash, evicted: 0 }); // anchor two behind — not a benign one-step lag
	ok('a ledger anchor two-or-more behind is still detected as tampering', (await reason(vid)) === 'truncated');

	// --- removing the OLDEST retained entry is caught by the eviction watermark (no real eviction yet) ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	e = await getEvents(vid); await setEvents(vid, e.slice(0, e.length - 1)); // drop the oldest (genesis)
	ok('deleting the oldest retained entry is detected', (await reason(vid)) === 'oldest-removed');

	// --- corrupting the genesis link is caught ---
	vid = freshVid();
	for (const k of ['a', 'b']) await Integrity.logTamper(vid, { kind: k });
	e = await getEvents(vid); e[e.length - 1] = { ...e[e.length - 1], prevHash: 'f'.repeat(64) }; // the n===1 tail
	// its self-hash still has to match, so recompute nothing — this simulates a swapped-in chain start
	await setEvents(vid, e);
	ok('a chain whose genesis link is wrong is detected', ['bad-genesis', 'edited'].includes(await reason(vid)));

	// --- a rollback BELOW a signed checkpoint is caught even if the attacker also fixes the head anchor ---
	vid = freshVid();
	for (const k of ['a', 'b', 'c']) await Integrity.logTamper(vid, { kind: k });
	await Integrity.signTamperHead(vid, kp.priv); // checkpoint at n=3
	e = await getEvents(vid); const kept = e.slice(1); await setEvents(vid, kept); // roll back to n=2
	const cp = (await getAnchor(vid)).checkpoint; // preserve the signed checkpoint (n=3)
	await setAnchor(vid, { n: kept[0].n, hash: kept[0].hash, evicted: 0, checkpoint: cp }); // attacker fixes the head too
	ok('a rollback below a signed checkpoint is detected', (await reason(vid, kp.pub)) === 'rolled-back');

	// --- legitimate cap-eviction still verifies, and its watermark then guards the new oldest entry ---
	vid = freshVid();
	const N = 203; // a couple past the 200 cap to force eviction
	for (let i = 0; i < N; i++) await Integrity.logTamper(vid, { kind: 'evt', seq: i });
	v = await Integrity.verifyTamperLog(vid);
	ok('a log past its cap still verifies (legit eviction)', v.ok === true);
	const anch = await getAnchor(vid);
	ok('the eviction watermark advanced past the dropped entries', (anch.evicted || 0) >= N - 200);
	e = await getEvents(vid); await setEvents(vid, e.slice(0, e.length - 1)); // now delete the oldest RETAINED
	ok('deleting the oldest entry after eviction is still detected', (await reason(vid)) === 'oldest-removed');

	// --- BENIGN interrupted append AT THE EVICTION CAP: the crash between the two writes leaves BOTH ends one
	// behind — the head anchor AND the eviction watermark — because that same append also evicted one entry. This
	// must still read as clean (it self-heals on the next append), not as 'oldest-removed'. ---
	vid = freshVid();
	for (let i = 0; i < 203; i++) await Integrity.logTamper(vid, { kind: 'evt', seq: i }); // window 200, 3 evicted
	e = await getEvents(vid); // e[0] = head (n=203), e[1] = n=202
	const preAnchor = await getAnchor(vid); // committed anchor: n=203, evicted=3
	// Roll the anchor back to the PRE-append state: n and evicted both one behind, head links to n=202.
	await setAnchor(vid, { n: e[1].n, hash: e[1].hash, evicted: (preAnchor.evicted || 0) - 1 });
	ok('an interrupted append at the eviction cap (both ends one behind) is NOT reported as tampering', (await Integrity.verifyTamperLog(vid)).ok === true);
	// But a watermark two behind (a genuine oldest-removal on top of the lag) is still caught.
	await setAnchor(vid, { n: e[1].n, hash: e[1].hash, evicted: (preAnchor.evicted || 0) - 3 });
	ok('an eviction watermark more than one behind is still detected', (await reason(vid)) === 'oldest-removed');

	// --- a signed checkpoint that has AGED OUT of the retained window no longer anchors it: report chained, not
	// signed (claiming "signed" there would overstate the guarantee an evicted checkpoint no longer provides) ---
	vid = freshVid();
	await Integrity.logTamper(vid, { kind: 'first' });
	await Integrity.signTamperHead(vid, kp.priv); // checkpoint at n=1
	for (let i = 0; i < 205; i++) await Integrity.logTamper(vid, { kind: 'evt', seq: i }); // push n=1 out of the retained window
	v = await Integrity.verifyTamperLog(vid, kp.pub);
	ok('an aged-out checkpoint is reported chained, not signed', v.ok === true && v.signed === false && v.verdict === 'chained');

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TAMPER-CHAIN CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

async function cleanup() {
	// The whole data dir is this test's own throwaway temp, so removing it takes the tamper log and ledger with it.
	try { await fsp.rm(DATA_DIR, { recursive: true, force: true }); } catch (_) {}
}

main().catch(e => { console.error(e); process.exitCode = 1; }).finally(cleanup);
