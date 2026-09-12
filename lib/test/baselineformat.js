'use strict';
// lib/test/baselineformat.js — the in-vault signed baseline record is stored with its file list as newline-delimited
// JSON after a small header line, so the reader can parse a huge (up to ~256 MB) baseline COOPERATIVELY instead of one
// uninterruptible JSON.parse that stalls the event loop on mount and audit. This pins the format contract:
//   • a round-trip preserves the header fields and the file list exactly;
//   • the file list is bound the same way regardless of storage (the Merkle root over the reparsed files is identical,
//     so the Ed25519 signature over the header still verifies — a storage-layout change, not a signed-content change);
//   • a LEGACY single-JSON-object record (the old format) is still read unchanged, so existing vaults keep verifying
//     until their next snapshot rewrites them;
//   • a corrupt file line is rejected (throws), which the callers treat as an unreadable/corrupt record.
//
// Run:  node lib/test/baselineformat.js  (no engine, no vault — pure format logic)

const Vault = require('../Vault');
const Integrity = require('../Integrity');
const { serializeBaselineAsync, parseBaselineAsync } = Vault._baselineFormat;
const { BASELINE_VERSION, SCHEME } = Vault._bundleVersions;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// A record shaped like a real deep baseline: a header plus a file list mixing size-only and content-hash entries,
	// including a path with a semicolon and a space (the characters the listing/hashsum parsers guard).
	const files = [];
	for (let i = 0; i < 2500; i++) files.push({ path: 'dir/f ;' + i + '.bin', size: i * 7, hash: (i % 3 === 0) ? null : ('a' + i) });
	const record = {
		version: BASELINE_VERSION, tool: 'x', scheme: SCHEME, createdAt: '2020-01-02T03:04:05.000Z',
		deep: true, auto: false, sealed: true, count: files.length, files,
		merkleRoot: await Integrity.merkleRoot(files), prevRoot: null, seq: 9,
		hmac: 'deadbeef', sig: 'cafef00d',
	};

	// Round-trip: serialize (new format) → parse → identical header and file list.
	const blob = await serializeBaselineAsync(record);
	const back = await parseBaselineAsync(blob);
	ok('the round-trip preserves the file list exactly', JSON.stringify(back.files) === JSON.stringify(files));
	ok('the round-trip preserves the header fields', back.version === record.version && back.scheme === record.scheme && back.merkleRoot === record.merkleRoot && back.seq === record.seq && back.hmac === record.hmac && back.sig === record.sig && back.sealed === true && back.deep === true && back.createdAt === record.createdAt);
	ok('the parsed record carries no internal storage marker', back.filesNdjson === undefined);

	// The file list is stored one entry per line after a header line (so the reader can yield between lines).
	const lines = blob.split('\n');
	ok('the new format is a header line plus one line per file', lines.length === files.length + 1);
	ok('the header line marks the newline-delimited format', JSON.parse(lines[0]).filesNdjson === true && JSON.parse(lines[0]).files === undefined);

	// Signature transparency: what is signed (the header fields) and the Merkle root over the REPARSED files are both
	// unchanged, so a signature made over the original record still verifies against the reparsed one.
	ok('the Merkle root over the reparsed files matches the original (signature stays valid)', (await Integrity.merkleRoot(back.files)) === record.merkleRoot);

	// Backward compatibility: a LEGACY record is a single JSON object with the file list inline. It must still parse.
	const legacy = JSON.stringify(record);
	const fromLegacy = await parseBaselineAsync(legacy);
	ok('a legacy single-object record still parses (existing vaults keep verifying)', JSON.stringify(fromLegacy.files) === JSON.stringify(files) && fromLegacy.merkleRoot === record.merkleRoot && fromLegacy.seq === 9);

	// A corrupt file line is rejected (throws), which the callers treat as an unreadable/corrupt record.
	let threwOnCorruptLine = false;
	try { await parseBaselineAsync(JSON.stringify({ version: BASELINE_VERSION, filesNdjson: true }) + '\n{not json}'); } catch (_) { threwOnCorruptLine = true; }
	ok('a corrupt file line is rejected (treated as corrupt)', threwOnCorruptLine);
	// A corrupt legacy record likewise throws.
	let threwOnCorruptLegacy = false;
	try { await parseBaselineAsync('{not json at all'); } catch (_) { threwOnCorruptLegacy = true; }
	ok('a corrupt legacy record is rejected', threwOnCorruptLegacy);

	// An empty file list round-trips (a first snapshot of an empty vault).
	const empty = { version: BASELINE_VERSION, scheme: SCHEME, files: [], merkleRoot: await Integrity.merkleRoot([]), seq: 1, sealed: false, deep: false, createdAt: 't', prevRoot: null, hmac: 'h', sig: 's' };
	const emptyBack = await parseBaselineAsync(await serializeBaselineAsync(empty));
	ok('an empty file list round-trips', Array.isArray(emptyBack.files) && emptyBack.files.length === 0 && emptyBack.merkleRoot === empty.merkleRoot);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BASELINE-FORMAT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
