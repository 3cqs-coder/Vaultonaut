'use strict';
// lib/test/baselinedrift.js — a DRIFT GUARD for the signed tamper-baseline record format. Two independent writers in
// lib/Vault.js construct the baseline that is HMAC'd and hybrid-signed (Ed25519 + ML-DSA): establishBaselineInStore and
// writeSnapshot. They MUST build the identical `record` (and identical `fields` signing input) — a field added,
// removed, or reordered in one but not the other would silently diverge the signed integrity format between the two
// paths, a correctness and security hazard that the shared Integrity.signingInput only partly catches. There is no
// single source for these literals (they are inlined for clarity), so this guard pins that their field SETS stay
// identical. It is a pure source scan, so it can never hang or flake.
//
// Run:  node lib/test/baselinedrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
// The KEY set of a `{ key: expr, ... }` literal body (values are simple `key: expr` with no nested commas here).
const keysOf = (body) => body.split(',').map((s) => s.trim().split(':')[0].trim()).filter(Boolean).sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// The two signed baseline `record` writers both begin "version: BASELINE_VERSION, tool: Brand.slug".
const records = [...src.matchAll(/const record = \{ (version: BASELINE_VERSION, tool: Brand\.slug[^}]*)\}/g)].map((m) => keysOf(m[1]));
ok('exactly two signed baseline record writers exist (establishBaselineInStore + writeSnapshot)', records.length === 2);
ok('the two signed baseline record literals have identical field sets (no format drift)', records.length === 2 && same(records[0], records[1]));

// The baseline `fields` signing input appears in both writers AND the verify-side reconstruction — all must agree.
const fields = [...src.matchAll(/const fields = \{ (scheme: Integrity\.SCHEME, root[^}]*)\}/g)].map((m) => keysOf(m[1]));
ok('at least two baseline fields (signing-input) literals exist', fields.length >= 2);
ok('every baseline fields literal has the identical field set (writers and verifier agree)', fields.length >= 2 && fields.every((f) => same(f, fields[0])));

// Pin the exact record field set, so ADDING a field forces a deliberate update here (and to both writers) rather than
// slipping into one path only. Update this list intentionally when the signed baseline format is versioned up.
const EXPECTED_RECORD = ['auto', 'count', 'createdAt', 'deep', 'files', 'hmac', 'merkleRoot', 'prevRoot', 'scheme', 'sealed', 'seq', 'sig', 'sigPq', 'tool', 'version'];
ok('the signed baseline record covers exactly the reviewed field set', records.length === 2 && same(records[0], EXPECTED_RECORD));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BASELINE-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
