'use strict';
// lib/test/keyslotformatdrift.js — key slots are the vault's most sensitive on-disk structure. withKeySlots() in
// lib/Vault.js persists each slot through an explicit per-slot field ALLOWLIST (not a spread), a security guard so no
// transient or secret field can ever leak into a stored slot. The documented trade-off is that a NEW persistable
// per-slot field must (a) be added to the allowlist AND (b) bump SUPPORTED_FORMAT, so an older build refuses the vault
// instead of silently stripping the field on its next key op. Nothing at runtime enforces that pairing, so this guard
// pins both allowlists (the member branch and the passphrase-family branch) to a frozen snapshot tied to the current
// SUPPORTED_FORMAT. Adding a field without bumping the format fails here and forces the author to do both together.
//
// Run:  node lib/test/keyslotformatdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const setsEqual = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));

const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');

// The format version this snapshot is tied to. If SUPPORTED_FORMAT changes, the snapshot below must be
// re-reviewed and this constant updated in lock-step — that is the whole point of the pairing.
const SNAPSHOT_FORMAT = 5;
const EXPECTED_MEMBER = new Set(['id', 'kind', 'label', 'createdAt', 'role', 'owner', 'memberId', 'pub', 'pubFp', 'sealed']);
const EXPECTED_PASSPHRASE = new Set(['id', 'kind', 'label', 'createdAt', 'kdf', 'wrappedKey', 'webauthn', 'keyfileName']);

// 1. The live SUPPORTED_FORMAT in source must match the format this snapshot was frozen against. If they diverge, a
//    field may have been added (or the format bumped) without updating this guard — stop and re-review.
const fmtMatch = src.match(/const\s+SUPPORTED_FORMAT\s*=\s*(\d+)/);
ok('found SUPPORTED_FORMAT in Vault.js', !!fmtMatch);
const liveFormat = fmtMatch ? Number(fmtMatch[1]) : NaN;
ok('SUPPORTED_FORMAT (' + liveFormat + ') matches this snapshot (' + SNAPSHOT_FORMAT + ') — bump both together when adding a per-slot field', liveFormat === SNAPSHOT_FORMAT);

// 2. Extract the withKeySlots function body, then the two per-slot object literals from it.
const fnMatch = src.match(/function withKeySlots\(manifest, slots\)\s*\{([\s\S]*?)\n\}/);
ok('found the withKeySlots function', !!fnMatch);
const body = fnMatch ? fnMatch[1] : '';

// The member branch is the object literal that carries `kind: s.kind` AND `sealed: s.sealed`; the passphrase-family
// branch is the one that carries `wrappedKey: s.wrappedKey`. Pull the field NAMES (the `name:` keys) from each.
function fieldsOfLiteralContaining(marker) {
	// Find the `{ ... }` object literal (single-line, as written) that contains the marker text.
	const lines = body.split('\n').filter((l) => l.includes(marker) && l.includes('s.id'));
	if (!lines.length) return null;
	const line = lines[0];
	const braced = line.slice(line.indexOf('{'));
	// Collect `name:` at the start of each field. Handles both bare `id: s.id` and spread-guarded `...(s.x ? { x: s.x }`.
	// A field is `name: <expr that reads s.something>` — allow a leading `!!` (owner) or `{` (spread-guarded field).
	const names = new Set();
	for (const m of braced.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:!!)?s\./g)) names.add(m[1]);
	return names;
}

const memberFields = fieldsOfLiteralContaining('sealed: s.sealed');
const passphraseFields = fieldsOfLiteralContaining('wrappedKey: s.wrappedKey');

ok('extracted the member-slot allowlist', !!memberFields && memberFields.size > 0);
ok('extracted the passphrase-slot allowlist', !!passphraseFields && passphraseFields.size > 0);

if (memberFields) ok('member-slot allowlist matches the frozen snapshot (add a field here → bump SUPPORTED_FORMAT and update this test)', setsEqual(memberFields, EXPECTED_MEMBER));
if (passphraseFields) ok('passphrase-slot allowlist matches the frozen snapshot (add a field here → bump SUPPORTED_FORMAT and update this test)', setsEqual(passphraseFields, EXPECTED_PASSPHRASE));

// SLOT-CAP drift guard: the number of slots an unlock attempt will TRY and the number the add paths ALLOW must be the
// same, or a credential enrolled past the unlock ceiling silently never opens the vault. Both sides now reference one
// named constant each; pin that the constants are sane and that no bare numeric slice (an un-single-sourced cap) has
// crept back into the slot logic.
const caps = require('../Vault')._slotCaps;
ok('slot caps are exported as positive integers', caps && Number.isInteger(caps.MAX_PASSPHRASE_SLOTS) && caps.MAX_PASSPHRASE_SLOTS > 0 && Number.isInteger(caps.MAX_MEMBER_SLOTS) && caps.MAX_MEMBER_SLOTS > 0);
// Each cap constant must appear in BOTH an unlock context (`.slice(0, CAP)`) and an add-time guard (`>= CAP`), proving
// the two sides share the one constant rather than a copy that could drift.
for (const name of ['MAX_PASSPHRASE_SLOTS', 'MAX_MEMBER_SLOTS']) {
	ok(name + ' bounds the unlock loop (single-sourced)', src.includes('.slice(0, ' + name + ')'));
	ok(name + ' bounds an add path (single-sourced)', src.includes('>= ' + name));
}
// A bare numeric slot cap would defeat the single-sourcing, so it must not reappear.
ok('no hardcoded numeric slot-cap slice remains (must use the named constants)', !/\.slice\(0,\s*(?:64|256)\)/.test(src));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL KEY-SLOT FORMAT-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
