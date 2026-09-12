'use strict';
// lib/test/slotlabel.js — the key-slot label bound. A slot label is short human text shown in the key list; it
// arrives from the API/CLI with no length limit of its own, so it must be capped before it is stored in the vault
// manifest, exactly the way the note-field and security-key labels are. Without the cap a single request could
// write a multi-kilobyte label into the manifest. This tests the codepoint-aware cap and its default fallback, and
// pins that both slot builders (a password/recovery/device/keyfile/read-only slot and a member slot) route through
// it, so a new slot-creation path cannot silently reintroduce an unbounded label.
//
// Run:  node lib/test/slotlabel.js

const fs = require('fs');
const path = require('path');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const { cleanSlotLabel, MAX_SLOT_LABEL } = Vault._slotLabel;
	ok('the cap is a sane positive bound', Number.isInteger(MAX_SLOT_LABEL) && MAX_SLOT_LABEL > 0 && MAX_SLOT_LABEL <= 1000);

	// Length cap, counted in CODEPOINTS (not UTF-16 units), so a multi-byte character is never split in half.
	const long = 'x'.repeat(MAX_SLOT_LABEL + 500);
	ok('a very long label is capped to the maximum', [...cleanSlotLabel(long, 'Password')].length === MAX_SLOT_LABEL);
	const astral = '😀'.repeat(MAX_SLOT_LABEL + 50); // each emoji is one codepoint but two UTF-16 units
	const cappedAstral = cleanSlotLabel(astral, 'Password');
	ok('the cap counts codepoints, never splitting a multi-byte character', [...cappedAstral].length === MAX_SLOT_LABEL && !cappedAstral.includes('�'));

	// Default fallback for empty/whitespace/nullish input.
	ok('an empty label falls back to the default', cleanSlotLabel('', 'Password') === 'Password');
	ok('a nullish label falls back to the default', cleanSlotLabel(null, 'Recovery key') === 'Recovery key' && cleanSlotLabel(undefined, 'Member') === 'Member');
	ok('a whitespace-only label falls back to the default', cleanSlotLabel('   ', 'Password') === 'Password');
	// A normal label is preserved (trimmed).
	ok('a normal label is preserved and trimmed', cleanSlotLabel('  My laptop  ', 'Password') === 'My laptop');

	// Source pins: both slot builders must route their label through the cap, so a future path cannot store an
	// unbounded label. Static, because exercising every add-key path end to end needs a full vault + engine.
	const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('makeSlot caps the label via cleanSlotLabel', /label: cleanSlotLabel\(label, kind === 'recovery'/.test(src));
	ok('memberCapSlot caps the label via cleanSlotLabel', /label: cleanSlotLabel\(label, 'Member'\)/.test(src));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SLOT-LABEL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
