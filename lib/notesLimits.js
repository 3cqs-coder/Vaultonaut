'use strict';
// lib/notesLimits.js — the limits that must agree between the secure-note writer and the import parser. They live in
// one module so a change to the field cap or the per-item body cap can never make the importer build an item that
// noteSave refuses. The importer's own input/record ceilings (a hostile file) are separate and stay in NotesImport.
module.exports = {
	MAX_FIELDS: 200,                    // one item's field count; noteSave trims to this and the importer caps to it
	MAX_BODY_BYTES: 1024 * 1024,        // one item's sealed content (fields + note), in UTF-8 bytes
};
