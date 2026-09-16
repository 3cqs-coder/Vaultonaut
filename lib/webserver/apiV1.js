'use strict';
// lib/webserver/apiV1.js — the PUBLISHED, versioned API surface, in one tiny module so the server (which registers
// the /api/v1 alias) and the drift test (which checks the README's "Local API" section matches) share ONE list. The
// contract then cannot drift between code, docs, and tests. It is a CURATED subset of the internal /api endpoints —
// /api/v1/<name> serves the exact same handler as /api/<name>, so there is one implementation, not a copy.
//
// Stability policy: additive within a version. Add an endpoint here and document it in the README's Local API section;
// never change or remove one within v1 (that would be a new version). Keep the list conservative — it is easier to add
// an endpoint later than to support one forever.
module.exports = {
	VERSIONS: ['v1'],
	// The v1 endpoints, by their internal /api name (all POST unless noted in docs/API.md; /api/v1/state is GET).
	V1: [
		'state',        // GET  — the whole UI state (vaults, mounts, settings) in one read
		'create',       // POST — create a new vault
		'mount',        // POST — mount a vault as a drive
		'unmount',      // POST — unmount a vault
		'notes-list',   // POST — list the secure-note items in an open vault
		'note-get',     // POST — read one secure-note item
		'note-save',    // POST — create or update a secure-note item
		'note-delete',  // POST — delete a secure-note item
		'notes-import', // POST — import logins/notes from a .csv, Bitwarden .json, or 1Password .1pux export
	],
};
