'use strict';
// lib/NotesImport.js — parse an EXPORT from another password manager into Vaultonaut's secure-note item shape.
//
// This module is PURE: it takes the export text and returns normalized items — no file I/O, no vault, no engine, no
// network, no dependencies. That keeps it identical on macOS, Windows, and Linux, and unit-testable on its own (the
// parser tests run on every platform with no mount driver). The caller (the CLI or the web route) reads the file and
// hands the text here, then writes each returned item through the existing Vault.noteSave path — so imported items are
// ordinary secure notes, sealed the same way, and readable by any release (nothing new in the manifest).
//
// A normalized item is exactly what noteSave accepts:
//   { title: string, type: string, fields: [{ kind, label, value, secret? }], note: string }
// `type` and each field `kind` are RENDER HINTS ONLY — an unknown value is shown generically and never dropped
// (see sanitizeNoteFields in Vault.js) — so mapping can emit any source's shapes without ever breaking an item.
//
// Phase 1 formats: a generic/LastPass/Chrome CSV, and a Bitwarden JSON export. 1Password .1pux (a ZIP) is Phase 2.

const MAX_INPUT_BYTES = 100 * 1024 * 1024; // refuse an absurdly large export outright rather than load it into memory
const MAX_ITEMS = 200000;                   // a sane ceiling so a hostile/huge file cannot create unbounded work
const MAX_FIELDS_PER_ITEM = 200;            // matches noteSave's own field cap; trim here so the mapping stays honest

// ---- small helpers ----
const s = (v) => (v == null ? '' : String(v));
const trimmed = (v) => s(v).trim();
// A field record for a normalized item. Empty values are dropped by the callers so an item never carries blank fields.
function field(kind, label, value, secret) {
	const rec = { kind: s(kind) || 'text', label: s(label), value: s(value) };
	if (secret) rec.secret = true;
	return rec;
}
// Keep an item within the field cap, preserving order (the earliest, most meaningful fields win).
function capFields(fields) { return fields.slice(0, MAX_FIELDS_PER_ITEM); }

// ---- RFC 4180 CSV parser ----
// Handles quoted fields, escaped quotes (""), embedded commas and newlines, and both LF and CRLF line endings. Pure
// character scan (no regex on the whole file), so a value that contains a newline or a comma inside quotes is parsed
// correctly rather than splitting a record. Returns an array of rows, each an array of string cells.
function parseCsvRows(text) {
	const rows = [];
	let row = [], cell = '', inQuotes = false;
	const str = s(text);
	for (let i = 0; i < str.length; i++) {
		const c = str[i];
		if (inQuotes) {
			if (c === '"') {
				if (str[i + 1] === '"') { cell += '"'; i++; } // an escaped quote inside a quoted field
				else inQuotes = false;                        // closing quote
			} else cell += c;
			continue;
		}
		if (c === '"') { inQuotes = true; continue; }
		if (c === ',') { row.push(cell); cell = ''; continue; }
		if (c === '\r') { continue; } // fold CRLF: the '\n' ends the row
		if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; continue; }
		cell += c;
	}
	// Flush the final cell/row if the file did not end with a newline.
	if (cell.length || row.length) { row.push(cell); rows.push(row); }
	// Drop fully-empty rows (a trailing blank line, or blank separators some exports add).
	return rows.filter((r) => r.some((c) => trimmed(c) !== ''));
}

// Column-name vocabulary shared by the generic/LastPass/Chrome CSV shapes. All lower-cased for matching.
const COL = {
	title: ['name', 'title', 'account', 'item', 'account name'],
	username: ['username', 'user', 'login', 'login_username', 'user name'],
	password: ['password', 'pass', 'pwd', 'login_password'],
	url: ['url', 'uri', 'website', 'site', 'login_uri', 'web site', 'link'],
	otp: ['otp', 'totp', 'otpauth', 'totpauth', '2fa', 'two-factor'],
	email: ['email', 'e-mail'],
	note: ['note', 'notes', 'extra', 'comments', 'comment'],
};
// Meta columns that carry no item value worth keeping as a field (folder/organization/flags a manager adds).
const SKIP_COLS = new Set(['folder', 'grouping', 'group', 'collection', 'favorite', 'fav', 'type', 'reprompt', 'android', 'ios', 'organization', 'organization id', 'collection id']);
function classify(header) {
	const h = trimmed(header).toLowerCase();
	for (const key of Object.keys(COL)) if (COL[key].includes(h)) return key;
	if (SKIP_COLS.has(h)) return 'skip';
	return null; // an unrecognized column becomes a custom field, labeled by its original header
}

// Map one CSV row (given the classified header) to a normalized item. Unknown columns become custom text fields so
// nothing in the export is silently lost; empty cells are dropped so an item never carries blank fields.
function csvRowToItem(headers, roles, cells) {
	let title = '', username = '', password = '', otp = '', note = '';
	const urls = [], extras = [];
	for (let i = 0; i < headers.length; i++) {
		const role = roles[i], value = trimmed(cells[i]);
		if (!value) continue;
		switch (role) {
			case 'title': if (!title) title = value; break;
			case 'username': if (!username) username = value; break;
			case 'password': if (!password) password = value; break;
			case 'otp': if (!otp) otp = value; break;
			case 'url': urls.push(value); break;
			case 'email': if (!username) username = value; else extras.push(field('email', 'Email', value)); break;
			case 'note': note = note ? note + '\n' + value : value; break;
			case 'skip': break;
			default: extras.push(field('text', headers[i] || 'Field', value)); break; // custom column, preserved
		}
	}
	const fields = [];
	if (username) fields.push(field('text', 'Username', username));
	if (password) fields.push(field('password', 'Password', password, true));
	if (otp) fields.push(field('otp', 'One-time code', otp, true));
	for (const u of urls) fields.push(field('url', 'Website', u));
	for (const e of extras) fields.push(e);
	const type = (username || password || urls.length) ? 'login' : 'note';
	return { title: title || (username || 'Imported item'), type, fields: capFields(fields), note };
}

function parseCsv(text) {
	const rows = parseCsvRows(text);
	if (rows.length < 2) return []; // need a header plus at least one record
	const headers = rows[0].map((h) => trimmed(h));
	const roles = headers.map(classify);
	const items = [];
	for (let r = 1; r < rows.length && items.length < MAX_ITEMS; r++) {
		const it = csvRowToItem(headers, roles, rows[r]);
		if (it.title || it.fields.length || it.note) items.push(it);
	}
	return items;
}

// ---- Bitwarden JSON ----
// A Bitwarden export is { items: [ { type, name, login?, card?, identity?, fields?, notes } ] }. type: 1=login,
// 2=secure note, 3=card, 4=identity. Custom fields carry type 1=hidden (a secret).
function bwCustomFields(item) {
	const out = [];
	if (Array.isArray(item.fields)) {
		for (const f of item.fields) {
			const value = trimmed(f && f.value);
			if (!value) continue;
			out.push(field('text', trimmed(f && f.name) || 'Field', value, Number(f && f.type) === 1));
		}
	}
	return out;
}
function bwLogin(item) {
	const lg = item.login || {}, fields = [];
	if (trimmed(lg.username)) fields.push(field('text', 'Username', trimmed(lg.username)));
	if (trimmed(lg.password)) fields.push(field('password', 'Password', trimmed(lg.password), true));
	if (trimmed(lg.totp)) fields.push(field('otp', 'One-time code', trimmed(lg.totp), true));
	if (Array.isArray(lg.uris)) for (const u of lg.uris) { const uri = trimmed(u && u.uri); if (uri) fields.push(field('url', 'Website', uri)); }
	return { type: 'login', fields: fields.concat(bwCustomFields(item)) };
}
function bwCard(item) {
	const cd = item.card || {}, fields = [];
	if (trimmed(cd.cardholderName)) fields.push(field('text', 'Cardholder', trimmed(cd.cardholderName)));
	if (trimmed(cd.brand)) fields.push(field('text', 'Brand', trimmed(cd.brand)));
	if (trimmed(cd.number)) fields.push(field('text', 'Card number', trimmed(cd.number), true));
	const exp = [trimmed(cd.expMonth), trimmed(cd.expYear)].filter(Boolean).join('/');
	if (exp) fields.push(field('text', 'Expires', exp));
	if (trimmed(cd.code)) fields.push(field('text', 'Security code', trimmed(cd.code), true));
	return { type: 'card', fields: fields.concat(bwCustomFields(item)) };
}
function bwIdentity(item) {
	const id = item.identity || {}, fields = [];
	const map = [['title', 'Title'], ['firstName', 'First name'], ['middleName', 'Middle name'], ['lastName', 'Last name'],
		['company', 'Company'], ['phone', 'Phone'], ['address1', 'Address'], ['address2', 'Address 2'],
		['city', 'City'], ['state', 'State'], ['postalCode', 'Postal code'], ['country', 'Country'],
		['ssn', 'SSN'], ['passportNumber', 'Passport'], ['licenseNumber', 'License']];
	for (const [k, label] of map) if (trimmed(id[k])) fields.push(field('text', label, trimmed(id[k]), k === 'ssn' || k === 'passportNumber'));
	if (trimmed(id.email)) fields.push(field('email', 'Email', trimmed(id.email)));
	if (trimmed(id.username)) fields.push(field('text', 'Username', trimmed(id.username)));
	return { type: 'identity', fields: fields.concat(bwCustomFields(item)) };
}
function parseBitwarden(text) {
	let doc;
	try { doc = JSON.parse(text); } catch (_) { throw new Error('This does not look like a valid Bitwarden JSON export (it is not valid JSON).'); }
	if (doc && doc.encrypted === true) throw new Error('This is an ENCRYPTED Bitwarden export. Export again with encryption turned off, then import the plain JSON.');
	const list = doc && Array.isArray(doc.items) ? doc.items : null;
	if (!list) throw new Error('This JSON is not a Bitwarden export (no "items" array).');
	const items = [];
	for (const item of list) {
		if (items.length >= MAX_ITEMS) break;
		if (!item || typeof item !== 'object') continue;
		const t = Number(item.type);
		let mapped;
		if (t === 1) mapped = bwLogin(item);
		else if (t === 3) mapped = bwCard(item);
		else if (t === 4) mapped = bwIdentity(item);
		else mapped = { type: 'note', fields: bwCustomFields(item) }; // type 2 (secure note) or anything unrecognized
		items.push({ title: trimmed(item.name) || 'Imported item', type: mapped.type, fields: capFields(mapped.fields), note: trimmed(item.notes) });
	}
	return items;
}

// ---- format detection + top-level parse ----
// Detect the export format from the filename and a peek at the content. Kept conservative: JSON with an "items" array
// is Bitwarden; otherwise CSV. An explicit `format` from the caller always wins.
function detectFormat(filename, text) {
	const name = s(filename).toLowerCase();
	if (name.endsWith('.json')) return 'bitwarden';
	if (name.endsWith('.csv')) return 'csv';
	const head = s(text).slice(0, 4096).trim();
	if (head.startsWith('{') && /"items"\s*:/.test(head)) return 'bitwarden';
	return 'csv';
}
// Parse an export into normalized items. Returns { format, items }. Throws a clear, user-facing message on a bad file.
function parse(text, { format, filename } = {}) {
	const body = s(text);
	if (Buffer.byteLength(body, 'utf8') > MAX_INPUT_BYTES) throw new Error('That file is too large to import here (over 100 MB). Split the export, or import it in parts.');
	const fmt = format && format !== 'auto' ? String(format) : detectFormat(filename, body);
	let items;
	if (fmt === 'bitwarden') items = parseBitwarden(body);
	else if (fmt === 'csv') items = parseCsv(body);
	else throw new Error('Unsupported import format "' + fmt + '". Supported: csv, bitwarden.');
	return { format: fmt, items };
}

module.exports = { parse, detectFormat, SUPPORTED: ['csv', 'bitwarden'], MAX_ITEMS };
// Exported for the unit tests so each layer is checked in isolation, without duplicating the vocabulary.
module.exports._internals = { parseCsvRows, parseCsv, parseBitwarden, csvRowToItem, classify, field };
