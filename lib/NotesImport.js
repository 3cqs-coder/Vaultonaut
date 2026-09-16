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
// Formats: a generic/LastPass/Chrome CSV, a Bitwarden JSON export, and a 1Password .1pux export (a ZIP whose
// export.data holds the account tree). The .1pux path reads the ZIP with Node's built-in zlib — no external `unzip`
// binary (absent on Windows) and no dependency — so it behaves identically on macOS, Windows, and Linux.

const Zip = require('./Zip'); // the app-wide, non-blocking, crash-proof zip module — single-entry buffer reads live there
const MAX_INPUT_BYTES = 100 * 1024 * 1024;     // refuse an absurdly large export outright rather than load it into memory
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

// ---- 1Password .1pux (ZIP -> export.data JSON tree) ----
// The .1pux ZIP is read through the shared lib/Zip.js (Zip.readEntry) — see parse1pux below.
// Map ONE 1Password field value object to a normalized field. A .1pux value is an object with a single key naming its
// type (string, concealed, totp, email, url, phone, date, monthYear, creditCardNumber, …). An unrecognized shape is
// stringified to text rather than dropped, so nothing in the export is lost.
function opValue(v) {
	if (v == null) return null;
	if (typeof v !== 'object') return { kind: 'text', value: s(v) };
	if ('string' in v) return { kind: 'text', value: s(v.string) };
	if ('concealed' in v) return { kind: 'password', value: s(v.concealed), secret: true };
	if ('totp' in v) return { kind: 'otp', value: s(v.totp), secret: true };
	if ('email' in v) return { kind: 'email', value: v.email && typeof v.email === 'object' ? s(v.email.email_address) : s(v.email) };
	if ('url' in v) return { kind: 'url', value: s(v.url) };
	if ('phone' in v) return { kind: 'text', value: s(v.phone) };
	if ('date' in v) return { kind: 'date', value: s(v.date) };
	if ('monthYear' in v) { const my = s(v.monthYear); return { kind: 'date', value: my.length === 6 ? my.slice(0, 4) + '/' + my.slice(4) : my }; }
	if ('creditCardNumber' in v) return { kind: 'text', value: s(v.creditCardNumber), secret: true };
	if ('creditCardType' in v) return { kind: 'text', value: s(v.creditCardType) };
	for (const k of Object.keys(v)) { const val = v[k]; if (val != null && typeof val !== 'object') return { kind: 'text', value: s(val) }; }
	return null;
}
// 1Password category UUIDs -> a Vaultonaut item type (a render hint only).
const OP_CATEGORY = { '001': 'login', '002': 'card', '004': 'identity', '005': 'login' }; // else -> note
function op1puxItem(rec) {
	const item = rec && rec.item ? rec.item : rec;
	if (!item || typeof item !== 'object') return null;
	const ov = item.overview || {}, det = item.details || {};
	const type = OP_CATEGORY[String(item.categoryUuid || '')] || 'note';
	const fields = [];
	if (Array.isArray(det.loginFields)) for (const f of det.loginFields) {
		const value = trimmed(f && f.value); if (!value) continue;
		const des = s(f && f.designation), ft = s(f && f.fieldType);
		if (des === 'username') fields.push(field('text', 'Username', value));
		else if (des === 'password' || ft === 'P') fields.push(field('password', 'Password', value, true));
		else if (ft === 'E') fields.push(field('email', trimmed(f.name) || 'Email', value));
		else fields.push(field('text', trimmed(f.name) || 'Field', value));
	}
	if (trimmed(det.password)) fields.push(field('password', 'Password', trimmed(det.password), true)); // Password category
	if (trimmed(ov.url)) fields.push(field('url', 'Website', trimmed(ov.url)));
	if (Array.isArray(ov.urls)) for (const u of ov.urls) { const url = trimmed(u && (u.url != null ? u.url : u)); if (url) fields.push(field('url', 'Website', url)); }
	if (Array.isArray(det.sections)) for (const sec of det.sections) {
		if (!sec || !Array.isArray(sec.fields)) continue;
		for (const f of sec.fields) { const m = opValue(f && f.value); if (!m || !trimmed(m.value)) continue; fields.push(field(m.kind, trimmed(f.title) || 'Field', m.value, m.secret)); }
	}
	return { title: trimmed(ov.title) || 'Imported item', type, fields: capFields(fields), note: trimmed(det.notesPlain) };
}
async function parse1pux(buffer) {
	const dataBuf = await Zip.readEntry(buffer, 'export.data');
	if (!dataBuf) throw new Error('This does not look like a 1Password .1pux export (no export.data inside the archive).');
	let doc;
	try { doc = JSON.parse(dataBuf.toString('utf8')); } catch (_) { throw new Error('The 1Password export.data is not valid JSON.'); }
	const items = [];
	for (const acc of (doc && Array.isArray(doc.accounts) ? doc.accounts : [])) {
		for (const vault of (acc && Array.isArray(acc.vaults) ? acc.vaults : [])) {
			for (const rec of (vault && Array.isArray(vault.items) ? vault.items : [])) {
				if (items.length >= MAX_ITEMS) break;
				const it = op1puxItem(rec); if (it) items.push(it);
			}
		}
	}
	return items;
}

// ---- format detection + top-level parse ----
// Detect the export format from the filename and a peek at the content. A ZIP magic number (PK\x03\x04) or a .1pux
// extension is 1Password; JSON with an "items" array is Bitwarden; otherwise CSV. An explicit `format` always wins.
// `input` may be a Buffer (binary .1pux) or a string (text CSV/JSON).
function detectFormat(filename, input) {
	const name = s(filename).toLowerCase();
	if (name.endsWith('.1pux')) return '1pux';
	if (name.endsWith('.json')) return 'bitwarden';
	if (name.endsWith('.csv')) return 'csv';
	if (Buffer.isBuffer(input)) {
		if (input.length >= 4 && input[0] === 0x50 && input[1] === 0x4b && input[2] === 0x03 && input[3] === 0x04) return '1pux'; // "PK\x03\x04"
		const head = input.slice(0, 4096).toString('utf8').trim();
		if (head.startsWith('{') && /"items"\s*:/.test(head)) return 'bitwarden';
		return 'csv';
	}
	const head = s(input).slice(0, 4096).trim();
	if (head.startsWith('{') && /"items"\s*:/.test(head)) return 'bitwarden';
	return 'csv';
}
// Parse an export into normalized items. `input` may be a Buffer (a binary .1pux) or a string (text CSV/JSON).
// Async so the .1pux decompression stays off the event loop; returns { format, items }. Throws a clear, user-facing
// message on a bad file.
async function parse(input, { format, filename } = {}) {
	const isBuf = Buffer.isBuffer(input);
	const size = isBuf ? input.length : Buffer.byteLength(s(input), 'utf8');
	if (size > MAX_INPUT_BYTES) throw new Error('That file is too large to import here (over 100 MB). Split the export, or import it in parts.');
	const fmt = format && format !== 'auto' ? String(format) : detectFormat(filename, input);
	let items;
	if (fmt === '1pux') items = await parse1pux(isBuf ? input : Buffer.from(s(input), 'binary'));
	else if (fmt === 'bitwarden') items = parseBitwarden(isBuf ? input.toString('utf8') : s(input));
	else if (fmt === 'csv') items = parseCsv(isBuf ? input.toString('utf8') : s(input));
	else throw new Error('Unsupported import format "' + fmt + '". Supported: csv, bitwarden, 1pux.');
	return { format: fmt, items };
}

module.exports = { parse, detectFormat, SUPPORTED: ['csv', 'bitwarden', '1pux'], MAX_ITEMS };
// Exported for the unit tests so each layer is checked in isolation, without duplicating the vocabulary.
module.exports._internals = { parseCsvRows, parseCsv, parseBitwarden, parse1pux, op1puxItem, opValue, csvRowToItem, classify, field };
