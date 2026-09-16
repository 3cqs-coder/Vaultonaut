'use strict';
// lib/test/notesimport.js — the password-manager import PARSERS turn a CSV or a Bitwarden JSON export into
// Vaultonaut's secure-note item shape correctly, losing nothing. Pure and fast: NotesImport does no I/O, no engine,
// and no network, so this runs on every platform with no mount driver — which is why it is a good gate.
//
// Run:  node lib/test/notesimport.js

const NI = require('../NotesImport');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function fieldByLabel(item, label) { return (item.fields || []).find((f) => f.label === label); }
async function rejects(p, re) { try { await p; return false; } catch (e) { return re.test(e.message); } }

// Build a real single-entry ZIP (deflate) in-test, so the .1pux reader is exercised against genuine bytes rather than
// a mock. CRC is left 0 — the reader never verifies it (we only read our own export). Pure Node zlib, cross-platform.
const zlib = require('zlib');
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n >>> 0); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
function makeZip(name, content) {
	const nameBuf = Buffer.from(name, 'utf8'), data = zlib.deflateRawSync(content), comp = data.length, uncomp = content.length;
	const local = Buffer.concat([u32(0x04034b50), u16(20), u16(0), u16(8), u16(0), u16(0), u32(0), u32(comp), u32(uncomp), u16(nameBuf.length), u16(0), nameBuf, data]);
	const central = Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(8), u16(0), u16(0), u32(0), u32(comp), u32(uncomp), u16(nameBuf.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(0), nameBuf]);
	const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(central.length), u32(local.length), u16(0)]);
	return Buffer.concat([local, central, eocd]);
}

async function main() {
	// --- RFC 4180 CSV parsing: quotes, escaped quotes, embedded commas and newlines, CRLF ---
	const rows = NI._internals.parseCsvRows('a,b,c\r\n"x,y","he said ""hi""","multi\nline"\n');
	ok('CSV splits a simple header row', rows[0].join('|') === 'a|b|c');
	ok('CSV keeps a comma inside quotes as one cell', rows[1][0] === 'x,y');
	ok('CSV unescapes a doubled quote', rows[1][1] === 'he said "hi"');
	ok('CSV keeps an embedded newline inside quotes', rows[1][2] === 'multi\nline');
	ok('CSV drops fully-blank rows', NI._internals.parseCsvRows('a,b\n\n1,2\n').length === 2);

	// --- generic/Chrome CSV: name,url,username,password ---
	const chrome = await NI.parse('name,url,username,password\nGmail,https://mail.google.com,me@x.com,s3cr3t\n', { filename: 'chrome.csv' });
	ok('Chrome CSV detects as csv', chrome.format === 'csv');
	ok('Chrome CSV yields one item', chrome.items.length === 1);
	ok('Chrome CSV maps the title', chrome.items[0].title === 'Gmail');
	ok('Chrome CSV types a login', chrome.items[0].type === 'login');
	ok('Chrome CSV maps the username', fieldByLabel(chrome.items[0], 'Username').value === 'me@x.com');
	ok('Chrome CSV marks the password secret', fieldByLabel(chrome.items[0], 'Password').secret === true);
	ok('Chrome CSV maps the website as a url field', fieldByLabel(chrome.items[0], 'Website').kind === 'url');

	// --- LastPass CSV: url,username,password,totp,extra,name,grouping,fav — extra→note, grouping/fav dropped, totp secret ---
	const lp = await NI.parse('url,username,password,totp,extra,name,grouping,fav\nhttps://x.com,bob,pw,JBSWY3DP,my note,MyLogin,Work,1\n', { format: 'csv' });
	const lpItem = lp.items[0];
	ok('LastPass CSV maps name to title', lpItem.title === 'MyLogin');
	ok('LastPass CSV maps extra to the note', lpItem.note === 'my note');
	ok('LastPass CSV carries the TOTP as a secret otp field', fieldByLabel(lpItem, 'One-time code').secret === true && fieldByLabel(lpItem, 'One-time code').kind === 'otp');
	ok('LastPass CSV drops the grouping/fav meta columns', !fieldByLabel(lpItem, 'grouping') && !fieldByLabel(lpItem, 'fav'));

	// --- an unrecognized CSV column is preserved as a custom field, never dropped ---
	const custom = await NI.parse('name,password,security_question\nBank,pw,First pet\n', { format: 'csv' });
	ok('an unknown CSV column becomes a custom field', fieldByLabel(custom.items[0], 'security_question').value === 'First pet');

	// --- Bitwarden JSON: login, card, identity, secure note, custom hidden field ---
	const bw = await NI.parse(JSON.stringify({ items: [
		{ type: 1, name: 'Site', login: { username: 'u', password: 'p', totp: 'T', uris: [{ uri: 'https://s.com' }] }, fields: [{ name: 'PIN', value: '1234', type: 1 }], notes: 'n' },
		{ type: 3, name: 'Visa', card: { cardholderName: 'A B', number: '4111', code: '123', expMonth: '04', expYear: '2030' } },
		{ type: 4, name: 'Me', identity: { firstName: 'A', lastName: 'B', email: 'a@b.com' } },
		{ type: 2, name: 'Secret', notes: 'just text' },
	] }), { filename: 'bitwarden.json' });
	ok('Bitwarden detects as bitwarden', bw.format === 'bitwarden');
	ok('Bitwarden yields all four items', bw.items.length === 4);
	ok('Bitwarden login types correctly', bw.items[0].type === 'login');
	ok('Bitwarden login carries the TOTP secret', fieldByLabel(bw.items[0], 'One-time code').secret === true);
	ok('Bitwarden login carries the URL', fieldByLabel(bw.items[0], 'Website').value === 'https://s.com');
	ok('Bitwarden custom hidden field is marked secret', fieldByLabel(bw.items[0], 'PIN').secret === true);
	ok('Bitwarden card types correctly', bw.items[1].type === 'card');
	ok('Bitwarden card number is secret', fieldByLabel(bw.items[1], 'Card number').secret === true);
	ok('Bitwarden identity types correctly', bw.items[2].type === 'identity');
	ok('Bitwarden identity email uses the email kind', fieldByLabel(bw.items[2], 'Email').kind === 'email');
	ok('Bitwarden secure note types as note', bw.items[3].type === 'note' && bw.items[3].note === 'just text');

	// --- 1Password .1pux: build a REAL ZIP (deflate) in-test so the dependency-free reader is exercised end to end ---
	const opData = { accounts: [{ vaults: [{ items: [
		{ item: { categoryUuid: '001', overview: { title: 'GitHub', url: 'https://github.com', urls: [{ url: 'https://github.com/login' }] },
			details: { loginFields: [{ value: 'me', designation: 'username', fieldType: 'T' }, { value: 'pw', designation: 'password', fieldType: 'P' }],
				notesPlain: 'my note', sections: [{ title: '', fields: [{ title: 'One-time password', value: { totp: 'otpauth://x' } }, { title: 'Recovery', value: { concealed: 'abc' } }] }] } } },
		{ item: { categoryUuid: '002', overview: { title: 'Visa' }, details: { sections: [{ title: '', fields: [{ title: 'number', value: { creditCardNumber: '4111' } }, { title: 'expiry', value: { monthYear: 202612 } }] }] } } },
		{ item: { categoryUuid: '003', overview: { title: 'A note' }, details: { notesPlain: 'secret text' } } },
	] }] }] };
	const zip = makeZip('export.data', Buffer.from(JSON.stringify(opData), 'utf8'));
	const px = await NI.parse(zip, { filename: 'export.1pux' });
	ok('.1pux detects as 1pux', px.format === '1pux');
	ok('.1pux ZIP magic is detected from a raw Buffer too', NI.detectFormat('', zip) === '1pux');
	ok('.1pux yields all three items', px.items.length === 3);
	ok('.1pux login types correctly', px.items[0].type === 'login');
	ok('.1pux login maps username and secret password', fieldByLabel(px.items[0], 'Username').value === 'me' && fieldByLabel(px.items[0], 'Password').secret === true);
	ok('.1pux login carries a website', fieldByLabel(px.items[0], 'Website').value === 'https://github.com');
	ok('.1pux TOTP section field becomes a secret otp', fieldByLabel(px.items[0], 'One-time password').kind === 'otp' && fieldByLabel(px.items[0], 'One-time password').secret === true);
	ok('.1pux carries the plain note', px.items[0].note === 'my note');
	ok('.1pux card maps monthYear to a date', fieldByLabel(px.items[1], 'expiry').kind === 'date' && fieldByLabel(px.items[1], 'expiry').value === '2026/12');
	ok('.1pux card number is secret', fieldByLabel(px.items[1], 'number').secret === true);
	ok('.1pux secure note types as note', px.items[2].type === 'note' && px.items[2].note === 'secret text');
	ok('a non-ZIP passed as 1pux is refused', await rejects(NI.parse('not a zip', { format: '1pux' }), /valid ZIP|not look like a 1Password/));

	// --- error paths are clear and fail closed ---
	ok('an encrypted Bitwarden export is refused with guidance', await rejects(NI.parse(JSON.stringify({ encrypted: true, items: [] }), { format: 'bitwarden' }), /ENCRYPTED/));
	ok('invalid Bitwarden JSON is refused', await rejects(NI.parse('not json', { format: 'bitwarden' }), /not valid JSON|not a Bitwarden/));
	ok('an unsupported format is refused', await rejects(NI.parse('x', { format: 'keepass' }), /Unsupported import format/));

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL NOTES-IMPORT PARSER CHECKS PASSED');
}
main().catch((e) => { console.error(e); process.exit(1); });
