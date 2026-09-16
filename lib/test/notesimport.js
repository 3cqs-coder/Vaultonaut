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
function throws(fn, re) { try { fn(); return false; } catch (e) { return re.test(e.message); } }

function main() {
	// --- RFC 4180 CSV parsing: quotes, escaped quotes, embedded commas and newlines, CRLF ---
	const rows = NI._internals.parseCsvRows('a,b,c\r\n"x,y","he said ""hi""","multi\nline"\n');
	ok('CSV splits a simple header row', rows[0].join('|') === 'a|b|c');
	ok('CSV keeps a comma inside quotes as one cell', rows[1][0] === 'x,y');
	ok('CSV unescapes a doubled quote', rows[1][1] === 'he said "hi"');
	ok('CSV keeps an embedded newline inside quotes', rows[1][2] === 'multi\nline');
	ok('CSV drops fully-blank rows', NI._internals.parseCsvRows('a,b\n\n1,2\n').length === 2);

	// --- generic/Chrome CSV: name,url,username,password ---
	const chrome = NI.parse('name,url,username,password\nGmail,https://mail.google.com,me@x.com,s3cr3t\n', { filename: 'chrome.csv' });
	ok('Chrome CSV detects as csv', chrome.format === 'csv');
	ok('Chrome CSV yields one item', chrome.items.length === 1);
	ok('Chrome CSV maps the title', chrome.items[0].title === 'Gmail');
	ok('Chrome CSV types a login', chrome.items[0].type === 'login');
	ok('Chrome CSV maps the username', fieldByLabel(chrome.items[0], 'Username').value === 'me@x.com');
	ok('Chrome CSV marks the password secret', fieldByLabel(chrome.items[0], 'Password').secret === true);
	ok('Chrome CSV maps the website as a url field', fieldByLabel(chrome.items[0], 'Website').kind === 'url');

	// --- LastPass CSV: url,username,password,totp,extra,name,grouping,fav — extra→note, grouping/fav dropped, totp secret ---
	const lp = NI.parse('url,username,password,totp,extra,name,grouping,fav\nhttps://x.com,bob,pw,JBSWY3DP,my note,MyLogin,Work,1\n', { format: 'csv' });
	const lpItem = lp.items[0];
	ok('LastPass CSV maps name to title', lpItem.title === 'MyLogin');
	ok('LastPass CSV maps extra to the note', lpItem.note === 'my note');
	ok('LastPass CSV carries the TOTP as a secret otp field', fieldByLabel(lpItem, 'One-time code').secret === true && fieldByLabel(lpItem, 'One-time code').kind === 'otp');
	ok('LastPass CSV drops the grouping/fav meta columns', !fieldByLabel(lpItem, 'grouping') && !fieldByLabel(lpItem, 'fav'));

	// --- an unrecognized CSV column is preserved as a custom field, never dropped ---
	const custom = NI.parse('name,password,security_question\nBank,pw,First pet\n', { format: 'csv' });
	ok('an unknown CSV column becomes a custom field', fieldByLabel(custom.items[0], 'security_question').value === 'First pet');

	// --- Bitwarden JSON: login, card, identity, secure note, custom hidden field ---
	const bw = NI.parse(JSON.stringify({ items: [
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

	// --- error paths are clear and fail closed ---
	ok('an encrypted Bitwarden export is refused with guidance', throws(() => NI.parse(JSON.stringify({ encrypted: true, items: [] }), { format: 'bitwarden' }), /ENCRYPTED/));
	ok('invalid Bitwarden JSON is refused', throws(() => NI.parse('not json', { format: 'bitwarden' }), /not valid JSON|not a Bitwarden/));
	ok('an unsupported format is refused', throws(() => NI.parse('x', { format: 'keepass' }), /Unsupported import format/));

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL NOTES-IMPORT PARSER CHECKS PASSED');
}
main();
