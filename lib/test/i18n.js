'use strict';
// Guards the language-agnostic text layer: the shared i18n helper behaves, each pure model exports a complete string
// catalog (every plural base has both forms; every language covers the same keys), and the models no longer build a
// user-facing sentence with "+" or a hardcoded English plural — a ratchet so they cannot drift back to untranslatable
// concatenation. English-only ships today; this is what keeps the dashboard/devices/fleet models translation-ready.
const fs = require('fs'), path = require('path');
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const SHARED = path.join(__dirname, '..', 'webserver', 'public', 'shared');
const I18n = require(path.join(SHARED, 'i18n.js'));

// --- the shared helper ---
ok('interp fills {vars} and leaves an unknown one in place', I18n.interp('{a}/{b}', { a: 'x' }) === 'x/{b}');
ok('interp is safe on a null template', I18n.interp(null, { a: 1 }) === '');
ok('plural gives English one vs other (0 and 2 are other)', I18n.plural('en', 1) === 'one' && I18n.plural('en', 2) === 'other' && I18n.plural('en', 0) === 'other');
const CAT = { en: { k_one: '{n} cat', k_other: '{n} cats', plain: 'Hi {who}' } };
ok('t selects the plural form from the count', I18n.t(CAT, 'en', 'k', { n: 1 }) === '1 cat' && I18n.t(CAT, 'en', 'k', { n: 3 }) === '3 cats');
ok('t falls back to the en catalog for an unknown language', I18n.t(CAT, 'zz', 'plain', { who: 'you' }) === 'Hi you');
ok('t returns the key itself when a string is missing (visible, never a crash)', I18n.t(CAT, 'en', 'nope') === 'nope');

// --- every model exports a complete catalog ---
const models = {
	dashboard: require(path.join(SHARED, 'dashboard-model.js')).STRINGS,
	devices: require(path.join(SHARED, 'devices-model.js')).STRINGS,
	fleet: require(path.join(SHARED, 'fleet-model.js')).STRINGS
};
Object.keys(models).forEach(function (name) {
	const STR = models[name];
	ok(name + '-model exports a STRINGS catalog with an "en" language', !!(STR && STR.en));
	if (!STR || !STR.en) return;
	const bases = {};
	Object.keys(STR.en).forEach(function (k) { const m = k.match(/^(.*)_(one|other)$/); if (m) bases[m[1]] = true; });
	Object.keys(bases).forEach(function (b) { ok(name + ': plural base "' + b + '" defines both _one and _other', (b + '_one') in STR.en && (b + '_other') in STR.en); });
	const enKeys = Object.keys(STR.en).sort().join(',');
	Object.keys(STR).forEach(function (l) { ok(name + ': language "' + l + '" covers exactly the "en" keys', Object.keys(STR[l]).sort().join(',') === enKeys); });
});

// --- ratchet: the models must not reintroduce "+"-built English or a hardcoded plural ---
const BAD = [
	{ rx: /===\s*1\s*\?\s*['"]/, what: 'a hardcoded "n === 1 ? ..." plural' },
	{ rx: /\+\s*['"]\s*(vaults?|nodes?|devices?|remotes?|schedules?|items?|errors?|warnings?)\b/i, what: 'a concatenated English count word' }
];
['dashboard-model.js', 'devices-model.js', 'fleet-model.js'].forEach(function (f) {
	let src = fs.readFileSync(path.join(SHARED, f), 'utf8');
	src = src.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, ''); // strip comments so prose never trips the ratchet
	BAD.forEach(function (b) { ok(f + ' no longer contains ' + b.what + ' (use the catalog)', !b.rx.test(src)); });
});

console.log(failures ? ('\n' + failures + ' CHECK(S) FAILED') : '\nALL I18N CHECKS PASSED');
process.exit(failures ? 1 : 0);
