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

// --- the plumbing is genuinely locale-driven, not English hardcoded ---
// A multi-form fixture in a language with more than one/other (Russian: one/few/many). English ships today, but the
// machinery must already pick a form by the LOCALE's rule and degrade to the base/other form when a form is absent,
// so adding a real translation later is only data. ICU support varies by build, so the rich checks are gated on the
// runtime actually distinguishing the forms; a reduced-ICU platform (plural() then falls back to n===1) still passes.
var RU = { en: { k_one: '{n} file', k_other: '{n} files' },
	ru: { k_one: '{n} файл', k_few: '{n} файла', k_many: '{n} файлов' } };
var icuRich = false;
try { icuRich = (new Intl.PluralRules('ru').select(2) === 'few' && new Intl.PluralRules('ru').select(5) === 'many'); } catch (e) { icuRich = false; }
if (icuRich) {
	ok('plural surfaces a non-English rule (ru: 1=one, 2=few, 5=many)', I18n.plural('ru', 1) === 'one' && I18n.plural('ru', 2) === 'few' && I18n.plural('ru', 5) === 'many');
	ok('t selects the locale-specific plural form (ru few/many)', I18n.t(RU, 'ru', 'k', { n: 2 }) === '2 файла' && I18n.t(RU, 'ru', 'k', { n: 5 }) === '5 файлов');
	ok('t degrades a missing plural form to _other (ru "few" absent -> k_other)', I18n.t({ ru: { k_other: '{n} шт' } }, 'ru', 'k', { n: 2 }) === '2 шт');
} else {
	ok('plural degrades safely without rich ICU (n===1 fallback: 1=one, else other)', I18n.plural('ru', 1) === 'one' && I18n.plural('ru', 2) === 'other');
}
ok('interp passes any script through unchanged and fills every var', I18n.interp('{a}·{b}·{a}', { a: 'файл', b: '2' }) === 'файл·2·файл');

// --- the migrated resolvers map every known token and fall back safely (no raw catalog key, no crash) ---
var Dash = require(path.join(SHARED, 'dashboard-model.js'));
var Dev = require(path.join(SHARED, 'devices-model.js'));
var UI = require(path.join(SHARED, 'ui-strings.js'));
ok('statusPillText maps ok/warn/error and treats an unknown level as ok', Dash.statusPillText('ok') === 'All systems normal' && Dash.statusPillText('warn') === 'Needs a look' && Dash.statusPillText('error') === 'Attention needed' && Dash.statusPillText('???') === 'All systems normal');
ok('deviceKindLabel maps every kind and falls back to the token', Dev.deviceKindLabel('peer') === 'Paired device' && Dev.deviceKindLabel('serve') === 'Serving' && Dev.deviceKindLabel('zzz') === 'zzz' && Dev.deviceKindLabel(null) === '');
ok('fieldKindLabel maps every field kind and falls back to the token', UI.fieldKindLabel('totp') === 'One-time code (2FA)' && UI.fieldKindLabel('month-year') === 'Month / year' && UI.fieldKindLabel('zzz') === 'zzz' && UI.fieldKindLabel(null) === '');
ok('keyKindLabel maps every slot kind and falls back to "password"', UI.keyKindLabel('recovery') === 'recovery' && UI.keyKindLabel('readonly') === 'read-only' && UI.keyKindLabel('zzz') === 'password' && UI.keyKindLabel(null) === 'password');
ok('the shared catalog carries the phone address labels and reach guidance', UI.text('mobileNetworkAddress') === 'Network address' && UI.text('mobileAddressHint').indexOf('Wi-Fi') >= 0 && UI.text('mobileReachSecure').indexOf('https') >= 0 && UI.text('mobileReachAlt').indexOf('virtual machine') >= 0);

// --- every model exports a complete catalog ---
const models = {
	dashboard: require(path.join(SHARED, 'dashboard-model.js')).STRINGS,
	devices: require(path.join(SHARED, 'devices-model.js')).STRINGS,
	fleet: require(path.join(SHARED, 'fleet-model.js')).STRINGS,
	uiStrings: require(path.join(SHARED, 'ui-strings.js')).STRINGS
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
['dashboard-model.js', 'devices-model.js', 'fleet-model.js', 'ui-strings.js'].forEach(function (f) {
	let src = fs.readFileSync(path.join(SHARED, f), 'utf8');
	src = src.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, ''); // strip comments so prose never trips the ratchet
	BAD.forEach(function (b) { ok(f + ' no longer contains ' + b.what + ' (use the catalog)', !b.rx.test(src)); });
});

console.log(failures ? ('\n' + failures + ' CHECK(S) FAILED') : '\nALL I18N CHECKS PASSED');
process.exit(failures ? 1 : 0);
