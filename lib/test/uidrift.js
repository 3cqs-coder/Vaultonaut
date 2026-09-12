'use strict';
// lib/test/uidrift.js — pins the web UI's <select> options to the single source of truth each one mirrors, so a
// rename, a typo, or a dropped option cannot silently drift. This matters most where a drifted value would be
// SILENTLY ACCEPTED at a weaker setting rather than rejected: an unknown KDF security level or recovery tier used
// to fall through to the default ('standard' / 'medium'), quietly downgrading the protection the user chose. The
// core now rejects an unknown value, and this test keeps the dropdown itself honest against the source list.
// Static/source analysis only (render-free string parsing, like settingsdrift.js/commanddrift.js) — no engine,
// no server, fast and cross-platform.
//
// Run:  node lib/test/uidrift.js

const fs = require('fs');
const path = require('path');
const Kdf = require('../Kdf');
const Recovery = require('../Recovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const web = path.join(__dirname, '..', 'webserver');
const read = (p) => fs.readFileSync(p, 'utf8');

// Pull the option VALUES (in order) out of a named <select> in the markup.
function optionValues(html, selectId) {
	const m = html.match(new RegExp('<select[^>]*id="' + selectId + '"[\\s\\S]*?</select>'));
	if (!m) return null;
	return [...m[0].matchAll(/<option[^>]*value="([^"]*)"/g)].map(x => x[1]);
}
const sameSet = (a, b) => a && b && a.length === b.length && [...a].sort().join(',') === [...b].sort().join(',');

function main() {
	const ejs = read(path.join(web, 'public', 'views', 'index.ejs'));
	const app = read(path.join(web, 'public', 'js', 'app.js'));

	// 1. KDF security levels: #createLevel options === Kdf.LEVELS (the list the CLI and the create core validate against).
	const levelOpts = optionValues(ejs, 'createLevel');
	ok('the #createLevel dropdown exists', !!levelOpts && levelOpts.length > 0);
	ok('#createLevel options match Kdf.LEVELS exactly (no silent security downgrade on drift)', sameSet(levelOpts, Object.keys(Kdf.LEVELS)));

	// 2. Recovery tiers: #protectTier options === Recovery.TIERS, and each label's "about N% extra space" matches.
	const tierOpts = optionValues(ejs, 'protectTier');
	ok('the #protectTier dropdown exists', !!tierOpts && tierOpts.length > 0);
	ok('#protectTier options match Recovery.TIERS exactly', sameSet(tierOpts, Object.keys(Recovery.TIERS)));
	const tierBlock = (ejs.match(/<select[^>]*id="protectTier"[\s\S]*?<\/select>/) || [''])[0];
	for (const [tier, pct] of Object.entries(Recovery.TIERS)) {
		const optMatch = tierBlock.match(new RegExp('<option[^>]*value="' + tier + '"[^>]*>([^<]*)</option>'));
		const label = optMatch ? optMatch[1] : '';
		ok('#protectTier "' + tier + '" label states its real ' + pct + '% overhead', new RegExp('\\b' + pct + '%').test(label));
	}

	// 3. Sync-speed presets: #bwPreset values (minus the "custom" escape hatch) === the BW_PRESETS array in app.js.
	const bwOpts = (optionValues(ejs, 'bwPreset') || []).filter(v => v !== 'custom');
	const bwArrMatch = app.match(/const BW_PRESETS\s*=\s*\[([^\]]*)\]/);
	const bwArr = bwArrMatch ? [...bwArrMatch[1].matchAll(/'([^']*)'/g)].map(x => x[1]) : null;
	ok('the #bwPreset dropdown and the BW_PRESETS array both exist', bwOpts.length > 0 && !!bwArr);
	ok('#bwPreset option values match the BW_PRESETS array in app.js', sameSet(bwOpts, bwArr));

	// 4. Cloud WORM gate: app.js keys the tamper-proof (Object Lock) rows on the 's3' cloud type, so that option
	//    value must still exist in #cloudType — otherwise the WORM UI silently never appears.
	const cloudOpts = optionValues(ejs, 'cloudType') || [];
	ok('#cloudType still offers the "s3" type the WORM gate depends on', cloudOpts.includes('s3'));
	ok('app.js still gates the WORM rows on the s3 cloud type', /['"]s3['"]/.test(app) && /data-type/.test(app));

	// 5. Display-safety: both the desktop escaper (esc) and the mobile one (escapeHtml) must NEUTRALIZE invisible
	//    bidi-formatting and non-whitespace control characters, not only escape HTML — otherwise a file or note name in
	//    a shared/team vault could embed a right-to-left override (U+202E) to spoof how it reads in the list. Lock that
	//    both escapers strip the U+202E .. U+202E range (the override) plus the isolates, so a refactor cannot drop it.
	const mobileApp = read(path.join(web, 'public', 'mobile', 'app.js'));
	// The character class must be DEFINED (the bidi override + isolate ranges) AND the escaper must APPLY it. Checking
	// only that the range literals appear somewhere would still pass if a refactor removed the `.replace(UNSAFE_DISPLAY,
	// …)` from the escaper body while leaving the now-dead const — silently reopening the RTL-override spoofing hole.
	const neutralizesBidi = (src, fnName) => {
		const defined = /UNSAFE_DISPLAY\s*=\s*\/\[[^\n]*\\u202A-\\u202E[^\n]*\\u2066-\\u2069/.test(src);
		const head = (src.match(new RegExp('function\\s+' + fnName + '\\([\\s\\S]{0,300}')) || [''])[0]; // the escaper's opening; the strip is the first thing it does
		const applied = /\.replace\(UNSAFE_DISPLAY,\s*['"`]\\uFFFD/.test(head);
		return defined && applied;
	};
	ok('the desktop esc() DEFINES and APPLIES the bidi/control neutralization (anti-spoofing)', neutralizesBidi(app, 'esc'));
	ok('the mobile escapeHtml() DEFINES and APPLIES the bidi/control neutralization (anti-spoofing)', neutralizesBidi(mobileApp, 'escapeHtml'));

	// 6. First-run recovery safety net: a vault created with only a password is an unrecoverable lockout if that
	//    password is forgotten, so the create flow must OFFER a Recovery Kit right after creation. This lives only in
	//    the client, so pin it statically: the helper exists AND the create handler invokes it, so a refactor cannot
	//    silently drop the one prompt that steers a new user to a recovery method.
	ok('app.js defines the first-run offerRecoveryKit helper', /async function offerRecoveryKit\(/.test(app));
	ok('the create flow invokes offerRecoveryKit after a vault is created', /await offerRecoveryKit\(/.test(app));

	// 6. The notes filter normalizes to NFC before comparing, matching the server-side search, so an accented query
	// typed in the browser (NFC) still matches a title stored decomposed (NFD, as macOS produces). A drift back to a
	// bare toLowerCase() would silently miss those notes.
	ok('the notes filter NFC-normalizes the query and the compared titles', /\$\('#notesFilter'\)[\s\S]{0,60}\.normalize\('NFC'\)\.toLowerCase\(\)/.test(app) && /\(n\.title \|\| ''\)\.normalize\('NFC'\)\.toLowerCase\(\)/.test(app));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UI-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
