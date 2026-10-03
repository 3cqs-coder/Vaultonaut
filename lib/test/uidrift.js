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

	// 5. Display-safety: the SHARED escaper (public/shared/safe-text.js, used by both the desktop and mobile bundles)
	//    must NEUTRALIZE invisible bidi-formatting and non-whitespace control characters, not only escape HTML —
	//    otherwise a file or note name in a shared/team vault could embed a right-to-left override (U+202E) to spoof how
	//    it reads in the list. Lock that the shared escaper DEFINES the override+isolate range AND APPLIES it, and that
	//    both bundles use the shared escaper rather than a private copy that could drift (see also frontendsafetext.js).
	const mobileApp = read(path.join(web, 'public', 'mobile', 'app.js'));
	const safeText = read(path.join(web, 'public', 'shared', 'safe-text.js'));
	// The character class must be DEFINED (the bidi override + isolate ranges) AND the escaper must APPLY it. Checking
	// only that the range literals appear somewhere would still pass if a refactor removed the `.replace(UNSAFE_DISPLAY,
	// …)` while leaving the now-dead const — silently reopening the RTL-override spoofing hole.
	const definesNeutralization = /UNSAFE_DISPLAY\s*=\s*\/\[[^\n]*\\u202A-\\u202E[^\n]*\\u2066-\\u2069/.test(safeText);
	const appliesNeutralization = /\.replace\(UNSAFE_DISPLAY,\s*['"`]\\uFFFD/.test(safeText);
	ok('the shared escaper DEFINES and APPLIES the bidi/control neutralization (anti-spoofing)', definesNeutralization && appliesNeutralization);
	ok('the desktop bundle uses the shared escaper, not a private copy', /window\.VaultSafe\.escapeHtml/.test(app));
	ok('the mobile bundle uses the shared escaper, not a private copy', /window\.VaultSafe\.escapeHtml/.test(mobileApp));

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

	// 7. Cloud vaults do not support packing or a shared folder, so the Keys and Share dialogs must be cloud-aware or
	//    they present dead paths that only error server-side. Cloud key rotation IS supported now (it re-encrypts and
	//    re-uploads the store), so the Keys dialog shows the rotate action for a cloud vault and adds a cloud-specific
	//    note, and the Share dialog swaps its file/folder delivery for cloud guidance. Pin that awareness statically.
	ok('the Keys dialog shows a cloud-specific rotate note for a cloud vault', /#keysRotateCloudNote'\)\.hidden = !keysCloud/.test(app) && /vaultsByPath\[path\] \|\| \{\}\)\.cloud/.test(app));
	ok('the Share dialog shows cloud guidance instead of pack/folder for a cloud vault', /#shareDeliverLocal'\)\.hidden = shareCloud/.test(app) && /#shareDeliverCloud'\)\.hidden = !shareCloud/.test(app));

	// 8. The mobile note reader decrypts notes itself and must fail CLOSED on a note written by a NEWER version than it
	//    understands (rather than misreading it as the current format, as it once did with a bare `>= 3`). Its version
	//    literal must equal the desktop NOTE_VERSION so the two client/server readers can't drift.
	const vaultSrc = read(path.join(__dirname, '..', 'Vault.js'));
	const nv = (vaultSrc.match(/const NOTE_VERSION = (\d+)/) || [])[1];
	ok('Vault.js defines NOTE_VERSION', nv != null);
	ok('the mobile note reader fails closed on a note newer than NOTE_VERSION', nv != null && new RegExp('Number\\(j\\.v\\) > ' + nv + '\\)').test(mobileApp));
	ok('the mobile note reader still handles the current NOTE_VERSION', nv != null && new RegExp('Number\\(j\\.v\\) >= ' + nv + '\\b').test(mobileApp));

	// 9. The desktop and mobile bundles are isolated (nothing runs both), yet hardcode the SAME theme cycle and storage
	//    key. Pin them equal so a change to one is mirrored in the other rather than silently drifting.
	const themeCycle = /\[\s*'auto',\s*'light',\s*'dark',\s*'sepia'\s*\]/;
	ok('the desktop bundle defines the auto/light/dark/sepia theme cycle', themeCycle.test(app));
	ok('the mobile bundle defines the same auto/light/dark/sepia theme cycle', themeCycle.test(mobileApp));
	ok('both bundles use the same theme storage key', /'vdisk-theme'/.test(app) && /'vdisk-theme'/.test(mobileApp));

	// 10. The system-notifications dropdown holds a variable number of findings (a healthy install shows one line; a
	//     machine with several stale vaults and low disk can show many). It MUST stay bounded to the viewport and scroll
	//     its own contents — it once used "overflow: hidden" with no max-height, so a long list simply ran off the bottom
	//     of the screen with no way to reach the rest. Pin that it scrolls vertically and is capped with a viewport-
	//     relative height, so this cannot silently regress on any platform or window size.
	const css = read(path.join(web, 'public', 'css', 'app.css'));
	const notifRule = (css.match(/\.notif-panel\s*\{[^}]*\}/) || [''])[0];
	ok('the notifications dropdown scrolls its contents vertically (overflow-y: auto)', /overflow-y:\s*auto/.test(notifRule) && !/overflow:\s*hidden/.test(notifRule));
	ok('the notifications dropdown is bounded to the viewport (a vh/dvh-relative max-height)', /max-height:\s*calc\([^;]*\d(?:dvh|vh)\b/.test(notifRule));
	ok('the notifications dropdown contains its scroll so the page behind does not chain-scroll', /overscroll-behavior:\s*contain/.test(notifRule));
	// Long UNBREAKABLE tokens (a vault's full folder path, a peer's onion/tunnel URL, an off-site host, an error
	// string, an identity in a toast) must WRAP rather than run to the edge and force a horizontal scrollbar. Each
	// surface that renders such a value from data is pinned here, since this class of overflow has regressed twice.
	const wraps = (sel) => new RegExp(sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[^{}]*\\{[^}]*overflow-wrap:\\s*anywhere').test(css);
	ok('the environment/notification banner wraps a long token (base .banner; the dropdown inherits it)', /\.banner\s*\{[^}]*overflow-wrap:\s*anywhere/.test(css));
	ok('peer/off-site/cloud list rows wrap a long label so it cannot push the buttons off-screen', wraps('.row-between > span:first-child'));
	ok('the shared result box wraps a long host/URL/error instead of overflowing', wraps('.tamper-result'));
	ok('a sticky toast wraps a long identity or command token', wraps('.toast'));
	ok('a device activity line wraps a long token', wraps('.dev-evt-text'));

	// 11. Creating a vault on an external drive (or any folder) must be a low-effort pick, not a typed path: the location
	//     field offers a Browse button that reuses the shared folder picker and fills the field. Pin that the button
	//     exists and is wired to the picker and the location field, so it cannot be orphaned or silently drift.
	ok('the create-vault location field has a Browse button', /id="createPathBrowse"/.test(ejs));
	ok('the location Browse button opens the folder picker and fills the location field', /createPathBrowse'\)[\s\S]{0,600}openBrowse\(\{[\s\S]{0,900}onChoose[\s\S]{0,700}createPath'\)/.test(app));
	// Join the chosen folder using a reliable Windows test (a drive-letter or UNC prefix), not "contains a backslash",
	// so a folder name that legitimately contains a backslash on macOS/Linux still joins with "/" and the vault lands
	// where the user chose. (A plain includes-backslash check would silently create it in the wrong folder.)
	ok('the location picker detects Windows by a drive-letter/UNC prefix, not a bare backslash', /\^\[A-Za-z\]:\|\^\\\\\\\\/.test(app) && !/sep = folder\.includes\('\\\\'\)/.test(app));
	// Only open the picker at the current value's folder when that value is an ABSOLUTE path; a bare name would resolve
	// outside the browsable area and open the picker on an error toast.
	ok('the picker only derives its start folder from an absolute path', /startDir = \/\^\(\\\/\|\[A-Za-z\]:\|\\\\\\\\\)\//.test(app));
	// Creating a vault on a read-only or full location (an external drive that is locked or formatted for another OS)
	// must fail with plain guidance, not a raw errno. Pin that create translates these filesystem errors.
	ok('create translates a read-only/permission/space failure into a clear message', /EROFS'\s*\|\|\s*code === 'EACCES'\s*\|\|\s*code === 'EPERM'/.test(vaultSrc) && /ENOSPC/.test(vaultSrc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UI-DRIFT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
