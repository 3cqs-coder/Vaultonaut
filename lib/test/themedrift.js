'use strict';
// lib/test/themedrift.js — the theme single-source-of-truth watchdog. The desktop interface, the login page, the phone
// viewer, and the Send page must all present the same palette and behavior as css/theme.css and js/theme.js.
// Before this guard the desktop and mobile stylesheets each repeated the palette, each bundle repeated the theme cycle
// and storage key, and the pre-paint boot scripts repeated the chrome colors — four copies that could drift silently.
// This test pins:
//   • one token definition site (css/theme.css), with no private palette in the desktop or mobile stylesheets;
//   • every page loads the shared stylesheet and theme model before its own stylesheet;
//   • the Send page's self-contained palette matches the shared light and dark tokens;
//   • js/theme.js's browser-chrome map matches the shared --bg values;
//   • the shared model actually boots, cycles, and persists the choice (loaded in a sandbox, no browser);
//   • neither bundle keeps a private theme cycle or storage key.
// Pure source/runtime analysis: no engine, no network, no browser.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const PUBLIC = path.join(__dirname, '..', 'webserver', 'public');
const read = (p) => fs.readFileSync(path.join(PUBLIC, p), 'utf8');

function block(css, re) {
	const i = css.search(re); if (i < 0) return '';
	const open = css.indexOf('{', i), close = css.indexOf('}', open);
	return css.slice(open, close);
}
function tokens(text) {
	const out = {};
	for (const m of text.matchAll(/--([\w-]+):\s*([^;}\n]+)/g)) out[m[1]] = m[2].trim();
	return out;
}
function before(html, first, second) {
	const a = html.indexOf(first), b = html.indexOf(second);
	return a >= 0 && b >= 0 && a < b;
}

const themeCss = read('css/theme.css');
const themeJs = read('js/theme.js');
const desktopCss = read('css/app.css');
const mobileCss = read('mobile/app.css');
const index = read('views/index.ejs');
const login = read('views/login.ejs');
const mobileHtml = read('mobile/index.html');
const sendHtml = read('send/index.html');
const desktopApp = read('js/app.js');
const mobileApp = read('mobile/app.js');

const LIGHT = tokens(block(themeCss, /:root\s*\{/));
const DARK = tokens(block(themeCss, /:root\[data-theme="dark"\]\s*\{/));
const SEPIA = tokens(block(themeCss, /:root\[data-theme="sepia"\]\s*\{/));
const CORE = ['bg', 'panel', 'panel-2', 'text', 'muted', 'border', 'accent', 'accent-text', 'accent-btn', 'accent-ink', 'danger', 'good'];

ok('the shared stylesheet defines the light palette', CORE.every((k) => !!LIGHT[k]));
ok('the shared stylesheet defines the dark palette', CORE.every((k) => !!DARK[k]));
ok('the shared stylesheet defines the sepia palette', CORE.every((k) => !!SEPIA[k]));
ok('the desktop stylesheet keeps no private palette', !/--bg:\s*#/.test(desktopCss) && !/--accent:\s*#/.test(desktopCss));
ok('the phone stylesheet keeps no private palette', !/--bg:\s*#/.test(mobileCss) && !/--accent:\s*#/.test(mobileCss));

ok('the desktop page loads the shared theme model before its stylesheet', before(index, '/js/theme.js', '/css/app.css'));
ok('the desktop page loads the shared tokens before its stylesheet', before(index, '/css/theme.css', '/css/app.css'));
ok('the login page loads the shared theme model before its stylesheet', before(login, '/js/theme.js', '/css/app.css'));
ok('the login page loads the shared tokens before its stylesheet', before(login, '/css/theme.css', '/css/app.css'));
ok('the phone page loads the shared theme model before its stylesheet', before(mobileHtml, 'js/theme.js', 'app.css'));
ok('the phone page loads the shared tokens before its stylesheet', before(mobileHtml, 'css/theme.css', 'app.css'));
ok('no page references the retired per-surface theme-boot scripts', ![index, login, mobileHtml].some((h) => /theme-boot\.js/.test(h)));

// The Send page is deliberately self-contained (a recipient may open it without the app shell). Its inline palette
// must still match the shared light and dark tokens, so a palette retune cannot leave a stale recipient page behind.
const sendLight = tokens((sendHtml.match(/:root\s*\{\s*color-scheme:\s*light[^}]*\}/) || [''])[0]);
const sendDark = tokens((sendHtml.match(/:root\s*\{\s*color-scheme:\s*dark[^}]*\}/) || [''])[0]);
ok('the Send page declares its light and dark palettes', Object.keys(sendLight).length > 0 && Object.keys(sendDark).length > 0);
ok('the Send page palette matches the shared light tokens', CORE.every((k) => !sendLight[k] || sendLight[k].replace(/\s+/g, '') === LIGHT[k].replace(/\s+/g, '')));
ok('the Send page dark palette matches the shared dark tokens', CORE.every((k) => !sendDark[k] || sendDark[k].replace(/\s+/g, '') === DARK[k].replace(/\s+/g, '')));

// Chrome colors in the model must match the real page backgrounds, so the status bar never seams against the page.
const chrome = (() => { const m = themeJs.match(/var CHROME = \{([^}]*)\}/); if (!m) return {}; const o = {}; for (const x of m[1].matchAll(/(\w+):\s*'(#[0-9a-fA-F]{6})'/g)) o[x[1]] = x[2].toLowerCase(); return o; })();
ok('the shared model defines chrome colors for light, dark, and sepia', !!(chrome.light && chrome.dark && chrome.sepia));
ok('the light chrome color matches the shared --bg', chrome.light === LIGHT.bg.toLowerCase());
ok('the dark chrome color matches the shared --bg', chrome.dark === DARK.bg.toLowerCase());
ok('the sepia chrome color matches the shared --bg', chrome.sepia === SEPIA.bg.toLowerCase());
ok('the desktop page meta theme-color matches the shared light background', new RegExp('<meta name="theme-color" content="' + LIGHT.bg + '"', 'i').test(index));
ok('the phone page meta theme-color matches the shared dark background', new RegExp('<meta name="theme-color" content="' + DARK.bg + '"', 'i').test(mobileHtml));

// Neither bundle may keep a private copy of the cycle or the storage key; both must call the shared model.
const CYCLE = /\[\s*'auto',\s*'light',\s*'dark',\s*'sepia'\s*\]/;
ok('the shared model owns the four-choice cycle', CYCLE.test(themeJs));
ok('the shared model owns the storage key', /'vdisk-theme'/.test(themeJs));
ok('the desktop bundle uses the shared model, with no private cycle or key', /window\.VaultTheme/.test(desktopApp) && !CYCLE.test(desktopApp) && !/'vdisk-theme'/.test(desktopApp));
ok('the phone bundle uses the shared model, with no private cycle or key', /window\.VaultTheme/.test(mobileApp) && !CYCLE.test(mobileApp) && !/'vdisk-theme'/.test(mobileApp));

// Load the shared model the way a browser would, with a tiny DOM, and prove it boots, resolves, cycles, and persists.
{
	const attrs = {};
	const store = {};
	const media = { matches: false, addEventListener: () => {}, addListener: () => {} };
	const document = {
		documentElement: { setAttribute(k, v) { attrs[k] = String(v); }, getAttribute(k) { return attrs[k] == null ? null : attrs[k]; } },
		body: null,
		querySelector: () => null,
	};
	const sandbox = {
		window: { matchMedia: () => media, document },
		document,
		localStorage: { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
	};
	sandbox.window.localStorage = sandbox.localStorage;
	vm.createContext(sandbox);
	vm.runInContext(themeJs, sandbox);
	const T = sandbox.window.VaultTheme;
	ok('the shared model exposes the theme API', T && typeof T.boot === 'function' && typeof T.cycle === 'function' && typeof T.saved === 'function');
	if (T) {
		ok('the shared model boots to auto when nothing is saved', attrs['data-theme'] === 'auto' && T.saved() === 'auto');
		ok('the shared model resolves auto to light under a light system preference', T.resolved('auto') === 'light');
		media.matches = true;
		ok('the shared model resolves auto to dark under a dark system preference', T.resolved('auto') === 'dark');
		media.matches = false;
		ok('the shared model cycles auto → light', T.cycle() === 'light' && attrs['data-theme'] === 'light' && store['vdisk-theme'] === 'light');
		ok('the shared model cycles through every choice in order', T.cycle() === 'dark' && T.cycle() === 'sepia' && T.cycle() === 'auto');
		ok('the shared model normalizes an unknown saved value to auto', T.normalize('chartreuse') === 'auto');
	}
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL THEME-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
