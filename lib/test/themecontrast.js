'use strict';
// lib/test/themecontrast.js — a watchdog that locks the web UI's color contrast to WCAG 2.1 AA, so a future theme
// retune cannot silently reintroduce an unreadable combination. The CSS header claims "Contrast is tuned to clear WCAG
// AA on each theme's surfaces"; this proves it, for every theme, by parsing the theme token blocks out of app.css and
// computing the actual contrast ratios. It is pure and offline (no browser, no engine), so it runs everywhere.
//
// The token roles it checks:
//   --accent-btn  is the button FILL behind white --accent-text  -> needs >= 4.5:1 (normal-size button text).
//   --accent-ink  is the accent used AS small text on --panel and --accent-soft -> needs >= 4.5:1.
//   --accent      is used for focus rings / borders / decorative fills -> needs >= 3:1 against the theme background.
//
// Run:  node lib/test/themecontrast.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond, detail) { console.log((cond ? '  ok   ' : '  FAIL ') + name + (cond ? '' : '  ' + (detail || ''))); if (!cond) failures++; }

const css = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'public', 'css', 'app.css'), 'utf8');

// sRGB relative luminance and the WCAG contrast ratio.
function lin(c) { c = c / 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
function lum(hex) { const n = parseInt(hex.slice(1), 16); return 0.2126 * lin((n >> 16) & 255) + 0.7152 * lin((n >> 8) & 255) + 0.0722 * lin(n & 255); }
function ratio(a, b) { const la = lum(a), lb = lum(b), hi = Math.max(la, lb), lo = Math.min(la, lb); return (hi + 0.05) / (lo + 0.05); }

// Pull the value of a token from a slice of CSS (the last definition wins, matching the cascade within one block).
function tok(block, name) {
	const m = [...block.matchAll(new RegExp('--' + name + ':\\s*(#[0-9a-fA-F]{6})', 'g'))];
	return m.length ? m[m.length - 1][1].toLowerCase() : null;
}

// Extract the three theme blocks by their selector. The "auto" dark block mirrors the explicit dark block, so testing
// the explicit light (:root) and the explicit [data-theme] blocks covers every rendered theme.
function block(startRe) {
	const i = css.search(startRe); if (i < 0) return '';
	const open = css.indexOf('{', i); const close = css.indexOf('}', open);
	return css.slice(open, close);
}
const THEMES = {
	light: block(/:root\s*\{/),
	dark: block(/:root\[data-theme="dark"\]\s*\{/),
	sepia: block(/:root\[data-theme="sepia"\]\s*\{/),
};

for (const [name, blk] of Object.entries(THEMES)) {
	ok(name + ' theme block found in app.css', blk.length > 0);
	if (!blk) continue;
	const accent = tok(blk, 'accent'), btn = tok(blk, 'accent-btn'), ink = tok(blk, 'accent-ink');
	const text = tok(blk, 'accent-text'), panel = tok(blk, 'panel'), soft = tok(blk, 'accent-soft'), bg = tok(blk, 'bg');
	ok(name + ' defines accent, accent-btn, accent-ink, accent-text, panel, accent-soft, bg', !!(accent && btn && ink && text && panel && soft && bg));
	if (!(accent && btn && ink && text && panel && soft && bg)) continue;

	const r1 = ratio(text, btn);
	ok(name + ': button text on --accent-btn clears AA (>=4.5)', r1 >= 4.5, 'got ' + r1.toFixed(2));
	const r2 = ratio(ink, panel);
	ok(name + ': --accent-ink as text on --panel clears AA (>=4.5)', r2 >= 4.5, 'got ' + r2.toFixed(2));
	const r3 = ratio(ink, soft);
	ok(name + ': --accent-ink as text on --accent-soft clears AA (>=4.5)', r3 >= 4.5, 'got ' + r3.toFixed(2));
	const r4 = ratio(accent, bg);
	ok(name + ': --accent as a focus ring clears 3:1 on --bg', r4 >= 3.0, 'got ' + r4.toFixed(2));
	const r5 = ratio(accent, panel);
	ok(name + ': --accent as a border clears 3:1 on --panel', r5 >= 3.0, 'got ' + r5.toFixed(2));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL THEME-CONTRAST CHECKS PASSED'));
process.exit(failures ? 1 : 0);
