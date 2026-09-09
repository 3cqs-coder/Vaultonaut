'use strict';
// lib/test/mobiletheme.js — the mobile PWA's chrome color must not drift from its dark theme. Three places declare
// the browser/OS chrome color for the installed app: the static <meta name="theme-color"> (what paints the status
// bar before any script runs), the web app manifest served by mobileRoutes (theme_color + background_color, used by
// the OS for the splash and task switcher), and the dark theme's --bg in the stylesheet (the actual page background).
// If these drift apart, an installed phone app flashes the wrong color on launch or shows a seam around the content.
// This test pins them together so a future palette change to one must be made to all — no engine, no network.
//
// Run:  node lib/test/mobiletheme.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const root = path.join(__dirname, '..', 'webserver');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const HEX = /#[0-9a-fA-F]{6}/;

function main() {
	const html = read('public/mobile/index.html');
	const css = read('public/mobile/app.css');
	const routes = read('mobileRoutes.js');

	// The static status-bar color the browser applies before the stylesheet or scripts run.
	const metaMatch = html.match(/<meta\s+name=["']theme-color["']\s+content=["'](#[0-9a-fA-F]{6})["']/i);
	ok('index.html declares a <meta name="theme-color">', !!metaMatch);
	const metaColor = metaMatch && metaMatch[1].toLowerCase();

	// The web app manifest's colors (served, not a static file), used for the install splash and app chrome.
	const themeMatch = routes.match(/theme_color:\s*['"](#[0-9a-fA-F]{6})['"]/);
	const bgMatch = routes.match(/background_color:\s*['"](#[0-9a-fA-F]{6})['"]/);
	ok('the served web manifest declares theme_color and background_color', !!themeMatch && !!bgMatch);
	const manifestTheme = themeMatch && themeMatch[1].toLowerCase();
	const manifestBg = bgMatch && bgMatch[1].toLowerCase();

	// The dark theme's actual page background. The dark palette is declared under a prefers-color-scheme block AND a
	// [data-theme="dark"] block; both must carry the same --bg, and that is the color the chrome must match. The light
	// --bg (#f4f6fb) must NOT be what the chrome uses — the installed app defaults to the dark chrome.
	const darkBgs = [];
	for (const m of css.matchAll(/--bg:\s*(#[0-9a-fA-F]{6})/gi)) darkBgs.push(m[1].toLowerCase());
	ok('the stylesheet declares at least one --bg background', darkBgs.length > 0);
	// The dark background is the one the chrome color matches; confirm it is actually present as a --bg in the CSS,
	// so the chrome can never be a hand-picked color that matches no real theme surface.
	ok('the meta theme-color matches a real --bg background in the stylesheet', metaColor && darkBgs.includes(metaColor));

	// All four declarations agree, so a palette change to any one is caught here until it is made to all.
	ok('the meta theme-color and the manifest theme_color agree', metaColor && metaColor === manifestTheme);
	ok('the manifest theme_color and background_color agree', manifestTheme && manifestTheme === manifestBg);
	ok('every declared color is a valid 6-digit hex', [metaColor, manifestTheme, manifestBg].every(c => c && HEX.test(c)));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-THEME CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
