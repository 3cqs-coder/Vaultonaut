'use strict';
// lib/test/help.js — guards the in-app Help feature's moving parts so it cannot silently break. Help renders the
// shipped docs/README.md with the vendored `marked` library inside a wired-up dialog, served at /readme.md. If any
// of those pieces is removed or renamed the Help would quietly stop working, so this pins each in place: the
// markdown library loads and renders, the guide file exists and is the real README, the route is registered, the
// library is loaded before app.js, the dialog and its controls are in the page, and app.js wires them up.
// Pure/static — no engine and no running server, so it is fast and cross-platform.
//
// Run:  node lib/test/help.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const web = path.join(__dirname, '..', 'webserver');
const read = (p) => fs.readFileSync(p, 'utf8');

function main() {
	// 1. The vendored markdown library loads and actually renders markdown to HTML (not just present on disk).
	let marked = null; try { marked = require(path.join(web, 'public', 'js', 'vendor', 'marked', 'marked.min.js')); } catch (_) {}
	ok('the vendored marked library loads', !!(marked && typeof marked.parse === 'function'));
	const html = (marked && marked.parse) ? marked.parse('# Title\n\nA paragraph with a [link](#a) and `code`.') : '';
	ok('marked renders a heading, paragraph, link, and code', /<h1/.test(html) && /<p/.test(html) && /<a /.test(html) && /<code/.test(html));

	// 2. The guide file Help serves exists and is the real, substantial README.
	const readme = path.join(__dirname, '..', '..', 'docs', 'README.md');
	const md = fs.existsSync(readme) ? read(readme) : '';
	ok('the guide file docs/README.md exists, is the Vaultonaut README, and is substantial', /^# Vaultonaut/m.test(md) && md.length > 5000);

	// 3. The server registers the /readme.md route that Help fetches.
	ok('the /readme.md route is registered on the web server', /['"]\/readme\.md['"]/.test(read(path.join(web, 'index.js'))));

	// 4. The Help dialog and its controls are in the page, and the markdown library loads BEFORE app.js uses it.
	const ejs = read(path.join(web, 'public', 'views', 'index.ejs'));
	ok('the page loads the marked library before app.js', ejs.indexOf('marked.min.js') >= 0 && ejs.indexOf('marked.min.js') < ejs.indexOf('js/app.js'));
	['helpBtn', 'helpDialog', 'helpBody', 'helpSearch', 'helpMatches', 'helpPrev', 'helpNext'].forEach(id => ok('the page has #' + id, ejs.indexOf('id="' + id + '"') >= 0));

	// 5. app.js wires opening Help, rendering with marked, the "/" shortcut, and the jump-to-section bar.
	const app = read(path.join(web, 'public', 'js', 'app.js'));
	ok('app.js fetches /readme.md and renders it with marked', /fetch\('\/readme\.md'/.test(app) && /marked\.parse/.test(app));
	ok('app.js wires the "/" open shortcut and the section-jump bar', /key !== '\/'/.test(app) && /helpRenderSections/.test(app));
	// Regression guard: the search must NOT pre-filter text nodes with a stateful global rx.test(), whose lastIndex
	// carries across nodes and silently under-counts matches. Strip comments first so the explanatory note is not
	// mistaken for the bug, then require the buggy call to be absent and the per-node lastIndex reset to be present.
	const activeCode = app.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
	ok('help search never calls a stateful global rx.test() (would under-count across text nodes)', !/rx\.test\s*\(/.test(activeCode));
	ok('help search resets the regex lastIndex per text node', /rx\.lastIndex = 0/.test(app) && /rx\.exec\(/.test(app));
	// Search-quality guards: a multi-word phrase that misses falls back to matching ANY word (so a near-miss
	// surfaces the relevant sections, not "no matches"); the section chips are RANKED by match count and land on
	// the most-relevant section; and each chip shows its per-section count.
	ok('help search falls back to matching any word when the exact phrase misses', /terms\.join\('\|'\)/.test(app) && /\/\\s\/\.test\(query\)/.test(app));
	ok('help sections are ranked by match count (most first)', /sort\(\([^)]*\)\s*=>\s*b\.count - a\.count\)/.test(app));
	ok('help search lands on the most-matched section', /ranked\.length \? ranked\[0\]\.firstIdx/.test(app));
	ok('each help section chip shows its match count (styled badge)', /class="help-chip-n"/.test(app) && /\.help-chip-n\s*\{/.test(read(path.join(web, 'public', 'css', 'app.css'))));

	// 6. Regression guard: a <dialog> stays hidden until opened only because of the UA rule
	// `dialog:not([open]) { display: none }`. The base .help-dialog rule must therefore NOT set `display`; any
	// display it needs for its flex layout must be scoped to .help-dialog[open]. Setting display unconditionally
	// once rendered the whole guide in normal flow, below the page, on every load before anyone opened it.
	const css = read(path.join(web, 'public', 'css', 'app.css'));
	const baseRule = (css.match(/\.help-dialog\s*\{[^}]*\}/) || [''])[0]; // the base rule, not the [open] variant
	ok('the base .help-dialog rule does not set display (so a closed dialog stays hidden)', !!baseRule && !/display\s*:/.test(baseRule));
	ok('.help-dialog[open] provides the flex layout only when open', /\.help-dialog\[open\]\s*\{[^}]*display\s*:\s*flex/.test(css));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL HELP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
