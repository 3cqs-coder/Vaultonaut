'use strict';
// lib/test/uiaccessibility.js — locks the accessibility affordances of the web and mobile interfaces so a future
// edit cannot silently drop them. These are the attributes screen-reader and keyboard users depend on: live
// regions that announce feedback, a page heading, list semantics, a stateful favorite control, keyboard-operable
// mobile rows, and accessible names on icon-only or otherwise unlabeled controls. It renders the EJS views and
// scans the client scripts for the exact markers each fix added.
//
// Run:  node lib/test/uiaccessibility.js  (no engine, no network)

const fs = require('fs');
const path = require('path');
let ejs; try { ejs = require('ejs'); } catch (_) { ejs = null; }

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const PUB = path.join(__dirname, '..', 'webserver', 'public');
const read = (p) => fs.readFileSync(path.join(PUB, p), 'utf8');

function main() {
	// --- Rendered desktop view (index.ejs) ---
	if (!ejs) { console.log('  skip  (ejs not resolved)'); return done(); }
	const indexHtml = ejs.render(read('views/index.ejs'), { appName: 'Vaultonaut', cli: 'vdisk', packExt: '.vdisk', version: '1.0.0', isMac: true });
	// The page's top-level <h1> is the content heading ("Your vaults"), which is the correct screen-reader page
	// structure; the product name in the rail is identity, not the page heading, so it is a <span>.
	ok('the page has a top-level content <h1> (screen-reader page structure)', /<div class="main-title"><h1>[^<]+<\/h1>/.test(indexHtml));
	ok('the toast is an ARIA live region', /id="toast"[^>]*aria-live=/.test(indexHtml));
	ok('the toast is a popover, so it renders above an open modal dialog', /id="toast"[^>]*popover=/.test(indexHtml));
	ok('the vault list has list semantics', /id="vaults"[^>]*role="list"/.test(indexHtml));
	ok('the Auto-lock select has an accessible name', /id="autoLock"[^>]*aria-label=/.test(indexHtml));
	ok('the sync-speed preset select has an accessible name', /id="bwPreset"[^>]*aria-label=/.test(indexHtml));
	ok('the custom sync-speed input has an accessible name', /id="bwLimit"[^>]*aria-label=/.test(indexHtml));
	ok('the read-link expiry select has an accessible name', /id="keysReadCapExpiry"[^>]*aria-label=/.test(indexHtml));
	// Every serve copy button must name its own target, not just say "Copy".
	const copyButtons = indexHtml.match(/<button[^>]*class="copy-btn"[^>]*>/g) || [];
	ok('every serve copy button has a distinct accessible name', copyButtons.length >= 4 && copyButtons.every(b => /aria-label=/.test(b)));
	// The start-at-login dialog's scope choice is a radio group, so it must carry a group name (fieldset + legend),
	// and its conditional password field must have a visible label — else a screen-reader user gets two unlabeled
	// radios and an unnamed input.
	ok('the autostart scope radios are grouped in a fieldset with a legend', /<fieldset class="field-group">\s*<legend>[^<]+<\/legend>/.test(indexHtml) && /name="autostartScope"/.test(indexHtml));
	ok('the autostart password field has a visible label', /<span>Web login password[^<]*<\/span>\s*<input[^>]*id="autostartPass"/.test(indexHtml));
	// The search-scope radios are a group, so they carry a group name (fieldset + legend) like the other radio groups.
	ok('the search-scope radios are grouped in a fieldset with a legend', /<fieldset class="field-group">\s*<legend>[^<]+<\/legend>[\s\S]{0,200}name="searchScope"/.test(indexHtml));
	// Icon-only "up one folder" buttons must carry an accessible name, not just a glyph.
	ok('the browse and import "up" buttons have accessible names', /id="browseUp"[^>]*aria-label=/.test(indexHtml) && /id="importUp"[^>]*aria-label=/.test(indexHtml));
	// The active navigation item marks itself as the current page for assistive tech.
	ok('the active nav item exposes aria-current', /class="rail-item active"[^>]*aria-current="page"/.test(indexHtml));

	// --- Rendered login view (login.ejs) ---
	const loginHtml = ejs.render(read('views/login.ejs'), { appName: 'Vaultonaut', error: null, webauthn: [] });
	ok('the login page has an <h1>', /<h1[^>]*class="brand-name"[^>]*>/.test(loginHtml));
	// A failed sign-in reloads the page with focus in the password field, so the error must be a live region or a
	// screen-reader user gets no indication the password was wrong.
	const loginErrHtml = ejs.render(read('views/login.ejs'), { appName: 'Vaultonaut', error: 'The password is incorrect.', webauthn: [] });
	ok('the login error is announced to screen readers (role=alert)', /class="login-error"[^>]*role="alert"/.test(loginErrHtml));

	// --- Desktop client script (app.js) ---
	const app = read('js/app.js');
	ok('the toast() helper sets aria-live before showing the message', /function toast\([^)]*\)\s*\{[\s\S]{0,450}setAttribute\('aria-live'/.test(app));
	ok('the toast() helper shows the toast as a top-layer popover (above modals)', /function toast\([\s\S]{0,1100}showPopover\(/.test(app));
	ok('showResult() marks the result panel as a live region', /function showResult\([^)]*\)\s*\{[\s\S]{0,200}aria-live/.test(app));
	ok('the vault card is a list item', /class="card\$\{[^`]*\}"\s+role="listitem"/.test(app) || /role="listitem"/.test(app));
	ok('the favorite star exposes its pressed state', /star-btn[\s\S]{0,200}aria-pressed=/.test(app));
	ok('the favorite star has a stateful accessible name (not a static one)', /aria-label="\$\{v\.favorite \? 'Remove from favorites' : 'Add to favorites'\}"/.test(app));
	ok('read-only search hits use a non-clickable class (no misleading pointer)', app.includes('class="search-hit"') && !/class="note-item"[^>]*>' \+ esc\(m/.test(app));
	// Vault name and path carry dir="auto" so a non-Latin (e.g. right-to-left) name renders in its own base
	// direction instead of being visually reordered inside the LTR chrome.
	ok('the vault name is wrapped for bidirectional text (dir=auto)', /<span dir="auto">\$\{esc\(v\.name\)\}<\/span>/.test(app));
	ok('the vault path carries dir=auto', /class="path" dir="auto"/.test(app));
	// Every modal dialog gets an accessible name from its heading at startup — a native <dialog> is otherwise a
	// nameless "dialog" to a screen reader. One helper covers all of them (current and future) via aria-labelledby.
	ok('a startup helper names every dialog from its heading (aria-labelledby)', /function nameDialogs\(\)[\s\S]{0,500}aria-labelledby/.test(app) && /\bnameDialogs\(\);/.test(app));

	// --- Mobile client ---
	const mIndex = read('mobile/index.html');
	ok('the mobile toast is an ARIA live region', /id="toast"[^>]*aria-live=/.test(mIndex));
	ok('the mobile pairing error is announced (role=alert)', /id="pairError"[^>]*role="alert"/.test(mIndex));
	const mApp = read('mobile/app.js');
	ok('the mobile toast() sets aria-live before showing the message', /function toast\([^)]*\)\s*\{[\s\S]{0,160}setAttribute\('aria-live'/.test(mApp));
	ok('mobile file rows are keyboard-operable buttons (role, tabindex, key handler)', /role',\s*'button'/.test(mApp) && /tabIndex/.test(mApp) && /keydown/.test(mApp) && /Enter'\s*\|\|\s*e\.key === ' '/.test(mApp));
	// The full-screen file viewer is a modal overlay used on phones AND by the desktop "View files" action, so it
	// must move focus into itself, make the content behind it inert, close on Escape, and restore focus on close.
	ok('the mobile viewer moves focus into itself on open', /function showViewer[\s\S]{0,400}el\('viewerClose'\)\.focus\(\)/.test(mApp));
	ok('the mobile viewer makes the background inert while open', /function showViewer[\s\S]{0,400}setBgInert\(true\)/.test(mApp));
	// The inert must cover EVERY region behind the overlay — the two views AND the header (its theme toggle), or a
	// keyboard/screen-reader user could reach the toggle behind the opaque overlay.
	ok('the viewer inert covers the views and the header topbar', /function setBgInert[\s\S]{0,300}browseView[\s\S]{0,200}pairView[\s\S]{0,200}\.topbar/.test(mApp));
	ok('the mobile viewer restores focus to the opener on close', /function closeViewer[\s\S]{0,400}lastFocusBeforeViewer[\s\S]{0,80}\.focus\(\)/.test(mApp));
	ok('the mobile viewer closes on Escape', /e\.key === 'Escape'[\s\S]{0,90}closeViewer\(\)/.test(mApp));
	// File/folder names and breadcrumbs carry dir=auto for right-to-left names, like the desktop card.
	ok('mobile file/folder names carry dir=auto', /className = 'nm';\s*n\.setAttribute\('dir', 'auto'\)/.test(mApp));
	ok('the mobile viewer title carries dir=auto', /id="viewerName"[^>]*dir="auto"/.test(mIndex));

	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL UI-ACCESSIBILITY CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
