'use strict';
// lib/test/frontendsafetext.js — every browser bundle must escape untrusted display text (file names, labels) through
// ONE shared sanitizer, so the desktop and mobile clients can never drift to different escaping and leave one with a
// cross-site-scripting hole the other lacks. This loads the shared module (public/shared/safe-text.js) and checks its
// behavior, then pins that neither app bundle keeps its own escape copy and that each page loads the shared file before
// its app code. Pure, no engine, no browser.
//
// Run:  node lib/test/frontendsafetext.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const pub = path.join(__dirname, '..', 'webserver', 'public');
const read = (p) => fs.readFileSync(path.join(pub, p), 'utf8');

// --- load the shared module the way a browser would (it attaches VaultSafe to `window`) ---
const sandbox = { window: {} };
vm.createContext(sandbox);
vm.runInContext(read('shared/safe-text.js'), sandbox);
const VaultSafe = sandbox.window.VaultSafe;
ok('the shared sanitizer defines VaultSafe.escapeHtml', VaultSafe && typeof VaultSafe.escapeHtml === 'function');

if (VaultSafe && VaultSafe.escapeHtml) {
	const esc = VaultSafe.escapeHtml;
	ok('escapes the five markup-significant characters', esc('<a href="x">\'&\'</a>') === '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
	ok('replaces a C0 control character with the replacement character', esc('a\x00b') === 'a�b');
	ok('replaces a bidi OVERRIDE (spoofing) character', esc('safe‮txt.exe') === 'safe�txt.exe');
	ok('leaves a genuine right-to-left letter alone', esc('אב') === 'אב'); // Hebrew letters are not format chars
	ok('null and undefined escape to the empty string', esc(null) === '' && esc(undefined) === '');
}

// --- neither app bundle keeps its OWN escape copy (they must reference the shared one) ---
const MARKUP_ESCAPE = /replace\(\/\[&<>"'\]\/g/; // the signature of a hand-rolled HTML escaper
const OWN_UNSAFE_DEF = /(const|var|let)\s+UNSAFE_DISPLAY\s*=/;
for (const [label, file] of [['desktop', 'js/app.js'], ['mobile', 'mobile/app.js']]) {
	const src = read(file);
	ok(label + ' app bundle references the shared VaultSafe.escapeHtml', /window\.VaultSafe\.escapeHtml/.test(src));
	ok(label + ' app bundle does NOT define its own HTML escaper', !MARKUP_ESCAPE.test(src));
	ok(label + ' app bundle does NOT define its own UNSAFE_DISPLAY regex', !OWN_UNSAFE_DEF.test(src));
}

// --- the MOBILE client renders decrypted, attacker-influenceable strings (file names, field values, note body, the
//     viewer title) through its own DOM code, so it must neutralize bidi/control characters the same way the desktop
//     viewer does — a right-to-left override in a URL label could otherwise spoof a different address on the phone. ---
{
	const m = read('mobile/app.js');
	ok('mobile app defines a display-safe text helper', /function safeText\(/.test(m));
	ok('mobile safeText reuses the shared strip (displaySafe or UNSAFE_DISPLAY), not a hand-rolled one', /VaultSecret\.displaySafe/.test(m) && /VaultSafe\.UNSAFE_DISPLAY/.test(m));
	ok('mobile strips file/folder names', /textContent = safeText\(name\)/.test(m));
	ok('mobile strips typed-field labels and values', /textContent = safeText\(f\.label/.test(m) && /textContent = safeText\(f\.value/.test(m));
	ok('mobile strips the note body', /pre\.textContent = safeText\(content\.note\)/.test(m));
	ok('mobile strips the viewer title', /viewerName'\)\.textContent = safeText\(name\)/.test(m));
}

// --- each page loads the shared sanitizer BEFORE its app code (or VaultSafe would be undefined at first use) ---
function loadsBefore(html, sharedTag, appTag) {
	const a = html.indexOf(sharedTag), b = html.indexOf(appTag);
	return a >= 0 && b >= 0 && a < b;
}
const desktopHtml = read('views/index.ejs');
ok('the desktop page loads safe-text.js before app.js', loadsBefore(desktopHtml, 'safe-text.js', '/js/app.js'));
const mobileHtml = read('mobile/index.html');
ok('the mobile page loads safe-text.js before app.js', loadsBefore(mobileHtml, 'safe-text.js', 'app.js'));

// --- the shared secret renderer strips bidi/control chars from displayed values (spoofing defense) ---
// renderItem places values with textContent (no markup risk), but a right-to-left override or invisible control inside
// a stored value — most dangerously a URL label — can make the DISPLAYED text read differently from what it is. The
// module exposes displaySafe for that; load it the way a browser would (it attaches VaultSecret to `self`).
const schemaBox = { self: {} };
vm.createContext(schemaBox);
vm.runInContext(read('shared/secret-schema.js'), schemaBox);
const VaultSecret = schemaBox.self.VaultSecret;
ok('the shared schema exposes VaultSecret.displaySafe', VaultSecret && typeof VaultSecret.displaySafe === 'function');
if (VaultSecret && VaultSecret.displaySafe) {
	const ds = VaultSecret.displaySafe;
	ok('displaySafe replaces a bidi OVERRIDE character in a value', ds('example.com‮moc.live') === 'example.com�moc.live');
	ok('displaySafe replaces a C0 control character', ds('a\x00b') === 'a�b');
	ok('displaySafe leaves genuine right-to-left letters alone', ds('אב') === 'אב');
	ok('displaySafe maps null/undefined to the empty string', ds(null) === '' && ds(undefined) === '');
}
// Static: the renderer routes every user-controlled display string through displaySafe — the field label, the plain
// value, the URL link text, and the note body — so none can be a spoofing vector.
const schemaSrc = read('shared/secret-schema.js');
ok('renderItem strips the field label', /lab\.textContent = displaySafe\(/.test(schemaSrc));
ok('renderItem strips the plain value and the URL link text', /a\.textContent = displaySafe\(f\.value\)/.test(schemaSrc) && /val\.textContent = displaySafe\(f\.value/.test(schemaSrc));
ok('renderItem strips the note body', /pre\.textContent = displaySafe\(item\.note\)/.test(schemaSrc));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL FRONTEND-SAFE-TEXT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
