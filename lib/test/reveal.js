'use strict';
// lib/test/reveal.js — the "Reveal in file manager" cross-platform contract. The Reveal button failed on Windows
// twice for different reasons (a bare drive letter, then launching through the engine spawn wrapper), so lock the
// platform behavior in: the right opener command on every OS, and the Windows drive-letter normalization. These
// are pure checks — no file manager is actually launched — so the whole matrix runs from one host.
//
// Run:  node -r ./lib/test/_setup.js lib/test/reveal.js

const fs = require('fs');
const path = require('path');
const Vault = require('../Vault');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function eq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
const readSrc = (rel) => { try { return fs.readFileSync(path.join(__dirname, '..', '..', rel), 'utf8'); } catch (_) { return ''; } };

// The opener command is the standard file manager for each platform, and the path is passed as a single argv
// entry (so a space in it never needs quoting). One mechanism, three commands. fileManagerCommand stays PURE and
// deterministic (it never probes what is installed), so this matrix runs identically on every host and CI.
ok('macOS uses `open`', eq(Vault.fileManagerCommand('darwin', '/Vaults/My Vault'), ['open', ['/Vaults/My Vault']]));
ok('Windows uses `explorer`', eq(Vault.fileManagerCommand('win32', 'C:\\Users\\A\\My Vault'), ['explorer', ['C:\\Users\\A\\My Vault']]));
ok('Linux uses `xdg-open`', eq(Vault.fileManagerCommand('linux', '/Vaults/My Vault'), ['xdg-open', ['/Vaults/My Vault']]));
ok('an unknown Unix platform falls back to xdg-open', eq(Vault.fileManagerCommand('freebsd', '/v'), ['xdg-open', ['/v']]));

// openerCommand() maps a resolved Linux/Unix opener to its argv. `gio` needs an "open" subcommand; every other
// opener takes the target as its single argument. This is the pure mapping the reveal/open-external fallback chain
// uses once unixOpener() has picked whichever opener actually exists on the box.
ok('openerCommand: gio takes an "open" subcommand', eq(Common.openerCommand('gio', '/Vaults/My Vault'), ['gio', ['open', '/Vaults/My Vault']]));
ok('openerCommand: xdg-open takes the target directly', eq(Common.openerCommand('xdg-open', '/v'), ['xdg-open', ['/v']]));
ok('openerCommand: kde-open takes the target directly', eq(Common.openerCommand('kde-open5', '/v'), ['kde-open5', ['/v']]));

// normalizeMountpoint maps a BARE Windows drive letter to the drive root (so `explorer X:` — which is
// drive-relative and opens nothing — becomes `explorer X:\`). Force the platform so the Windows branch is
// exercised from any host; a path that already has a separator, or any non-Windows platform, is left to resolve.
const realPlat = process.platform;
try {
	Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
	ok('Windows: bare "X:" -> drive root "X:\\"', Vault.normalizeMountpoint('X:') === 'X:\\');
	ok('Windows: lowercase "d:" is upper-cased to "D:\\"', Vault.normalizeMountpoint('d:') === 'D:\\');
	ok('Windows: an already-rooted "X:\\Vaults\\v" is NOT turned into a bare-letter root', Vault.normalizeMountpoint('X:\\Vaults\\v') !== 'X:\\');
} finally {
	Object.defineProperty(process, 'platform', { value: realPlat, configurable: true });
}

// A search result opens in the built-in ZERO-RESIDUE viewer, not an external app — the file decrypts in the browser
// with no OS preview cache, reusing the existing "View files & notes" flow. Two invariants keep the deep-link private
// and robust: the desktop side carries the target file path in the URL FRAGMENT (never the query, so it is not sent to
// the server) as `&f=<url-encoded path>`, and the viewer scrubs it from the address bar (replaceState) and opens the
// file only after the names are decrypted locally, treating a missing file as "just show the list". These are source
// checks across the desktop client and the viewer.
const clientSrc = readSrc('lib/webserver/public/js/app.js');
ok('a clicked search result opens in the in-app viewer, never an external app', !/\/api\/open-match/.test(clientSrc) && /openMobile\(searchTarget,[^;]*,\s*rel\)/.test(clientSrc));
ok('a MOUNTED vault opens the result with no password prompt (reuses the mounted key via a local mobile-start)', /v\.mounted\)[\s\S]{0,400}\/api\/mobile-start',\s*\{\s*path:\s*searchTarget,\s*local:\s*true\s*\}/.test(clientSrc));
ok('the viewer deep-link rides in the URL fragment, so the file path is never sent to the server', /'#'\s*\+\s*r\.code\s*\+\s*\(viewerFileTarget\s*\?\s*'&f='\s*\+\s*encodeURIComponent\(viewerFileTarget\)/.test(clientSrc));
ok('a plain browser reuses one named viewer window (no window per file); the desktop app navigates in place', /const VIEWER_WINDOW = 'vaultonaut-viewer'/.test(clientSrc) && /window\.open\('', VIEWER_WINDOW\)/.test(clientSrc) && /r\.inApp\)[\s\S]{0,90}location\.href = url/.test(clientSrc));
// Search results are real keyboard controls, not mouse-only divs: each hit carries role="button" tabindex="0" and a
// keydown handler opens the focused one on Enter or Space, so results are reachable and usable without a mouse.
ok('search results are keyboard-accessible (role=button, tabindex, Enter/Space activation)', /class="search-hit search-hit-open" role="button" tabindex="0"/.test(clientSrc) && /addEventListener\('keydown'[\s\S]{0,160}e\.key !== 'Enter' && e\.key !== ' '[\s\S]{0,160}hit\.click\(\)/.test(clientSrc));
const webSrc = readSrc('lib/webserver/index.js');
ok('the no-password (mounted-key) viewer session is refused over the network — this-computer-only', /useMountedKey = !!local && !password && !exposed/.test(webSrc));
const vaultSrc = readSrc('lib/Vault.js');
ok('the mounted key is reused ONLY for an ephemeral, unrecorded local grant (never a recorded/revocable one)', /if \(master && !record\)/.test(vaultSrc) && /useMountedKey\) master = await mountedMasterFor/.test(vaultSrc));
const viewerSrc = readSrc('lib/webserver/public/mobile/app.js');
ok('the viewer scrubs the deep-link from the address bar and opens the file only after local decryption', /history\.replaceState\(null, '', location\.pathname\)/.test(viewerSrc) && /function maybeOpenPending\(\)/.test(viewerSrc) && /if \(!hit\)/.test(viewerSrc));
ok('the viewer matches the deep-linked file with a normalization- and whitespace-tolerant key (macOS exotic spaces)', /function matchKey\(s\)/.test(viewerSrc) && /normalize\('NFC'\)\.replace\(\/\\s\+\/g, ' '\)/.test(viewerSrc) && /matchKey\(allFiles\[i\]\.path\)\s*===\s*target/.test(viewerSrc));
// The manual "Update index" rebuild confirms first (it reads the whole vault and rewrites the in-vault index); the
// automatic search-time refresh and the watcher stay silent.
ok('the manual Update index button confirms before rebuilding', /#searchIndexBtn'\)\.addEventListener\('click'[\s\S]{0,500}await uiConfirm\(\{[\s\S]{0,600}if \(!go\) return;/.test(clientSrc));

// Back from a search-opened file returns to the SEARCH, not the vault's file list or the dashboard. The app remembers
// the search (vault + scope + query) before opening the viewer, and re-opens it on return; the viewer routes a
// deep-linked Back back to the app (or closes its own tab), instead of dropping into the file list.
ok('the app remembers the search before opening a result and restores it on return', /rememberSearchReturn\(\)/.test(clientSrc) && /sessionStorage\.setItem\('vdisk-search-return'/.test(clientSrc) && /function maybeRestoreSearchReturn\(\)/.test(clientSrc) && /openSearch\(ctx\.path, ctx\.name\)/.test(clientSrc) && /if \(ctx\.query\) \{ try \{ \$\('#searchForm'\)\.requestSubmit\(\)/.test(clientSrc));
ok('the search restore runs once per page load and only after its vault is rendered', /if \(searchReturnChecked\) return;/.test(clientSrc) && /if \(!vaultsByPath\[ctx\.path\]\) return;/.test(clientSrc) && /renderVaults\(\);\s*\n\s*try \{ maybeRestoreSearchReturn\(\);/.test(clientSrc));
ok('the viewer routes a deep-linked Back to the search (close its own tab, else back to the app)', /deepLinked = true;/.test(viewerSrc) && /if \(deepLinked && wasOpen\) \{ deepLinked = false;[\s\S]{0,80}returnToSearch\(\); return; \}/.test(viewerSrc) && /window\.opener && !window\.opener\.closed\) \{ window\.close\(\); return; \}/.test(viewerSrc));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REVEAL CHECKS PASSED'));
process.exit(failures ? 1 : 0);
