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

// Opening a search result (revealInVault) opens a file BY ITS PATH RELATIVE TO A MOUNTED VAULT. Two invariants keep
// that from becoming an arbitrary-file opener: the relative path is resolved against the mountpoint and CONFINED to it
// (a crafted "../" can never point the opener outside the vault), and the web route is refused over the network exactly
// like the reveal route (the opener runs on the machine hosting the app). These are source checks — no file is opened.
const vaultSrc = readSrc('lib/Vault.js');
ok('revealInVault confines the target to the mount (pathWithin) before opening', /async function revealInVault\([\s\S]{0,600}Common\.pathWithin\(abs,\s*mountpoint\)[\s\S]{0,200}throw new Error/.test(vaultSrc));
ok('revealInVault strips a leading slash so the relative path cannot become absolute', /revealInVault\([\s\S]{0,400}replace\(\/\^\[\\\\\/\]\+\//.test(vaultSrc));
const webSrc = readSrc('lib/webserver/index.js');
ok('the open-match route is refused over the network (this-computer-only, like reveal)', /\/api\/open-match'[\s\S]{0,300}if\s*\(exposed\)\s*throw new Error/.test(webSrc));
ok('the open-match route opens only through revealInVault (mount-confined), never a raw path', /\/api\/open-match'[\s\S]{0,400}Vault\.revealInVault\(/.test(webSrc));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REVEAL CHECKS PASSED'));
process.exit(failures ? 1 : 0);
