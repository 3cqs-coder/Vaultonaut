'use strict';
// lib/test/crossplatformdrift.js — static drift guards for the cross-platform bug CLASSES found during real
// per-OS testing. Each escaped the suite once; these source-level assertions fail the build if any regresses.
// Engine-free and fast — they read source and check invariants, in the style of the other *drift.js guards.
//
//   1. res.sendFile dotfiles:'allow' — Express send() 404s any absolute path with a dot-directory component, and
//      the Linux data dir is under ~/.local/share, so a bare sendFile there 404'd (worked on Windows/macOS).
//   2. Reveal spawn shape — the file manager must launch DETACHED with stdio ignored and WITHOUT windowsHide
//      (which suppresses explorer's window). Reveal broke twice by launching through the engine spawn wrapper.
//   3. One mount-liveness primitive — the Watchdog and the Windows isMounted branch must both probe through
//      Rclone.mountProbeCall (access-based), never fs.stat on the mount, which false-alarmed on WinFsp.
//   4. Desktop viewer back control — the local in-app viewer must keep a way back to the main window (a single
//      WebView cannot open a second tab), gated on session.local and navigating to '/'.
//
// Run:  node -r ./lib/test/_setup.js lib/test/crossplatformdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
// The body of a named function, from its declaration to the next top-level `\n}`, with line comments stripped so a
// keyword mentioned in a comment (e.g. "NOT windowsHide:") is never mistaken for the code doing it.
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return ''; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

// 1. Every bare res.sendFile passes dotfiles:'allow'. (express.static is exempt — its dotfiles check applies to the
//    request path relative to the root, not the root's own filesystem path.)
for (const rel of ['lib/webserver/index.js', 'lib/webserver/mobileRoutes.js']) {
	const src = read(rel);
	let idx = 0, n = 0, missing = 0;
	while ((idx = src.indexOf('.sendFile(', idx)) !== -1) { n++; if (!/dotfiles:\s*'allow'/.test(src.slice(idx, idx + 400))) missing++; idx += 10; }
	ok(rel + ": every sendFile passes dotfiles:'allow' (" + n + ' found)', n > 0 && missing === 0);
}

// 2. Reveal launches the file manager detached, stdio ignored, and NEVER with windowsHide.
{
	const body = fnBody(read('lib/Vault.js'), 'async function reveal(');
	ok('reveal() launches DETACHED', /detached:\s*true/.test(body));
	ok('reveal() ignores stdio (fire-and-forget)', /stdio:\s*'ignore'/.test(body));
	ok('reveal() does NOT pass windowsHide (it would suppress explorer\'s window)', !/windowsHide/.test(body));
	ok('reveal() does NOT go through the engine spawn wrapper (Rclone.exec)', !/Rclone\.exec/.test(body));
}

// 3. One access-based mount-liveness primitive, single-sourced.
{
	const Rclone = require('../Rclone');
	ok('Rclone.mountProbeCall is exported', typeof Rclone.mountProbeCall === 'function');
	const wd = read('lib/Watchdog.js');
	ok('the Watchdog probes via Rclone.mountProbeCall, not fs.stat', /Rclone\.mountProbeCall\(/.test(wd) && !/fsp?\.stat\(/.test(wd));
	const isMounted = fnBody(read('lib/Rclone.js'), 'async function isMounted(');
	ok('the Windows isMounted branch probes via mountProbeCall', /mountProbeCall\(/.test(isMounted));
}

// 4. The desktop in-app viewer keeps a way back to the main window.
{
	const html = read('lib/webserver/public/mobile/index.html');
	const js = read('lib/webserver/public/mobile/app.js');
	ok('the viewer defines a back control (#backBtn)', /id="backBtn"/.test(html));
	ok('the back control is shown only for the local desktop session', /el\('backBtn'\)\.hidden\s*=\s*!session\.local/.test(js));
	ok("the back control returns to the main app ('/')", /el\('backBtn'\)[\s\S]{0,80}location\.href\s*=\s*'\/'/.test(js));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CROSS-PLATFORM-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
