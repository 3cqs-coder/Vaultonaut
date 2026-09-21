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

// 5. The time-lock pairing must stay OFF the worker thread on Windows: Node's worker-thread teardown segfaults there
//    after the worker loaded the elliptic curve, so BOTH seal() and open() must short-circuit to the synchronous core
//    when !PAIRING_IN_WORKER, and no module OTHER than Timelock.js / TimelockWorker.js may spawn TimelockWorker (which
//    would reintroduce the crash on Windows). A regression here brings back the exit-139 crash.
{
	const tl = read('lib/Timelock.js');
	ok('Timelock derives the worker gate from the platform (win32 => synchronous)', /PAIRING_IN_WORKER\s*=\s*process\.platform\s*!==\s*'win32'/.test(tl));
	const seal = fnBody(tl, 'async function seal('), open = fnBody(tl, 'async function open(');
	ok('Timelock.seal short-circuits to the synchronous core when the worker is disabled', /if \(!PAIRING_IN_WORKER\) return sealToRound\(/.test(seal));
	ok('Timelock.open short-circuits to the synchronous core when the worker is disabled', /if \(!PAIRING_IN_WORKER\) return openWithSignature\(/.test(open));
	// No file outside Timelock.js / TimelockWorker.js references TimelockWorker (which would be a second, ungated way to
	// run the pairing in a worker and could crash on Windows).
	const offenders = [];
	const walk = (dir) => { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { if (e.name === 'node_modules' || e.name === 'test' || e.name.startsWith('.')) continue; const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else if (e.name.endsWith('.js') && e.name !== 'Timelock.js' && e.name !== 'TimelockWorker.js' && /TimelockWorker/.test(fs.readFileSync(p, 'utf8'))) offenders.push(path.relative(ROOT, p)); } };
	try { walk(path.join(ROOT, 'lib')); } catch (_) {}
	ok('no module outside Timelock spawns TimelockWorker (the pairing worker is single-sourced)', offenders.length === 0);
	if (offenders.length) for (const o of offenders) console.log('        ' + o);
}

// 6. The serve readiness probe must connect to LOOPBACK when the server is bound to a wildcard address (0.0.0.0 / ::,
//    used for a LAN or WAN serve), never TO the wildcard itself. Connecting to 0.0.0.0 maps to loopback on macOS and
//    Linux but Windows rejects it (WSAEADDRNOTAVAIL), so a probe against the bind address would fail every retry and
//    tear down an engine that is actually listening — LAN/WAN serving would never come up on Windows. A regression here
//    is invisible on the macOS/Linux CI, so pin it at the source.
{
	const serve = read('lib/Serve.js');
	ok('the serve readiness probe maps a wildcard bind to loopback (0.0.0.0/:: -> 127.0.0.1)', /probeHost\s*=\s*\(host === '0\.0\.0\.0' \|\| host === '::' \|\| !host\) \? '127\.0\.0\.1' : host/.test(serve));
	ok('the serve readiness probe connects to probeHost, not the raw bind host', /net\.connect\(\{ host: probeHost, port \}/.test(serve));
}

// 7. The vault-folder rename feature must stay cross-platform. Folder renames go through Common.renameWithRetry (it
//    retries the Windows EPERM/EBUSY/EACCES lock that a bare fs.rename would throw on a folder another handle still
//    holds), and opaqueVaultIdFromPath must strip the vault extension case-insensitively BEFORE the hex test — else an
//    opaque folder named with an upper-case ".VAULT" (as Windows/macOS may present it) would not be recognized as
//    already-opaque, and the auto-convert would try to rename it again. Both regress invisibly on the macOS/Linux CI.
{
	const anon = fnBody(read('lib/Vault.js'), 'async function anonymizeVault(');
	ok('anonymizeVault renames the folder via Common.renameWithRetry (Windows lock retry)', /Common\.renameWithRetry\(/.test(anon));
	ok('anonymizeVault does NOT use a raw fs.rename for the folder', !/fsp?\.rename\(/.test(anon));
	const mig = fnBody(read('lib/Vault.js'), 'async function migrateVaultPathSettings(');
	ok('migrateVaultPathSettings relocates its state via Common.renameWithRetry', /Common\.renameWithRetry\(/.test(mig) && !/fsp?\.rename\(/.test(mig));
	const src = read('lib/Vault.js');
	const opaque = src.slice(src.indexOf('function opaqueVaultIdFromPath('), src.indexOf('function opaqueVaultIdFromPath(') + 200);
	ok('opaqueVaultIdFromPath strips the vault extension (case-insensitively) before the hex test', /stripVaultExt\(/.test(opaque) && /\[0-9a-f\]\{32\}/.test(opaque));
}

// 8. Publishing the downloaded engine binary into place must ride out the transient Windows AV/indexer lock, like
//    every other file-into-place path, by moving through Common.renameWithRetry — never a bare fs.rename, which
//    fails its first attempt under that lock and reports a spurious fresh-install failure (no old binary to fall
//    back on). macOS/Linux never take that lock, so a regression here is invisible on the CI.
{
	const body = fnBody(read('lib/RcloneSetup.js'), 'async function liftBinary(');
	ok('liftBinary publishes the engine binary via Common.renameWithRetry (Windows lock retry)', /Common\.renameWithRetry\(/.test(body));
	ok('liftBinary does NOT use a bare fsp.rename for the binary', !/fsp\.rename\(/.test(body));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CROSS-PLATFORM-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
