'use strict';
// lib/test/servestatus.js — a source-level guard that every "serve as a node" mode SHOWS the user what is happening
// while it starts, instead of a frozen "starting…". Starting a node can take minutes (a Tor bootstrap, a router-port
// map, hub registration), so the server reports step-by-step progress through the serve onEvent channel, the web
// server buffers it, the UI polls it, and Tor's own bootstrap percent is surfaced. This is engine-free (source-only),
// so it runs on every platform and CI runner and fails the build if any part of that progress path is dropped.
//
// Run:  node lib/test/servestatus.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
function fnBody(src, decl) { const i = src.indexOf(decl); if (i < 0) return null; const j = src.indexOf('\n}', i); const raw = j < 0 ? src.slice(i) : src.slice(i, j); return raw.replace(/\/\/.*$/gm, ''); }

const Onion = read('lib/Onion.js');
const Vault = read('lib/Vault.js');
const Web = read('lib/webserver/index.js');
const App = read('lib/webserver/public/js/app.js');

// 1. Tor surfaces its OWN bootstrap progress, not just the final 100%. _spawnTor takes an onProgress and reports the
//    parsed "Bootstrapped N%" percentage as it advances, so a multi-minute connect is never a frozen status.
{
	const b = fnBody(Onion, 'async function _spawnTor(') || '';
	ok('_spawnTor accepts an onProgress callback', /_spawnTor\(extraArgs, bridge, onProgress/.test(Onion));
	ok('_spawnTor parses intermediate Tor bootstrap percent (not only 100%)', /Bootstrapped \(\\d/.test(b) && /onProgress\(\{\s*percent/.test(b));
	ok('_spawnTor still resolves on Bootstrapped 100%', /Bootstrapped 100%/.test(b));
	// The connect-timeout message must be ACTIONABLE: name the likely cause and the fix (a bridge), not just "failed".
	ok('the Tor connect-timeout message tells the user to try a bridge', /could not connect to the anonymizing network/.test(b) && /bridge/i.test(b));
}

// 2. provideTor and the managed-Tor helpers thread onProgress through, so the serve path can receive live bootstrap
//    status whether it uses a fresh managed client Tor or a single-hop server Tor.
{
	const pv = fnBody(Onion, 'async function provideTor(') || '';
	ok('provideTor reads opts.onProgress', /opts\.onProgress/.test(pv));
	ok('provideTor passes onProgress to the managed client Tor', /startManagedTor\(bridge, onProgress/.test(pv));
	ok('provideTor passes onProgress to the single-hop server Tor', /startManagedServerTor\(bridge, onProgress/.test(pv));
	ok('startManagedTor/ServerTor thread onProgress into _ensureManaged', /_ensureManaged\(false, bridge, onProgress/.test(Onion) && /_ensureManaged\(true, bridge, onProgress/.test(Onion));
}

// 3. The serve transport reports human-readable progress for EVERY mode through onEvent, so the UI can show what is
//    happening for onion, LAN, WAN, and relay alike — not just one of them.
{
	const b = fnBody(Vault, 'async function serveDirTransport(') || '';
	ok('serveDirTransport defines a progress reporter that emits an onEvent progress event', /const prog = /.test(b) && /type: 'progress'/.test(b));
	ok('onion mode reports the Tor bootstrap percent as progress', /provideTor\(\{[^}]*onProgress:/.test(b) && /Connecting to the Tor network/.test(b));
	ok('WAN mode reports opening a router port', /Opening a port on your router/.test(b));
	ok('LAN/relay report preparing the certificate', /Preparing the security certificate/.test(b));
	ok('LAN mode reports announcing on the local network', /Announcing on your local network/.test(b));
	ok('relay mode reports connecting to and registering with the hub', /Connecting to the relay hub/.test(b) && /Registering with the relay hub/.test(b));
}

// 4. The web server buffers that progress per vault and exposes it to the UI, and clears it once the start settles so
//    stale status never lingers.
{
	ok('the web server keeps a per-vault serveProgress map', /serveProgress = new Map\(/.test(Web));
	ok('a progress onEvent is recorded into serveProgress', /ev\.type === 'progress'[^\n]*serveProgress\.set/.test(Web));
	ok('serveProgress is cleared when the start settles (finally)', /finally \{ startingServe\.delete\(key\); serveProgress\.delete\(key\);/.test(Web));
	ok('the /api/serve-progress poll route is registered', /'\/api\/serve-progress'/.test(Web));
	ok('the poll returns the current step message and percent', /progress: pr \? \{ message: pr\.message, percent: pr\.percent \}/.test(Web));
}

// 5. The UI polls that endpoint WHILE the serve-start request is in flight and stops the moment it settles, so the
//    displayed status advances live and never overwrites the final result.
{
	ok('the serve dialog polls /api/serve-progress', /api\('\/api\/serve-progress'/.test(App));
	ok('the poll updates the serve status message', /serveMsg\('', esc\(pr\.progress\.message\)\)/.test(App));
	ok('the poll is started before the serve-start request and stopped when it settles', /pollServeStatus\(\);/.test(App) && /servePolling = false;/.test(App));
}

// 6. A start can be CANCELED, with a confirmation, and canceling actually tears the attempt down rather than leaving a
//    node starting or serving in the background. An AbortSignal threads from the web server through provideTor down to
//    the Tor spawn, so a cancel kills the managed Tor mid-bootstrap instead of hanging out the full timeout.
{
	const spawnBody = fnBody(Onion, 'async function _spawnTor(') || '';
	ok('_spawnTor accepts an AbortSignal and kills Tor on abort', /_spawnTor\(extraArgs, bridge, onProgress, signal\)/.test(Onion) && /signal\.addEventListener\('abort'/.test(spawnBody));
	const pv = fnBody(Onion, 'async function provideTor(') || '';
	ok('provideTor threads the abort signal to the managed Tor', /opts\.signal/.test(pv) && /startManagedTor\(bridge, onProgress, signal\)/.test(pv));
	const sd = fnBody(Vault, 'async function serveDirTransport(') || '';
	ok('serveDirTransport passes the signal to provideTor and bails out when aborted', /provideTor\(\{[^}]*signal/.test(sd) && /signal && signal\.aborted/.test(sd));
	ok('the web server tracks an AbortController per in-flight start and passes its signal into the serve', /startAborters = new Map\(/.test(Web) && /new AbortController\(\)/.test(Web) && /signal: aborter\.signal/.test(Web));
	ok('a start that finished despite a cancel is torn down (canceledStarts check)', /canceledStarts\.add\(/.test(Web) && /canceledStarts\.has\(/.test(Web));
	ok('the /api/serve-cancel route is registered (handles a vault path and the store)', /'\/api\/serve-cancel'/.test(Web) && /storeAborter/.test(Web));
	ok('the serve dialog Cancel confirms before aborting, then calls serve-cancel', /uiConfirm\(\{ title: 'Stop starting the node\?'/.test(App) && /'\/api\/serve-cancel', \{ path: serveTarget \}/.test(App));
	ok('the storage-node dialog also supports a confirmed cancel', /uiConfirm\(\{ title: 'Stop starting the storage node\?'/.test(App) && /'\/api\/serve-cancel', \{ store: true \}/.test(App));
	ok('Escape during a start routes through the confirmed cancel, not a silent close', /addEventListener\('cancel', \(e\) => \{ if \(serveStarting\)/.test(App));
	ok('while starting, the plain Close is hidden and a Cancel start button is shown', /setServeStarting\(/.test(App) && /id="serveCancel"/.test(read('lib/webserver/public/views/index.ejs')) && /id="storeNodeCancel"/.test(read('lib/webserver/public/views/index.ejs')));
	ok('stopping a live serve asks for confirmation first', /uiConfirm\(\{ title: 'Stop serving this node\?'/.test(App));
	ok('stopping the storage node asks for confirmation first', /uiConfirm\(\{ title: 'Stop the storage node\?'/.test(App));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SERVE-STATUS CHECKS PASSED'));
process.exit(failures ? 1 : 0);
