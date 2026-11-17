'use strict';
// lib/test/networkdoor.js — pins the on-demand "network door": the way a phone reaches THIS running instance on the LAN
// WITHOUT enabling start-at-login. The door is one extra 0.0.0.0 HTTPS listener opened in the SAME backend process (so
// mobile pairing state is shared with the app window), and "exposed" becomes a PER-REQUEST fact carried by
// AsyncLocalStorage: a request on the door (or a start-at-login network bind) is exposed and gated; a loopback request from
// the owner is not. This is security-critical — if a guard read the process-wide value instead of the per-request one, a
// LAN request would bypass a "refuse over the network" guard — so these source guards pin the wiring. (A full live
// exposed-bind test needs TLS + a login and would be flaky; the request/transport contract lives in closures inside
// start(), so a source guard is the right, cheap level, matching routeguards.js.)
//
// Run:  node lib/test/networkdoor.js

const fs = require('fs');
const path = require('path');
let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const server = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
const mroutes = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'mobileRoutes.js'), 'utf8');
const bodyOf = (route, span = 900) => { const at = server.indexOf("'" + route + "'"); return at >= 0 ? server.slice(at, at + span) : ''; };

// ---- Per-request exposure: the foundation every guard below relies on ------------------------------------------------
ok('exposure is a PER-REQUEST fact: reqExposed is the base bind OR a request on the network door port',
	/const reqExposed = \(req\) => exposed \|\| !!\(networkDoor && req && req\.socket && req\.socket\.localPort === networkDoor\.port\)/.test(server));
ok('isExposed() reads the per-request value from the AsyncLocalStorage store, falling back to the base',
	/const isExposed = \(\) => \{ const s = reqCtx\.getStore\(\); return s \? s\.exposed : exposed; \}/.test(server));
ok('the FIRST middleware runs the chain inside the per-request exposure context',
	/app\.use\(\(req, res, next\) => reqCtx\.run\(\{ exposed: reqExposed\(req\) \}, next\)\)/.test(server));
// The context middleware must come BEFORE the auth gate and the /api guard, or those would read a stale value.
ok('the exposure context is established before the /api guard and the login gate', (function () {
	const ctx = server.indexOf('reqCtx.run({ exposed: reqExposed(req) }');
	const apiGuard = server.indexOf("app.use('/api',");
	const loginGate = server.indexOf('Login gate.');
	return ctx > 0 && ctx < apiGuard && ctx < loginGate;
})());

// ---- The "refuse over the network" guards all read the per-request value, not the process-wide one -------------------
ok('refuseOutboundIfExposed uses isExposed()', /const refuseOutboundIfExposed = \(what\) => \{ if \(isExposed\(\)\) throw/.test(server));
ok('refuseHostFsIfExposed uses isExposed()', /const refuseHostFsIfExposed = \(action\) => \{ if \(isExposed\(\)\) throw/.test(server));
ok('refuseEmergencyConfigIfExposed uses isExposed()', /const refuseEmergencyConfigIfExposed = \(\) => \{ if \(isExposed\(\)\) throw/.test(server));
ok('requireVaultReadIfExposed uses isExposed()', /requireVaultReadIfExposed = async[\s\S]{0,80}if \(!isExposed\(\)\) return;/.test(server));
// A sweep: NO request-handling code still branches on the raw process-wide `exposed` (only the reviewed STARTUP sites may).
// Allowed startup sites: the bind computation + its two mirror assignments, the ownerToken, the IP-rule validation/install,
// the startup TLS block, and the listen-callback log/pidfile. Anything else reading `exposed` (not isExposed/reqExposed/
// interfaceExposed) would be a per-request guard left on the stale value.
{
	// Each reviewed, process-wide `exposed` site, matched on the COMMENT-STRIPPED, trimmed line start. All are startup-time
	// (bind computation + mirrors, ownerToken, IP-rule validation/install, the TLS block, the listen-callback log/pidfile)
	// EXCEPT `} else if (exposed) {` — the mobile-start host-advertising branch, which deliberately reads the start-at-login
	// bind (a server-config fact, not request gating) to advertise those hosts when there is no door.
	const STARTUP_OK = [
		'const exposed = !isLoopbackAddr', 'redactErrorPaths = exposed;', 'const ownerToken = exposed ?',
		'if (exposed && ipAllow.dropped', 'if (exposed && ipDeny.dropped', 'if (exposed && !uiAuth.enabled)',
		'if (exposed) {', 'if (exposed && (ipAllow.list.length', '} else if (exposed) {', 'const shown = exposed ?',
		'if (!exposed && runDirHardened)', "if (exposed) Common.log('Exposed",
	];
	const offenders = [];
	for (const raw of server.split('\n')) {
		const line = raw.replace(/\/\/.*$/, '').trim();                        // drop the inline comment, where "exposed" often appears in prose
		if (!line || !/\bexposed\b/.test(line)) continue;
		if (/isExposed|reqExposed|interfaceExposed/.test(line)) continue;      // the per-request forms + the /api/state mirror
		if (STARTUP_OK.some((s) => line.startsWith(s))) continue;             // a reviewed startup (or host-advertising) site
		offenders.push(line.slice(0, 90));
	}
	ok('no request-path code still branches on the process-wide `exposed` (only reviewed startup sites)', offenders.length === 0);
	if (offenders.length) for (const o of offenders) console.log('        ' + o);
}

// ---- Opening / closing the door --------------------------------------------------------------------------------------
ok('openNetworkDoor requires a web password (a network interface must need a login)',
	/async function openNetworkDoor\(\)[\s\S]{0,260}if \(!a\.enabled\) throw/.test(server));
ok('the door binds 0.0.0.0 on a dedicated port with the shared self-signed LAN cert',
	/Cert\.ensureLanCert\(\)/.test(server) && /s\.listen\(DOOR_PORT, '0\.0\.0\.0'/.test(server) && /const DOOR_PORT = port \+ 1/.test(server));
ok('a post-listen door socket error is logged, never thrown (crash-proof)',
	/s\.on\('error', \(e\) => \{[\s\S]{0,80}Common\.warn\('\[web\] network-door socket error/.test(server));
// The toggle is loopback-only (a network caller must not open/close the door) and sets a web password when enabling.
ok('/api/network-expose refuses over a network connection (loopback-only)',
	/if \(isExposed\(\)\) throw new Error\('Network access can only be changed/.test(bodyOf('/api/network-expose', 1200)));
ok('/api/network-expose sets a web password (>=8) when none exists, then opens the door',
	/pw\.length < 8\) throw[\s\S]{0,260}setUiPassword\(pw\)[\s\S]{0,400}openNetworkDoor\(\)/.test(bodyOf('/api/network-expose', 1500)));
ok('/api/network-expose closes the door when disabled', /if \(!body\.enable\) \{ await closeNetworkDoor\(\)/.test(bodyOf('/api/network-expose', 1200)));

// ---- Teardown: the door must never outlive a shutdown, travel, or lock-all (no leaked listener) -----------------------
ok('the shutdown drain closes the network door', /await closeNetworkDoor\(\); \} catch \(_\) \{\} \/\/ close the on-demand network listener/.test(server));
ok('travel mode closes the network door', /travel-start'[\s\S]{0,120}await closeNetworkDoor\(\)/.test(server));
ok('"Lock all" closes the network door', /lock-all'[\s\S]{0,120}await closeNetworkDoor\(\)/.test(server));

// ---- State + pairing integration -------------------------------------------------------------------------------------
ok('/api/state reports the network-door status (open, port, hosts)',
	/networkDoor: \(networkDoor \? \{ open: true, port: networkDoor\.port, hosts: networkDoor\.hosts \} : \{ open: false \}\)/.test(server));
ok('mobile-start advertises the door (its own HTTPS port) so the phone URL uses it, not the loopback port',
	/if \(networkDoor\) \{\s*out\.hosts = networkDoor\.hosts; out\.port = networkDoor\.port;/.test(server));
ok('the mobile router is given the per-request exposure getter, not a fixed boolean', /isLoopbackAddr, exposed: isExposed \}\)/.test(server));
ok('the mobile router accepts a boolean OR a getter (one contract, no drift)',
	/const exposedNow = typeof exposed === 'function' \? exposed : \(\) => !!exposed;/.test(mroutes) && /if \(!exposedNow\(\)\)/.test(mroutes));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NETWORK-DOOR CHECKS PASSED'));
process.exit(failures ? 1 : 0);
