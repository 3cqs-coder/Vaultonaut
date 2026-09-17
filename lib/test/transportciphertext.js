'use strict';
// lib/test/transportciphertext.js — the P2P data plane (relay hub, stream tunnel, hole-punch) is a BLIND byte-splicer:
// only already-encrypted, certificate-pinned bytes ever cross it, and it never holds a vault key, never terminates the
// inner TLS, and never writes payload bytes anywhere they could be read back. That guarantee is architectural today —
// the transport modules simply do not import the decrypt path — but nothing pinned it, so a future edit that reached
// for the vault decryptor or logged a frame's contents would silently break "the relay only ever sees ciphertext".
// This static guard locks it: the transport plane may import only node built-ins and other transport modules, never a
// credential/decrypt module, and it emits no ad-hoc payload logging.
//
// Static only (no engine, no server, no network — fast and cross-platform).
//
// Run:  node lib/test/transportciphertext.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const LIB = path.join(__dirname, '..');
// The transport data plane. If a new transport module is added, list it here so it inherits the same guarantee.
const TRANSPORT = ['Relay.js', 'Tunnel.js', 'HolePunch.js', 'PortMap.js', 'LanDiscovery.js'];
// The ONLY local (`./`) modules a transport module may import. Common is shared utilities (no decryptor); the rest are
// other transport modules. Anything outside this set — above all the vault decryptor or a credential/KDF path — must
// never be pulled into the byte-splicer, so a new local import here fails the build until a human confirms it is safe.
const ALLOWED_LOCAL = new Set(['Common', 'PortMap', 'Relay', 'Tunnel', 'LanDiscovery']);
// Modules that live on the decrypt / credential / plaintext-serving path. Importing any of these into the transport
// plane would mean a key or plaintext could reach a route that is supposed to only ever move ciphertext.
const FORBIDDEN = /\b(Vault|KdfWorker|SearchWorker|SearchDefs|Serve|UiAuth|Recovery|Emergency|Notes)\b/;

function localRequires(src) {
	const out = [];
	for (const m of src.matchAll(/require\('\.\/([A-Za-z0-9_]+)'\)/g)) out.push(m[1]);
	return out;
}

function main() {
	for (const rel of TRANSPORT) {
		let src;
		try { src = fs.readFileSync(path.join(LIB, rel), 'utf8'); } catch (_) { ok(rel + ' exists to audit', false); continue; }

		// 1. Every local import is on the transport allowlist — no reach into the decrypt/credential path.
		const locals = localRequires(src);
		const stray = locals.filter((n) => !ALLOWED_LOCAL.has(n));
		ok(rel + ' imports only transport/shared modules (no decrypt path)' + (stray.length ? ': ' + stray.join(', ') : ''), stray.length === 0);

		// 2. Defense in depth: no forbidden module name appears in ANY require in the file (catches a non-`./` or
		//    dynamically spelled import of a credential/plaintext module).
		const reqLines = (src.match(/require\([^)]*\)/g) || []).filter((l) => FORBIDDEN.test(l));
		ok(rel + ' never requires a credential/plaintext module' + (reqLines.length ? ': ' + reqLines.join(' ') : ''), reqLines.length === 0);

		// 3. The data plane emits no ad-hoc payload logging: no console.* and no diagnostic logger is pulled in, so a
		//    frame's bytes can never be written to a log line. (Comments are allowed to mention these words.)
		const code = src.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, ''); // strip comments before scanning
		ok(rel + ' makes no console.* call (never prints payload bytes)', !/\bconsole\s*\./.test(code));
		ok(rel + ' pulls in no diagnostic logger on the data plane', !/require\('\.\/Logger'\)/.test(code) && !/\bLogger\./.test(code));
	}

	// A guard on the guard: the transport list must actually name the shipping data-plane files, so this test cannot
	// quietly pass by auditing nothing if a file is renamed.
	const present = TRANSPORT.filter((rel) => { try { return fs.statSync(path.join(LIB, rel)).isFile(); } catch (_) { return false; } });
	ok('all listed transport modules exist (the audit list is not stale)', present.length === TRANSPORT.length);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TRANSPORT-CIPHERTEXT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
