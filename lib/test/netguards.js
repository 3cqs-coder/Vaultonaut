'use strict';
// lib/test/netguards.js — the outbound-fetch safety rails. The only URLs the tool fetches are hardcoded/pinned
// (the release-metadata and driver-installer hosts), and downloads verify a SHA-256, so this is defense in depth —
// but the transport guards must not silently erode: a redirect must never DOWNGRADE https to plain http (which would
// let an on-path attacker strip TLS mid-fetch on the very requests whose integrity is otherwise trusted), and the
// redirect chain must be bounded. A trusted-HTTPS loopback server is not feasible here (the client validates certs by
// design), so the downgrade refusal is unit-tested directly and its WIRING into the fetch path is pinned statically;
// the redirect bound and normal fetch are exercised behaviorally against a loopback HTTP server.
//
// Run:  node lib/test/netguards.js

const http = require('http');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const path = require('path');
const Net = require('../Net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const { assertNoDowngrade, resolveRedirect } = Net._test;

// --- the downgrade guard itself: https -> http is refused; every other combination is allowed ---
function throws(fn) { try { fn(); return false; } catch (_) { return true; } }
ok('a redirect that downgrades https -> http is refused', throws(() => assertNoDowngrade('https://a.example/x', 'http://a.example/y')));
ok('an https -> https redirect is allowed', !throws(() => assertNoDowngrade('https://a.example/x', 'https://a.example/y')));
ok('an http -> http redirect is allowed', !throws(() => assertNoDowngrade('http://a.example/x', 'http://a.example/y')));
ok('an http -> https upgrade is allowed', !throws(() => assertNoDowngrade('http://a.example/x', 'https://a.example/y')));

// --- the redirect resolver: absolute, root-relative, and path-relative Location values all resolve correctly ---
ok('an absolute Location is used as-is', resolveRedirect('https://a.example/dir/x', 'https://b.example/y') === 'https://b.example/y');
ok('a root-relative Location resolves against the host', resolveRedirect('https://a.example/dir/x', '/y') === 'https://a.example/y');
ok('a path-relative Location resolves against the current directory', resolveRedirect('https://a.example/dir/x', 'y') === 'https://a.example/dir/y');

// --- the downgrade guard is actually WIRED into both fetch paths (getBuffer and downloadTo), on every redirect hop ---
const src = fs.readFileSync(path.join(__dirname, '..', 'Net.js'), 'utf8');
ok('the downgrade guard is called on the redirect path', (src.match(/assertNoDowngrade\(/g) || []).length >= 2);
ok('a redirect chain is bounded (too-many-redirects guard present)', /too many redirects/.test(src) && /redirectsLeft/.test(src));

// --- behavioral: a redirect LOOP over plain http is bounded, and a normal fetch works ---
async function main() {
	let hits = 0;
	const BLOB = Buffer.from('vaultonaut download checksum gate fixture — arbitrary bytes'); // known content to hash
	const server = http.createServer((req, res) => {
		if (req.url === '/ok') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('hello'); return; }
		if (req.url === '/blob') { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(BLOB); return; }
		hits++; // /loop always redirects to itself -> the client must give up, not follow forever
		res.writeHead(302, { location: '/loop' }); res.end();
	});
	await new Promise((r) => server.listen(0, '127.0.0.1', r));
	const port = server.address().port;
	try {
		const body = await Net.getText('http://127.0.0.1:' + port + '/ok');
		ok('a normal fetch returns the body', body === 'hello');
		let loopErr = '';
		try { await Net.getText('http://127.0.0.1:' + port + '/loop'); } catch (e) { loopErr = e.message; }
		ok('a redirect loop is stopped with a too-many-redirects error', /too many redirects/i.test(loopErr));
		ok('the redirect loop was bounded (the server was not hit an unbounded number of times)', hits > 0 && hits <= 12);

		// --- the SUPPLY-CHAIN checksum gate: this is the single guard behind EVERY downloaded binary (the storage
		// engine, Tor, its pluggable transports, the mount driver, OCR data). A matching SHA-256 accepts the file; a
		// MISMATCH must reject AND delete it, so a compromised mirror or an on-path swap can never leave an unverified
		// binary on disk. Exercised behaviorally so an inverted comparison or a lost unlink cannot pass unnoticed.
		const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-netdl-'));
		const url = 'http://127.0.0.1:' + port + '/blob';
		const goodSha = crypto.createHash('sha256').update(BLOB).digest('hex');
		const badSha = crypto.createHash('sha256').update(Buffer.concat([BLOB, Buffer.from('x')])).digest('hex');
		try {
			const okDest = path.join(tmp, 'good.bin');
			const p = await Net.download(url, okDest, { expectedSha256: goodSha, label: 'fixture' });
			ok('a download whose SHA-256 matches the pin is accepted and left on disk', p === okDest && fs.existsSync(okDest) && Buffer.compare(fs.readFileSync(okDest), BLOB) === 0);

			const badDest = path.join(tmp, 'bad.bin');
			let mismatch = '';
			try { await Net.download(url, badDest, { expectedSha256: badSha, label: 'fixture' }); } catch (e) { mismatch = e.message; }
			ok('a download whose SHA-256 does NOT match the pin is rejected', /checksum mismatch/i.test(mismatch));
			// The unlink is fired just before the reject and is async, so wait (bounded) for it to complete rather than
			// racing it — this keeps the assertion deterministic on every platform.
			let gone = false;
			for (let i = 0; i < 100 && !gone; i++) { if (!fs.existsSync(badDest)) gone = true; else await new Promise((r) => setTimeout(r, 10)); }
			ok('a checksum-mismatched download is DELETED, never left on disk (fail closed)', gone);
		} finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} }
	} finally { server.close(); }

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL NET-GUARDS CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
