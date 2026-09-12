'use strict';
// lib/test/mobilehttp.js — the /m HTTP routes end to end over a real socket, using the SAME router the web
// server mounts (mobileRoutes.buildRouter). It drives the exact phone flow with fetch: redeem the one-time
// pairing code, then bearer-authenticated list + ciphertext GET (including an HTTP Range request), decrypt a
// fetched file locally to confirm correctness, and check that missing-bearer and traversal requests fail.
//
// Run:  node lib/test/mobilehttp.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const express = require('express');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null, server = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-mobilehttp-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Mobile = require('../Mobile');
	const MobileRoutes = require('../webserver/mobileRoutes');
	const reader = require('../webserver/public/mobile/crypt-reader.js');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	// A vault with a file big enough to Range into.
	const src = path.join(tmp, 'src');
	const files = { 'report.txt': Buffer.from('the quick brown fox jumps over the lazy dog '.repeat(50), 'utf8') };
	for (const [rel, buf] of Object.entries(files)) { const p = path.join(src, rel); await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.writeFile(p, buf); }
	const v = path.join(tmp, 'Http.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	const s = await Mobile.start(v, { password: 'pw1' });

	// Minimal app mounting the REAL router (loopback, not exposed).
	const app = express();
	app.use(express.json());
	app.use('/m', MobileRoutes.buildRouter({ mobileDir: path.join(__dirname, '..', 'webserver', 'public', 'mobile'), isLoopbackAddr: () => true, exposed: false }));
	await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); });
	const base = 'http://127.0.0.1:' + server.address().port;

	// Pair (single-use).
	let r = await fetch(base + '/m/pair', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: s.code }) });
	const paired = await r.json();
	ok('POST /m/pair returns the cap + bearer', r.status === 200 && /^vdwrc1\./.test(paired.cap) && !!paired.token);
	const again = await fetch(base + '/m/pair', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: s.code }) });
	ok('a used pairing code is rejected (401)', again.status === 401);
	const bearer = paired.token;
	const H = { Authorization: 'Bearer ' + bearer };

	// List requires the bearer.
	ok('GET /m/list without a bearer is 401', (await fetch(base + paired.list)).status === 401);
	r = await fetch(base + paired.list, { headers: H });
	const listing = (await r.json()).files;
	ok('GET /m/list with the bearer returns the files', r.status === 200 && listing.length >= 1);

	// Decrypt the cap and pull each ciphertext file, checking bytes.
	const cap = JSON.parse(Buffer.from(paired.cap.split('.')[1], 'base64url').toString('utf8'));
	const keys = reader.deriveKeys(cap.key, cap.salt);
	let contentOk = true, target = null;
	for (const e of listing) {
		let name; try { name = reader.decryptPath(keys.nameKey, keys.nameTweak, e.path, cap.dn); } catch (_) { continue; }
		const cr = await fetch(base + paired.base + e.path, { headers: H });
		const bytes = new Uint8Array(await cr.arrayBuffer());
		const plain = Buffer.from(reader.decryptContent(keys.dataKey, bytes));
		if (name === 'report.txt') { target = e.path; if (!plain.equals(files['report.txt'])) contentOk = false; }
	}
	ok('a ciphertext GET decrypts to the original file', contentOk && !!target);

	// A ciphertext GET needs the bearer.
	ok('a ciphertext GET without a bearer is 401', (await fetch(base + paired.base + target)).status === 401);

	// HTTP Range: ask for the first 16 ciphertext bytes -> 206 + Content-Range + 16 bytes.
	const rr = await fetch(base + paired.base + target, { headers: { ...H, Range: 'bytes=0-15' } });
	const partial = new Uint8Array(await rr.arrayBuffer());
	ok('an HTTP Range request yields 206 with the right slice', rr.status === 206 && /bytes 0-15\//.test(rr.headers.get('content-range') || '') && partial.length === 16);

	// Path traversal is refused.
	ok('a traversal path is refused (404)', (await fetch(base + '/m/files/' + s.sessionId + '/..%2f..%2f..%2fetc%2fpasswd', { headers: H })).status === 404);

	// POST /m/stop ends the session. It is refused without the bearer; with the bearer in the BODY (as a tab-close
	// sendBeacon must send it, since it cannot set a header) the session is dropped, and further requests then 401.
	ok('POST /m/stop without a bearer is 401', (await fetch(base + '/m/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sessionId: s.sessionId }) })).status === 401);
	const stopped = await fetch(base + '/m/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sessionId: s.sessionId, bearer }) });
	ok('POST /m/stop with the bearer in the body ends the session (200)', stopped.status === 200);
	ok('after /m/stop the bearer no longer authorizes (list is 401)', (await fetch(base + paired.list, { headers: H })).status === 401);

	return done();
}

async function done() {
	if (server) try { server.close(); } catch (_) {}
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-HTTP CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (server) try { server.close(); } catch (_) {} if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
