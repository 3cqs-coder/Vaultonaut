'use strict';
// lib/test/leakscan.js — locks in the identity-leak scanner (src-tauri/scan-leaks.js), the gate that keeps a
// shared desktop build from carrying the build machine's identity. A FALSE PASS here would expose whoever built
// the binary, so the checks below cover the ways that could happen: a planted identifier must be found, a match
// that straddles the reader's chunk boundary must still be found, a UTF-16 form must be found, and — the subtle
// one — a personal HOSTNAME must still be scanned even when the build login is a generic name (admin/root/CI),
// because only the username and home are non-personal on such accounts. Skips if the packaging tree is absent.
//
// Run:  node -r ./lib/test/_setup.js lib/test/leakscan.js

const fs = require('fs');
const os = require('os');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LEAK-SCAN CHECKS PASSED')); process.exit(failures ? 1 : 0); }

function labels(nds) { return nds.map((n) => n.label); }

function main() {
	const mod = path.join(__dirname, '..', '..', 'src-tauri', 'scan-leaks.js');
	if (!fs.existsSync(mod)) { console.log('  skip  (no src-tauri packaging tree in this checkout)'); return done(); }
	const S = require(mod);

	ok('exports scanFile, needles, and GENERIC_ACCOUNTS', typeof S.scanFile === 'function' && typeof S.needles === 'function' && S.GENERIC_ACCOUNTS instanceof Set);

	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-leakscan-'));
	try {
		const nd = (s) => [{ label: s, buf: Buffer.from(s, 'utf8') }, { label: s + ' [utf16]', buf: Buffer.from(s, 'utf16le') }];

		// A planted identifier is found.
		const f1 = path.join(tmp, 'plain.bin'); fs.writeFileSync(f1, Buffer.from('lorem ZZ-LEAK-NEEDLE-ZZ ipsum'));
		ok('finds a planted identifier', S.scanFile(f1, nd('ZZ-LEAK-NEEDLE-ZZ')) !== null);
		ok('reports clean when the identifier is absent', S.scanFile(f1, nd('NOT-PRESENT-XYZ')) === null);

		// A match that straddles the 4 MiB chunk boundary is still found (the carry/overlap logic).
		const CHUNK = 4 * 1024 * 1024, needle = 'ZZ-BOUNDARY-NEEDLE-ZZ';
		const f2 = path.join(tmp, 'boundary.bin');
		const fill = Buffer.alloc(CHUNK - 5, 0x61); // 'a' filler; needle starts 5 bytes before the boundary
		fs.writeFileSync(f2, Buffer.concat([fill, Buffer.from(needle), Buffer.alloc(1024, 0x62)]));
		ok('finds a needle spanning the chunk boundary', S.scanFile(f2, nd(needle)) !== null);

		// A UTF-16LE occurrence is found (Windows-style storage).
		const f3 = path.join(tmp, 'utf16.bin'); fs.writeFileSync(f3, Buffer.from('X' + 'ZZ-UTF16-NEEDLE-ZZ' + 'Y', 'utf16le'));
		ok('finds a UTF-16LE occurrence', S.scanFile(f3, nd('ZZ-UTF16-NEEDLE-ZZ')) !== null);

		// needles(): a PERSONAL account yields username, home, and hostname needles.
		const personal = labels(S.needles({ username: 'janedoe', home: '/Users/janedoe', hostname: 'Janes-MacBook-Pro.local', env: [] }));
		ok('personal account: username is scanned', personal.includes('janedoe'));
		ok('personal account: home path is scanned', personal.includes('/Users/janedoe'));
		ok('personal account: hostname is scanned', personal.includes('Janes-MacBook-Pro.local'));

		// needles(): a GENERIC account skips username/home but STILL scans the hostname (the P1 false-pass fix).
		const generic = labels(S.needles({ username: 'root', home: '/root', hostname: 'Janes-MacBook-Pro', env: [] }));
		ok('generic account: username is NOT scanned', !generic.includes('root'));
		ok('generic account: home path is NOT scanned', !generic.includes('/root'));
		ok('generic account: hostname IS still scanned', generic.includes('Janes-MacBook-Pro'));

		// Sub-three-character identifiers are dropped.
		const tiny = labels(S.needles({ username: 'jo', home: '', hostname: '', env: [] }));
		ok('a one/two-character identifier is dropped', !tiny.includes('jo'));

		ok('GENERIC_ACCOUNTS includes CI/build logins', S.GENERIC_ACCOUNTS.has('runner') && S.GENERIC_ACCOUNTS.has('root'));
	} finally {
		try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
	}
	return done();
}
main();
