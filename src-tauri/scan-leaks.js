'use strict';
// scan-leaks.js — refuse to ship a desktop build that carries build-machine identity. It scans every file in the
// produced bundle for this machine's OS username, hostname, and home path (the things that identify who built
// it), and exits non-zero if any are found. It runs after the Tauri build on EVERY platform, so the guarantee is
// enforced wherever the build happens, not assumed — the recommended validation for path leaks is exactly this
// (search the artifacts for the build path), done automatically and turned into a hard gate.
//
// This is a backstop on top of building at a neutral path: it also catches anything that survives, such as
// installer metadata. Pure Node built-ins, cross-platform.
//
// Scope note: this is a plain byte search, so it sees into the uncompressed app tree (the .app bundle and the
// binary inside it — where a path leak would live), but NOT inside a COMPRESSED installer stream (.dmg, .msi,
// NSIS). That is acceptable because the identity-bearing binary is scanned uncompressed; point the scan at the
// staged/app tree, or the bundle directory that contains the uncompressed .app, for the strongest coverage.
//
//   node scan-leaks.js [dir]     default dir: target/release/bundle

const fs = require('fs');
const os = require('os');
const path = require('path');

const targetDir = path.resolve(process.argv[2] || path.join(__dirname, 'target', 'release', 'bundle'));

// Accounts that are shared/disposable build identities, not a person. On a CI runner or a dedicated build VM the
// login is one of these, and its name and home path appear in the workspace path by design — that is not a
// personal-identity leak. A real person's daily login is essentially never one of these.
const GENERIC_ACCOUNTS = new Set(['runner', 'runneradmin', 'root', 'builder', 'build', 'buildbot', 'vsts', 'cloudtest', 'admin', 'administrator', 'github', 'gitlab', 'ci', 'jenkins']);

// The identity of the machine running the build. Split out so it can be supplied in a test.
function currentIdentity() {
	let username = ''; try { username = String(os.userInfo().username || ''); } catch (_) {}
	let hostname = ''; try { hostname = os.hostname(); } catch (_) {}
	let home = ''; try { home = os.homedir(); } catch (_) {}
	return { username, hostname, home, env: [process.env.USER, process.env.USERNAME, process.env.LOGNAME] };
}

// The identifying strings to hunt for, as UTF-8 and UTF-16LE byte forms (Windows artifacts often store UTF-16).
// The username and home directory identify a PERSON, so on a shared/CI build account they are skipped — they are
// in the workspace path by design and are not personal. The HOSTNAME is ALWAYS scanned: a personal machine's
// name (for example "Janes-MacBook") is personal even when the login is a generic name like admin or root (or a
// sudo build), so it must never ride along in a shared build. Values under three characters are dropped, since a
// one- or two-character token would match everywhere and is not a meaningful identifier.
function needles(id = currentIdentity()) {
	const raw = new Set();
	const add = (s) => { s = s && String(s).trim(); if (s && s.length >= 3) raw.add(s); };
	const generic = GENERIC_ACCOUNTS.has(String(id.username || '').toLowerCase());
	if (!generic) {
		add(id.username);
		(id.env || []).forEach(add);
		if (id.home) { add(id.home); add(id.home.replace(/\\/g, '/')); }
	}
	if (id.hostname) { add(id.hostname); add(String(id.hostname).split('.')[0]); }
	const out = [];
	for (const s of raw) { out.push({ label: s, buf: Buffer.from(s, 'utf8') }); out.push({ label: s + ' [utf16]', buf: Buffer.from(s, 'utf16le') }); }
	return out;
}

let skipped = 0;
function* walk(dir) {
	let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
	for (const e of entries) {
		const full = path.join(dir, e.name);
		if (e.isSymbolicLink()) continue;
		if (e.isDirectory()) yield* walk(full);
		else if (e.isFile()) yield full;
	}
}

// Search a file for any needle without holding the whole file in memory: read in chunks with an overlap larger
// than any needle so a match spanning a boundary is still found. Keeps the scan safe on any-size artifacts.
function scanFile(file, nds) {
	const maxLen = nds.reduce((m, n) => Math.max(m, n.buf.length), 0);
	const OVERLAP = Math.max(64, maxLen);
	const CHUNK = 4 * 1024 * 1024;
	let fd; try { fd = fs.openSync(file, 'r'); } catch (_) { skipped++; console.warn('  (warning: could not read ' + file + ' — skipped)'); return null; }
	try {
		const buf = Buffer.allocUnsafe(OVERLAP + CHUNK);
		let held = 0, pos = 0;
		for (;;) {
			const n = fs.readSync(fd, buf, held, CHUNK, pos);
			if (n <= 0) break;
			const view = buf.subarray(0, held + n);
			for (const nd of nds) if (view.includes(nd.buf)) return nd.label;
			pos += n;
			held = Math.min(OVERLAP, view.length);
			view.subarray(view.length - held).copy(buf, 0); // carry the tail so a boundary-spanning match is caught
		}
	} finally { fs.closeSync(fd); }
	return null;
}

function main() {
	if (!fs.existsSync(targetDir)) { console.error('scan-leaks: nothing to scan at ' + targetDir + ' (build first).'); process.exit(1); }
	const nds = needles();
	if (!nds.length) { console.log('Leak scan: no personal identifiers to scan for on this build account.'); return; }
	const hits = [];
	for (const f of walk(targetDir)) { const hit = scanFile(f, nds); if (hit) hits.push({ f, hit }); }
	if (hits.length) {
		console.error('\nLEAK SCAN FAILED — build-machine identity found in the produced artifacts:');
		for (const h of hits.slice(0, 25)) console.error('  ' + path.relative(targetDir, h.f) + '  contains  "' + h.hit + '"');
		console.error('\nRefusing to ship this build. A build path was probably not neutralized (build at a neutral path with a');
		console.error('neutral CARGO_HOME), or an installer field derived from the build user. (A hit is a false positive only if');
		console.error('your username or hostname is also an ordinary word in a bundled file — rename it or adjust the scan if so.)\n');
		process.exit(1);
	}
	console.log('Leak scan: no build-machine username, hostname, or home path in ' + path.relative(process.cwd(), targetDir) + '.' + (skipped ? ' (' + skipped + ' unreadable file(s) skipped)' : ''));
}

module.exports = { needles, currentIdentity, scanFile, walk, GENERIC_ACCOUNTS };

if (require.main === module) main();
