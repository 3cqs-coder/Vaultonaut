'use strict';
// lib/test/commonhelpers.js — guards the shared Common helpers that other modules call as Common.X. A helper can
// be added to Common but forgotten in module.exports; nothing else in the suite would catch that until the caller
// crashed at runtime (the folder picker did exactly this with mapLimit). This asserts each recently-added helper
// is EXPORTED and behaves, so an export drift is caught here instead of in production.
//
// Run:  node lib/test/commonhelpers.js  (no engine needed)

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	// EXPORT PRESENCE: every helper a caller reaches through Common must actually be exported (this is the drift
	// the folder picker hit — mapLimit was defined but not listed in module.exports, so Common.mapLimit was undefined).
	for (const fn of ['mapLimit', 'fsyncPath', 'sha256', 'sha256Hex', 'windowsHiddenRunVbs', 'pathExistsBounded', 'writeJsonAtomic', 'renameWithRetry', 'uniqueTempPath', 'timingSafeEqualHashed', 'pathWithin', 'resolveThroughSymlinks', 'readFileCapped', 'foldPath', 'samePath', 'splitHostPort', 'isLoopbackHost', 'redactPaths', 'openExternal']) {
		ok('Common.' + fn + ' is exported', typeof Common[fn] === 'function');
	}

	// mapLimit: order-preserving, bounded concurrency, edge cases, and Promise.all-style rejection.
	ok('mapLimit on empty input returns []', JSON.stringify(await Common.mapLimit([], 4, async x => x)) === '[]');
	ok('mapLimit preserves order', JSON.stringify(await Common.mapLimit([1, 2, 3, 4, 5], 2, async x => x * 10)) === '[10,20,30,40,50]');
	ok('mapLimit tolerates limit larger than the list', JSON.stringify(await Common.mapLimit([1, 2], 9, async x => x)) === '[1,2]');
	ok('mapLimit clamps a zero/negative limit to at least one worker', JSON.stringify(await Common.mapLimit([1, 2, 3], 0, async x => x)) === '[1,2,3]');
	// Never runs more than `limit` at once, and never skips or double-processes an index.
	let live = 0, peak = 0; const seen = [];
	await Common.mapLimit(Array.from({ length: 20 }, (_, i) => i), 4, async (x) => {
		live++; peak = Math.max(peak, live); await Common.sleep(2); seen.push(x); live--; return x;
	});
	ok('mapLimit never exceeds the concurrency cap', peak <= 4);
	ok('mapLimit processes every index exactly once', seen.slice().sort((a, b) => a - b).join(',') === Array.from({ length: 20 }, (_, i) => i).join(','));
	let threw = false;
	try { await Common.mapLimit([1, 2, 3], 2, async x => { if (x === 2) throw new Error('boom'); return x; }); } catch (_) { threw = true; }
	ok('mapLimit rejects when a task rejects (like Promise.all)', threw);

	// sha256 / sha256Hex: stable, correct width, hex form matches the buffer form.
	const buf = Common.sha256('vaultonaut');
	ok('sha256 returns a 32-byte buffer', Buffer.isBuffer(buf) && buf.length === 32);
	ok('sha256Hex matches the buffer form', Common.sha256Hex('vaultonaut') === buf.toString('hex'));

	// windowsHiddenRunVbs: the doubled-quote escaping both installers depend on.
	const vbs = Common.windowsHiddenRunVbs('C\\n.exe', 'C\\a.js', 'ui --port 1');
	ok('windowsHiddenRunVbs wraps the paths in doubled double-quotes and runs hidden', /WshShell\.Run """C\\n\.exe"" ""C\\a\.js"" ui --port 1", 0, False/.test(vbs));

	// fsyncPath: never throws, even on a missing path, and flushes a real file.
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-common-'));
	try {
		const f = path.join(dir, 'x');
		await fsp.writeFile(f, 'hi');
		let fsyncThrew = false;
		try { await Common.fsyncPath(f); await Common.fsyncPath(path.join(dir, 'does-not-exist')); } catch (_) { fsyncThrew = true; }
		ok('fsyncPath flushes a file and never throws on a missing path', !fsyncThrew);
	} finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {} }

	// GOLDEN guard for the tamper-ignore set. It is now BUILT from a shared OS-junk core that the mount-empty check
	// also uses, so pin the exact set of basenames it excludes from the integrity scan — a build-logic slip, or a
	// change to the shared core that unintentionally shifts this set, is caught here. ".localized" is deliberately
	// NOT ignored by the integrity scan (it is only mount-empty junk), which confirms the two scopes stay distinct.
	const Vault = require('../Vault');
	const ignored = ['.DS_Store', '._foo', '._', '.Spotlight-V100', '.metadata_never_index', '.Trashes', '.fseventsd', '.TemporaryItems', '.DocumentRevisions-V100', '.apDisk', 'Thumbs.db', 'desktop.ini', '.fuse_hidden', '.fuse_hidden9a', '.nfs', '.nfs00ab'];
	const notIgnored = ['notes.txt', '.localized', 'DS_Store', '.DS_Storex', 'x.DS_Store', 'desktopXini', '.Spotlight', 'photo.jpg'];
	ok('the tamper-ignore set matches its golden basename list', ignored.every(n => Vault.isIgnoredVaultPath(n) === true) && notIgnored.every(n => Vault.isIgnoredVaultPath(n) === false));

	// validateBwlimit: accepts a plain rate, an asymmetric upload:download pair, and a weekday timetable, and
	// rejects garbage. The weekday case is the one that regressed silently before — sanitizeBwlimit used to strip
	// the hyphen out of "Mon-23:00,off", turning a valid spec into one the engine rejects, while the validator
	// still passed it. Pin that the hyphen now survives, and that a bare leading "-" (which could look like an
	// engine flag) is still refused.
	const bwOk = ['512k', '1M', '10MiB', '1Gi', '10M:1M', '512k:off', 'off:1M', '08:00,512k 23:00,off', 'Mon-23:00,off', 'Mon-08:00,512k Fri-23:00,off'];
	const bwBad = ['fast', '', '-1M', '-08:00,512k', '08:00,512k -23:00,off', 'Xyz-08:00,1M', '1M,', '25:99,512k', '24:00,off', '08:60,512k'];
	const accepts = (s) => { try { Common.validateBwlimit(s); return true; } catch (_) { return false; } };
	ok('validateBwlimit accepts rates, pairs, and weekday timetables', bwOk.every(accepts));
	ok('validateBwlimit keeps the weekday hyphen intact', Common.validateBwlimit('Mon-23:00,off') === 'Mon-23:00,off');
	ok('validateBwlimit rejects garbage and a bare leading hyphen', bwBad.every(s => !accepts(s)));

	// isLoopbackHost gates real security decisions (skip login/TLS on an exposed bind; allow a writable direct
	// serve). It is the ONE shared, DNS-safe predicate, so pin its whole truth table here: every genuine loopback
	// form is local, and — critically — no DNS name that merely starts with "127" or contains "localhost" can pass,
	// since that would let a rebinding host masquerade as local. A regression here is a silent security downgrade.
	ok('isLoopbackHost is exported', typeof Common.isLoopbackHost === 'function');
	// A plain IPv4 peer reaches a dual-stack ("--bind ::") listener as an IPv4-mapped IPv6 address, so those forms
	// must resolve exactly like their bare IPv4 originals — a same-machine "::ffff:127.0.0.1" is loopback, while a
	// mapped non-loopback or DNS-name spoof is not. A regression here would globally rate-limit a local owner on a
	// dual-stack bind (the redeem-throttle exemption), or worse, treat a remote peer as local.
	const loopbackYes = ['127.0.0.1', '127.0.0.2', '127.1.2.3', '127.255.255.254', 'localhost', 'LOCALHOST', '::1', '', '  127.0.0.1  ', '::ffff:127.0.0.1', '::ffff:127.1.2.3', '  ::ffff:127.0.0.1  '];
	const loopbackNo = ['0.0.0.0', '128.0.0.1', '126.255.255.255', '192.168.1.10', '10.0.0.1', '::2', '227.0.0.1', '1127.0.0.1', '127.0.0.1.evil.com', '127.example.com', 'localhost.attacker.com', 'notlocalhost', '127.0.0.256', 'example.com', '::ffff:192.168.1.10', '::ffff:128.0.0.1', '::ffff:127.example.com', '::ffff:'];
	ok('isLoopbackHost accepts every genuine loopback form (127/8, localhost, ::1, empty, trimmed, IPv4-mapped)', loopbackYes.every(h => Common.isLoopbackHost(h) === true));
	ok('isLoopbackHost rejects non-loopback addresses, DNS-name spoofs, and mapped non-loopback', loopbackNo.every(h => Common.isLoopbackHost(h) === false));
	// An absent host is the loopback default (an unset bind stays on this machine) — pin that so it can't drift.
	ok('isLoopbackHost treats an absent host (null/undefined) as the loopback default', Common.isLoopbackHost(null) === true && Common.isLoopbackHost(undefined) === true);

	// redactPaths keeps absolute filesystem paths out of an error shown to a remote caller on an exposed interface.
	// Pin that it removes the given roots (longest first, so a nested root goes before its parent), preserves the
	// rest of the message, and is a safe no-op on empty/absent input — a regression would leak the install layout.
	ok('redactPaths is exported', typeof Common.redactPaths === 'function');
	const roots = ['/home/u/.local/share/App', '/home/u', '/opt/app'];
	const red = Common.redactPaths('failed to delete /home/u/.local/share/App/vaults/Secret.vault/vault.json and /opt/app/lib/Vault.js', roots);
	ok('redactPaths removes every sensitive root', !red.includes('/home/u') && !red.includes('/opt/app') && red.includes('…'));
	ok('redactPaths keeps the actionable, non-path text', red.includes('failed to delete') && red.includes('Secret.vault'));
	ok('redactPaths redacts the longer nested root, not just its parent', Common.redactPaths('/home/u/.local/share/App/x', roots) === '…/x');
	ok('redactPaths is a safe no-op on empty input or no roots', Common.redactPaths('', roots) === '' && Common.redactPaths('plain message', []) === 'plain message' && Common.redactPaths(null, roots) === '');

	// pathWithin is the containment boundary behind vault-root checks and the zip-slip guard. The one that MUST hold
	// is the shared-prefix trap: a sibling whose name merely starts with the parent's name is NOT inside it. A
	// regression to a naive startsWith would silently reopen path escape.
	ok('pathWithin: a path is within itself', Common.pathWithin('/data/vault', '/data/vault') === true);
	ok('pathWithin: a real child is inside its parent', Common.pathWithin('/data/vault/sub/file.txt', '/data/vault') === true);
	ok('pathWithin: a sibling that shares a name prefix is NOT inside (the classic prefix trap)', Common.pathWithin('/data/vault-evil', '/data/vault') === false);
	ok('pathWithin: a ".." escape is not inside', Common.pathWithin('/data/vault/../other', '/data/vault') === false);

	// foldPath is what lets two spellings of the same name compare equal. Pin NFC unification (so a macOS NFD name
	// matches a Linux NFC one) and the per-platform case behavior — a drift here fools samePath/pathWithin.
	ok('foldPath unifies NFD and NFC of the same accented name', Common.foldPath('café') === Common.foldPath('café'));
	ok('foldPath is idempotent', Common.foldPath(Common.foldPath('/Some/Pâth')) === Common.foldPath('/Some/Pâth'));
	const foldsCase = process.platform === 'win32' || process.platform === 'darwin';
	ok('foldPath case behavior matches the platform', (Common.foldPath('/A/B') === '/a/b') === foldsCase);

	// splitHostPort feeds host checks (including isLoopbackHost), so a mis-split IPv6 literal could corrupt a
	// security decision. Pin bracketed IPv6 (with and without a port), host:port, a bare IPv6 literal, and a bare host.
	const shp = (s) => Common.splitHostPort(s, 7420);
	ok('splitHostPort parses a bracketed IPv6 with a port', shp('[::1]:8080').host === '::1' && shp('[::1]:8080').port === 8080);
	ok('splitHostPort parses a bracketed IPv6 without a port', shp('[::1]').host === '::1' && shp('[::1]').port === 7420);
	ok('splitHostPort parses host:port', shp('127.0.0.1:9000').host === '127.0.0.1' && shp('127.0.0.1:9000').port === 9000);
	ok('splitHostPort treats a bare IPv6 literal (many colons) as a host on the default port', shp('::1').host === '::1' && shp('::1').port === 7420);
	ok('splitHostPort returns the default port for a bare host', shp('example.com').host === 'example.com' && shp('example.com').port === 7420);

	// resolveThroughSymlinks and readFileCapped need real files.
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-cmnhlp-'));
	try {
		// resolveThroughSymlinks must follow a symlink to its REAL target even when the leaf does not exist yet —
		// this is the check a containment guard relies on to catch a symlink that textually looks contained but
		// resolves outside. A lexical-only resolve would miss it.
		const realDir = path.join(tmp, 'real'); await fsp.mkdir(realDir);
		const realDirReal = await fsp.realpath(realDir);
		const link = path.join(tmp, 'link'); await fsp.symlink(realDir, link);
		ok('resolveThroughSymlinks resolves through a symlink even for a not-yet-existing leaf', (await Common.resolveThroughSymlinks(path.join(link, 'newfile'))) === path.join(realDirReal, 'newfile'));
		const outside = path.join(tmp, 'outside'); await fsp.mkdir(outside);
		const outsideReal = await fsp.realpath(outside);
		const escapeLink = path.join(realDir, 'escape'); await fsp.symlink(outside, escapeLink);
		ok('resolveThroughSymlinks follows a symlink to its real (outside) target, defeating a lexical-only check', (await Common.resolveThroughSymlinks(path.join(escapeLink, 'x'))) === path.join(outsideReal, 'x'));
		ok('resolveThroughSymlinks returns the real path of a fully-existing path', (await Common.resolveThroughSymlinks(realDir)) === realDirReal);

		// readFileCapped is the no-password DoS guard for untrusted files (a shared vault's plaintext manifest). Pin
		// that it returns content under the cap and fails CLOSED above it, and honors the encoding argument.
		const capFile = path.join(tmp, 'cap.txt'); await fsp.writeFile(capFile, 'hello');
		ok('readFileCapped returns content under the cap', (await Common.readFileCapped(capFile, 100, 'utf8')) === 'hello');
		ok('readFileCapped returns a Buffer when no encoding is given', Buffer.isBuffer(await Common.readFileCapped(capFile, 100)));
		let capThrew = false; try { await Common.readFileCapped(capFile, 3); } catch (e) { capThrew = /larger than the allowed/.test(e.message); }
		ok('readFileCapped refuses a file over the cap (fails closed)', capThrew);
	} finally { await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); }

	// openExternal hands a URL to the OS default handler cross-platform. On Windows it runs through cmd's `start`,
	// so the URL is quoted and the arguments are passed VERBATIM (see the source pin below); a URL carrying a double
	// quote or a control character could otherwise break out of that quoting, so it is refused. These reject cases
	// return before any process is spawned, so the check is side-effect-free. The URLs opened in practice are
	// app-generated (the loopback Recovery Kit page and similar), so a real target is never rejected.
	{
		const origPlat = Object.getOwnPropertyDescriptor(process, 'platform');
		try {
			Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
			ok('openExternal refuses a Windows URL with an embedded double quote (no cmd break-out)', Common.openExternal('http://127.0.0.1/a"b') === false);
			ok('openExternal refuses a Windows URL with a control character', Common.openExternal('http://127.0.0.1/a\nb') === false);
		} finally { Object.defineProperty(process, 'platform', origPlat); }
		// Source pin: the Windows launcher MUST pass its hand-quoted cmd arguments verbatim. Without this, Node re-escapes
		// the embedded quotes and cmd's `start` receives a mangled command line, so the URL silently fails to open.
		const commonSrc = fs.readFileSync(path.join(__dirname, '..', 'Common.js'), 'utf8');
		ok('openExternal passes cmd arguments verbatim on Windows (windowsVerbatimArguments)', /windowsVerbatimArguments:\s*true/.test(commonSrc));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL COMMON-HELPER CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
