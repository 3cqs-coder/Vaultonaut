'use strict';
// lib/test/gittracking.js — a WATCHDOG over what the PUBLIC repository actually tracks. This project is a public
// repo, so anything committed becomes publicly visible. Two channels are already guarded: packaging.js checks the
// npm tarball and leakscan.js checks the built binary. Neither checks the git tree itself, which is the real public
// exposure. A stray `git add` of the test data directory (which the suite fills with a test credential key and state),
// the private release-signing key, a detached release signature, or live vault/lock/cert state would publish secrets.
// This asserts the git index contains none of them, and that .gitignore still lists the two most dangerous paths so
// they cannot be added by accident. Skips cleanly when this is not a git checkout or git is unavailable (so it never
// fails a from-tarball build); on CI the checkout is a real repo, so it actually runs.
//
// Run:  node -r ./lib/test/_setup.js lib/test/gittracking.js

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const REPO = path.join(__dirname, '..', '..');

// Paths that must NEVER be tracked in the public repo. Each is tested against every line of `git ls-files` (which
// prints forward-slash paths on every platform, so these are POSIX patterns).
const FORBIDDEN = [
	{ re: /(^|\/)\.test-data\//, what: 'the test data directory (holds a test credential key and state)' },
	{ re: /(^|\/)release-signing-key\.json$/, what: 'the private release signing key' },
	{ re: /(^|\/)SHA256SUMS\.sig$/, what: 'a detached release signature (a per-release artifact, not tracked)' },
	{ re: /(^|\/)data\/(credkey|state\.json|settings\.json|integrity\.json|tamper-log\.json|service\.pid)$/, what: 'live per-user service state' },
	{ re: /(^|\/)data\/(vaults|locks|certs|run|sync|mirror-versions|staging)\//, what: 'live vault or runtime state' },
];

function main() {
	const r = spawnSync('git', ['ls-files', '-z'], { cwd: REPO, encoding: 'utf8' });
	if (r.error || r.status !== 0 || typeof r.stdout !== 'string') {
		console.log('  skip  (not a git checkout, or git is unavailable — nothing to inspect)');
		return done();
	}
	const tracked = r.stdout.split('\0').filter(Boolean);

	let leaks = [];
	for (const f of FORBIDDEN) {
		const hits = tracked.filter((p) => f.re.test(p));
		if (hits.length) leaks.push(f.what + ' → ' + hits.slice(0, 3).join(', '));
		ok('the repo does not track ' + f.what, hits.length === 0);
	}
	if (leaks.length) leaks.forEach((l) => console.log('        LEAK: ' + l));

	// The two most dangerous paths must stay listed in .gitignore, so a careless `git add -A` cannot pick them up.
	let ignore = '';
	try { ignore = fs.readFileSync(path.join(REPO, '.gitignore'), 'utf8'); } catch (_) {}
	ok('.gitignore still excludes the test data directory (.test-data/)', /^\.test-data\/?\s*$/m.test(ignore));
	ok('.gitignore still excludes the private release signing key', /^release-signing-key\.json\s*$/m.test(ignore));

	done();
}
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL GIT-TRACKING CHECKS PASSED')); process.exit(failures ? 1 : 0); }
main();
