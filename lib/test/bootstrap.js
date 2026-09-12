'use strict';
// lib/test/bootstrap.js — the earliest startup guard. isNodeOlder must compare versions NUMERICALLY (so
// 24.9 < 24.15, which a string compare gets backwards), and enforceNodeVersion must exit on an unsupported
// runtime yet be a no-op on a supported one, and never throw when the check itself can't run.
//
// Run:  node lib/test/bootstrap.js   (no engine needed)

const os = require('os');
const path = require('path');
const fs = require('fs');
const Bootstrap = require('../Bootstrap');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// isNodeOlder — the load-bearing numeric comparison.
ok('older major is older', Bootstrap.isNodeOlder('24.0.0', '22.15.0') === true);
ok('newer major is not older', Bootstrap.isNodeOlder('24.0.0', '25.0.0') === false);
ok('24.9 is older than 24.15 (numeric, not string)', Bootstrap.isNodeOlder('24.15.0', '24.9.0') === true);
ok('24.11 is not older than 24.7', Bootstrap.isNodeOlder('24.7.0', '24.11.1') === false);
ok('equal is not older', Bootstrap.isNodeOlder('24.0.0', '24.0.0') === false);
ok('a satisfied patch is not older', Bootstrap.isNodeOlder('24.7.0', '24.7.1') === false);
ok('a non-numeric suffix is tolerated', Bootstrap.isNodeOlder('24.0.0', '24.5.1-nightly') === false);
ok('differing lengths compare by the components present', Bootstrap.isNodeOlder('24', '25.0.0') === false && Bootstrap.isNodeOlder('24.1', '24') === true);

// enforceNodeVersion — exits on an unsupported runtime, is a no-op on a supported one, never throws otherwise.
function withExitStubbed(fn) {
	const realExit = process.exit, realErr = console.error;
	let exited = false;
	process.exit = function () { exited = true; throw new Error('__exit__'); }; // trap the exit without killing the test
	console.error = function () {};
	try { fn(); } catch (e) { if (!(e && e.message === '__exit__')) throw e; }
	finally { process.exit = realExit; console.error = realErr; }
	return exited;
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-bootstrap-'));
// Each case gets its OWN directory: require() caches package.json by path (correct in production, where it
// never changes mid-run), so reusing one path across cases would return the first case's cached contents.
function dirWith(pkg) { const d = fs.mkdtempSync(path.join(tmpRoot, 'c-')); if (pkg) fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify(pkg)); return d; }
try {
	ok('an unsupported runtime exits', withExitStubbed(() => Bootstrap.enforceNodeVersion(dirWith({ engines: { node: '>=99.0.0' } }), 'Vaultonaut')) === true);
	ok('a supported runtime does NOT exit', withExitStubbed(() => Bootstrap.enforceNodeVersion(dirWith({ engines: { node: '>=1.0.0' } }), 'Vaultonaut')) === false);
	// A malformed / missing engines field must never block startup (no exit, no throw).
	ok('a missing engines field never blocks startup', withExitStubbed(() => Bootstrap.enforceNodeVersion(dirWith({ name: 'x' }), 'Vaultonaut')) === false);
	ok('a nonexistent package.json never blocks startup', withExitStubbed(() => Bootstrap.enforceNodeVersion(path.join(tmpRoot, 'nope'), 'Vaultonaut')) === false);
} finally { try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (_) {} }

// DRIFT GUARD: the minimum Node version the README states to users must match the version actually enforced by
// package.json engines.node, so a future bump to the minimum can never leave the README quoting an older, wrong
// floor. Bind the README's human-facing "Node.js X.Y or newer" line to the enforced range's major.minor.
{
	const root = path.join(__dirname, '..', '..');
	const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
	const min = (String((pkg.engines && pkg.engines.node) || '').match(/(\d+)\.(\d+)/) || [])[0]; // ">=24.7.0" -> "24.7"
	const readme = fs.readFileSync(path.join(root, 'docs', 'README.md'), 'utf8');
	ok('the README states the same minimum Node version as package.json engines.node', !!min && readme.includes('Node.js ' + min + ' or newer'));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BOOTSTRAP CHECKS PASSED'));
process.exitCode = failures ? 1 : 0;
