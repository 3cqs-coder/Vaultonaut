'use strict';
// lib/test/depdrift.js — supply-chain drift guards for the deliberate no-committed-lockfile posture. The three
// delivery modes (standalone, Docker, and the desktop bundle) each `npm install` from caret ranges at their own
// time, so a dependency can float silently. Two kinds of float actually matter for a zero-knowledge vault:
//   • a NATIVE addon creeping in — it breaks the pure-JS, nothing-to-compile, cross-platform promise; the desktop
//     bundle strips *.node at stage time, so such a regression would fail only at runtime, and only on some builds.
//   • a MAJOR bump — the one float allowed to change a library's API or an on-disk/crypto format, which could stop
//     an existing vault from opening.
// This guard turns both from a silent runtime failure into a red build. Engine-free and fast; it inspects the
// installed node_modules, and cleanly skips when dependencies are not installed (nothing to check yet).
//
// Run:  node lib/test/depdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const NM = path.join(ROOT, 'node_modules');

if (!fs.existsSync(NM)) { console.log('  skip  (node_modules not installed — nothing to check)'); console.log('\nALL DEP-DRIFT CHECKS PASSED'); process.exit(0); }

const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const deps = pkg.dependencies || {};

// 1. No native addon anywhere in the tree — the pure-JS, nothing-to-compile invariant. A *.node file means a
//    dependency (or an optional peer, such as a PDF renderer's canvas) pulled a compiled binary, which can fail to
//    install or run on a platform and is silently dropped from the desktop bundle. Walk once, bounded so a huge tree
//    cannot make the guard slow.
const addons = [];
(function walk(dir, depth) {
	if (depth > 12 || addons.length > 5) return;
	let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
	for (const e of ents) {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) walk(p, depth + 1);
		else if (e.name.endsWith('.node')) addons.push(path.relative(ROOT, p));
	}
})(NM, 0);
ok('no native addon (*.node) is present in node_modules — the pure-JS invariant holds', addons.length === 0);
if (addons.length) for (const a of addons.slice(0, 5)) console.log('        ' + a);

function installed(name) { try { return JSON.parse(fs.readFileSync(path.join(NM, name, 'package.json'), 'utf8')); } catch (_) { return null; } }
const majorOf = (v) => { const m = String(v || '').match(/(\d+)\./); return m ? Number(m[1]) : null; };

// 2. Every declared dependency is installed, is pinned by a caret range with a concrete major, and its INSTALLED
//    major equals the range's major — so a future minor/patch float is allowed, but a major bump (the only float
//    that can change an API or an on-disk/crypto format) fails the build until it is reviewed. 3. And no runtime
//    dependency declares an install lifecycle script, which would run unsandboxed on the machine that builds the
//    signed artifacts (none do today; this catches a float that adds one).
// Known-harmless install scripts a dependency legitimately ships. These never run in the release/Docker build (those
// installs pass --ignore-scripts), and each is a no-op, not a build or download step. Allowlisted by EXACT value, so a
// supply-chain change to the script re-triggers review. Today: tesseract.js ships an OpenCollective FUNDING banner as
// its postinstall; its WASM core installs as an ordinary dependency, so skipping the banner changes nothing.
const ALLOWED_SCRIPTS = { 'tesseract.js': { postinstall: 'opencollective-postinstall || true' } };

for (const [name, range] of Object.entries(deps)) {
	const rm = String(range).match(/^\^(\d+)\./);
	ok('dependency "' + name + '" is pinned by a caret range with a concrete major (' + range + ')', !!rm);
	const inst = installed(name);
	ok('dependency "' + name + '" is installed', !!inst);
	if (rm && inst) ok('dependency "' + name + '" installed major matches its range (' + majorOf(inst.version) + ' vs ^' + rm[1] + ')', majorOf(inst.version) === Number(rm[1]));
	if (inst) { const s = inst.scripts || {}; const allow = ALLOWED_SCRIPTS[name] || {}; const life = ['preinstall', 'install', 'postinstall'].filter(x => s[x] && s[x] !== allow[x]); ok('dependency "' + name + '" declares no unreviewed install lifecycle script', life.length === 0); if (life.length) console.log('        scripts: ' + life.map(x => x + '=' + s[x]).join('; ')); }
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DEP-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
