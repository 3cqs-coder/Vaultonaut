'use strict';
// lib/test/branddrift.js — the product identity lives in ONE place (lib/Brand.js), and the standing rule is that the
// name must never be hardcoded elsewhere. This guard enforces that in two ways:
//
//   1. Contract: Brand.js still exports every identity field the rest of the code depends on, each a non-empty string of
//      the right shape (a missing or malformed field would break data-dir paths, the process name, vault-suffix
//      stripping, and the service id — silently, far from here). This locks the single source's integrity.
//   2. No hardcoded DISPLAY name: no executable code outside Brand.js may embed the quoted display name literal, which
//      would drift from a rename. The one documented exception is the web client's data-* fallback (public/js/app.js),
//      which Brand.js's own note allowlists.
//
// It deliberately does NOT scan for the lowercase slug: that token is legitimately FROZEN into wire-format strings that
// must never change on a rename (an HKDF info string, a release-bundle schema id, the control-file basenames) and into
// the real on-disk entry-point filename. Those are the opposite of drift, so flagging them would be wrong.
//
// Run:  node lib/test/branddrift.js

const fs = require('fs');
const path = require('path');
const Brand = require('../Brand');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');

// 1. Brand.js contract — every field present, a non-empty string, and correctly shaped.
const str = (v) => typeof v === 'string' && v.length > 0;
ok('Brand.name is a non-empty string', str(Brand.name));
ok('Brand.cli is a non-empty string with no spaces', str(Brand.cli) && !/\s/.test(Brand.cli));
ok('Brand.slug is a non-empty lowercase string with no spaces', str(Brand.slug) && Brand.slug === Brand.slug.toLowerCase() && !/\s/.test(Brand.slug));
ok('Brand.serviceId is a non-empty string with no spaces', str(Brand.serviceId) && !/\s/.test(Brand.serviceId));
ok('Brand.mountDirName is a non-empty string', str(Brand.mountDirName));
ok('Brand.vaultExt is a non-empty dot-prefixed suffix', str(Brand.vaultExt) && Brand.vaultExt.startsWith('.'));
ok('Brand.packExt is a non-empty dot-prefixed suffix', str(Brand.packExt) && Brand.packExt.startsWith('.'));
ok('Brand.vaultExtRe matches Brand.vaultExt (and only at the end)', Brand.vaultExtRe instanceof RegExp && Brand.vaultExtRe.test('anything' + Brand.vaultExt) && !Brand.vaultExtRe.test(Brand.vaultExt + 'x'));

// 2. No hardcoded display name in executable code. Walk lib/**/*.js, strip comments, and fail on a quoted display-name
//    literal outside Brand.js and the one documented fallback.
const DISPLAY = Brand.name; // 'Vaultonaut'
const ALLOW = new Set([
	path.join('lib', 'webserver', 'public', 'js', 'app.js'), // the documented data-* fallback (see Brand.js's note)
]);
function stripComments(src) {
	return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1'); // block comments, then line comments (leave "://" in URLs alone)
}
function walk(dir, out) {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, e.name);
		if (e.isDirectory()) { if (e.name === 'node_modules' || e.name === 'test') continue; walk(p, out); }
		else if (e.name.endsWith('.js')) out.push(p);
	}
}
const files = [];
walk(path.join(ROOT, 'lib'), files);
const quoted = new RegExp('[\'"`]' + DISPLAY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[\'"`]');
const offenders = [];
for (const abs of files) {
	const rel = path.relative(ROOT, abs);
	if (rel === path.join('lib', 'Brand.js') || ALLOW.has(rel)) continue;
	if (quoted.test(stripComments(fs.readFileSync(abs, 'utf8')))) offenders.push(rel);
}
ok('the display name is not hardcoded as a quoted literal anywhere in lib/ (outside Brand.js and the documented app.js fallback)' + (offenders.length ? ' — found in: ' + offenders.join(', ') : ''), offenders.length === 0);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BRAND-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
