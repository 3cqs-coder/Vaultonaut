'use strict';
// lib/test/apidrift.js — the published /api/v1 surface stays consistent across code, docs, and the alias. It pins the
// ONE shared list (lib/webserver/apiV1.js) against (a) the README's "Local API" section, so every published endpoint is
// documented and nothing undocumented is published, and (b) the real routes in the web server, so /api/v1 never aliases
// a path that has no handler. Pure and fast: it only reads source files. If a v1 endpoint is added without documenting
// it, or without a real /api route, this fails.
//
// Run:  node lib/test/apidrift.js

const fs = require('fs');
const path = require('path');
const ApiV1 = require('../webserver/apiV1');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const readme = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'README.md'), 'utf8');
	const src = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	// Only look at the README's "Local API" section, so a stray mention elsewhere cannot mask a missing entry.
	const sec = (readme.match(/\n## Local API\n[\s\S]*?(?=\n## )/) || [''])[0];
	ok('the README has a Local API section', sec.length > 0);
	ok('the README documents GET /api/version', /GET `?\/api\/version/.test(sec));
	ok('the version endpoint is registered in the server', /app\.get\('\/api\/version'/.test(src));

	for (const r of ApiV1.V1) {
		ok('the README documents /api/v1/' + r, sec.includes('/api/v1/' + r));
		ok('/api/' + r + ' is a real route in the server', new RegExp("app\\.(post|get)\\('/api/" + r + "'").test(src));
	}

	// Nothing is documented as /api/v1/<x> in the README that is not in the shared list (docs can't over-promise).
	const documented = [...sec.matchAll(/\/api\/v1\/([a-z0-9-]+)/g)].map((m) => m[1]);
	const listed = new Set(ApiV1.V1);
	for (const d of new Set(documented)) ok('documented endpoint /api/v1/' + d + ' is in the published list', listed.has(d));

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL API-DRIFT CHECKS PASSED');
}
main();
