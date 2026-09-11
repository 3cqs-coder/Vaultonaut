'use strict';
// lib/test/_runall.js — the cross-platform test runner behind `npm run test:all`. It replaces a bash-only
// `for … case … esac` one-liner so the full suite runs the same on macOS, Linux, and Windows (cmd/PowerShell),
// which a contributor on any platform needs. Behavior is faithful to the old loop: run every lib/test/*.js in sorted
// order, skip the `_`-prefixed helpers (fixtures and this runner), preload ./lib/test/_setup.js into each, print
// "# <file>" before it, and stop at the FIRST failure with a non-zero exit. The leading `_` keeps the runner itself
// out of the globbed set it runs.
//
// Run:  node lib/test/_runall.js   (or: npm run test:all)

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const testDir = __dirname;
const files = fs.readdirSync(testDir)
	.filter((n) => n.endsWith('.js') && !n.startsWith('_')) // skip helpers/fixtures/this runner, matching the old `_*)` skip
	.sort(); // stable, locale-independent order so a failure is reproducible run to run

const setup = path.join('lib', 'test', '_setup.js');
for (const name of files) {
	const rel = path.join('lib', 'test', name);
	console.log('# ' + rel);
	const r = spawnSync(process.execPath, ['-r', './' + setup.split(path.sep).join('/'), rel], { stdio: 'inherit' });
	if (r.status !== 0 || r.error) { process.exit(r.status || 1); } // fail-fast, like the old `|| exit 1`
}
