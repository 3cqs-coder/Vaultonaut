'use strict';
// lib/test/workflowdrift.js — a DRIFT GUARD over the two release-triggering GitHub workflows. The desktop release
// (release.yml) and the container image (docker.yml) must fire on the SAME set of git tags, or a release tag builds
// one artifact but not the other — for example a `v1.1.0-beta` tag would ship the desktop installers while the
// container image silently lagged a version. This is exactly the class of drift that already slipped through once
// (docker.yml was missing the v-prefixed pre-release pattern), so pin the two tag sets equal. Skips gracefully when a
// workflow file is absent (a checkout without .github/).
//
// Run:  node -r ./lib/test/_setup.js lib/test/workflowdrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const WF = path.join(__dirname, '..', '..', '.github', 'workflows');
function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return ''; } }

// Extract the quoted tag patterns from the `on: push: tags:` block. The block is a run of `- '<pattern>'` list items
// under a `tags:` key; collect every quoted pattern until the indentation drops back out of the list.
function pushTags(text) {
	const lines = text.split(/\r?\n/);
	const tags = [];
	let inTags = false, tagsIndent = -1;
	for (const line of lines) {
		if (/^\s*tags:\s*$/.test(line)) { inTags = true; tagsIndent = line.search(/\S/); continue; }
		if (!inTags) continue;
		if (/^\s*$/.test(line)) continue; // blank line inside the block is fine
		const indent = line.search(/\S/);
		const m = line.match(/^\s*-\s*'([^']+)'/);
		if (m && indent > tagsIndent) { tags.push(m[1]); continue; }
		// A non-list line at or below the tags-key indentation ends the block.
		if (indent <= tagsIndent || !m) break;
	}
	return tags.sort();
}

function main() {
	const relPath = path.join(WF, 'release.yml');
	const dockPath = path.join(WF, 'docker.yml');
	if (!fs.existsSync(relPath) || !fs.existsSync(dockPath)) { console.log('  skip  (a release workflow is absent in this checkout)'); return done(); }

	const relTags = pushTags(read(relPath));
	const dockTags = pushTags(read(dockPath));

	ok('the desktop release workflow declares at least one release tag pattern', relTags.length > 0);
	ok('the container image workflow declares at least one release tag pattern', dockTags.length > 0);
	const equal = relTags.length === dockTags.length && relTags.every((t, i) => t === dockTags[i]);
	if (!equal) {
		console.log('        release.yml tags: ' + JSON.stringify(relTags));
		console.log('        docker.yml  tags: ' + JSON.stringify(dockTags));
	}
	ok('the desktop and container workflows fire on the SAME set of release tags (no split release)', equal);

	done();
}
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL WORKFLOW-DRIFT CHECKS PASSED')); process.exit(failures ? 1 : 0); }
main();
