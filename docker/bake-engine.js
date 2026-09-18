'use strict';
// docker/bake-engine.js — BUILD-TIME ONLY. Fetch and checksum-verify the pinned storage engine into the directory
// named by VAULTONAUT_ENGINE_DIR, and place the engine's own license next to it. The container image runs this in its
// builder stage and copies the result into the runtime image, so a serving node has the engine already present and
// never downloads anything on its first serve — which makes an air-gapped or egress-restricted node work, and removes
// the runtime network dependency.
//
// Drift-free by construction: it does NOT name a version, URL, or checksum. It calls the application's own
// RcloneSetup, which is the single source of the pinned engine version and its committed per-platform checksums, so
// the baked engine can never drift from the version the app expects (a bump to the pin re-bakes automatically). The
// license is fetched at that same pinned tag.

const fs = require('fs');
const path = require('path');
const RcloneSetup = require('../lib/RcloneSetup');
const Net = require('../lib/Net');

const dir = process.env.VAULTONAUT_ENGINE_DIR;
if (!dir) { console.error('[bake-engine] VAULTONAUT_ENGINE_DIR must be set to the target directory'); process.exit(1); }
fs.mkdirSync(dir, { recursive: true });

(async () => {
	// RcloneSetup writes the verified engine (and its checksum/tag sidecars) into binDir(), which resolves to
	// VAULTONAUT_ENGINE_DIR here. A failure to fetch or verify fails the build, so a broken engine can never ship.
	const r = await RcloneSetup.ensure();
	if (!r.ok) { console.error('[bake-engine] engine fetch or checksum verification failed'); process.exit(1); }

	// The engine is MIT-licensed. Baking the binary into the image REDISTRIBUTES it, so its copyright and license text
	// must travel with it. Fetch the engine's own license at the SAME pinned tag (the single source) and place it beside
	// the binary; a build that cannot obtain the license fails rather than shipping the binary without its notice.
	const url = 'https://raw.githubusercontent.com/rclone/rclone/' + RcloneSetup.PINNED_TAG + '/COPYING';
	let text = '';
	try { text = await Net.getText(url); } catch (e) { console.error('[bake-engine] could not fetch the engine license: ' + (e && e.message)); process.exit(1); }
	if (!text || text.length < 400 || !/MIT|Permission is hereby granted/i.test(text)) { console.error('[bake-engine] the fetched engine license did not look like the expected MIT text'); process.exit(1); }
	fs.writeFileSync(path.join(dir, 'rclone-LICENSE.txt'), text);

	console.log('[bake-engine] engine ' + RcloneSetup.PINNED_TAG + ' baked and license saved into ' + dir);
})().catch((e) => { console.error('[bake-engine] failed: ' + (e && e.message)); process.exit(1); });
