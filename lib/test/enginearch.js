'use strict';
// lib/test/enginearch.js — the bundled engine is downloaded by matching this machine's platform and CPU
// architecture to the official release archive name. The mapping must name a real published build for every
// architecture the minimum supported Node runs on (64- and 32-bit x86, 64-bit and 32-bit ARM), and must return
// null for anything unknown so the caller shows a clear "no build for your platform" message instead of installing
// an unrunnable binary (the old code silently coerced every non-arm64 arch to amd64, so a 32-bit board downloaded
// and installed an amd64 engine that then failed to run with a misleading error).
//
// Run:  node lib/test/enginearch.js

const RcloneSetup = require('../RcloneSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	// Every (platform, arch) pair below must map to a real rclone release archive suffix.
	const expect = {
		'darwin/arm64': 'osx-arm64', 'darwin/x64': 'osx-amd64',
		'linux/x64': 'linux-amd64', 'linux/arm64': 'linux-arm64', 'linux/arm': 'linux-arm-v7', 'linux/ia32': 'linux-386',
		'win32/x64': 'windows-amd64', 'win32/arm64': 'windows-arm64', 'win32/ia32': 'windows-386',
	};
	for (const [key, want] of Object.entries(expect)) {
		const [platform, arch] = key.split('/');
		ok(key + ' → ' + want, RcloneSetup.archiveSuffix(platform, arch) === want);
	}

	// An unknown architecture must map to null (→ clear "not published for this platform" message), never silently
	// to amd64 (which would install a binary that cannot run on that CPU).
	ok('an unknown architecture maps to null, not a wrong build', RcloneSetup.rcloneArch('mips') === null);
	ok('archiveSuffix is null for an unknown architecture', RcloneSetup.archiveSuffix('linux', 'mips') === null);
	ok('archiveSuffix is null for an unknown platform', RcloneSetup.archiveSuffix('sunos', 'x64') === null);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENGINE-ARCH CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
