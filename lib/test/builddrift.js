'use strict';
// lib/test/builddrift.js — static drift guards for version pins that are DUPLICATED across the three delivery
// modes (standalone Node, the Docker fleet, and the Tauri desktop bundle). Each literal below lives in a separate
// file, so a release bump that updates one and forgets another drifts silently — and unlike the desktop build,
// which aborts on a Node mismatch, the Docker base image would just build on the wrong runtime. These checks read
// the source and fail the build when the pins disagree, in the style of the other *drift.js guards. Engine-free
// and fast.
//
// Run:  node lib/test/builddrift.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => { try { return fs.readFileSync(path.join(ROOT, rel), 'utf8'); } catch (_) { return ''; } };
// Parse a semver "x.y.z" into a comparable [x,y,z]; missing parts read as 0.
function semver(s) { const m = String(s || '').match(/(\d+)\.(\d+)\.(\d+)/); return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null; }
function gte(a, b) { for (let i = 0; i < 3; i++) { if (a[i] > b[i]) return true; if (a[i] < b[i]) return false; } return true; }

// The single source for the pinned Node runtime is PINNED_NODE in the desktop sidecar prep. Parse the literal
// rather than require()-ing the module, so this guard never runs the build script's side effects.
const sidecar = read('src-tauri/prepare-sidecar.js');
const pinnedMatch = sidecar.match(/PINNED_NODE\s*=\s*'(\d+\.\d+\.\d+)'/);
const PINNED_NODE = pinnedMatch ? pinnedMatch[1] : null;
const macMinMatch = sidecar.match(/PINNED_NODE_MACOS_MIN\s*=\s*'([\d.]+)'/);
const PINNED_NODE_MACOS_MIN = macMinMatch ? macMinMatch[1] : null;
ok('prepare-sidecar.js declares a PINNED_NODE literal', !!PINNED_NODE);
ok('prepare-sidecar.js declares the pinned runtime macOS floor', !!PINNED_NODE_MACOS_MIN);

// 0. The desktop bundle must not advertise an older macOS than its bundled Node runtime can start on. The official
//    Node 24.11.1 darwin binaries report LC_BUILD_VERSION minos 13.5; an older LSMinimumSystemVersion would install
//    the app on a Mac where the interpreter immediately fails with a dyld error.
if (PINNED_NODE_MACOS_MIN) {
	// macOS versions are commonly written with two parts ("13.5"), so use a lenient x[.y[.z]] parser here.
	const loose = (s) => { const m = String(s || '').match(/(\d+)\.(\d+)(?:\.(\d+))?/); return m ? [Number(m[1]), Number(m[2]), Number(m[3] || 0)] : null; };
	const conf = JSON.parse(read('src-tauri/tauri.conf.json') || '{}');
	const declared = conf && conf.bundle && conf.bundle.macOS && conf.bundle.macOS.minimumSystemVersion;
	const dv = loose(declared), fv = loose(PINNED_NODE_MACOS_MIN);
	ok('tauri.conf.json declares a macOS minimum system version', !!declared);
	ok('the desktop app macOS floor is at or above the bundled Node floor (' + PINNED_NODE_MACOS_MIN + ')', !!dv && !!fv && gte(dv, fv));
	if (dv && fv && !gte(dv, fv)) console.log('        tauri.conf macOS: ' + declared + ' vs runtime floor ' + PINNED_NODE_MACOS_MIN);
}

// 1. Every Docker base image must pin EXACTLY the same Node as the desktop bundle. Both the builder and the runtime
//    stage are checked, so they can never diverge from each other or from PINNED_NODE.
if (PINNED_NODE) {
	const dockerfile = read('docker/Dockerfile');
	const froms = [...dockerfile.matchAll(/^FROM\s+node:(\d+\.\d+\.\d+)-/gm)].map((m) => m[1]);
	ok('docker/Dockerfile has at least one pinned "FROM node:<version>" base', froms.length > 0);
	ok('every Docker base image pins exactly PINNED_NODE (' + PINNED_NODE + ')', froms.length > 0 && froms.every((v) => v === PINNED_NODE));
	if (froms.some((v) => v !== PINNED_NODE)) console.log('        Docker bases: ' + froms.join(', ') + ' vs PINNED_NODE ' + PINNED_NODE);
}

// 2. PINNED_NODE must satisfy the package.json engines floor, so the pinned build runtime is never BELOW the minimum
//    the package claims to support.
{
	const pkg = JSON.parse(read('package.json') || '{}');
	const floorStr = (pkg.engines && pkg.engines.node) || '';
	const floor = semver(floorStr);
	ok('package.json declares an engines.node floor', !!floor);
	if (PINNED_NODE && floor) ok('PINNED_NODE (' + PINNED_NODE + ') satisfies engines.node ' + floorStr, gte(semver(PINNED_NODE), floor));
}

// 2b. The SHIPPED app version is single-sourced from the root package.json. tauri.conf.json points at it. The Rust
//     crate version is a fixed 0.0.0 placeholder: Cargo cannot read JSON, and Tauri uses the package.json path for the
//     app/installer version (including the Windows version resource), so a second release literal would only drift.
{
	const conf = JSON.parse(read('src-tauri/tauri.conf.json') || '{}');
	const build = (conf && conf.build) || {};
	const cargo = read('src-tauri/Cargo.toml');
	const cargoVer = (cargo.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
	const lock = read('src-tauri/Cargo.lock');
	const lockVer = (lock.match(/name\s*=\s*"vaultonaut"\s*\nversion\s*=\s*"([^"]+)"/) || [])[1];
	ok('tauri.conf.json takes its shipped version from ../package.json', conf.version === '../package.json');
	ok('the desktop crate version is the fixed 0.0.0 placeholder (not a release literal)', cargoVer === '0.0.0');
	ok('the desktop lockfile uses the same fixed crate version', lockVer === '0.0.0');
	ok('no version-mirror hook remains in the Tauri config', build.beforeDevCommand == null && build.beforeBuildCommand == null);
	ok('no version-mirror script remains', !/sync-version/.test(read('src-tauri/package.json')) && !fs.existsSync(path.join(ROOT, 'sync-version.js')) && !fs.existsSync(path.join(ROOT, 'src-tauri', 'sync-version.js')));
	const buildRsCode = read('src-tauri/build.rs').replace(/\/\/.*$/gm, '');
	ok('build.rs does not enforce a duplicate Cargo version', !/CARGO_PKG_VERSION|package\.json/.test(buildRsCode));
	// Node 24 deprecates passing an args array with shell:true. The Windows wrapper must invoke cmd.exe explicitly.
	const tauriBuild = read('src-tauri/tauri-build.js');
	const tauriBuildCode = tauriBuild.replace(/\/\/.*$/gm, ''); // comments may mention the deprecated pattern
	ok('the Tauri build wrapper does not pass args with shell:true', !/shell:\s*(true|isWin)/.test(tauriBuildCode) && /ComSpec/.test(tauriBuildCode));
}

// 4. The release workflow's `npm install` steps must NOT omit optional dependencies. The Tauri CLI ships its
//    per-platform native binding as an OPTIONAL dependency (@tauri-apps/cli-<platform>), so `--omit=optional`
//    removes it and the desktop build fails on every OS with "Cannot find native binding". (The unused PDF-canvas
//    native peer is an optional PEER, which npm never auto-installs, so nothing native lands in the tree either way —
//    the flag has no upside here and a build-breaking downside.) Guard the command itself, ignoring the explanatory
//    comment on the same line by only inspecting the text before any `#`.
{
	const wf = read('.github/workflows/release.yml');
	const installs = [...wf.matchAll(/^\s*run:\s*npm install[^\n]*/gm)].map((m) => m[0].split('#')[0]);
	ok('the release workflow has npm install steps to check', installs.length > 0);
	const offenders = installs.filter((cmd) => /--omit[=\s]*optional|--no-optional/.test(cmd));
	ok('no release npm install omits optional deps (the Tauri CLI native binding is an optional dependency)', offenders.length === 0);
	if (offenders.length) for (const o of offenders) console.log('        ' + o.trim());
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL BUILD-DRIFT CHECKS PASSED'));
process.exit(failures ? 1 : 0);
