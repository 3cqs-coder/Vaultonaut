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
ok('prepare-sidecar.js declares a PINNED_NODE literal', !!PINNED_NODE);

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

// 3. The Rust crate version is a manual duplicate of the app version. tauri.conf.json single-sources the SHIPPED
//    version from package.json, but Cargo.toml carries its own literal that goes stale on a release bump — pin it
//    to the root package.json version so the two cannot drift.
{
	const pkg = JSON.parse(read('package.json') || '{}');
	const cargo = read('src-tauri/Cargo.toml');
	const cargoVer = (cargo.match(/^version\s*=\s*"(\d+\.\d+\.\d+[^"]*)"/m) || [])[1];
	ok('src-tauri/Cargo.toml declares a version', !!cargoVer);
	ok('src-tauri/Cargo.toml version matches package.json (' + pkg.version + ')', !!cargoVer && cargoVer === pkg.version);
	// tauri.conf.json must keep single-sourcing the shipped version from package.json (never a hard-coded literal).
	const tauriConf = read('src-tauri/tauri.conf.json');
	ok('tauri.conf.json single-sources its version from package.json', /"version"\s*:\s*"\.\.\/package\.json"/.test(tauriConf));
	// Cargo.lock pins the crate's OWN version too, and it does not auto-update on a Cargo.toml bump unless a build
	// runs — so it silently went stale at 1.0.0 after the 1.1.0 bump, which a `cargo build --locked`/`--frozen` would
	// reject as an out-of-date lockfile. Pin the vaultonaut package's Cargo.lock version to package.json so a bump that
	// forgets to regenerate the lockfile fails here instead of at release-build time.
	const lock = read('src-tauri/Cargo.lock');
	const lockVer = (lock.match(/name\s*=\s*"vaultonaut"\s*\nversion\s*=\s*"([^"]+)"/) || [])[1];
	ok('src-tauri/Cargo.lock has the vaultonaut crate version', !!lockVer);
	ok('src-tauri/Cargo.lock crate version matches package.json (' + pkg.version + ')', !!lockVer && lockVer === pkg.version);
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
