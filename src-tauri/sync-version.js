'use strict';
// src-tauri/sync-version.js — make the root package.json the SINGLE SOURCE OF TRUTH for the desktop crate's version.
//
// tauri.conf.json already reads the SHIPPED app/installer version from ../package.json, so that is automatic. But the
// Rust crate carries its own copy of the version in two places Cargo cannot derive from JSON — Cargo.toml (the
// [package] version) and Cargo.lock (the vaultonaut package entry) — and those went stale once already when the
// package.json version was bumped without regenerating them. This script rewrites those two literals to match
// package.json with a pure, targeted text edit: no cargo/toolchain needed, cross-platform, and idempotent.
//
// Usage: after bumping the version in package.json, run `npm run sync-version` (in src-tauri) and commit. The build
// runs it first as well, so a build always produces the correct version even if a manual sync was forgotten; the
// lib/test/builddrift.js guard is the backstop that fails the build if a committed copy is ever out of sync.

const fs = require('fs');
const path = require('path');

const version = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version;
if (!/^\d+\.\d+\.\d+/.test(String(version || ''))) { console.error('sync-version: package.json has no valid version.'); process.exit(1); }

const changed = [];

// Cargo.toml: the [package] version. Only a line that STARTS with `version =` matches, so an inline dependency
// `... { version = "2" }` is never touched, and only the first (the [package] one) is rewritten.
const tomlPath = path.join(__dirname, 'Cargo.toml');
const toml = fs.readFileSync(tomlPath, 'utf8');
const tomlNew = toml.replace(/^(version\s*=\s*")[^"]+(")/m, `$1${version}$2`);
if (tomlNew !== toml) { fs.writeFileSync(tomlPath, tomlNew); changed.push('Cargo.toml'); }

// Cargo.lock: the vaultonaut package's own version entry (leave every dependency's version alone).
const lockPath = path.join(__dirname, 'Cargo.lock');
if (fs.existsSync(lockPath)) {
	const lock = fs.readFileSync(lockPath, 'utf8');
	const lockNew = lock.replace(/(name = "vaultonaut"\nversion = ")[^"]+(")/, `$1${version}$2`);
	if (lockNew !== lock) { fs.writeFileSync(lockPath, lockNew); changed.push('Cargo.lock'); }
}

console.log(changed.length ? `sync-version: set the desktop crate version to ${version} in ${changed.join(', ')}.` : `sync-version: the desktop crate version is already ${version}.`);
