'use strict';
// lib/test/desktoplayout.js — a DRIFT GUARD over the desktop bundle's layout and identity contract, which is
// otherwise spread across three languages with nothing tying them together: the Rust shell (`src-tauri/src/
// main.rs`), the staging script (`src-tauri/prepare-sidecar.js`), and the Tauri config (`src-tauri/
// tauri.conf.json`). A mismatch here breaks app launch only at full-build-and-run time, which the unit suite
// never reaches — so assert the contract statically. Also enforces the single-sourced facts: the loopback port
// matches the Node default, the product name matches Brand, and the version matches across all three files.
// Skips gracefully when the packaging tree is absent.
//
// Run:  node -r ./lib/test/_setup.js lib/test/desktoplayout.js

const fs = require('fs');
const path = require('path');
const Common = require('../Common');
const Brand = require('../Brand');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DESKTOP-LAYOUT CHECKS PASSED')); process.exit(failures ? 1 : 0); }
const REPO = path.join(__dirname, '..', '..');
const ST = path.join(REPO, 'src-tauri');
function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return ''; } }

// Extract the Linux apt package set from a blob (the `apt install` line, across backslash continuations).
function aptPackages(text) {
	const lines = String(text).split('\n');
	let i = lines.findIndex((l) => l.includes('libwebkit2gtk'));
	if (i < 0) return null;
	let joined = '';
	for (; i < lines.length; i++) { joined += ' ' + lines[i]; if (!lines[i].trimEnd().endsWith('\\')) break; }
	const known = new Set(['build-essential', 'curl', 'wget', 'file']);
	return new Set(joined.replace(/\\/g, ' ').split(/\s+/).filter(Boolean).filter((t) => t.startsWith('lib') || known.has(t)));
}

function main() {
	if (!fs.existsSync(path.join(ST, 'src', 'main.rs'))) { console.log('  skip  (no src-tauri desktop shell in this checkout)'); return done(); }

	const mainRs = read(path.join(ST, 'src', 'main.rs'));
	let conf = {}; try { conf = JSON.parse(read(path.join(ST, 'tauri.conf.json'))); } catch (_) {}
	let prep; try { prep = require(path.join(ST, 'prepare-sidecar.js')); } catch (e) { ok('the staging script loads', false); return done(); }
	const pkg = (() => { try { return JSON.parse(read(path.join(REPO, 'package.json'))); } catch (_) { return {}; } })();
	const cargo = read(path.join(ST, 'Cargo.toml'));

	// Layout contract: the dirs the shell reads == the dirs the staging writes == the resources the config bundles.
	ok('the staged app dir is named "app"', path.basename(prep.APP_DIR) === 'app');
	ok('the runtime is staged INSIDE app/ (so the signed manifest covers the interpreter)', prep.RUNTIME_DIR === path.join(prep.APP_DIR, 'runtime'));
	ok('the config bundles the "app" resource', !!(conf.bundle && conf.bundle.resources && Object.prototype.hasOwnProperty.call(conf.bundle.resources, 'app')));
	ok('the shell resolves the runtime under app/runtime', /"app"\)\s*\.join\("runtime"\)/.test(mainRs));
	ok('the shell resolves the entry as app/vaultonaut.js', /"app"\)\s*\.join\("vaultonaut\.js"\)/.test(mainRs));

	// The loopback port is single-sourced in spirit: the Rust constant must equal the Node default.
	const portMatch = mainRs.match(/UI_PORT:\s*u16\s*=\s*(\d+)/);
	ok('the shell UI_PORT matches Common.DEFAULT_UI_PORT', !!portMatch && Number(portMatch[1]) === Common.DEFAULT_UI_PORT);

	// Identity is single-sourced in Brand; the config must not drift from it.
	ok('the config productName matches Brand.name', conf.productName === Brand.name);

	// One version across every file a release bump must touch.
	const cargoVer = (cargo.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
	ok('the config version matches package.json', conf.version === pkg.version);
	ok('the Cargo.toml version matches package.json', cargoVer === pkg.version);

	// Real installers on every OS (not just macOS app/dmg).
	ok('bundle targets are "all" (installers on every platform)', !!(conf.bundle && conf.bundle.targets === 'all'));

	// The pinned build runtime is single-sourced and must stay at/above the feature floor (post-quantum seals need
	// 24.7), so every platform bundles the same version and no pin bump silently disables a feature.
	const pin = String(prep.PINNED_NODE || '').split('.').map(Number);
	ok('the pinned Node version is set and >= 24.7 (all features enabled, same on every platform)', pin.length >= 2 && (pin[0] > 24 || (pin[0] === 24 && pin[1] >= 7)));

	// If the CI workflow exists, the Node it installs must match the pin (otherwise a CI build would be refused by
	// the runtime-version check — catch that here rather than at build time).
	const wf = path.join(REPO, '.github', 'workflows', 'release.yml');
	if (fs.existsSync(wf)) {
		const wfText = read(wf);
		const nv = (wfText.match(/node-version:\s*([0-9.]+)/) || [])[1];
		ok('the CI workflow pins the same Node version as PINNED_NODE', nv === prep.PINNED_NODE);

		// The Linux build dependencies are listed in two places (the workflow and the build README). They must
		// stay identical, or a hand-run Linux build will be missing what CI installs (or vice versa).
		const readmeApt = aptPackages(read(path.join(ST, 'README.md')));
		const wfApt = aptPackages(wfText);
		const same = readmeApt && wfApt && readmeApt.size === wfApt.size && [...readmeApt].every((p) => wfApt.has(p));
		ok('the Linux build dependencies match between the workflow and the build README', !!same);

		// The manual-build-without-a-version-bump path must stay wired: a workflow_dispatch release_tag input and
		// a release job. If either is renamed away, no-version builds or drafting break silently.
		ok('the workflow keeps its release_tag manual input', /release_tag:/.test(wfText));
		ok('the workflow keeps its release job', /^\s{2}release:/m.test(wfText));
	}

	return done();
}
main();
