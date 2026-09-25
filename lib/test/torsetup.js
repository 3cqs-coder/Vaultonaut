'use strict';
// lib/test/torsetup.js — the downloaded-Tor manager (lib/TorSetup.js), which fetches a known-good, CHECKSUM-VERIFIED
// Tor so onion mode works with no setup, exactly like the storage engine. This pins the invariants that make the
// download SAFE and cross-platform, without actually downloading (a real download + bootstrap is verified on a live
// machine): every desktop platform maps to an expert-bundle suffix and a committed SHA-256; the download is verified
// against that committed sum (never the mirror's word); macOS ad-hoc-signs the unsigned binary so it runs; and the
// paths live under the per-user bin dir. Pure/deterministic, cross-platform.
//
// Run:  node lib/test/torsetup.js

const fs = require('fs');
const path = require('path');
const TorSetup = require('../TorSetup');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// 1. Platform/arch → expert-bundle suffix, for every desktop target and the unsupported ones.
ok('macOS arm64 → macos-aarch64', TorSetup.torSuffix('darwin', 'arm64') === 'macos-aarch64');
ok('macOS x64 → macos-x86_64', TorSetup.torSuffix('darwin', 'x64') === 'macos-x86_64');
ok('Windows x64 → windows-x86_64', TorSetup.torSuffix('win32', 'x64') === 'windows-x86_64');
ok('Windows ia32 → windows-i686', TorSetup.torSuffix('win32', 'ia32') === 'windows-i686');
ok('Linux x64 → linux-x86_64', TorSetup.torSuffix('linux', 'x64') === 'linux-x86_64');
ok('Linux ia32 → linux-i686', TorSetup.torSuffix('linux', 'ia32') === 'linux-i686');
ok('an unsupported platform/arch (linux arm64) maps to null (falls back to a system Tor)', TorSetup.torSuffix('linux', 'arm64') === null);

// 2. Every supported platform has a committed 64-hex SHA-256, and the download is verified against it.
for (const [pf, arch] of [['darwin', 'arm64'], ['darwin', 'x64'], ['win32', 'x64'], ['win32', 'ia32'], ['linux', 'x64'], ['linux', 'ia32']]) {
	const sum = TorSetup.pinnedSha256(pf, arch);
	ok('a committed SHA-256 exists for ' + pf + '/' + arch, typeof sum === 'string' && /^[0-9a-f]{64}$/.test(sum));
}
ok('there is a committed checksum for every supported suffix, and none extra', Object.keys(TorSetup.PINNED_SHA256).length === 6);

// 3. Paths resolve under the per-user bin dir (never a system path).
const Common = require('../Common');
ok('the tor binary path is under the bin dir', TorSetup.torBinPath().startsWith(Common.binDir()));
ok('the geoip data path is under the bin dir', TorSetup.geoipPath().startsWith(Common.binDir()));

// 4. Source guards for the safety-critical bits that only run against a real download.
const src = fs.readFileSync(path.join(__dirname, '..', 'TorSetup.js'), 'utf8');
ok('the download is verified against the COMMITTED checksum (expectedSha256), never the mirror\'s', /Net\.download\(url, tmpArchive, \{ expectedSha256: sha256/.test(src));
ok('macOS ad-hoc-signs the unsigned Tor binary and its dylibs so it runs on Apple Silicon', /function adhocSignMac[\s\S]{0,400}codesign', \['--force', '--sign', '-'/.test(src));
ok('the pinned version and the download URL point at the Tor Project archive', /PINNED_TAG = '15\./.test(src) && /archive\.torproject\.org\/tor-package-archive\/torbrowser/.test(src));
ok('a version bump re-downloads (the cache is keyed on the pinned tag)', /readTag\(\)\) === PINNED_TAG/.test(src));

// 5. The manager wiring in Onion.js: prefer a running Tor, else a managed one; loopback-only; reaped by the registry.
const onion = fs.readFileSync(path.join(__dirname, '..', 'Onion.js'), 'utf8');
ok('provideTor prefers a Tor the user already runs before downloading one', /async function provideTor\([\s\S]{0,300}connectControl\(CONTROL_PORTS\[i\][\s\S]{0,200}startManagedTor\(\)/.test(onion));
ok('the managed Tor binds control and SOCKS on loopback only', /--SocksPort', '127\.0\.0\.1:'[\s\S]{0,80}--ControlPort', '127\.0\.0\.1:'/.test(onion));
ok('the managed Tor is tracked by the process registry (reaped on a hard kill, never leaks)', /ProcRegistry\.track\(proc\)/.test(onion));
ok('it waits for a full bootstrap before use, with a timeout', /Bootstrapped 100%/.test(onion) && /could not connect to the network in time/.test(onion));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL TOR-SETUP CHECKS PASSED'));
process.exit(failures ? 1 : 0);
