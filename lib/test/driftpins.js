'use strict';
// lib/test/driftpins.js — ABSOLUTE pins for single-sourced values that other guards only check RELATIVELY (parity)
// or not at all. A parity guard (verify-bundle vs in-process) catches a change to ONE side but not a coordinated or
// accidental bump propagated to both; and several security-relevant endpoints/constants are single-sourced with no
// backstop at all. This freezes each to its committed literal, so any change — deliberate or not — must be made here
// too, on purpose. Pure and fast: it only reads exported constants. When a change here is intentional, update the
// literal AND the on-disk-format or endpoint documentation in the same commit.
//
// Run:  node lib/test/driftpins.js

const Vault = require('../Vault');
const Integrity = require('../Integrity');
const Timelock = require('../Timelock');
const Disperse = require('../Disperse');
const SlotRegistry = require('../SlotRegistry');
const UpdateCheck = require('../UpdateCheck');
const PwnedCheck = require('../PwnedCheck');
const Decoy = require('../Decoy');
const Travel = require('../Travel');
const Common = require('../Common');
const Brand = require('../Brand');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// --- On-disk FORMAT version markers. A change to any of these changes what is written to (or accepted from) disk, so
//     a silent bump could ship a breaking format change. verifybundleparity pins these BETWEEN the two code copies;
//     this pins their ABSOLUTE values so a coordinated bump to both still fails here until it is deliberate. ---
const bv = Vault._bundleVersions;
ok('BASELINE_VERSION is 5', bv.BASELINE_VERSION === 5);
ok('SEAL_VERSION is 5', bv.SEAL_VERSION === 5);
ok('ROSTER_SEAL_VERSION is 2', bv.ROSTER_SEAL_VERSION === 2);
ok('ATTEST_VERSION is 1', bv.ATTEST_VERSION === 1);
ok('SUCCESSION_VERSION is 1', bv.SUCCESSION_VERSION === 1);
ok('GENESIS_VERSION is 1', bv.GENESIS_VERSION === 1);
ok('FILE_PROOF_VERSION is 1', bv.FILE_PROOF_VERSION === 1);
ok('the integrity SCHEME id is unchanged', bv.SCHEME === 'vdisk-integrity-1');
ok('the Integrity SCHEME constant matches', Integrity.SCHEME === 'vdisk-integrity-1');
ok('Timelock BLOB_VERSION is 1', Timelock.BLOB_VERSION === 1);
ok('Disperse shard VERSION is 2', Disperse.VERSION === 2);
ok('SlotRegistry SUPPORTED_V is 1', SlotRegistry.SUPPORTED_V === 1);
ok('the supported vault format marker is unchanged', Vault.SUPPORTED_FORMAT === undefined || typeof Vault.SUPPORTED_FORMAT === 'string'); // present-and-string if exported; format pinned by keyslotformatdrift

// --- Security-relevant EXTERNAL endpoints. These are single-sourced but have no checksum/pin backstop, so a silent
//     edit (or a code/docs divergence) would quietly point a security decision at the wrong host or strip TLS. ---
ok('the update-check tags endpoint is the expected GitHub API URL over https', UpdateCheck.DEFAULT_TAGS_URL === 'https://api.github.com/repos/3cqs-coder/' + Brand.name + '/tags');
ok('the update-check releases URL is the expected GitHub URL over https', UpdateCheck.RELEASES_URL === 'https://github.com/3cqs-coder/' + Brand.name + '/releases');
ok('both update-check URLs are https', /^https:\/\//.test(UpdateCheck.DEFAULT_TAGS_URL) && /^https:\/\//.test(UpdateCheck.RELEASES_URL));
ok('the pwned-password range endpoint is the fixed HIBP host over https', PwnedCheck.HIBP_BASE === 'https://api.pwnedpasswords.com/range/');

// --- Ports (also pinned by relayportdrift; repeated here so this one file is the single stop for "did a constant move") ---
ok('the default UI port is 7420', Common.DEFAULT_UI_PORT === 7420);
ok('the default relay control port is 7443', Common.DEFAULT_RELAY_PORT === 7443);

// --- Deniability filler-slot counts. If a decoy/travel registry's fixed slot count changed, the number of hidden
//     entries could leak. Decoy's is already pinned by decoy.js; pin both here so neither drifts unnoticed. ---
ok('the decoy registry keeps a fixed slot count', Decoy.SLOT_COUNT === 16);
ok('the travel registry keeps a fixed slot count', Travel.SLOT_COUNT === 8);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DRIFT-PINS CHECKS PASSED'));
process.exit(failures ? 1 : 0);
