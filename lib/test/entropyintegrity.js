'use strict';
// lib/test/entropyintegrity.js — the single most catastrophic failure class for any key-holding tool is WEAK KEY
// ENTROPY: if key material is generated from a non-cryptographic pseudo-random source (a Mersenne-Twister-style PRNG,
// or one seeded from the clock), or if a build/configuration slip lets a crypto path SILENTLY fall back to a weaker
// generator, the resulting keys are brute-forceable offline — no theft of the device or the vault folder required, and
// no update can retroactively rescue a key already generated that way. Real-world losses in this class have run to
// tens and hundreds of millions of dollars, from both software and hardware key generators, and the defect is usually
// invisible until funds vanish. This guard makes that class impossible to introduce into Vaultonaut without a test
// failure. It pins three things:
//
//   1. No non-cryptographic randomness (`Math.random`) anywhere in the BACKEND, where every persisted key, seed, salt,
//      and nonce is generated. The one legitimate `Math.random` in the whole project is a last-resort DOM field-id
//      fallback in the browser UI (a non-secret element id, used only if the platform has no crypto at all) — the
//      backend must never contain it.
//   2. No SILENT FALLBACK to a weaker source in a crypto path: a CSPRNG call must fail closed, never quietly swap in a
//      lesser generator. (Node's crypto.randomBytes and the browser's crypto.getRandomValues both throw when entropy
//      is unavailable, so the correct posture is simply to have no weaker alternative wired in behind them.)
//   3. FULL-WIDTH key material and a MEMORY-HARD KDF: seeds are 256-bit, the KDF salt is 128-bit, and the Argon2id
//      levels meet memory/iteration floors that keep a stolen vault infeasible to brute-force offline (the failure
//      that turned stolen password-manager vaults into drained ones was a KDF left at a trivially low work factor).
//
// Plus a live statistical probe of the actual generator the tool uses, so a future swap to a degenerate source is
// caught by its output, not just its source text. Pure, no engine.
//
// Run:  node lib/test/entropyintegrity.js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Kdf = require('../Kdf');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const libDir = path.join(__dirname, '..');
// Every backend .js file: the whole lib/ tree EXCEPT the tests, the browser UI (lib/webserver/public — its own crypto
// uses crypto.getRandomValues and its only Math.random is the documented non-secret field-id fallback), and any
// vendored third-party bundle. These are the files that generate or handle persisted key material.
function backendFiles(dir, out) {
	for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, ent.name);
		if (ent.isDirectory()) {
			if (ent.name === 'test' || ent.name === 'vendor' || full.includes(path.join('webserver', 'public'))) continue;
			backendFiles(full, out);
		} else if (ent.name.endsWith('.js')) out.push(full);
	}
	return out;
}

function part1_source() {
	const files = backendFiles(libDir, []);
	ok('found the backend source set to scan', files.length > 10);

	// 1. No non-cryptographic randomness in the backend.
	const withMathRandom = files.filter(f => /Math\.random\s*\(/.test(fs.readFileSync(f, 'utf8'))).map(f => path.relative(libDir, f));
	ok('no backend file uses Math.random for anything' + (withMathRandom.length ? ' (found in: ' + withMathRandom.join(', ') + ')' : ''), withMathRandom.length === 0);

	// 2. No SILENT FALLBACK: a CSPRNG call must never be paired with the weaker Math.random as an alternative (behind a
	//    `||`, a ternary, or a catch) — the shape a build/config slip would take to quietly downgrade key strength. The
	//    backend having zero Math.random (check 1) already makes this hold; pinning the co-occurrence explicitly
	//    documents the invariant and catches a future line that wires a weak generator behind a crypto call.
	let fallbackHits = 0;
	for (const f of files) {
		const src = fs.readFileSync(f, 'utf8');
		for (const line of src.split('\n')) {
			if (/random(Bytes|Fill|UUID|Int)\s*\(/.test(line) && /Math\.random/.test(line)) fallbackHits++;
		}
	}
	ok('no crypto path pairs a CSPRNG with a weaker (Math.random) fallback generator', fallbackHits === 0);

	// 3a. Full-width seeds: the vault's write seed, owner seed, and rotated write seed are the roots of all signing and
	//     wrapping authority. Each must be generated at the full 256-bit width (32 bytes). Pin the exact generation so a
	//     future edit that narrows the width — the precise defect behind reduced-strength key disasters — fails here.
	const vaultSrc = fs.readFileSync(path.join(libDir, 'Vault.js'), 'utf8');
	for (const name of ['writeSeed', 'ownerSeed', 'newWriteSeed']) {
		const re = new RegExp('const\\s+' + name + '\\s*=\\s*crypto\\.randomBytes\\(32\\)');
		ok(name + ' is generated at the full 256-bit width', re.test(vaultSrc));
	}
	// No suspiciously narrow CSPRNG width for key-like material: a seed/key/secret must never be drawn from fewer than
	// 16 bytes. (Six-byte draws exist for NON-secret record ids — memberId, remote/dest/peer ids — which is fine; this
	// check targets the key words specifically.)
	const narrowKey = /(seed|masterKey|writeSeed|ownerSeed|secret|signSeed)\s*=\s*crypto\.randomBytes\((?:[0-9]|1[0-5])\)/i.test(vaultSrc);
	ok('no key/seed/secret is drawn from fewer than 16 random bytes', narrowKey === false);
}

function part2_kdf() {
	// Memory-hard KDF floors: keep a stolen vault infeasible to brute-force offline. Argon2id at 64 MiB / 3 passes is
	// the floor; a regression that lowered these (the trivial-work-factor mistake that doomed stolen vaults elsewhere)
	// fails here. hashLen is pinned to 32 (AES-256).
	for (const [name, p] of Object.entries(Kdf.LEVELS)) {
		ok('KDF level "' + name + '" is memory-hard (>= 64 MiB, >= 3 passes)', p.memKiB >= 65536 && p.iterations >= 3 && p.parallelism >= 1);
	}
	const params = Kdf.defaultParams('standard');
	ok('default KDF params select Argon2id with a 32-byte (AES-256) output', params.algo === 'argon2id' && params.hashLen === 32);
	ok('the default KDF salt is a full 128-bit (16-byte) random value', Buffer.from(params.salt, 'base64').length === 16);
}

function part3_liveProbe() {
	// Live statistical probe of the ACTUAL generator the tool uses (crypto.randomBytes, exercised through the real KDF
	// salt generator). A degenerate source — a low-bit PRNG, a clock-seeded generator, or a stuck value — would betray
	// itself here through collisions or a skewed bit balance, catching a bad swap by its OUTPUT, not just its source.
	const N = 5000;
	const salts = new Set();
	let ones = 0, bits = 0, widthOk = true;
	for (let i = 0; i < N; i++) {
		const buf = Buffer.from(Kdf.defaultParams('standard').salt, 'base64');
		if (buf.length !== 16) widthOk = false;
		salts.add(buf.toString('hex'));
		for (const byte of buf) { for (let b = 0; b < 8; b++) ones += (byte >> b) & 1; bits += 8; }
	}
	ok('every generated salt is full-width (16 bytes)', widthOk);
	ok(N + ' generated salts are all unique (no collisions — real entropy, not a narrow source)', salts.size === N);
	const balance = ones / bits;
	ok('the generated bits are ~balanced (0.48-0.52 set) — no stuck or low-entropy source', balance > 0.48 && balance < 0.52);

	// And the platform CSPRNG itself, directly: a 32-byte draw must be full-width and non-repeating across many draws.
	const seeds = new Set();
	for (let i = 0; i < N; i++) seeds.add(crypto.randomBytes(32).toString('hex'));
	ok(N + ' direct 256-bit CSPRNG draws are all unique', seeds.size === N);
}

part1_source();
part2_kdf();
part3_liveProbe();
console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL ENTROPY-INTEGRITY CHECKS PASSED'));
process.exit(failures ? 1 : 0);
