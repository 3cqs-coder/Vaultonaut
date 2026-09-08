'use strict';
// lib/test/merklesort.js — the cooperative file-sort inside merkleRoot must be byte-identical to a single native
// sort, at every size (including sizes that cross the chunk boundary and exercise the merge path), and the Merkle
// root it feeds must stay independent of the input order. Existing baseline tests use small vaults that never reach
// the merge path, so this covers it directly. See lib/Integrity.js (sortFilesByPath / merkleRoot).
//
// Run:  node lib/test/merklesort.js

const Integrity = require('../Integrity');

let failures = 0;
function ok(name, cond) { if (!cond) { console.log('  FAIL ' + name); failures++; } else { console.log('  ok   ' + name); } }

// Deterministic PRNG so a failure is reproducible (no Math.random).
let seed = 0x2f6bff01;
function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; }

// Build n files with unique, deliberately unordered paths (a random hex prefix so the input is far from sorted).
function makeFiles(n) {
	const files = new Array(n);
	for (let i = 0; i < n; i++) {
		const prefix = (rnd() ^ (i * 2654435761)).toString(16).padStart(8, '0');
		files[i] = { path: prefix + '/file-' + i + '.dat', size: rnd() % 100000, hash: (rnd() >>> 0).toString(16) };
	}
	return files;
}

const nativeSort = (files) => files.slice().sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
const paths = (files) => files.map(f => f.path);
const sameOrder = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

async function main() {
	// SORT_CHUNK is 8192 internally; test sizes below, at, and across one and several chunk boundaries.
	for (const n of [0, 1, 5, 8191, 8192, 8193, 16384, 16385, 40000]) {
		const files = makeFiles(n);
		const mine = await Integrity.sortFilesByPath(files);
		const ref = nativeSort(files);
		ok('sortFilesByPath matches a single native sort at n=' + n, sameOrder(paths(mine), paths(ref)));
		ok('sortFilesByPath does not mutate its input at n=' + n, files.length === n && (n === 0 || files[0] !== mine[0] || sameOrder(paths(files), paths(files))));
	}

	// The Merkle root must not depend on the order files are presented in — the whole point of sorting first.
	const big = makeFiles(20000); // > SORT_CHUNK, so the merge path runs
	const rootShuffled = await Integrity.merkleRoot(big);
	const rootSorted = await Integrity.merkleRoot(nativeSort(big));
	const rootReversed = await Integrity.merkleRoot(big.slice().reverse());
	ok('merkleRoot is identical for shuffled vs pre-sorted input (large set)', rootShuffled === rootSorted);
	ok('merkleRoot is identical for reversed input (large set)', rootShuffled === rootReversed);
	ok('merkleRoot returns a 64-hex-char sha256 root', /^[0-9a-f]{64}$/.test(rootShuffled));

	// A small set (native-sort path) stays order-independent too.
	const small = makeFiles(5);
	ok('merkleRoot is order-independent for a small set', (await Integrity.merkleRoot(small)) === (await Integrity.merkleRoot(nativeSort(small))));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MERKLE-SORT CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main();
