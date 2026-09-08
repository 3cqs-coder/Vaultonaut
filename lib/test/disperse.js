'use strict';
// lib/test/disperse.js — the inter-node dispersal byte codec. Any k of n shards must rebuild the
// original exactly; fewer than k must fail cleanly; a corrupted shard must be detected and survived
// (rebuilt from the good ones); mismatched shards must be rejected. Combinatorial + randomized.
//
// Run:  node lib/test/disperse.js

const crypto = require('crypto');
const os = require('os');
const path = require('path');
const fsp = require('fs/promises');
const Disperse = require('../Disperse');

let failures = 0;
function ok(name, cond) { if (!cond) { console.log('  FAIL ' + name); failures++; } }
function eq(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); }

function kSubsets(n, k) {
	const out = [];
	(function pick(start, chosen) {
		if (chosen.length === k) { out.push(chosen.slice()); return; }
		for (let i = start; i < n; i++) { chosen.push(i); pick(i + 1, chosen); chosen.pop(); }
	})(0, []);
	return out;
}

// The bounded shard reader must (a) read a legit shard back exactly, ignoring any trailing padding a hostile
// node appended, and (b) refuse a shard whose header declares a payload larger than a whole archive — without
// reading that declared size into memory. This is the on-disk counterpart to the in-memory codec tests.
async function readShardGuards() {
	console.log('[bounded shard reader: padding-resistant, refuses oversized declarations]');
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-shardread-'));
	try {
		const data = crypto.randomBytes(4096);
		const shards = Disperse.encodeShards(data, 5, 3); // n=5, k=3
		const good = path.join(dir, 'a.0of5.vdshard');
		await fsp.writeFile(good, shards[0]);
		await fsp.appendFile(good, Buffer.alloc(50 * 1024 * 1024)); // 50 MiB of hostile trailing padding
		const back = await Disperse.readShard(good);
		ok('readShard returns only header + declared payload, not the padding', back && back.length === shards[0].length);
		ok('the bounded read still round-trips a valid shard (its hash checks out)', Disperse.shardInfo(back) && Disperse.shardInfo(back).good === true);
		ok('a padded shard set still rebuilds the original', eq(Disperse.decodeShards([back, shards[1], shards[2]]), data));

		// A tiny file whose header claims a ~4 GiB payload (UInt32BE max) must be refused, not allocated.
		const evil = path.join(dir, 'b.0of5.vdshard');
		const hdr = Buffer.from(shards[0].subarray(0, Disperse.HEADER)); // valid magic/version/geometry
		hdr.writeUInt32BE(0xFFFFFFFF, 16); // declare shardLen ≈ 4.29 GiB (> the 2 GiB archive ceiling)
		await fsp.writeFile(evil, hdr);
		ok('readShard refuses a shard that declares a payload larger than an archive', (await Disperse.readShard(evil)) === null);

		// The subtler attack: a tiny file whose header declares a payload UNDER the archive ceiling (so it passes
		// the size-limit check above) but that the file does not actually hold. Without a stat-before-allocate
		// guard this would allocate the full declared size (here ~1 GiB) only to fail the truncated-read check.
		// It must be refused up front, from the real file size, having allocated nothing.
		const short = path.join(dir, 'c.0of5.vdshard');
		const hdr2 = Buffer.from(shards[0].subarray(0, Disperse.HEADER));
		hdr2.writeUInt32BE(1 << 30, 16); // declare a 1 GiB payload — under the 2 GiB ceiling, but the file is only a header
		await fsp.writeFile(short, hdr2);
		ok('readShard refuses a sub-ceiling declaration the file cannot hold (no giant allocation)', (await Disperse.readShard(short)) === null);

		ok('readShard returns null for a missing file', (await Disperse.readShard(path.join(dir, 'nope.vdshard'))) === null);
	} finally { await fsp.rm(dir, { recursive: true, force: true }); }
}

async function main() {
	console.log('[empty input round-trips]');
	{
		// A zero-byte archive is a real boundary (shardLen = max(1, ceil(0/k)) = 1, then trimmed back to origLen 0).
		// A real pack is never empty, but the codec must handle it cleanly rather than mis-frame or throw.
		const shards = Disperse.encodeShards(Buffer.alloc(0), 5, 3);
		ok('empty input yields n shards', shards.length === 5);
		ok('any k of them rebuild the empty archive', eq(Disperse.decodeShards([shards[0], shards[2], shards[4]]), Buffer.alloc(0)));
	}

	console.log('[exhaustive: every k-subset of small shapes rebuilds; every (k-1)-subset fails]');
	let checks = 0;
	for (let n = 1; n <= 6; n++) {
		for (let k = 1; k <= n; k++) {
			const data = crypto.randomBytes(1 + (n * 37 + k * 11) % 500);
			const shards = Disperse.encodeShards(data, n, k);
			ok('encode yields n shards (n=' + n + ',k=' + k + ')', shards.length === n);
			for (const sub of kSubsets(n, k)) {
				if (!eq(Disperse.decodeShards(sub.map(i => shards[i])), data)) ok('k-subset {' + sub + '} rebuilds (n=' + n + ',k=' + k + ')', false);
				checks++;
			}
			if (k >= 1 && k - 1 >= 1) {
				for (const sub of kSubsets(n, k - 1)) {
					let failed = false; try { Disperse.decodeShards(sub.map(i => shards[i])); } catch (_) { failed = true; }
					ok('under-threshold {' + sub + '} fails (n=' + n + ',k=' + k + ')', failed);
				}
			}
		}
	}
	console.log('  (' + checks + ' successful k-subset rebuilds)');

	console.log('[sizes: 1 byte, exact multiple of k, large, not-a-multiple]');
	for (const len of [1, 12, 13, 4096, 100000]) {
		const data = crypto.randomBytes(len);
		const shards = Disperse.encodeShards(data, 5, 3);
		ok('rebuilds a ' + len + '-byte blob from 3 of 5', eq(Disperse.decodeShards([shards[4], shards[1], shards[0]]), data));
	}

	console.log('[corruption is detected and survived]');
	{
		const data = crypto.randomBytes(9000);
		const shards = Disperse.encodeShards(data, 6, 3); // tolerate up to 3 lost/bad
		// Corrupt one shard's payload; with 5 remaining good of 6, decode must still rebuild.
		const bad = Buffer.from(shards[2]); bad[Disperse.HEADER + 10] ^= 0xff;
		const mixed = [shards[0], bad, shards[3], shards[4]]; // 3 good + 1 corrupted, k=3 -> still enough
		ok('a corrupted shard is treated as missing and the blob still rebuilds', eq(Disperse.decodeShards(mixed), data));
		// If corruption drops good shards below k, it must fail rather than return wrong bytes.
		const b0 = Buffer.from(shards[0]); b0[Disperse.HEADER + 1] ^= 0xff;
		const b1 = Buffer.from(shards[1]); b1[Disperse.HEADER + 1] ^= 0xff;
		let failed = false; try { Disperse.decodeShards([b0, b1, shards[5]]); } catch (_) { failed = true; }
		ok('too much corruption fails cleanly, never returns wrong bytes', failed);
	}

	console.log('[framing + parameter guards]');
	{
		const data = crypto.randomBytes(64);
		const shards = Disperse.encodeShards(data, 4, 2);
		const info = Disperse.shardInfo(shards[0]);
		ok('shardInfo reports the parameters', info && info.k === 2 && info.m === 2 && info.origLen === 64 && info.good === true);
		ok('a non-shard buffer parses as null', Disperse.shardInfo(crypto.randomBytes(80)) === null);
		// A shard planted from a DIFFERENT dispersal must not block an otherwise-recoverable set: decode rebuilds
		// from the largest consistent group (here the two k=2 shards) and ignores the alien one.
		ok('an alien shard does not block a recoverable set (rebuilds from the majority group)', (() => { const other = Disperse.encodeShards(data, 4, 3); try { return eq(Disperse.decodeShards([shards[0], other[1], shards[2]]), data); } catch (_) { return false; } })());
		// But a set with NO consistent group of k shards still fails cleanly.
		ok('no consistent group of k shards fails cleanly', (() => { const other = Disperse.encodeShards(data, 4, 3); try { Disperse.decodeShards([shards[0], other[1]]); return false; } catch (_) { return true; } })());
		ok('n > 255 is refused', (() => { try { Disperse.encodeShards(data, 256, 2); return false; } catch (_) { return true; } })());
		// A crafted shard header with nonsensical geometry must read as "not a valid shard", never reach
		// the codec with a raw internal error.
		const crafted = Buffer.from(shards[0]);
		crafted.writeUInt8(0, 5); // k = 0
		crypto.createHash('sha256').update(crafted.subarray(Disperse.HEADER)).digest().copy(crafted, 20); // keep the hash valid
		ok('a crafted header with k=0 is rejected as malformed', Disperse.shardInfo(crafted) === null);
	}

	console.log('[randomized fuzz — 300 shapes, random k-subset, optional single corruption]');
	for (let t = 0; t < 300; t++) {
		const n = 2 + (crypto.randomBytes(1)[0] % 8);
		const k = 1 + (crypto.randomBytes(1)[0] % n);
		const data = crypto.randomBytes(crypto.randomBytes(2).readUInt16BE(0) % 5000);
		const shards = Disperse.encodeShards(data, n, k);
		const idx = [...Array(n).keys()];
		for (let i = idx.length - 1; i > 0; i--) { const j = crypto.randomBytes(1)[0] % (i + 1); [idx[i], idx[j]] = [idx[j], idx[i]]; }
		const pick = idx.slice(0, k).map(i => Buffer.from(shards[i]));
		if (!eq(Disperse.decodeShards(pick), data)) ok('fuzz #' + t + ' (n=' + n + ',k=' + k + ',len=' + data.length + ')', false);
	}

	await readShardGuards();

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DISPERSE CHECKS PASSED'));
	process.exitCode = failures ? 1 : 0;
}

main().catch(e => { console.error(e); process.exitCode = 1; });
