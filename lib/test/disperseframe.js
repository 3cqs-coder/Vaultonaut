'use strict';
// lib/test/disperseframe.js — the dispersal shard FRAMING. Two integrity properties the codec depends on:
//   (1) the SHA-256 covers the self-describing header (not just the payload), so a flipped index/geometry byte is
//       rejected instead of silently placing the shard in the wrong slot and rebuilding wrong bytes; and
//   (2) each dispersal carries a random id, so two separate dispersals of coincidentally equal length are never
//       combined into a blended, corrupt rebuild.
// It also confirms v1 shards (payload-only hash, no id) still READ, so a set dispersed by an older build rebuilds.
//
// Run:  node lib/test/disperseframe.js

const crypto = require('crypto');
const Disperse = require('../Disperse');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Reproduce the OLD v1 frame (payload-only hash, 52-byte header, no dispersal id) to prove backward-compatible read.
function frameV1(k, m, idx, origLen, y) {
	const head = Buffer.alloc(52);
	Buffer.from('VDSH', 'ascii').copy(head, 0);
	head.writeUInt8(1, 4); head.writeUInt8(k, 5); head.writeUInt8(m, 6); head.writeUInt8(idx, 7);
	head.writeBigUInt64BE(BigInt(origLen), 8); head.writeUInt32BE(y.length, 16);
	crypto.createHash('sha256').update(y).digest().copy(head, 20);
	return Buffer.concat([head, y]);
}

function main() {
	const A = crypto.randomBytes(3000);

	// (1) header-tamper detection: flip the index byte of one shard; its identity hash must now fail.
	const shards = Disperse.encodeShards(A, 5, 3); // n=5, k=3
	const tampered = Buffer.from(shards[0]); tampered[7] ^= 0x01; // flip a bit in the idx byte (offset 7)
	ok('a valid v2 shard reports good', Disperse.shardInfo(shards[0]).good === true);
	ok('flipping the index byte is caught (identity is hashed, not just the payload)', Disperse.shardInfo(tampered).good === false);
	// The tampered shard is skipped; the remaining k good shards still rebuild the original exactly.
	const rebuilt = Disperse.decodeShards([tampered, shards[1], shards[2], shards[3]]);
	ok('the original rebuilds from the untampered shards', rebuilt.equals(A));

	// (2) two equal-length dispersals must not merge: mixing their shards rebuilds ONE cleanly, never a blend.
	const B = crypto.randomBytes(3000); // same length as A → identical geometry, but a different dispersal id
	const sa = Disperse.encodeShards(A, 5, 3), sb = Disperse.encodeShards(B, 5, 3);
	ok('the two dispersals have different ids', Disperse.shardInfo(sa[0]).id !== Disperse.shardInfo(sb[0]).id);
	const mixed = Disperse.decodeShards([sa[0], sa[1], sa[2], sb[3], sb[4]]); // 3 from A (a full set), 2 from B
	ok('a mix of two dispersals rebuilds one of them exactly, not a corrupt blend', mixed.equals(A) || mixed.equals(B));
	ok('specifically the majority (A) group wins', mixed.equals(A));

	// (3) backward compatibility: v1 shards (no id, payload-only hash) still read and rebuild.
	const k = 3, shardLen = Math.ceil(A.length / k);
	const v1 = [];
	for (let i = 0; i < k; i++) { const s = Buffer.alloc(shardLen); A.copy(s, 0, i * shardLen, Math.min((i + 1) * shardLen, A.length)); v1.push(frameV1(k, 0, i, A.length, s)); }
	ok('a v1 shard reads as good with a null id', Disperse.shardInfo(v1[0]).good === true && Disperse.shardInfo(v1[0]).id === null);
	ok('a v1-dispersed set still rebuilds the original', Disperse.decodeShards(v1).equals(A));

	// (4) refuse forward: shards written by a NEWER format (our magic, a version above what this build writes) must
	// give a clear "made by a newer version — update" error, not the generic "no readable shards" corruption message.
	const newer = sa.map(b => { const c = Buffer.from(b); c.writeUInt8(Disperse.VERSION + 1, 4); return c; }); // bump the version byte past what we support
	ok('newerShardVersion flags a bumped-version shard', Disperse.newerShardVersion(newer[0]) === Disperse.VERSION + 1);
	let newerErr = null; try { Disperse.decodeShards(newer); } catch (e) { newerErr = e; }
	ok('a newer-format shard set is refused with an "update" message', !!newerErr && /newer version/i.test(newerErr.message));
	let corruptErr = null; try { Disperse.decodeShards([crypto.randomBytes(200)]); } catch (e) { corruptErr = e; }
	ok('genuinely unreadable shards still say "no readable shards" (not the newer-version message)', !!corruptErr && /no readable shards/i.test(corruptErr.message));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DISPERSE-FRAME CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
