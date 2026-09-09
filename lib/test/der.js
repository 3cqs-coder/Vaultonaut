'use strict';
// lib/test/der.js — locks the shared ASN.1/DER encoders (lib/Der.js) so the certificate, timestamp-request, and
// token-fixture builders that all depend on them can never drift. Checks each primitive against a known-correct
// DER encoding, and the two INTEGER forms that must stay distinct (canonical strips leading zeros; the flexible
// request form does not).
//
// Run:  node lib/test/der.js   (no engine, no network)

const Der = require('../Der');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const hex = (b) => Buffer.from(b).toString('hex');

function main() {
	ok('short length', hex(Der.len(5)) === '05');
	ok('long length (>= 0x80)', hex(Der.len(0x80)) === '8180' && hex(Der.len(256)) === '820100');
	ok('tlv wraps tag+len+content', hex(Der.tlv(0x04, Buffer.from([1, 2, 3]))) === '04030102 03'.replace(/ /g, ''));
	ok('SEQUENCE', hex(Der.seq(Der.NULL)) === '30020500');
	ok('SET', hex(Der.set(Der.NULL)) === '31020500');
	ok('context [0] constructed', hex(Der.ctx(0, Der.NULL)) === 'a0020500');
	ok('OID sha256', hex(Der.oid('2.16.840.1.101.3.4.2.1')) === '0609608648016503040201');
	ok('OID rsaEncryption', hex(Der.oid('1.2.840.113549.1.1.1')) === '06092a864886f70d010101');
	ok('NULL', hex(Der.NULL) === '0500' && hex(Der.nullDer()) === '0500');
	ok('BOOLEAN true/false', hex(Der.bool(true)) === '0101ff' && hex(Der.bool(false)) === '010100');
	ok('OCTET STRING', hex(Der.octet(Buffer.from([0xaa, 0xbb]))) === '0402aabb');
	ok('BIT STRING (0 unused bits)', hex(Der.bitString(Buffer.from([0xff]))) === '030200ff');
	ok('UTF8String', hex(Der.utf8('AB')) === '0c024142');

	// INTEGER — canonical strips a redundant leading zero, and adds one only to stay non-negative.
	ok('canonical integer strips leading zeros', hex(Der.integer(Buffer.from([0x00, 0x00, 0x2a]))) === '02012a');
	ok('canonical integer keeps a zero to stay positive', hex(Der.integer(Buffer.from([0x80]))) === '02020080');
	ok('smallInt encodes a number minimally', hex(Der.smallInt(1)) === '020101' && hex(Der.smallInt(256)) === '02020100');
	ok('smallInt keeps a value positive', hex(Der.smallInt(128)) === '02020080');
	// The flexible request form does NOT strip leading zeros (historical timestamp-request encoding, preserved).
	ok('intFlexible does not strip leading zeros', hex(Der.intFlexible(Buffer.from([0x00, 0x2a]))) === '0202002a');
	ok('intFlexible on a small number', hex(Der.intFlexible(1)) === '020101');

	// ---- parsers: round-trip against the encoders, and fail-closed on malformed input ----
	const seqBuf = Der.seq(Der.integer(Buffer.from([0x2a])), Der.octet(Buffer.from([0xaa, 0xbb])));
	const top = Der.readTLV(seqBuf, 0);
	ok('readTLV reads the SEQUENCE tag and span', top.tag === 0x30 && top.end === seqBuf.length);
	const kids = Der.children(seqBuf, top.start, top.end);
	ok('children returns the two inner elements', kids.length === 2 && kids[0].tag === 0x02 && kids[1].tag === 0x04);
	ok('contentOf returns an element\'s value bytes', hex(Der.contentOf(seqBuf, kids[1])) === 'aabb');
	ok('decodeOid round-trips the encoded OID', Der.decodeOid(Der.contentOf(Der.oid('2.16.840.1.101.3.4.2.1'), Der.readTLV(Der.oid('2.16.840.1.101.3.4.2.1'), 0))) === '2.16.840.1.101.3.4.2.1');
	// Fail-closed: indefinite length, an over-long length claim, trailing bytes, and a child overrunning its parent.
	ok('readTLV rejects indefinite length', (() => { try { Der.readTLV(Buffer.from([0x30, 0x80]), 0); return false; } catch (_) { return true; } })());
	ok('readTLV rejects a length that runs past the buffer', (() => { try { Der.readTLV(Buffer.from([0x04, 0x05, 0x01]), 0); return false; } catch (_) { return true; } })());
	ok('children rejects trailing bytes in a span', (() => { try { Der.children(Buffer.from([0x05, 0x00, 0xff]), 0, 3); return false; } catch (_) { return true; } })());

	// DER length minimality: the shortest encoding is the only legal one, so a malleable re-encoding of a signed
	// token cannot slip through. Long form for a value that fits short form (< 0x80), and a long form carrying a
	// leading zero byte, are both rejected — while a legitimately minimal long form still parses.
	ok('readTLV rejects long form used for a short value (0x81 0x05)', (() => { try { Der.readTLV(Buffer.from([0x04, 0x81, 0x05]), 0); return false; } catch (_) { return true; } })());
	ok('readTLV rejects a long form with a leading zero byte (0x82 0x00 0x05)', (() => { try { Der.readTLV(Buffer.from([0x04, 0x82, 0x00, 0x05]), 0); return false; } catch (_) { return true; } })());
	ok('readTLV still accepts a minimal long form (length 128 => 0x81 0x80)', (() => { const b = Der.tlv(0x04, Buffer.alloc(128)); const t = Der.readTLV(b, 0); return t.len === 128 && t.end === b.length; })());

	// decodeOid is used as a structural gate ("is this element a SignedData?"), so a malformed OID must never
	// decode to a value that could accidentally equal a real one. Empty content and a truncated final arc both
	// return '' — a sentinel no real dotted OID can equal. And a hostile arc wider than 32 bits must accumulate
	// exactly (BigInt), never wrap to a smaller or negative number the old shift-based decoder would have produced.
	ok('decodeOid refuses empty content', Der.decodeOid(Buffer.alloc(0)) === '' && Der.decodeOid(null) === '');
	ok('decodeOid refuses a truncated final arc', Der.decodeOid(Buffer.from([0x2a, 0x81])) === '');
	{
		const b128 = (v) => { const s = [Number(v & 0x7fn)]; v >>= 7n; while (v > 0n) { s.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; } return s; };
		const big = (1n << 40n) + 123456789n; // 40-bit arc — well past what a 32-bit accumulator can hold
		const content = Buffer.from([0x2a, ...b128(big)]); // 0x2a = 42 = 40*1 + 2, i.e. arcs "1.2"
		ok('decodeOid accumulates a >32-bit arc without overflow', Der.decodeOid(content) === '1.2.' + big.toString());
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DER CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
