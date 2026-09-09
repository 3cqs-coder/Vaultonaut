'use strict';
// lib/Der.js — the minimal ASN.1 / DER codec shared by everything in the app that reads or writes DER: the
// self-signed TLS certificate builder (Cert.js), the RFC 3161 timestamp request/token verifier and the token test
// fixture (Attest.js, test/_tsa.js). One canonical copy so the encoders AND the parsers can never drift apart.
// Pure Node (Buffers only) — server-side, cross-platform, no dependencies.
//
// The one deliberate exception is the vendored verify-bundle.js: it is COPIED into every proof bundle and must run
// standalone with nothing but stock Node, so it keeps its own self-contained copy of these helpers on purpose. The
// verifybundleparity test keeps that copy in step with this module.
//
// ENCODERS: every function returns a Buffer; lengths are DER long-form for >= 0x80; values are minimal where a
// canonical form is required (see `integer`). PARSERS are fail-closed and bounds/depth-checked (see below).

// Definite length. Uses Math.floor (not a 32-bit shift) so a length beyond 2^31 still encodes correctly for a
// large certificate or token.
function len(n) {
	if (n < 0x80) return Buffer.from([n]);
	const bytes = [];
	while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
	return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, content) { return Buffer.concat([Buffer.from([tag]), len(content.length), content]); }

const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const set = (...parts) => tlv(0x31, Buffer.concat(parts));
const ctx = (n, ...parts) => tlv(0xa0 | n, Buffer.concat(parts)); // [n] constructed context-tagged element

// Canonical INTEGER from raw big-endian bytes: strip leading zeros to the minimal form, then keep it non-negative
// (a leading 0x00 only when the top bit would otherwise make it negative). Used for serial numbers and any value
// that must be minimally encoded.
function integer(buf) {
	let b = buf, i = 0;
	while (i < b.length - 1 && b[i] === 0) i++;
	b = b.subarray(i);
	if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
	return tlv(0x02, b);
}
// INTEGER from a non-negative JS number (multi-byte), minimally encoded and kept non-negative.
function smallInt(n) {
	const b = []; let x = n;
	do { b.unshift(x & 0xff); x = Math.floor(x / 256); } while (x > 0);
	if (b[0] & 0x80) b.unshift(0);
	return tlv(0x02, Buffer.from(b));
}
// INTEGER from either a small number (single byte) or a buffer, WITHOUT stripping leading zeros — the historical
// shape the timestamp-request builder uses. Kept distinct from `integer` so that path's bytes are unchanged.
function intFlexible(nOrBuf) {
	let b = Buffer.isBuffer(nOrBuf) ? nOrBuf : Buffer.from([nOrBuf]);
	if (b.length && (b[0] & 0x80)) b = Buffer.concat([Buffer.from([0]), b]);
	if (b.length === 0) b = Buffer.from([0]);
	return tlv(0x02, b);
}

function oid(dotted) {
	const parts = dotted.split('.').map(Number);
	const body = [40 * parts[0] + parts[1]];
	for (let i = 2; i < parts.length; i++) {
		let v = parts[i];
		const stack = [v & 0x7f]; v = Math.floor(v / 128);
		while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
		body.push(...stack);
	}
	return tlv(0x06, Buffer.from(body));
}

const NULL = Buffer.from([0x05, 0x00]);
const nullDer = () => NULL; // for call sites that expect a function
const octet = (buf) => tlv(0x04, buf);
const bitString = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0x00]), buf])); // 0 unused bits
const bool = (v) => Buffer.from([0x01, 0x01, v ? 0xff : 0x00]);
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const ia5 = (s) => tlv(0x16, Buffer.from(s, 'ascii'));

// ASN.1 time types (always UTC, seconds precision, "Z"). utcTime is the two-digit-year form; generalizedTime the
// four-digit form. `time` picks per the X.509 rule (UTCTime before 2050, else GeneralizedTime).
const pad2 = (n) => String(n).padStart(2, '0');
const timeCore = (d) => pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate()) + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + 'Z';
const utcTime = (d) => tlv(0x17, Buffer.from(pad2(d.getUTCFullYear() % 100) + timeCore(d), 'ascii'));
const generalizedTime = (d) => tlv(0x18, Buffer.from(String(d.getUTCFullYear()) + timeCore(d), 'ascii'));
const time = (d) => d.getUTCFullYear() < 2050 ? utcTime(d) : generalizedTime(d);

// ---- parsers (fail-closed: every bound is checked and every malformed shape throws) ----
// Read one TLV at `offset`. Returns { tag, len, hlen, start, end }. Rejects indefinite length, an over-4-byte
// length claim, and any length that runs past the buffer.
function readTLV(buf, offset) {
	if (offset < 0 || offset + 2 > buf.length) throw new Error('DER: truncated element');
	const tag = buf[offset];
	let p = offset + 1;
	let len = buf[p++];
	if (len === 0x80) throw new Error('DER: indefinite length not allowed');
	if (len & 0x80) {
		const num = len & 0x7f;
		if (num > 4) throw new Error('DER: length too large'); // >4 GiB claims are never legitimate here
		if (p + num > buf.length) throw new Error('DER: truncated length');
		// DER requires the SHORTEST length encoding: long form must carry no leading zero byte. This rejects
		// non-minimal encodings (e.g. 0x82 0x00 0x05) that BER would allow — the same structure must have exactly
		// one byte sequence, so a malleable re-encoding of a signed token cannot slip through the parser.
		if (buf[p] === 0) throw new Error('DER: non-minimal length (leading zero byte)');
		len = 0;
		for (let i = 0; i < num; i++) len = (len * 256) + buf[p++]; // multiply (not <<) so it can't wrap negative
		// ...and long form must not be used at all for a value that fits short form (< 0x80).
		if (len < 0x80) throw new Error('DER: non-minimal length (long form for a short value)');
	}
	const end = p + len;
	if (end > buf.length || end < p) throw new Error('DER: length exceeds buffer');
	return { tag, len, hlen: p - offset, start: p, end };
}
// The children TLVs of a constructed value spanning [start, end). It reads one level (no recursion), and every
// caller walks deeper structure with its own explicit reads, so there is no structural recursion to overflow the
// stack; the depth of a nested value is only followed as far as the calling code descends. It must consume the
// span exactly (no trailing bytes), and each child must stay within the parent.
function children(buf, start, end) {
	const out = [];
	let p = start;
	while (p < end) { const t = readTLV(buf, p); if (t.end > end) throw new Error('DER: child overruns parent'); out.push(t); p = t.end; }
	if (p !== end) throw new Error('DER: trailing bytes');
	return out;
}
const contentOf = (buf, tlvObj) => buf.subarray(tlvObj.start, tlvObj.end);
// Decode a DER OID's content bytes into a dotted string. OID equality is used as a structural gate (e.g. "is this a
// SignedData?"), so a malformed OID must never accidentally decode to a real one: an empty content or a truncated
// final arc (a continuation byte with the high bit still set) returns '' — a value no real dotted OID can equal.
// Arcs are accumulated with BigInt so a hostile arc longer than 32 bits can't overflow to a wrong (or negative) value.
function decodeOid(bytes) {
	if (!bytes || bytes.length === 0) return '';
	// Decode EVERY sub-identifier as a full base-128 value (the first one can span multiple bytes too, so it is not
	// just bytes[0]). Reject a non-minimal encoding — a sub-identifier whose leading byte is 0x80 carries a redundant
	// leading zero group — so a BER-malleable OID cannot decode to the same dotted string as its canonical form and
	// slip past a content-type/algorithm gate. Arcs use BigInt so a hostile >32-bit arc can't overflow.
	const subs = [];
	let v = 0n, inSub = false;
	for (let i = 0; i < bytes.length; i++) {
		const b = bytes[i];
		if (!inSub) { if (b === 0x80) return ''; inSub = true; } // leading 0x80 = non-minimal sub-identifier
		v = (v << 7n) | BigInt(b & 0x7f);
		if (!(b & 0x80)) { subs.push(v); v = 0n; inSub = false; }
	}
	if (inSub) return ''; // last sub-identifier truncated (continuation bit still set)
	// Split the first sub-identifier (z) into the first two arcs: z = 40*X + Y, with X in {0,1,2} and Y unbounded
	// once X is 2. The single-byte formula floor(z/40),z%40 is only correct for z < 80.
	const z = subs[0];
	let x, y;
	if (z < 40n) { x = 0n; y = z; }
	else if (z < 80n) { x = 1n; y = z - 40n; }
	else { x = 2n; y = z - 80n; }
	return [x.toString(), y.toString(), ...subs.slice(1).map(s => s.toString())].join('.');
}

module.exports = { len, tlv, seq, set, ctx, integer, smallInt, intFlexible, oid, NULL, nullDer, octet, bitString, bool, utf8, ia5, utcTime, generalizedTime, time, readTLV, children, contentOf, decodeOid };
