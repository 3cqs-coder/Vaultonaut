'use strict';
// lib/Emergency.js — OPTIONAL emergency / inheritance access (a dead-man's switch). The honest pattern (as
// used by modern password managers): the owner SEALS the vault's READ capability to a trusted contact's public
// key NOW, so only that contact's private key can ever open it. A timer only gates the MOMENT the sealed blob
// is handed to the contact; anyone holding the blob before then holds ciphertext they cannot open. This module
// is the crypto core: a contact keypair (the contact generates it and shares only the PUBLIC half), and an
// anonymous sealed box built entirely on Node's built-in crypto — no third-party dependency. It seals ONLY a
// read capability, so the heir can read but can never rotate keys, delete data, or evict the owner (that is
// enforced by the capability, not by trust).
//
// The sealed blob can outlive the owner by years, so it is the one place harvest-now-decrypt-later matters: a
// future quantum computer could break a classical key-exchange recorded today. So the seal uses a POST-QUANTUM
// HYBRID key exchange — X-Wing (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem) — which stays secure as long
// as EITHER X25519 or ML-KEM-768 is unbroken. ML-KEM is Node's built-in (>= 24.7); on an older runtime the seal
// falls back to classical X25519-only, and every blob is versioned so an already-armed seal always still opens.
//
// Sealed-box shape (HPKE base-mode in spirit): a hybrid KEM encapsulates a one-time shared secret to the
// recipient; HKDF derives an AEAD key bound to a version/context string; ChaCha20-Poly1305 encrypts under it
// with a zero nonce (safe because the key is unique per message — a fresh KEM encapsulation each time). No
// sender identity is revealed.

const crypto = require('crypto');

const INFO = Buffer.from('vault:emergency:v1');    // v1 (classical) context binding (HKDF info + AEAD AAD) — do not change
const INFO_V2 = Buffer.from('vault:emergency:v2'); // v2 (post-quantum hybrid) context binding
// DOMAIN SEPARATION: the same seal is reused for several distinct purposes (an emergency read capability, a team
// member's sealed capability, an owner-recovery Shamir share, a portable share bundle). Binding a per-USE label
// into the HKDF info and the AEAD AAD makes a blob minted for one purpose fail to open under another, so a blob
// can never be relocated across contexts even if a future format made two of them structurally interchangeable.
// An empty context reproduces the original bytes exactly, so an already-armed emergency seal still opens.
function bindCtx(base, context) { return context ? Buffer.concat([base, Buffer.from(':' + context)]) : base; }
const XWING_LABEL = Buffer.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]); // the X-Wing combiner label:  \.//^\
// Built-in ML-KEM (FIPS 203) lands in Node's crypto in 24.7+. When present, new keypairs and seals are the
// post-quantum hybrid; otherwise they are classical X25519. Detected once so the choice is consistent.
const PQ = typeof crypto.encapsulate === 'function' && typeof crypto.decapsulate === 'function';

// ── serialization ─────────────────────────────────────────────────────────────
function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
// A versioned, length-prefixed container: version byte, then each part as u16-length + bytes.
function packParts(ver, parts) { const out = [Buffer.from([ver])]; for (const p of parts) { out.push(u16(p.length), p); } return Buffer.concat(out); }
// Read exactly `count` length-prefixed parts starting after the version byte; returns [parts, offsetAfter].
function readParts(buf, count) {
	let o = 1; const out = [];
	for (let i = 0; i < count; i++) {
		// Validate each length prefix and its payload stay within the buffer, so a truncated or malformed pasted
		// key/blob fails with a clear domain error instead of a raw RangeError (readUInt16BE past the end) or a
		// silently short subarray that would surface as a confusing decryption failure later.
		if (o + 2 > buf.length) throw new Error('This value is not a valid emergency key or sealed file (it is truncated).');
		const len = buf.readUInt16BE(o); o += 2;
		if (o + len > buf.length) throw new Error('This value is not a valid emergency key or sealed file (it is truncated).');
		out.push(buf.subarray(o, o + len)); o += len;
	}
	return [out, o];
}
// Read exactly `count` parts AND require they consume the whole buffer — for a packed KEY, which is nothing but its
// parts (unlike a sealed blob, whose tail after the parts is the tag + ciphertext). Rejecting trailing bytes closes a
// malleability gap where a key with junk appended would validate as "the same" key under two different encodings.
function readPartsExact(buf, count) {
	const [parts, off] = readParts(buf, count);
	if (off !== buf.length) throw new Error('This value is not a valid emergency key (it has unexpected trailing data).');
	return parts;
}
// A v2 (hybrid) key or blob is tagged with a leading 0x02. A v1 X25519 SPKI/PKCS8 DER begins with 0x30 (ASN.1
// SEQUENCE), and a v1 sealed blob begins with the ephemeral-key length (44 = 0x2c), so 0x02 is unambiguous.
function isV2(buf) { return buf.length > 0 && buf[0] === 0x02; }
// Forward ceiling for a packed key/blob. The packed (v2) format tags its version in the leading byte (0x02); the
// classical v1 formats begin with a structural marker well above this range (a bare DER key with 0x30, a v1 sealed
// blob with its 0x2c ephemeral-key length). So a leading byte in 0x03..0x0f is a PACKED version this build does not
// implement — refuse it with a clear "update" message instead of misrouting it into the v1 path, where it would fail
// with a confusing low-level crypto error. Anything at or above 0x10 is a v1 structural start and is left to v1.
function assertKnownFormat(buf) {
	if (buf && buf.length && buf[0] > 0x02 && buf[0] < 0x10) throw new Error('This emergency key or sealed access was made by a newer version of the app — update to use it.');
}
// The raw 32-byte X25519 key is the tail of its 44-byte SPKI DER (a fixed 12-byte prefix + the 32-byte key).
function x25519Raw(spkiDer) { return spkiDer.subarray(spkiDer.length - 32); }

const spki = (k) => k.export({ type: 'spki', format: 'der' });
const pkcs8 = (k) => k.export({ type: 'pkcs8', format: 'der' });
function importPub(der) { return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }); }
function importPriv(der) { return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }); }

// The hybrid combiner: one 32-byte shared secret bound to BOTH KEM shared secrets AND the X25519 ciphertext and
// public key, so a passive attacker who breaks only one primitive still cannot recover it. This is an APP-INTERNAL
// construction, not a wire-compatible X-Wing: seal and open use this exact function, so the term order and label only
// have to be self-consistent, and they are frozen here so every previously sealed blob keeps opening. (The X-Wing
// draft places its label first; matching it is unnecessary because these blobs are only ever opened by this tool, and
// changing the order now would break existing seals.) The order and label must therefore never change.
function xwingCombine(ssM, ssX, ctXraw, pkXraw) {
	return crypto.createHash('sha3-256').update(ssM).update(ssX).update(ctXraw).update(pkXraw).update(XWING_LABEL).digest();
}

// A contact keypair. The contact generates it and shares ONLY the public half. Hybrid (X25519 + ML-KEM-768)
// when the runtime supports ML-KEM, else classical X25519 (a v1 bare-DER key that stays fully compatible).
function generateContactKeypair() {
	const x = crypto.generateKeyPairSync('x25519');
	if (!PQ) return { publicKey: spki(x.publicKey).toString('base64'), privateKey: pkcs8(x.privateKey).toString('base64') };
	const m = crypto.generateKeyPairSync('ml-kem-768');
	return {
		publicKey: packParts(0x02, [spki(x.publicKey), spki(m.publicKey)]).toString('base64'),
		privateKey: packParts(0x02, [pkcs8(x.privateKey), pkcs8(m.privateKey)]).toString('base64'),
	};
}

// Seal a message (the read capability) to a contact's public key. A hybrid (v2) key produces a post-quantum
// sealed blob; a classical (v1) key produces a classical one — so an old contact key keeps working.
function seal(recipientPubB64, message, context = '') {
	const pub = Buffer.from(String(recipientPubB64), 'base64');
	assertKnownFormat(pub);
	if (!isV2(pub)) return sealV1(recipientPubB64, message, context);
	if (!PQ) throw new Error('This contact key uses post-quantum encryption, which needs Node 24.7 or newer to seal to on this computer. Update Node, or have the contact generate a classical keypair.');
	const [xDer, mDer] = readPartsExact(pub, 2);
	const recX = importPub(xDer), recM = importPub(mDer);
	const { sharedKey: ssM, ciphertext: ctM } = crypto.encapsulate(recM);  // ML-KEM encapsulation
	const eph = crypto.generateKeyPairSync('x25519');                       // fresh X25519 ephemeral
	const ctXspki = spki(eph.publicKey);
	const ssX = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recX });
	const ss = xwingCombine(ssM, ssX, x25519Raw(ctXspki), x25519Raw(xDer));
	const info = bindCtx(INFO_V2, context);
	const key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.alloc(0), info, 32));
	const iv = Buffer.alloc(12, 0); // key is unique per message (fresh ML-KEM encaps + fresh ephemeral) -> a fixed nonce is safe
	const c = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
	c.setAAD(info);
	const ct = Buffer.concat([c.update(Buffer.from(String(message), 'utf8')), c.final()]);
	return Buffer.concat([packParts(0x02, [ctXspki, ctM]), c.getAuthTag(), ct]).toString('base64');
}

// Open a sealed blob with the contact's private key. Returns the message string, or throws if the key is wrong
// or the blob was altered (the AEAD tag fails closed). Handles both hybrid (v2) and classical (v1) blobs.
function open(contactPrivB64, sealedB64, context = '') {
	const buf = Buffer.from(String(sealedB64), 'base64');
	assertKnownFormat(buf);
	if (!isV2(buf)) return openV1(contactPrivB64, sealedB64, context);
	if (!PQ) throw new Error('This sealed access uses post-quantum encryption and needs Node 24.7 or newer to open. Update Node, then open it again.');
	const [[ctXspki, ctM], off] = readParts(buf, 2);
	if (off + 16 > buf.length) throw new Error('This sealed access data is incomplete or corrupt (truncated within its authentication tag).'); // friendly message, matching readParts/openV1, instead of a raw crypto tag-length error
	const tag = buf.subarray(off, off + 16);
	const ct = buf.subarray(off + 16);
	const priv = Buffer.from(String(contactPrivB64), 'base64');
	const [xPrivDer, mPrivDer] = readPartsExact(priv, 2);
	const xPriv = importPriv(xPrivDer), mPriv = importPriv(mPrivDer);
	const ssM = crypto.decapsulate(mPriv, ctM);
	const ssX = crypto.diffieHellman({ privateKey: xPriv, publicKey: importPub(ctXspki) });
	const pkXraw = x25519Raw(spki(crypto.createPublicKey(xPriv)));
	const ss = xwingCombine(ssM, ssX, x25519Raw(ctXspki), pkXraw);
	const info = bindCtx(INFO_V2, context);
	const key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.alloc(0), info, 32));
	const d = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.alloc(12, 0), { authTagLength: 16 });
	d.setAAD(info); d.setAuthTag(tag);
	return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// ── v1 (classical X25519) — kept unchanged so contact keys and sealed blobs created before the hybrid open ──
//   wire format: epkLen(1) || epk(spki) || tag(16) || ciphertext
function sealV1(recipientPubB64, message, context = '') {
	const recipient = importPub(Buffer.from(String(recipientPubB64), 'base64'));
	const { publicKey: epk, privateKey: esk } = crypto.generateKeyPairSync('x25519');
	const shared = crypto.diffieHellman({ privateKey: esk, publicKey: recipient });
	const epkRaw = spki(epk), recRaw = spki(recipient);
	const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), bindCtx(Buffer.concat([INFO, epkRaw, recRaw]), context), 32));
	const c = crypto.createCipheriv('chacha20-poly1305', key, Buffer.alloc(12, 0), { authTagLength: 16 });
	c.setAAD(bindCtx(INFO, context));
	const ct = Buffer.concat([c.update(Buffer.from(String(message), 'utf8')), c.final()]);
	return Buffer.concat([Buffer.from([epkRaw.length]), epkRaw, c.getAuthTag(), ct]).toString('base64');
}
function openV1(contactPrivB64, sealedB64, context = '') {
	const priv = importPriv(Buffer.from(String(contactPrivB64), 'base64'));
	const buf = Buffer.from(String(sealedB64), 'base64');
	// Validate the length-prefixed layout before slicing, so a truncated or garbage bundle fails with a clean
	// domain error instead of a raw crypto error — matching the bounds checks the v2 path already performs.
	if (buf.length < 1) throw new Error('This value is not a valid sealed file (it is empty or malformed).');
	let o = 0; const epkLen = buf[o]; o += 1;
	if (o + epkLen + 16 > buf.length) throw new Error('This value is not a valid sealed file (it is truncated).');
	const epkRaw = buf.subarray(o, o + epkLen); o += epkLen;
	const tag = buf.subarray(o, o + 16); o += 16;
	const ct = buf.subarray(o);
	const epk = importPub(epkRaw);
	const shared = crypto.diffieHellman({ privateKey: priv, publicKey: epk });
	const recRaw = spki(crypto.createPublicKey(priv));
	const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), bindCtx(Buffer.concat([INFO, epkRaw, recRaw]), context), 32));
	const d = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.alloc(12, 0), { authTagLength: 16 });
	d.setAAD(bindCtx(INFO, context)); d.setAuthTag(tag);
	return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// Whether this runtime seals with the post-quantum hybrid (true) or classical X25519 (false).
function isPostQuantum() { return PQ; }

module.exports = { generateContactKeypair, seal, open, isPostQuantum };
