'use strict';
// lib/Attest.js — provable, timestamped attestation of a vault's signed state (RFC 3161 trusted
// timestamps). It takes a digest that binds a vault (its identity), its exact contents (the Merkle
// root), and its version (the counter), asks a Time-Stamping Authority (TSA) to sign that digest
// together with the current time, and returns a token that anyone can later use to prove "this vault
// existed in exactly this state no later than this moment." Only the digest ever leaves the machine —
// never the vault, its names, or its contents — so the proof is privacy-preserving by construction.
//
// The request and the binding check (does the token really certify OUR digest?) are done with Node's
// own crypto and a tiny ASN.1/DER reader here — no external dependency. Verifying the TSA's signature
// and certificate chain in full is optional and, when wanted, uses the platform's certificate tooling;
// the binding check plus the token's own signed time is the core, dependency-free proof.
//
//   buildRequest(digest, { hashOid, nonce, certReq }) -> Buffer            (a DER TimeStampReq)
//   parseResponse(respDer)                            -> { status, token } (token = DER TimeStampToken)
//   readToken(tokenDer)                               -> { imprintHex, hashOid, genTime, serialHex }
//   timestamp(digest, { tsaUrl, timeoutMs })          -> { token, genTime, serialHex, tsaUrl } (async)
//   verifyBinding(tokenDer, digest)                   -> { ok, genTime, serialHex }
//
// digest is a Buffer of the hash (SHA-256 by default). Everything is fail-closed: a malformed token,
// a status that is not "granted", or an imprint that does not match our digest is treated as no proof.

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const tls = require('tls');
const { URL } = require('url');
const Der = require('./Der');

// The default public Time-Stamping Authorities, tried IN ORDER until one returns a token that verifies — so a
// single authority being unreachable (the network can't route to it), down, rate-limited, or blocked by a
// firewall never fails an attestation, which was a real single-point-of-failure before. Each is a well-known
// operator whose root ships in the platform's trusted-root store (the same Mozilla CA set Node bundles), so its
// token chains to a trusted root and verifies anywhere with no extra configuration. Listing several can only
// improve reachability, never weaken trust: EVERY token is fully verified (signature + chain to a trusted root
// + our exact digest) before it is ever used, so a bad or untrusted reply is skipped, not accepted. DigiCert is
// reached over HTTPS; the HTTP fallbacks are safe because a timestamp token's authenticity is CRYPTOGRAPHIC — a
// network attacker cannot forge or substitute a token that binds our digest and nonce and chains to a trusted
// root — so the verification, not the transport, is what protects it. A different authority can still be given
// per call (then no fallback is used); one whose root is not publicly trusted needs its root supplied as an
// extra trust anchor to verify.
const DEFAULT_TSAS = [
	'https://timestamp.digicert.com',
	'http://timestamp.sectigo.com',
	'http://timestamp.globalsign.com/tsa/r6advanced1'
];
const DEFAULT_TSA = DEFAULT_TSAS[0]; // the primary authority, kept for callers/tests that name a single default
const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

// ---- Minimal DER encoding (only what a TimeStampReq needs) ----

// The DER ENCODERS are shared via lib/Der.js (one canonical copy across the cert / timestamp-request / token
// builders). encInt keeps its historical non-stripping shape (Der.intFlexible) so the request bytes are unchanged.
const tlv = Der.tlv, encSeq = Der.seq, encOctet = Der.octet, encNull = Der.nullDer, encBool = Der.bool, encOid = Der.oid, encInt = Der.intFlexible;

// Build a DER TimeStampReq over `digest` (a Buffer). version=1; messageImprint = { AlgorithmId(hash),
// OCTET STRING(digest) }; a random nonce ties the response to this request; certReq=TRUE asks the TSA
// to embed its certificate so the token is verifiable on its own later.
function buildRequest(digest, { hashOid = SHA256_OID, nonce, certReq = true } = {}) {
	if (!Buffer.isBuffer(digest) || !digest.length) throw new Error('A digest buffer is required to build a timestamp request.');
	const algId = encSeq(encOid(hashOid), encNull());
	const messageImprint = encSeq(algId, encOctet(digest));
	const nonceBuf = nonce || crypto.randomBytes(16);
	const parts = [encInt(1), messageImprint, encInt(nonceBuf)];
	if (certReq) parts.push(encBool(true));
	return encSeq(...parts);
}

// ---- Minimal DER reading (strict, fail-closed) ----
//
// These parse UNTRUSTED input (a token from a network TSA), so every read is bounds-checked and any
// deviation from DER throws rather than limping on — a parser that continues past malformed structure
// is exactly how a forged token slips through. We only accept definite-length DER (a timestamp token is
// always DER); indefinite length (BER) is rejected outright, which removes a whole class of attacks.

// Read one TLV at offset. Returns { tag, len, hlen (header length), start (content), end }. Throws on any
// out-of-bounds read, indefinite length, or an over-long length field.
// The DER PARSERS are shared via lib/Der.js (one canonical codec across the cert / timestamp / token modules),
// aliased to their local names so the verification code below reads unchanged.
const readTLV = Der.readTLV, children = Der.children, contentOf = Der.contentOf, decodeOid = Der.decodeOid;
// Parse a GeneralizedTime string (YYYYMMDDHHMMSS[.fff]Z) into a Date.
function parseGeneralizedTime(s) {
	const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z?$/.exec(String(s).trim());
	if (!m) return null;
	const [, Y, Mo, D, H, Mi, S, frac] = m;
	const ms = frac ? Math.round(Number('0.' + frac) * 1000) : 0;
	return new Date(Date.UTC(+Y, +Mo - 1, +D, +H, +Mi, +S, ms));
}

// Parse a TimeStampResp: SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }. Returns the numeric
// status and the raw token DER (a CMS ContentInfo) when the request was granted (status 0 or 1).
function parseResponse(respDer) {
	// Any structural failure — a truncated response, an empty SEQUENCE, a missing PKIStatusInfo, or a bad length
	// deep in the DER that makes readTLV/children throw — must surface the module's tidy fail-closed error, never
	// a raw DER/TypeError. Wrap the whole parse so a hostile or broken TSA reply can only ever read as "malformed"
	// (timestamp() then re-checks the imprint binding, so a parseable-but-wrong token is still caught downstream).
	const MALFORMED = 'The timestamp server returned a malformed response.';
	try {
		const root = readTLV(respDer, 0);
		const kids = children(respDer, root.start, root.end);
		const statusInfo = kids[0];
		if (!statusInfo) throw new Error(MALFORMED);
		const statusKids = children(respDer, statusInfo.start, statusInfo.end);
		if (!statusKids[0]) throw new Error(MALFORMED);
		const statusVal = respDer[statusKids[0].start]; // small INTEGER
		const tokenTlv = kids[1] || null;
		const token = tokenTlv ? respDer.subarray(tokenTlv.start - tokenTlv.hlen, tokenTlv.end) : null;
		return { status: statusVal, token };
	} catch (_) { throw new Error(MALFORMED); }
}

// Walk a TimeStampToken (CMS SignedData) down to the embedded TSTInfo and read the fields we need:
// the message imprint (the hash the TSA certified), its hash algorithm, the signed time, and the
// serial number. Returns null if the structure is not as expected (treated as no proof upstream).
function readToken(tokenDer) {
	try {
		// ContentInfo ::= SEQ { contentType OID (signedData), [0] content }
		const ci = readTLV(tokenDer, 0);
		const ciKids = children(tokenDer, ci.start, ci.end);
		const ctOid = decodeOid(contentOf(tokenDer, ciKids[0]));
		if (ctOid !== OID_SIGNED_DATA) return null;
		const explicit0 = ciKids[1]; // [0] EXPLICIT
		const sd = children(tokenDer, explicit0.start, explicit0.end)[0]; // SignedData SEQUENCE
		const sdKids = children(tokenDer, sd.start, sd.end);
		// SignedData ::= SEQ { version, digestAlgorithms SET, encapContentInfo SEQ {...}, ... }
		const enc = sdKids[2];
		const encKids = children(tokenDer, enc.start, enc.end); // { eContentType OID, [0]{ OCTET STRING } }
		const explicitContent = encKids[1];
		const octet = children(tokenDer, explicitContent.start, explicitContent.end)[0]; // OCTET STRING
		const tstInfoDer = contentOf(tokenDer, octet); // the TSTInfo DER
		// TSTInfo ::= SEQ { version, policy OID, messageImprint SEQ{alg, OCTET}, serial INT, genTime GT, ... }
		const ti = readTLV(tstInfoDer, 0);
		const tiKids = children(tstInfoDer, ti.start, ti.end);
		const mi = tiKids[2]; // messageImprint SEQ { AlgorithmIdentifier, OCTET STRING }
		const miKids = children(tstInfoDer, mi.start, mi.end);
		const algIdKids = children(tstInfoDer, miKids[0].start, miKids[0].end); // { OID, NULL }
		const hashOid = decodeOid(contentOf(tstInfoDer, algIdKids[0]));
		const imprint = contentOf(tstInfoDer, miKids[1]); // OCTET STRING content = the hash
		const serial = tiKids[3];
		const genTimeTlv = tiKids[4];
		const genTime = parseGeneralizedTime(contentOf(tstInfoDer, genTimeTlv).toString('latin1'));
		// The optional nonce (TSTInfo INTEGER after genTime) — the first bare INTEGER among the trailing
		// optional fields (accuracy is a SEQUENCE, ordering a BOOLEAN, tsa/extensions are context-tagged).
		let nonceHex = null;
		for (let k = 5; k < tiKids.length; k++) { if (tiKids[k].tag === 0x02) { nonceHex = Buffer.from(contentOf(tstInfoDer, tiKids[k])).toString('hex'); break; } }
		return {
			imprintHex: Buffer.from(imprint).toString('hex'),
			hashOid,
			serialHex: Buffer.from(contentOf(tstInfoDer, serial)).toString('hex'),
			genTime,
			nonceHex,
		};
	} catch (_) { return null; }
}

// ---- Full CMS verification (pure Node crypto) ----
//
// The binding check above proves WHAT was stamped; this proves the token is AUTHENTIC — actually signed
// by a trusted Time-Stamping Authority for exactly this content. It verifies, with node:crypto only:
//   • the CMS signature over the signed attributes (RFC 5652 §5.4 — the SET OF re-tag), using the exact
//     signature algorithm the token declares (RSA PKCS#1 v1.5, RSA-PSS with its parameters, or ECDSA),
//   • that the message-digest signed attribute equals the hash of the TSTInfo (so the signature covers it),
//   • that the content-type signed attribute is id-ct-TSTInfo,
//   • that the SigningCertificate(V2) attribute (ESSCertID) pins the token to exactly one certificate,
//   • that this signing certificate carries the timestamping Extended Key Usage, marked critical,
//   • that the certificate chains to a TRUSTED ROOT (the platform's bundled CA set, plus any roots the
//     caller supplies), valid at the signed time — this is what stops a self-minted token from passing,
//   • that the signed time falls within the certificate's validity window.
// Revocation and full RFC 5280 path constraints (name constraints, path length) are not evaluated here;
// that is a documented, proportionate limit for an offline-first tool anchored to a pinned root set.
// Everything fails closed: any deviation, unknown algorithm, or broken link returns not-ok.

const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_CERT = '1.2.840.113549.1.9.16.2.12';   // SigningCertificate (ESSCertID, SHA-1)
const OID_SIGNING_CERT_V2 = '1.2.840.113549.1.9.16.2.47'; // SigningCertificateV2 (ESSCertIDv2, SHA-2)
const OID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_EKU = '2.5.29.37';
const OID_KP_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const HASH_BY_OID = { '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };
function hashNameForOid(oid) { return HASH_BY_OID[oid] || null; }
// Only these hashes are accepted for a signature or a certificate binding — SHA-1/MD5 are refused, so a
// weak-hash token can never verify. An allow-list (not a deny-list) so an unknown algorithm fails closed.
const STRONG_HASH = new Set(['sha256', 'sha384', 'sha512']);
// Signature algorithms, keyed by OID. `hash: null` means take the hash from the digest algorithm; 'pss'
// reads its hash + salt length from the algorithm parameters. Reading the scheme from the OID (never
// assuming RSA/SHA-256) is what keeps the verifier correct as authorities migrate algorithms.
const SIGALG = {
	'1.2.840.113549.1.1.5': { scheme: 'rsa', hash: 'sha1' },
	'1.2.840.113549.1.1.11': { scheme: 'rsa', hash: 'sha256' },
	'1.2.840.113549.1.1.12': { scheme: 'rsa', hash: 'sha384' },
	'1.2.840.113549.1.1.13': { scheme: 'rsa', hash: 'sha512' },
	'1.2.840.113549.1.1.1': { scheme: 'rsa', hash: null }, // rsaEncryption — hash from digestAlgorithm
	'1.2.840.113549.1.1.10': { scheme: 'pss' },            // id-RSASSA-PSS — params carry hash + salt
	'1.2.840.10045.4.1': { scheme: 'ecdsa', hash: 'sha1' },
	'1.2.840.10045.4.3.2': { scheme: 'ecdsa', hash: 'sha256' },
	'1.2.840.10045.4.3.3': { scheme: 'ecdsa', hash: 'sha384' },
	'1.2.840.10045.4.3.4': { scheme: 'ecdsa', hash: 'sha512' },
};

// The trust anchors that terminate a certificate chain: the platform's bundled Mozilla CA roots (which
// auto-update with Node) plus any extra roots the caller supplies (PEM), for an authority whose root is
// not publicly trusted. Parsed once and cached.
let _bundledAnchors = null;
function trustAnchors(extraPems = []) {
	if (!_bundledAnchors) {
		_bundledAnchors = [];
		for (const pem of tls.rootCertificates) { try { _bundledAnchors.push(new crypto.X509Certificate(pem)); } catch (_) {} }
	}
	const extra = [];
	for (const pem of (extraPems || [])) { try { extra.push(new crypto.X509Certificate(pem)); } catch (_) {} }
	return _bundledAnchors.concat(extra);
}
function certValidAt(x, t) { try { return t >= new Date(x.validFrom) && t <= new Date(x.validTo); } catch (_) { return false; } }
// child was issued by issuer AND its signature verifies under issuer's key (checkIssued alone only
// matches names, so the signature check is essential).
function issuedBy(child, issuer) { try { return !!child.checkIssued(issuer) && child.verify(issuer.publicKey); } catch (_) { return false; } }
// Build a path from `leaf` up to a trust anchor, using the embedded CA certificates as intermediates,
// with every certificate valid at `atTime`. Returns true only when an anchor is reached.
function verifyChain(leaf, intermediates, anchors, atTime) {
	let cur = leaf;
	const pool = intermediates.slice();
	const used = new Set();
	for (let depth = 0; depth < 12; depth++) {
		if (!certValidAt(cur, atTime)) return false;
		const anchor = anchors.find(a => issuedBy(cur, a)); // reached a trusted root?
		if (anchor) return certValidAt(anchor, atTime);
		const mid = pool.find(a => !used.has(a) && a.ca && issuedBy(cur, a)); // climb via an embedded CA
		if (!mid) return false;
		used.add(mid); cur = mid;
	}
	return false;
}

// Re-encode an element's content under a new tag (used to turn the [0] IMPLICIT signedAttrs into the
// SET OF (0x31) form that the signature is actually computed over).
function retag(buf, tlvObj, newTag) { return tlv(newTag, contentOf(buf, tlvObj)); }

// Parse a certificate's extension by OID from its DER. Returns { critical, value } or null.
function certExtension(certDer, wantOid) {
	try {
		const cert = readTLV(certDer, 0);
		const tbs = children(certDer, cert.start, cert.end)[0]; // TBSCertificate
		const tbsKids = children(certDer, tbs.start, tbs.end);
		const extsCtx = tbsKids.find(k => k.tag === 0xa3); // [3] EXPLICIT extensions
		if (!extsCtx) return null;
		const extsSeq = children(certDer, extsCtx.start, extsCtx.end)[0]; // SEQUENCE OF Extension
		for (const ext of children(certDer, extsSeq.start, extsSeq.end)) {
			const parts = children(certDer, ext.start, ext.end);
			if (decodeOid(contentOf(certDer, parts[0])) !== wantOid) continue;
			let critical = false, valTlv = parts[1];
			if (parts.length === 3) { critical = certDer[parts[1].start] !== 0; valTlv = parts[2]; } // BOOLEAN critical present
			return { critical, value: Buffer.from(contentOf(certDer, valTlv)) };
		}
	} catch (_) {}
	return null;
}
// True if the certificate declares the timestamping EKU and marks the extension critical (RFC 3161 §2.3).
function hasCriticalTimestampingEku(certDer) {
	const ext = certExtension(certDer, OID_EKU);
	if (!ext || !ext.critical) return false;
	try { const seq = readTLV(ext.value, 0); return children(ext.value, seq.start, seq.end).some(o => decodeOid(contentOf(ext.value, o)) === OID_KP_TIMESTAMPING); }
	catch (_) { return false; }
}

// Pull the pieces of the CMS SignedData needed for verification. Returns null on any structural surprise
// (fail-closed). certs is the list of embedded certificates (DER); the rest describe the single signer:
// its signed attributes, the digest algorithm, the SIGNATURE algorithm (with its parameters, for PSS),
// and the signature bytes.
function parseSignedData(tokenDer) {
	const ci = readTLV(tokenDer, 0);
	const ciKids = children(tokenDer, ci.start, ci.end);
	if (decodeOid(contentOf(tokenDer, ciKids[0])) !== OID_SIGNED_DATA) return null;
	const sd = children(tokenDer, ciKids[1].start, ciKids[1].end)[0];
	const sdKids = children(tokenDer, sd.start, sd.end);
	const enc = sdKids[2];
	const encKids = children(tokenDer, enc.start, enc.end);
	if (decodeOid(contentOf(tokenDer, encKids[0])) !== OID_CT_TSTINFO) return null;
	const octet = children(tokenDer, encKids[1].start, encKids[1].end)[0];
	const tstInfoDer = Buffer.from(contentOf(tokenDer, octet));
	const certsCtx = sdKids.find(k => k.tag === 0xa0); // [0] IMPLICIT certificates
	const certs = certsCtx ? children(tokenDer, certsCtx.start, certsCtx.end).filter(c => c.tag === 0x30).map(c => Buffer.from(tokenDer.subarray(c.start - c.hlen, c.end))) : [];
	const signerInfos = [...sdKids].reverse().find(k => k.tag === 0x31); // signerInfos is the trailing SET OF
	if (!signerInfos) return null;
	const si = children(tokenDer, signerInfos.start, signerInfos.end)[0];
	const siKids = children(tokenDer, si.start, si.end);
	// SignerInfo ::= SEQ { version, sid, digestAlgorithm, [0] signedAttrs OPTIONAL, signatureAlgorithm, signature, ... }
	const digestAlg = decodeOid(contentOf(tokenDer, children(tokenDer, siKids[2].start, siKids[2].end)[0]));
	let idx = 3;
	const signedAttrs = siKids[idx] && siKids[idx].tag === 0xa0 ? siKids[idx++] : null;
	const sigAlgSeq = siKids[idx++];
	const sigAlgKids = children(tokenDer, sigAlgSeq.start, sigAlgSeq.end);
	const sigAlgOid = decodeOid(contentOf(tokenDer, sigAlgKids[0]));
	const sigAlgParams = (sigAlgKids[1] && sigAlgKids[1].tag === 0x30) ? sigAlgKids[1] : null; // e.g. RSASSA-PSS-params
	const signatureTlv = siKids[idx++];
	return {
		tstInfoDer, certs, digestAlg, sigAlgOid, sigAlgParams,
		signedAttrsTlv: signedAttrs,
		signedAttrsSet: signedAttrs ? retag(tokenDer, signedAttrs, 0x31) : null, // the exact bytes the signature covers (SET OF re-tag)
		signature: Buffer.from(contentOf(tokenDer, signatureTlv)),
		fullBuf: tokenDer,
	};
}

// Read the signed attributes as a map of OID -> the raw value element bytes (the first value in the SET).
function readSignedAttrs(tokenDer, signedAttrsTlv) {
	const out = {};
	for (const attr of children(tokenDer, signedAttrsTlv.start, signedAttrsTlv.end)) {
		const parts = children(tokenDer, attr.start, attr.end);
		const oid = decodeOid(contentOf(tokenDer, parts[0]));
		const valueSet = parts[1];
		const first = children(tokenDer, valueSet.start, valueSet.end)[0];
		out[oid] = { tlv: first, buf: tokenDer };
	}
	return out;
}

// Read the RSASSA-PSS parameters (hash + salt length) so a PSS signature is verified with the exact
// scheme the token declares, rather than a wrong default.
function parsePssParams(buf, paramsTlv) {
	let hash = 'sha1', saltLength = 20; // ASN.1 defaults for RSASSA-PSS-params
	try {
		for (const el of children(buf, paramsTlv.start, paramsTlv.end)) {
			if (el.tag === 0xa0) { const alg = children(buf, el.start, el.end)[0]; hash = hashNameForOid(decodeOid(contentOf(buf, children(buf, alg.start, alg.end)[0]))) || hash; } // [0] hashAlgorithm
			else if (el.tag === 0xa2) { const i = children(buf, el.start, el.end)[0]; saltLength = parseInt(Buffer.from(contentOf(buf, i)).toString('hex') || '14', 16); } // [2] saltLength
		}
	} catch (_) {}
	return { hash, saltLength };
}

// Verify the CMS signature over `data` using the certificate's key and the token's declared signature
// algorithm. Returns false (never throws) on any unknown/weak algorithm or a bad signature.
function verifySignatureWith(certX, sd, data) {
	const info = SIGALG[sd.sigAlgOid];
	if (!info) return false;
	try {
		if (info.scheme === 'pss') {
			const { hash, saltLength } = sd.sigAlgParams ? parsePssParams(sd.fullBuf, sd.sigAlgParams) : { hash: hashNameForOid(sd.digestAlg), saltLength: 32 };
			if (!STRONG_HASH.has(hash)) return false;
			return crypto.verify(hash, data, { key: certX.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength }, sd.signature);
		}
		const hash = info.hash || hashNameForOid(sd.digestAlg); // ecdsa uses DER-encoded sig (Node's default), which CMS carries
		if (!hash || !STRONG_HASH.has(hash)) return false;
		return crypto.verify(hash, data, certX.publicKey, sd.signature);
	} catch (_) { return false; }
}

// Read the ESSCertID / ESSCertIDv2 from the SigningCertificate(V2) signed attribute: the hash algorithm
// and the certificate hash that authoritatively identify the one certificate that signed the token.
function essCertIdInfo(attrs) {
	let attr = attrs[OID_SIGNING_CERT_V2], v2 = true;
	if (!attr) { attr = attrs[OID_SIGNING_CERT]; v2 = false; }
	if (!attr) return null;
	try {
		const certsSeq = children(attr.buf, attr.tlv.start, attr.tlv.end)[0]; // SEQ OF ESSCertID(v2)
		const first = children(attr.buf, certsSeq.start, certsSeq.end)[0];    // the first ESSCertID(v2)
		const parts = children(attr.buf, first.start, first.end);
		let hashName = v2 ? 'sha256' : 'sha1', certHashTlv;
		if (v2 && parts[0].tag === 0x30) { hashName = hashNameForOid(decodeOid(contentOf(attr.buf, children(attr.buf, parts[0].start, parts[0].end)[0]))) || hashName; certHashTlv = parts[1]; }
		else { certHashTlv = parts[0]; }
		return { hashName, certHash: Buffer.from(contentOf(attr.buf, certHashTlv)) };
	} catch (_) { return null; }
}

// Full authenticity verification. Returns { ok, reason, genTime, tsaSubject, digestAlg, imprintHex,
// serialHex }. `digest` (optional) additionally re-checks the imprint; `extraRoots` adds trust anchors
// (PEM) for an authority whose root is not in the platform bundle.
// CAVEAT: the imprint binding is OPT-IN. Called WITHOUT `digest`, this proves only that a trusted TSA signed
// SOME imprint at `genTime` — it does NOT prove the token certifies OUR content. Any caller that needs proof a
// token attests a specific vault/version must pass the expected `digest` (as verifyBinding and timestamp() do).
function verifyToken(tokenDer, { digest, extraRoots = [] } = {}) {
	try {
		const sd = parseSignedData(tokenDer);
		if (!sd) return { ok: false, reason: 'unreadable' };
		if (!sd.signedAttrsTlv) return { ok: false, reason: 'no-signed-attrs' }; // RFC 3161 requires signed attributes
		const digestHash = hashNameForOid(sd.digestAlg);
		if (!digestHash) return { ok: false, reason: 'unknown-digest-alg' };
		// The message-digest binding below rests on this hash, so a weak one (SHA-1/MD5) would let a token bind
		// its signature to the TSTInfo over a broken hash even when the signature algorithm is strong. Refuse it.
		if (!STRONG_HASH.has(digestHash)) return { ok: false, reason: 'weak-digest-alg' };
		const attrs = readSignedAttrs(tokenDer, sd.signedAttrsTlv);
		// content-type signed attribute must be id-ct-TSTInfo
		const ct = attrs[OID_CONTENT_TYPE];
		if (!ct || decodeOid(contentOf(ct.buf, ct.tlv)) !== OID_CT_TSTINFO) return { ok: false, reason: 'bad-content-type' };
		// message-digest signed attribute must equal the hash of the TSTInfo, so the signature covers our content
		const md = attrs[OID_MESSAGE_DIGEST];
		if (!md) return { ok: false, reason: 'no-message-digest' };
		if (!Buffer.from(contentOf(md.buf, md.tlv)).equals(crypto.createHash(digestHash).update(sd.tstInfoDer).digest())) return { ok: false, reason: 'message-digest-mismatch' };
		// ESSCertID authoritatively names the signing certificate — the mandatory binding (RFC 5816).
		const ess = essCertIdInfo(attrs);
		if (!ess) return { ok: false, reason: 'no-signing-cert-attr' };
		if (!sd.certs.length) return { ok: false, reason: 'no-certs' }; // standalone verification needs the embedded cert(s)
		let leaf = null, leafDer = null;
		for (const der of sd.certs) { if (crypto.createHash(ess.hashName).update(der).digest().equals(ess.certHash)) { try { leaf = new crypto.X509Certificate(der); leafDer = der; } catch (_) {} break; } }
		if (!leaf) return { ok: false, reason: 'esscert-mismatch' };
		// The signature, verified with the pinned leaf and the declared algorithm.
		if (!verifySignatureWith(leaf, sd, sd.signedAttrsSet)) return { ok: false, reason: 'signature-invalid' };
		// The leaf must be a timestamping certificate, and that extension must be critical.
		if (!hasCriticalTimestampingEku(leafDer)) return { ok: false, reason: 'no-timestamping-eku' };
		const info = readToken(tokenDer);
		const genTime = info && info.genTime;
		if (!genTime) return { ok: false, reason: 'no-gentime' };
		// The chain must reach a trusted root, valid at the signed time. This is what stops a self-minted token.
		const intermediates = sd.certs.filter(d => d !== leafDer).map(d => { try { return new crypto.X509Certificate(d); } catch (_) { return null; } }).filter(Boolean);
		if (!verifyChain(leaf, intermediates, trustAnchors(extraRoots), genTime)) return { ok: false, reason: 'untrusted-chain' };
		// Bind to our digest, if given.
		if (digest) { const want = (Buffer.isBuffer(digest) ? digest.toString('hex') : String(digest)).toLowerCase(); if (info.imprintHex.toLowerCase() !== want) return { ok: false, reason: 'imprint-mismatch' }; }
		return { ok: true, reason: null, genTime, tsaSubject: leaf.subject, digestAlg: sd.digestAlg, imprintHex: info.imprintHex, serialHex: info.serialHex };
	} catch (e) { return { ok: false, reason: 'error:' + (e && e.message || 'parse') }; }
}

// Verify that a token certifies exactly `digest`, and return its signed time. This is the core,
// dependency-free proof: it does NOT by itself verify the TSA's signature/chain (that is optional and
// external), but it guarantees the token was issued for OUR digest and carries the TSA's stated time.
function verifyBinding(tokenDer, digest) {
	const info = readToken(tokenDer);
	if (!info) return { ok: false, reason: 'unreadable' };
	const want = Buffer.isBuffer(digest) ? digest.toString('hex') : String(digest);
	if (info.imprintHex.toLowerCase() !== want.toLowerCase()) return { ok: false, reason: 'imprint-mismatch' };
	if (!info.genTime) return { ok: false, reason: 'no-time' };
	return { ok: true, genTime: info.genTime, serialHex: info.serialHex, hashOid: info.hashOid };
}

// POST a request to the TSA and return the raw response body. Bounded so a slow or unreachable TSA can
// never hang the caller, and size-capped so it can never exhaust memory.
const MAX_TSA_RESPONSE = 256 * 1024;
function postRequest(tsaUrl, reqDer, timeoutMs) {
	return new Promise((resolve, reject) => {
		let u;
		try { u = new URL(tsaUrl); } catch (_) { return reject(new Error('The timestamp server address is not a valid URL.')); }
		const lib = u.protocol === 'http:' ? http : https;
		// The socket `timeout` below is only an IDLE timer; a hostile caller-supplied TSA could drip one byte just
		// inside each idle window and tie the request up far longer than intended. Pair it with an absolute
		// wall-clock deadline that ends the whole exchange no matter how the bytes are paced.
		let done = false;
		const finish = (fn, arg) => { if (done) return; done = true; clearTimeout(deadline); fn(arg); };
		const deadline = setTimeout(() => { try { req.destroy(new Error('The timestamp server did not respond in time.')); } catch (_) {} }, Math.max(1, timeoutMs));
		const req = lib.request(u, {
			method: 'POST',
			headers: { 'Content-Type': 'application/timestamp-query', 'Content-Length': reqDer.length },
			timeout: timeoutMs,
		}, (res) => {
			const chunks = []; let size = 0;
			// A timestamp token is a few kilobytes; cap the body so a malicious or broken TSA streaming a huge
			// response (within the timeout) can never exhaust memory. The URL is caller-suppliable, so this matters.
			res.on('data', (c) => { size += c.length; if (size > MAX_TSA_RESPONSE) { res.destroy(); return finish(reject, new Error('The timestamp server sent an unexpectedly large response.')); } chunks.push(c); });
			res.on('end', () => {
				if (res.statusCode !== 200) return finish(reject, new Error('The timestamp server returned HTTP ' + res.statusCode + '.'));
				finish(resolve, Buffer.concat(chunks));
			});
		});
		req.on('timeout', () => { req.destroy(new Error('The timestamp server did not respond in time.')); });
		req.on('error', (e) => finish(reject, new Error('Could not reach the timestamp server: ' + (e && e.message || e))));
		req.end(reqDer);
	});
}

// Request a trusted timestamp for `digest` from ONE authority. Returns the token plus the certified time and
// serial. Throws (fail-closed) if the server refuses, is unreachable, or the returned token does not certify
// our digest (or does not echo our nonce).
async function requestTimestampFrom(digest, tsaUrl, timeoutMs, hashOid) {
	const nonce = crypto.randomBytes(16);
	const reqDer = buildRequest(digest, { hashOid, nonce, certReq: true });
	const respDer = await postRequest(tsaUrl, reqDer, timeoutMs);
	const { status, token } = parseResponse(respDer);
	// PKIStatus: 0 = granted, 1 = grantedWithMods; anything else is a rejection.
	if (status !== 0 && status !== 1) throw new Error('The timestamp server declined the request (status ' + status + ').');
	if (!token) throw new Error('The timestamp server returned no token.');
	const binding = verifyBinding(token, digest);
	if (!binding.ok) throw new Error('The timestamp token did not certify this vault\'s state (' + binding.reason + ').');
	// If the TSA echoed our nonce, it must match — this ties the response to THIS request and rejects a
	// replayed prior token for the same digest. The nonce is optional in TSTInfo, so a TSA that omits it is
	// tolerated; the imprint binding above already ties the token to our exact content.
	const tok = readToken(token);
	if (tok && tok.nonceHex != null) {
		const want = BigInt('0x' + nonce.toString('hex'));
		let got = null; try { got = BigInt('0x' + (tok.nonceHex || '0')); } catch (_) {}
		if (got == null || got !== want) throw new Error('The timestamp token did not echo this request\'s nonce.');
	}
	return { token, genTime: binding.genTime, serialHex: binding.serialHex, tsaUrl, hashOid };
}

// Get a trusted timestamp for `digest`. With no `tsaUrl`, the built-in authorities are tried in order until one
// returns a token that fully verifies, so one authority being unreachable never fails the attestation. A given
// `tsaUrl` is used alone (no fallback), and its full verification is left to the caller so a custom root can be
// supplied. Throws (fail-closed) with a clear, self-explaining message when nothing usable can be obtained.
async function timestamp(digest, { tsaUrl, timeoutMs = 20000, hashOid = SHA256_OID } = {}) {
	const custom = tsaUrl != null && String(tsaUrl) !== '';
	const candidates = custom ? [tsaUrl] : DEFAULT_TSAS;
	let lastErr = null;
	for (const url of candidates) {
		try {
			const r = await requestTimestampFrom(digest, url, timeoutMs, hashOid);
			// For a built-in authority, require the token to FULLY verify (chain to a trusted root, binding our
			// digest) so an authority that is reachable but returns an unusable token is SKIPPED and the next is
			// tried, instead of failing the whole attestation. A custom authority is returned as-is: it may use a
			// root outside the platform bundle, so the caller finishes its verification (with any extra roots).
			if (!custom) { const v = verifyToken(r.token, { digest }); if (!v.ok) throw new Error('the authority returned a token that did not verify (' + v.reason + ')'); }
			return r;
		} catch (e) { lastErr = e; } // unreachable / declined / unusable — try the next authority
	}
	if (custom) throw lastErr || new Error('Could not reach the timestamp server.');
	throw new Error('Could not reach any timestamp authority (tried ' + candidates.length + '). Check this computer\'s internet connection or firewall, then try again — timestamping is optional and can always be done later.' + (lastErr && lastErr.message ? ' (Last error: ' + lastErr.message + ')' : ''));
}

module.exports = {
	DEFAULT_TSA, DEFAULT_TSAS, SHA256_OID,
	buildRequest, parseResponse, readToken, verifyBinding, verifyToken, timestamp,
	// exported for tests
	_der: { encInt, encOid, encSeq, encOctet, encNull, encBool, tlv, readTLV, children, decodeOid, parseGeneralizedTime },
};
