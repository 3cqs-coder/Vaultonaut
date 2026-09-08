'use strict';
// lib/test/_tsa.js — a TEST-ONLY fixture that mints a REAL, self-signed RFC 3161 timestamp token (a CMS
// SignedData over a TSTInfo, signed by a self-issued certificate that carries the critical timestamping EKU). It
// exists so the attestation verifier's anti-forgery path can be exercised OFFLINE: a self-minted token must be
// rejected (its chain reaches no trusted root), and must verify only when its own root is supplied as a trust
// anchor. The leading underscore keeps the battery runner from executing it as a test.
//
// It builds the token with the SAME shared DER encoders the production cert and timestamp-request builders use
// (lib/Der.js), so the fixture cannot drift from them; a token this builds is parsed by the real verifier.

const crypto = require('crypto');
const Der = require('../Der'); // the same shared DER encoders the production cert/token builders use

// DER shapes, from the shared module (SEQ/SET keep their local names for readability below).
const tlv = Der.tlv, SEQ = Der.seq, SET = Der.set, ctx = Der.ctx, oid = Der.oid, NULL = Der.NULL;
const octet = Der.octet, bitString = Der.bitString, utf8 = Der.utf8;
const intFromBuf = Der.integer, smallInt = Der.smallInt;
const boolTrue = Der.bool(true);
const utcTime = Der.utcTime, genTimeDer = Der.generalizedTime;

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const algSha256 = () => SEQ(oid(SHA256_OID), NULL);
const algSha256Rsa = () => SEQ(oid('1.2.840.113549.1.1.11'), NULL); // sha256WithRSAEncryption
const algRsa = () => SEQ(oid('1.2.840.113549.1.1.1'), NULL);        // rsaEncryption
const name = (cn) => SEQ(SET(SEQ(oid('2.5.4.3'), utf8(cn))));
const pem = (label, der) => '-----BEGIN ' + label + '-----\n' + der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '') + '\n-----END ' + label + '-----\n';

// A self-signed X.509 v3 certificate carrying the timestamping EKU. `ekuCritical` defaults true (RFC 3161 §2.3);
// pass false to build an otherwise-valid signer whose EKU is not marked critical (to exercise that rejection).
function makeSignerCert({ cn = 'Test TSA', notBefore, notAfter, ekuCritical = true } = {}) {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const spki = publicKey.export({ type: 'spki', format: 'der' });
	const ekuValue = SEQ(oid('1.3.6.1.5.5.7.3.8')); // ExtKeyUsageSyntax { id-kp-timeStamping }
	const ekuExt = SEQ(oid('2.5.29.37'), ...(ekuCritical ? [boolTrue] : []), octet(ekuValue));
	const extensions = ctx(3, SEQ(ekuExt)); // [3] EXPLICIT Extensions
	const tbs = SEQ(
		ctx(0, smallInt(2)),                 // [0] version v3
		intFromBuf(crypto.randomBytes(12)),  // serialNumber
		algSha256Rsa(),
		name(cn),                            // issuer (self)
		SEQ(utcTime(notBefore), utcTime(notAfter)),
		name(cn),                            // subject (self)
		spki,
		extensions,
	);
	const sig = crypto.sign('sha256', tbs, privateKey);
	const certDer = SEQ(tbs, algSha256Rsa(), bitString(sig));
	return { certDer, certPem: pem('CERTIFICATE', certDer), privateKey };
}

// Mint a full RFC 3161 timestamp token over `digest` (a Buffer), signed by a fresh self-signed timestamping cert.
// Returns { tokenDer, certPem, digest }. The token is structurally complete and internally consistent — it fails
// real verification ONLY because its root is not trusted, unless that root (certPem) is passed as an extra anchor.
function mintToken({ digest, genTime = new Date(), ekuCritical = true } = {}) {
	digest = digest || crypto.createHash('sha256').update('vaultonaut-forgery-fixture').digest();
	const cert = makeSignerCert({ notBefore: new Date(genTime.getTime() - 86400000), notAfter: new Date(genTime.getTime() + 365 * 86400000), ekuCritical });

	// TSTInfo ::= SEQ { version, policy, messageImprint SEQ{alg, hashedMessage}, serialNumber, genTime }
	const messageImprint = SEQ(algSha256(), octet(digest));
	const tstInfo = SEQ(smallInt(1), oid('1.3.6.1.4.1.99999.1'), messageImprint, intFromBuf(crypto.randomBytes(8)), genTimeDer(genTime));

	// SignedAttributes: content-type, message-digest (over TSTInfo), signing-certificate-v2 (ESSCertIDv2 = cert hash)
	const certHash = crypto.createHash('sha256').update(cert.certDer).digest();
	const essCertIdV2 = SEQ(octet(certHash));                    // hashAlgorithm omitted => sha256 (the default)
	const signingCertV2 = SEQ(SEQ(essCertIdV2));                 // SigningCertificateV2 { SEQ OF ESSCertIDv2 }
	const attrsContent = Buffer.concat([
		SEQ(oid('1.2.840.113549.1.9.3'), SET(oid('1.2.840.113549.1.9.16.1.4'))),                 // contentType = id-ct-TSTInfo
		SEQ(oid('1.2.840.113549.1.9.4'), SET(octet(crypto.createHash('sha256').update(tstInfo).digest()))), // messageDigest
		SEQ(oid('1.2.840.113549.1.9.16.2.47'), SET(signingCertV2)),                              // signingCertificateV2
	]);
	// The signature is computed over the SET OF form (tag 0x31) of the attributes, per CMS.
	const signature = crypto.sign('sha256', SET(attrsContent), cert.privateKey);

	const encap = SEQ(oid('1.2.840.113549.1.9.16.1.4'), ctx(0, octet(tstInfo))); // eContentType + [0] EXPLICIT OCTET(TSTInfo)
	const signerInfo = SEQ(
		smallInt(1),                                     // version
		SEQ(name('Test TSA'), intFromBuf(crypto.randomBytes(12))), // sid = IssuerAndSerialNumber (any serial; not checked)
		algSha256(),                                     // digestAlgorithm
		ctx(0, attrsContent),                            // [0] IMPLICIT signedAttrs (same content the signature covers)
		algRsa(),                                        // signatureAlgorithm = rsaEncryption
		octet(signature),
	);
	const signedData = SEQ(
		smallInt(3),                                     // CMS version
		SET(algSha256()),                                // digestAlgorithms
		encap,
		ctx(0, cert.certDer),                            // [0] IMPLICIT certificates (a CertificateSet holding the leaf)
		SET(signerInfo),                                 // signerInfos
	);
	const tokenDer = SEQ(oid('1.2.840.113549.1.7.2'), ctx(0, signedData)); // ContentInfo { id-signedData, [0] EXPLICIT SignedData }
	return { tokenDer, certPem: cert.certPem, digest };
}

module.exports = { mintToken, makeSignerCert };
