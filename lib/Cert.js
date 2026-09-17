'use strict';
// lib/Cert.js — the single source of self-signed TLS certificate generation, used to encrypt the
// relay hop end-to-end. A served node can present a certificate so the connection between the client
// and the node is TLS; the relay hub in the middle only ever splices the encrypted bytes and cannot
// read them, and the client PINS this exact certificate (via --ca-cert), so an impersonating hub or
// network attacker is rejected. Only ciphertext ever crosses the relay either way — this hardens the
// transport of the serve credential and the traffic itself.
//
// Generation is pure Node, with NO external process and NO extra dependency: the RSA key pair and the
// signature come from Node's own vetted crypto, and only the small X.509 structure around them is
// DER-encoded here. That makes it work identically on macOS, Linux, and Windows — a Windows host no
// longer needs `openssl` on PATH for an exposed interface or the relay hop to be encrypted. Every
// generated certificate is validated (parsed and its self-signature verified with Node's
// X509Certificate) before it is trusted, so a mis-encoding fails closed rather than shipping a bad cert.
//
// A cert is cached per host (a hash of the host name) under data/certs/ and reused, so a node keeps
// the SAME certificate across restarts and a client's pinned copy stays valid.

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const Common = require('./Common');
const Der = require('./Der');

function certDir() { return path.join(Common.dataDir(), 'certs'); }
const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':'); // IPv4 or a colon (IPv6/none)

// Every non-internal IPv4 address on this machine — the addresses a LAN peer might reach this node on. Deterministic
// (sorted, de-duped) so the LAN cert's cache key is stable while the addresses are. IPv4 only for Phase-1 LAN direct;
// IPv6 link-local is skipped (it needs a zone id and is not the common same-Wi-Fi case).
function lanIPv4s() {
	const out = [];
	const ifs = os.networkInterfaces();
	for (const name of Object.keys(ifs || {})) {
		for (const a of ifs[name] || []) {
			if (a && a.family === 'IPv4' && !a.internal && a.address) out.push(a.address);
		}
	}
	return [...new Set(out)].sort();
}

// ---- DER (ASN.1) building blocks: the generic encoders are shared via lib/Der.js (one canonical copy, so the
// certificate, timestamp-request, and token builders can never drift); only the X.509-specific shapes live here. ----
const tlv = Der.tlv, SEQ = Der.seq, SET = Der.set;
const derInteger = Der.integer, derSmallInt = Der.smallInt, derOid = Der.oid, derUtf8 = Der.utf8, derBitString = Der.bitString;
const DER_NULL = Der.NULL;
const algoSha256Rsa = () => SEQ(derOid('1.2.840.113549.1.1.11'), DER_NULL); // sha256WithRSAEncryption — RSA takes a NULL params
const derTime = Der.time; // UTCTime before 2050, else GeneralizedTime — the X.509 rule (shared)
// A Name with a single CN=... RDN.
function derName(cn) { return SEQ(SET(SEQ(derOid('2.5.4.3'), derUtf8(cn)))); }
// Pack an IPv6 literal into its 16 raw octets (handling "::" compression, a %zone suffix, and an embedded IPv4
// tail like ::ffff:1.2.3.4), or null if it does not parse. Needed because an iPAddress SAN for IPv6 must be the
// full 16-byte form; encoding it as 4 IPv4 octets produces a malformed SAN that a pinning client rejects.
function ipv6ToBytes(input) {
	let s = String(input).replace(/^\[/, '').replace(/\]$/, '').split('%')[0];
	if (!s.includes(':')) return null;
	const emb = s.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/); // trailing embedded IPv4 → two hextets
	if (emb) {
		const v4 = emb[2].split('.').map(Number);
		if (v4.some(o => !(o >= 0 && o <= 255))) return null;
		s = emb[1] + (((v4[0] << 8) | v4[1]).toString(16)) + ':' + (((v4[2] << 8) | v4[3]).toString(16));
	}
	const halves = s.split('::');
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(':') : [];
	const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;
	let groups;
	if (tail === null) { groups = head; } // no "::" — must be exactly 8 groups
	else { const fill = 8 - head.length - tail.length; if (fill < 0) return null; groups = [...head, ...Array(fill).fill('0'), ...tail]; }
	if (groups.length !== 8) return null;
	const bytes = [];
	for (const g of groups) { if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null; const v = parseInt(g, 16); bytes.push((v >> 8) & 0xff, v & 0xff); }
	return Buffer.from(bytes);
}
// subjectAltName GeneralNames: dNSName [2] IA5String, iPAddress [7] OCTET STRING.
function derSan(hosts) {
	const names = hosts.map(({ type, value }) => {
		if (type === 'dns') return tlv(0x82, Buffer.from(value, 'ascii'));
		if (value.includes(':')) { const b = ipv6ToBytes(value); return b ? tlv(0x87, b) : null; } // IPv6 as 16 octets (dropped if unparseable)
		return tlv(0x87, Buffer.from(value.split('.').map(Number))); // IPv4 as 4 octets
	}).filter(Boolean);
	return SEQ(...names);
}
// One extension: SEQUENCE { OID, [critical BOOLEAN], OCTET STRING value }.
function derExtension(oid, critical, valueDer) {
	const parts = [derOid(oid)];
	if (critical) parts.push(Buffer.from([0x01, 0x01, 0xff])); // BOOLEAN TRUE
	parts.push(tlv(0x04, valueDer)); // OCTET STRING wrapping the value
	return SEQ(...parts);
}

// The SAN entries the client validates against — the host(s) it connects to, plus loopback so a local test also
// verifies. `host` may be a single host or an ARRAY of hosts (a LAN serve covers every local IPv4 so a peer that
// reaches it on any of them still passes hostname verification against the pinned cert).
function sanEntries(host) {
	const out = [{ type: 'ip', value: '127.0.0.1' }, { type: 'dns', value: 'localhost' }];
	for (const h0 of (Array.isArray(host) ? host : [host])) {
		const h = String(h0 || '').trim();
		if (h && h !== '127.0.0.1' && h !== 'localhost' && !out.some((e) => e.value === h)) out.unshift({ type: isIp(h) ? 'ip' : 'dns', value: h });
	}
	return out;
}

// Build a self-signed certificate for `host` from an already-generated RSA key pair. Returns { certPem, keyPem }. Pure
// Node, no spawn, no I/O — split from key generation so a caller can generate the key asynchronously (off the event
// loop) and reuse this synchronous DER/signing step.
function buildSelfSigned(publicKey, privateKey, host) {
	const spkiDer = publicKey.export({ type: 'spki', format: 'der' }); // this IS the SubjectPublicKeyInfo
	const cn = String((Array.isArray(host) ? host[0] : host) || 'localhost');
	const now = new Date(Date.now() - 60 * 1000); // backdate a minute to tolerate small clock skew
	const notAfter = new Date(now.getTime() + 3650 * 24 * 60 * 60 * 1000);
	const basicConstraints = derExtension('2.5.29.19', true, SEQ(Buffer.from([0x01, 0x01, 0xff]))); // CA:TRUE (client pins it via --ca-cert)
	const san = derExtension('2.5.29.17', false, derSan(sanEntries(host)));
	const extensions = tlv(0xa3, SEQ(basicConstraints, san)); // [3] EXPLICIT Extensions
	const tbs = SEQ(
		tlv(0xa0, derSmallInt(2)),               // [0] version v3 (value 2)
		derInteger(crypto.randomBytes(16)),      // serialNumber (positive)
		algoSha256Rsa(),
		derName(cn),                             // issuer == subject (self-signed)
		SEQ(derTime(now), derTime(notAfter)),    // validity
		derName(cn),                             // subject
		spkiDer,                                 // subjectPublicKeyInfo
		extensions,
	);
	const signature = crypto.sign('sha256', tbs, privateKey);
	const certDerBuf = SEQ(tbs, algoSha256Rsa(), derBitString(signature));
	const certPem = pem('CERTIFICATE', certDerBuf);
	const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
	return { certPem, keyPem };
}
// Synchronous convenience (tests and any sync caller): generate the key pair then build the certificate.
function generateSelfSigned(host) {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	return buildSelfSigned(publicKey, privateKey, host);
}
// Async form for the shared service's serve path: generate the RSA key pair off the event loop (a keygen is CPU-bound
// and would otherwise block every other request for tens of milliseconds), then build the certificate.
function generateSelfSignedAsync(host) {
	return new Promise((resolve, reject) => {
		crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, publicKey, privateKey) => {
			if (err) return reject(err);
			try { resolve(buildSelfSigned(publicKey, privateKey, host)); } catch (e) { reject(e); }
		});
	});
}
function pem(label, der) {
	const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
	return '-----BEGIN ' + label + '-----\n' + b64 + '\n-----END ' + label + '-----\n';
}

// Ensure a self-signed cert+key for `host` exists (generating once), and return { certFile, keyFile, certPem }.
// Async so the private-key directory is hardened (owner-only permissions / NTFS ACL) BEFORE the key is written into
// it — otherwise the key could exist briefly in a world-readable directory, which matters most on Windows where the
// file's own mode bits are a no-op. Returns null only if generation could not be validated (never for a missing tool,
// since there is no external tool any more), so the caller then serves plain HTTP exactly as before.
async function ensureCert(host) {
	const key = Common.sha256Hex('cert:' + (host || '')).slice(0, 16);
	const certFile = path.join(certDir(), key + '.crt');
	const keyFile = path.join(certDir(), key + '.key');
	// Reuse a cached pair when both files are present (read fully async, so this never blocks the shared service).
	try { const certPem = await fsp.readFile(certFile, 'utf8'); await fsp.access(keyFile); return { certFile, keyFile, certPem }; } catch (_) { /* not cached (or unreadable) — (re)generate below */ }
	try { await Common.hardenDir(certDir()); } catch (_) { try { await fsp.mkdir(certDir(), { recursive: true }); } catch (_) {} }
	let cert;
	try { cert = await generateSelfSignedAsync(host); } catch (_) { return null; } // keygen off the event loop
	// Validate before trusting: parse it and verify the self-signature. A mis-encoding fails closed here (caller
	// serves plain HTTP) rather than presenting a certificate a client would reject.
	try {
		const x = new crypto.X509Certificate(cert.certPem);
		if (!x.verify(x.publicKey)) return null;
	} catch (_) { return null; }
	// Create the private key file owner-only from the start (mode on write), so there is no brief window where it
	// exists at the default umask before the chmod narrows it. The chmod remains as belt-and-suspenders (and to fix a
	// pre-existing loose file). The containing directory is already hardened to owner-only above.
	try { await fsp.writeFile(certFile, cert.certPem, { mode: 0o644 }); await fsp.writeFile(keyFile, cert.keyPem, { mode: 0o600 }); } catch (_) { return null; }
	try { await fsp.chmod(keyFile, 0o600); } catch (_) {}
	try { return { certFile, keyFile, certPem: await fsp.readFile(certFile, 'utf8') }; } catch (_) { return null; }
}

// A cert covering every current LAN IPv4 (plus loopback), for serving a vault DIRECTLY on the local network so a
// discovered peer can pin it and connect over HTTPS with hostname verification intact. `extra` adds further SAN hosts
// — used in WAN mode to also cover the public external address a router mapping exposes, so hostname verification
// passes whether the peer reaches this node on its LAN IP or its internet address. Cached by the address set
// (ensureCert keys on the SAN hosts), so it stays stable while the machine's IPs do and regenerates — covering the
// new address — only when they change. Returns { certFile, keyFile, certPem }, or null so the caller degrades safely.
async function ensureLanCert(extra) {
	const extras = (Array.isArray(extra) ? extra : (extra ? [extra] : [])).filter(Boolean);
	// Always cover loopback: besides the LAN IPs, a peer that reaches this node over a direct hole-punched tunnel
	// connects to it through a LOCAL proxy at 127.0.0.1, and pins THIS certificate, so 127.0.0.1 must verify too.
	const hosts = [...new Set(['127.0.0.1', ...lanIPv4s(), ...extras])];
	return ensureCert(hosts);
}

module.exports = { ensureCert, ensureLanCert, generateSelfSigned, lanIPv4s };
