'use strict';
// lib/test/cert.js — the self-signed TLS certificate generator is pure Node (no openssl, no extra dependency), so it
// works identically on macOS, Linux, and Windows. This checks that a generated certificate parses, self-verifies, and
// carries the right subject and subjectAltName for a DNS host and an IP host — and that it actually works as a TLS
// server certificate end to end (a client that pins it connects and verifies the host).
//
// Run:  node lib/test/cert.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const tls = require('tls');
const net = require('net');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function tlsRoundTrip(cert) {
	// Stand up a TLS server with the generated cert/key, then connect as a client that PINS the cert as its CA and
	// requires the hostname 'localhost' — exactly how the relay client pins a served node's certificate.
	return await new Promise((resolve) => {
		const server = tls.createServer({ cert: cert.certPem, key: cert.keyPem }, (s) => { s.end('hi'); });
		server.on('error', () => resolve(false));
		server.listen(0, '127.0.0.1', () => {
			const port = server.address().port;
			const c = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: [cert.certPem], checkServerIdentity: (host, peer) => tls.checkServerIdentity('localhost', peer) }, () => {
				const authorized = c.authorized; c.destroy(); server.close(() => resolve(authorized));
			});
			c.on('error', () => { try { server.close(); } catch (_) {} resolve(false); });
		});
	});
}

async function main() {
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-cert-'));
	const Common = require('../Common'); Common.dataDir = () => path.join(tmp, 'd');
	const Cert = require('../Cert');

	// --- a DNS host ---
	const dns = Cert.generateSelfSigned('vault.example.net');
	const xd = new crypto.X509Certificate(dns.certPem);
	ok('a generated certificate parses', !!xd.subject);
	ok('the certificate self-verifies (valid self-signature)', xd.verify(xd.publicKey));
	ok('the subject and issuer are the host CN (self-signed)', /CN=vault\.example\.net/.test(xd.subject) && xd.subject === xd.issuer);
	ok('the subjectAltName lists the DNS host, localhost, and loopback', /DNS:vault\.example\.net/.test(xd.subjectAltName) && /DNS:localhost/.test(xd.subjectAltName) && /IP Address:127\.0\.0\.1/.test(xd.subjectAltName));
	ok('notBefore is in the past and notAfter is years out', new Date(xd.validFrom) <= new Date() && (new Date(xd.validTo) - new Date()) > 9 * 365 * 24 * 3600 * 1000);
	ok('the key is a 2048-bit RSA key', (xd.publicKey.asymmetricKeyDetails || {}).modulusLength === 2048);

	// --- an IP host: the SAN must carry an iPAddress entry, not a DNS name ---
	const ip = Cert.generateSelfSigned('192.168.1.50');
	const xi = new crypto.X509Certificate(ip.certPem);
	ok('an IP host is emitted as an iPAddress SAN', /IP Address:192\.168\.1\.50/.test(xi.subjectAltName));
	ok('the IP certificate also self-verifies', xi.verify(xi.publicKey));

	// --- an IPv6 host: the SAN must be the full 16-byte iPAddress form, not a mangled IPv4 encoding ---
	const v6 = Cert.generateSelfSigned('2001:db8::1');
	const x6 = new crypto.X509Certificate(v6.certPem);
	ok('an IPv6 host is emitted as a valid (16-byte) iPAddress SAN', /IP Address:2001:DB8:0:0:0:0:0:1/i.test(x6.subjectAltName));
	ok('the IPv6 certificate self-verifies', x6.verify(x6.publicKey));
	const v6c = new crypto.X509Certificate(Cert.generateSelfSigned('::1').certPem);
	ok('a compressed IPv6 literal (::1) expands to the full loopback SAN', /IP Address:0:0:0:0:0:0:0:1/.test(v6c.subjectAltName));

	// --- ensureCert caches and validates, returning files ---
	const e1 = await Cert.ensureCert('localhost');
	ok('ensureCert returns cert and key files', !!(e1 && e1.certFile && e1.keyFile && e1.certPem));
	const e2 = await Cert.ensureCert('localhost');
	ok('ensureCert reuses the cached certificate across calls (stable pin)', e2 && e2.certPem === e1.certPem);

	// --- end-to-end: it really works as a TLS server certificate a pinning client accepts ---
	ok('a pinning TLS client connects and authorizes the certificate', (await tlsRoundTrip(Cert.generateSelfSigned('localhost'))) === true);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CERT CHECKS PASSED'));
	await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
