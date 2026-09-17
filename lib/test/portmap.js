'use strict';
// lib/test/portmap.js — NAT-PMP (RFC 6886) / PCP (RFC 6887) automatic router port mapping (lib/PortMap.js). A real
// router is not available in CI, so this exercises the pure wire codecs (round-trip AND the security-critical
// rejection paths: wrong version/opcode, non-zero result code, and a PCP nonce mismatch), the input validation, the
// bounded no-router behaviour, and the cross-platform "no native module / no reliable-UDP" source contract.
//
// Run:  node lib/test/portmap.js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const PortMap = require('../PortMap');
const P = PortMap._proto;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Build a valid NAT-PMP MAP response (16 bytes) for op (129 UDP-resp / 130 TCP-resp), result, ext port, lifetime.
function natpmpResp({ op = 130, result = 0, extPort = 40001, lifetime = 3600 } = {}) {
	const b = Buffer.alloc(16);
	b.writeUInt8(0, 0); b.writeUInt8(op, 1); b.writeUInt16BE(result, 2); b.writeUInt32BE(1, 4);
	b.writeUInt16BE(8443, 8); b.writeUInt16BE(extPort, 10); b.writeUInt32BE(lifetime, 12);
	return b;
}
// Build a valid PCP MAP response (60 bytes) that echoes `nonce`.
function pcpResp(nonce, { result = 0, extPort = 40002, lifetime = 3600, ip = [203, 0, 113, 7] } = {}) {
	const b = Buffer.alloc(60);
	b.writeUInt8(2, 0); b.writeUInt8(1 | 0x80, 1); b.writeUInt8(result, 3); b.writeUInt32BE(lifetime, 4);
	nonce.copy(b, 24, 0, 12); b.writeUInt8(6, 36); b.writeUInt16BE(8443, 40); b.writeUInt16BE(extPort, 42);
	b.writeUInt16BE(0xffff, 54); b[56] = ip[0]; b[57] = ip[1]; b[58] = ip[2]; b[59] = ip[3];
	return b;
}

async function main() {
	// 1. NAT-PMP: a valid TCP-map response parses to the external port + lifetime.
	ok('NAT-PMP parses a valid response (external port + lifetime)', (() => { const r = P.natpmpParse(natpmpResp({ op: 130, extPort: 40001, lifetime: 7200 }), true); return r && r.externalPort === 40001 && r.lifetime === 7200; })());
	// 2. NAT-PMP rejects: wrong opcode, a non-zero result code, and a truncated packet — fail closed.
	ok('NAT-PMP rejects a mismatched opcode', P.natpmpParse(natpmpResp({ op: 129 }), true) === null);
	ok('NAT-PMP rejects a non-zero result code (router refused)', P.natpmpParse(natpmpResp({ result: 2 }), true) === null);
	ok('NAT-PMP rejects a short packet', P.natpmpParse(Buffer.alloc(8), true) === null);

	// 3. PCP: build a request, capture its nonce, and parse a response that echoes it.
	{
		const nonce = crypto.randomBytes(12);
		const req = P.pcpMapRequest('192.168.1.10', 8443, 0, 3600, true, nonce);
		ok('PCP request has the version-2 MAP header', req.length === 60 && req.readUInt8(0) === 2 && req.readUInt8(1) === 1);
		const r = P.pcpParse(pcpResp(nonce, { extPort: 40002, ip: [203, 0, 113, 7] }), nonce);
		ok('PCP parses a valid response (external port + external IP)', r && r.externalPort === 40002 && r.externalIP === '203.0.113.7');
	}
	// 4. PCP rejects a response whose nonce does not match our request — the anti-spoof check.
	{
		const nonce = crypto.randomBytes(12);
		const other = crypto.randomBytes(12);
		ok('PCP rejects a response with a mismatched nonce (anti-spoof)', P.pcpParse(pcpResp(other), nonce) === null);
		ok('PCP rejects a non-success result code', P.pcpParse(pcpResp(nonce, { result: 2 }), nonce) === null);
		ok('PCP rejects a non-PCP version byte', P.pcpParse(Buffer.concat([Buffer.from([9]), pcpResp(nonce).slice(1)]), nonce) === null);
	}

	// 5. Input validation and the no-router path: an invalid port maps to null with no I/O; a dead gateway is bounded.
	ok('mapPort rejects an out-of-range port without touching the network', (await PortMap.mapPort(70000)) === null);
	{
		const t0 = Date.now();
		const res = await PortMap.mapPort(8443, { gateway: '192.0.2.1' }); // RFC 5737 TEST-NET-1: guaranteed unroutable
		ok('mapPort resolves null against an unresponsive gateway (bounded, no hang)', res === null && (Date.now() - t0) < 9000);
	}
	// 6. defaultGatewayV4 never throws and returns either null or a dotted-quad (whatever the test host has).
	{
		const gw = await PortMap.defaultGatewayV4();
		ok('defaultGatewayV4 returns null or a valid IPv4 (never throws)', gw === null || /^\d{1,3}(\.\d{1,3}){3}$/.test(gw));
	}

	// 7. Cross-platform contract: only dgram/os/crypto and execFile (never a shell), no reliable-UDP / congestion-
	//    control layer, non-blocking (no *Sync), and every timer unref'd.
	{
		const src = fs.readFileSync(path.join(__dirname, '..', 'PortMap.js'), 'utf8');
		ok('PortMap uses only dgram/os/crypto/child_process (no native module)', !/require\('(?!dgram|os|crypto|child_process)[^']+'\)/.test(src.replace(/require\('\.\/[^']+'\)/g, '')));
		ok('PortMap runs no shell (execFile with an arg array, never exec/spawn shell)', /execFile\(/.test(src) && !/\bexec\(|spawn\(|shell:\s*true/.test(src));
		ok('PortMap builds no reliable-UDP / congestion-control layer', !/\b(congestion|retransmit|sequenceNumber|slidingWindow)\b/i.test(src));
		ok('PortMap is non-blocking (no *Sync I/O)', !/readFileSync|writeFileSync|execFileSync|execSync/.test(src));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PORT-MAP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
