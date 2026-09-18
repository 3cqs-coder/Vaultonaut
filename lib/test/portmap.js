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

	// 4b. NAT-PMP external-address (op 0): the request is the 2-byte {version 0, op 0} probe, a valid response parses to
	//     the WAN IPv4, and a wrong version/opcode/non-zero result or a short packet fail closed to null.
	{
		const req = P.natpmpExtRequest();
		ok('NAT-PMP external-address request is {version 0, op 0} (2 bytes)', req.length === 2 && req.readUInt8(0) === 0 && req.readUInt8(1) === 0);
		const good = Buffer.alloc(12); good.writeUInt8(0, 0); good.writeUInt8(128, 1); good.writeUInt16BE(0, 2); good.writeUInt32BE(1, 4); good[8] = 203; good[9] = 0; good[10] = 113; good[11] = 9;
		ok('NAT-PMP external-address parses the WAN IPv4', P.natpmpExtParse(good) === '203.0.113.9');
		const badOp = Buffer.from(good); badOp.writeUInt8(129, 1);
		ok('NAT-PMP external-address rejects a mismatched opcode', P.natpmpExtParse(badOp) === null);
		const badRes = Buffer.from(good); badRes.writeUInt16BE(3, 2);
		ok('NAT-PMP external-address rejects a non-zero result code', P.natpmpExtParse(badRes) === null);
		ok('NAT-PMP external-address rejects a short packet', P.natpmpExtParse(Buffer.alloc(8)) === null);
	}
	// 4c. isPublicIPv4 only advertises a genuinely internet-reachable address: it accepts a public IPv4 and rejects
	//     private (RFC 1918), CGNAT (RFC 6598), loopback, link-local, multicast/reserved, and malformed input.
	{
		ok('isPublicIPv4 accepts a public address', PortMap.isPublicIPv4('203.0.113.9') === true && PortMap.isPublicIPv4('8.8.8.8') === true);
		const priv = ['10.0.0.1', '192.168.1.1', '172.16.5.4', '172.31.255.255', '100.64.0.1', '127.0.0.1', '169.254.1.1', '0.0.0.0', '224.0.0.1', '255.255.255.255'];
		ok('isPublicIPv4 rejects private/CGNAT/loopback/link-local/reserved', priv.every((ip) => PortMap.isPublicIPv4(ip) === false));
		ok('isPublicIPv4 rejects malformed input', ['', null, undefined, 'nope', '1.2.3', '1.2.3.4.5', '256.1.1.1'].every((ip) => PortMap.isPublicIPv4(ip) === false));
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

	// 6b. The /proc/net/route parser (the Linux `ip`-absent fallback). CI usually reaches the gateway via `ip route`,
	//     so the byte-reversal and flag checks here would otherwise never run. Pin them against fixtures. The header
	//     row is skipped; the default row is Destination 00000000 with Flags RTF_UP|RTF_GATEWAY (0x0003); the Gateway
	//     column is a little-endian hex IPv4, so 0101A8C0 -> 192.168.1.1 and 0102A8C0 -> 192.168.2.1.
	{
		const header = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n';
		const ppr = P.parseProcNetRoute;
		ok('parseProcNetRoute reverses the little-endian gateway to a dotted quad', ppr(header + 'eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n') === '192.168.1.1');
		ok('parseProcNetRoute picks the default row past a non-default one', ppr(header + 'eth0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\neth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n') === '192.168.2.1');
		ok('parseProcNetRoute returns null when there is no default (00000000) row', ppr(header + 'eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n') === null);
		ok('parseProcNetRoute returns null when the default route is not a gateway (RTF_GATEWAY unset)', ppr(header + 'eth0\t00000000\t0101A8C0\t0001\t0\t0\t0\t00000000\t0\t0\t0\n') === null);
		ok('parseProcNetRoute returns null when the default route is down (RTF_UP unset)', ppr(header + 'eth0\t00000000\t0101A8C0\t0002\t0\t0\t0\t00000000\t0\t0\t0\n') === null);
		ok('parseProcNetRoute returns null on a malformed gateway field', ppr(header + 'eth0\t00000000\tZZZZ\t0003\t0\t0\t0\t00000000\t0\t0\t0\n') === null);
		ok('parseProcNetRoute returns null on empty input', ppr('') === null && ppr(null) === null);
	}

	// 7. Cross-platform contract: only core node modules (dgram/os/fs/crypto and execFile — never a shell), no
	//    reliable-UDP / congestion-control layer, non-blocking (no *Sync), and every timer unref'd. `fs` is used only
	//    for the read-only, async /proc/net/route gateway fallback on Linux; it is core, not native or third-party.
	{
		const src = fs.readFileSync(path.join(__dirname, '..', 'PortMap.js'), 'utf8');
		ok('PortMap uses only core node modules dgram/os/fs/crypto/child_process (no third-party or native module)', !/require\('(?!(?:dgram|os|fs|crypto|child_process)')[^']+'\)/.test(src.replace(/require\('\.\/[^']+'\)/g, '')));
		ok('PortMap runs no shell (execFile with an arg array, never exec/spawn shell)', /execFile\(/.test(src) && !/\bexec\(|spawn\(|shell:\s*true/.test(src));
		ok('PortMap builds no reliable-UDP / congestion-control layer', !/\b(congestion|retransmit|sequenceNumber|slidingWindow)\b/i.test(src));
		ok('PortMap is non-blocking (no *Sync I/O)', !/readFileSync|writeFileSync|execFileSync|execSync/.test(src));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PORT-MAP CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
