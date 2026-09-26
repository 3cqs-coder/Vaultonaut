'use strict';
// lib/test/vaultlan.js — the Vault-level LAN direct-transport glue (findPeerOnLan / preferLanUrl) on top of the
// LanDiscovery module. No engine, no spawned binary: it announces over loopback and asserts a peer resolves ONLY the
// node whose pinned certificate it already holds — the core security property (discovery adds no trust). It also
// pins, via source scan, that serveVault's LAN mode announces and that mirror/testPeer prefer the LAN address.
//
// Run:  node lib/test/vaultlan.js

const fs = require('fs');
const path = require('path');
const Vault = require('../Vault');
const Cert = require('../Cert');
const LanDiscovery = require('../LanDiscovery');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
let nextPort = 41200 + Math.floor(Math.random() * 1500);
const testPort = () => nextPort++;

async function main() {
	const { certPem } = Cert.generateSelfSigned('127.0.0.1');
	const fp = LanDiscovery.certFp(certPem);

	// 1. A peer resolves the node's live LAN address ONLY by matching its pinned cert fingerprint.
	{
		const port = testPort();
		const ann = LanDiscovery.announce({ nodeId: 'n1', port: 8443, fp, discoveryPort: port, targets: ['127.0.0.1'] });
		const url = await Vault.findPeerOnLan({ ca: certPem }, { timeoutMs: 1500, discoveryPort: port });
		ann.stop();
		ok('findPeerOnLan resolves the LAN url when the announced cert matches the pinned ca', url === 'https://127.0.0.1:8443/');
	}

	// 2. A node announcing a DIFFERENT cert than the one this peer pinned is never matched — no auto-trust.
	{
		const port = testPort();
		const other = Cert.generateSelfSigned('127.0.0.1').certPem; // the peer pinned this; the node announces certPem's fp
		const ann = LanDiscovery.announce({ nodeId: 'n2', port: 9000, fp, discoveryPort: port, targets: ['127.0.0.1'] });
		const url = await Vault.findPeerOnLan({ ca: other }, { timeoutMs: 700, discoveryPort: port });
		ann.stop();
		ok('findPeerOnLan ignores a node whose cert the peer did NOT pin (no auto-trust)', url === null);
	}

	// 3. A peer with no pinned cert can never be LAN-resolved (fail closed).
	ok('findPeerOnLan returns null for a peer with no pinned ca', (await Vault.findPeerOnLan({}, { timeoutMs: 150 })) === null);

	// 4. preferLanUrl swaps in the LAN address when discoverable, and returns the peer untouched otherwise.
	{
		const port = testPort();
		const ann = LanDiscovery.announce({ nodeId: 'n3', port: 7777, fp, discoveryPort: port, targets: ['127.0.0.1'] });
		const peer = { url: 'https://relay.example:20001/', user: 'vd', ca: certPem };
		const got = await Vault.findPeerOnLan(peer, { timeoutMs: 1500, discoveryPort: port });
		ann.stop();
		ok('the LAN url replaces the stored relay url when the node is on this network', got === 'https://127.0.0.1:7777/');
		// preferLanUrl uses the default (real) discovery port, so with nothing announcing there it must return the peer
		// unchanged — the stored/relay address stays the fallback.
		const unchanged = await Vault.preferLanUrl(peer);
		ok('preferLanUrl returns the peer unchanged (stored address) when not discoverable', unchanged === peer && !unchanged.viaLan);
	}

	// 5. Direct candidates in the connect code (Phase 2): round-trip + hard sanitization of untrusted entries.
	{
		const Vault = require('../Vault');
		const code = Vault.makePeerCode({ url: 'https://relay.example:20001/', user: 'vd', pass: 'p', ca: certPem, cand: [{ host: '192.168.1.5', port: 8443 }, { host: 'bad host', port: 8443 }, { host: '1.2.3.4', port: 70000 }, { host: '10.0.0.9', port: 9000 }] });
		const parsed = Vault.parsePeerCode(code);
		ok('parsePeerCode keeps only well-formed candidates (drops bad host / out-of-range port)',
			parsed.cand.length === 2 && parsed.cand[0].host === '192.168.1.5' && parsed.cand[1].host === '10.0.0.9');
		const old = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://x/', user: 'vd', pass: 'p', ca: certPem }));
		ok('a connect code without candidates parses to an empty candidate list (1.0.0-compatible)', Array.isArray(old.cand) && old.cand.length === 0);
		// Unsafe candidate addresses must be dropped — probing them is useless or a reflection primitive.
		const mixed = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://x/', ca: certPem, cand: [
			{ host: '192.168.1.5', port: 8443 }, { host: '203.0.113.7', port: 9000 },   // LAN + public: kept
			{ host: '127.0.0.1', port: 8443 }, { host: '224.0.0.1', port: 8443 }, { host: '255.255.255.255', port: 8443 },
			{ host: '169.254.1.1', port: 8443 }, { host: '0.0.0.0', port: 8443 }, { host: '::1', port: 8443 } ] }));
		ok('unsafe candidates (loopback/multicast/broadcast/link-local/unspecified) are dropped',
			mixed.cand.length === 2 && mixed.cand[0].host === '192.168.1.5' && mixed.cand[1].host === '203.0.113.7');

		// The optional hole-punch coordination hint round-trips; a malformed hint is dropped; and its absence is fine.
		const withSig = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://relay:1/', ca: certPem, sig: { hub: 'relay.example.com:7443', node: 'abc123', cred: 'deadBEEF0123' } }));
		ok('parsePeerCode round-trips a well-formed hole-punch coordination hint (sig)', !!withSig.sig && withSig.sig.hub === 'relay.example.com:7443' && withSig.sig.node === 'abc123' && withSig.sig.cred === 'deadBEEF0123');
		const badSig = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://relay:1/', ca: certPem, sig: { hub: 'has space', node: 'n', cred: 'not-hex!' } }));
		ok('a malformed coordination hint is dropped (no whitespace, hex credential)', badSig.sig === undefined);
		ok('a connect code without a coordination hint parses fine (older/LAN codes)', old.sig === undefined && Array.isArray(old.cand));
		// SSRF classing: the hub in a hole-punch hint becomes a raw TCP connect target, so an internal/metadata address is
		// rejected while a LAN address and a hostname still work (blind server-side request forgery guard).
		const metaSig = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://relay:1/', ca: certPem, sig: { hub: '169.254.169.254:80', node: 'n', cred: 'abcd' } }));
		ok('a coordination hint whose hub is an internal/metadata address is dropped (blind-SSRF guard)', metaSig.sig === undefined);
		const lanSig = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://relay:1/', ca: certPem, sig: { hub: '192.168.1.10:7443', node: 'n', cred: 'abcd' } }));
		ok('a coordination hint whose hub is a LAN address is kept (LAN hubs still work)', !!lanSig.sig && lanSig.sig.hub === '192.168.1.10:7443');
		const hostSig = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://relay:1/', ca: certPem, sig: { hub: 'hub.example.com:7443', node: 'n', cred: 'abcd' } }));
		ok('a coordination hint whose hub is a hostname is kept', !!hostSig.sig && hostSig.sig.hub === 'hub.example.com:7443');
		// Carrier-grade NAT (100.64/10) candidates are dropped too (parity with the connect-target classing).
		const cgnat = Vault.parsePeerCode(Vault.makePeerCode({ url: 'https://x/', ca: certPem, cand: [{ host: '100.64.1.1', port: 8443 }, { host: '203.0.113.7', port: 8443 }] }));
		ok('a carrier-grade NAT (100.64/10) candidate is dropped while a public one is kept', cgnat.cand.length === 1 && cgnat.cand[0].host === '203.0.113.7');

		// Backward-compatibility guard (1.0.0 must keep reading connect codes): the code stays v:1, a minimal reader that
		// looks only at url/user/pass/ca still gets them intact even when sig/cand are present, and absent optional fields
		// are OMITTED (never null) so an old client's shape checks never trip.
		const full = Vault.makePeerCode({ url: 'https://relay:2/', user: 'vd', pass: 'pw', ca: certPem, cand: [{ host: '203.0.113.7', port: 9000 }], sig: { hub: 'h:7443', node: 'nid', cred: 'abc123' } });
		const raw = JSON.parse(Buffer.from(full, 'base64').toString('utf8'));
		ok('the connect code stays v:1 and a 1.0.0-style reader still gets url/user/pass/ca', raw.v === 1 && raw.url === 'https://relay:2/' && raw.user === 'vd' && raw.pass === 'pw' && raw.ca === certPem);
		const minimal = JSON.parse(Buffer.from(Vault.makePeerCode({ url: 'https://x/', user: 'u', pass: 'p' }), 'base64').toString('utf8'));
		ok('absent optional fields are omitted from the connect code, not set to null (old shape checks stay safe)', !('sig' in minimal) && !('cand' in minimal) && !('ca' in minimal));
	}

	// 6. preferReachableUrl probes advertised candidates and prefers a REACHABLE direct hop; otherwise the peer is
	//    returned unchanged so the stored (relay) address stays the fallback. ca is deliberately not a real cert here,
	//    so the LAN-discovery step short-circuits and only the candidate probe runs.
	{
		const Vault = require('../Vault');
		const net = require('net');
		const srv = net.createServer(() => {});
		await new Promise((r) => srv.listen(0, '127.0.0.1', r));
		const port = srv.address().port;
		const reachable = await Vault.preferReachableUrl({ url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port }] });
		srv.close();
		ok('preferReachableUrl prefers a reachable candidate (direct hop)', reachable.url === 'https://127.0.0.1:' + port + '/' && reachable.viaDirect === true);
		const peer = { url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port: 1 }] };
		const unreached = await Vault.preferReachableUrl(peer);
		ok('preferReachableUrl leaves the peer unchanged when no candidate is reachable (relay fallback)', unreached === peer);

		// Happy-Eyeballs pacing: a dead candidate listed FIRST must not stall the reachable one behind it. With an
		// unreachable entry ahead of a live one, the live one is still selected — and promptly (a dead candidate brings
		// the next probe forward instead of serially waiting out the full per-probe timeout).
		const srv2 = net.createServer(() => {});
		await new Promise((r) => srv2.listen(0, '127.0.0.1', r));
		const port2 = srv2.address().port;
		const t0 = Date.now();
		const raced = await Vault.preferReachableUrl({ url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port: 1 }, { host: '127.0.0.1', port: port2 }] });
		const elapsed = Date.now() - t0;
		srv2.close();
		ok('preferReachableUrl selects a reachable candidate listed after a dead one (Happy-Eyeballs), without a serial stall',
			raced.url === 'https://127.0.0.1:' + port2 + '/' && raced.viaDirect === true && elapsed < 1400);

		// Transport-mode gating (Auto / Relay only / Direct only). 'relay' skips every direct attempt even when a
		// candidate is reachable; 'direct' refuses the relay fallback and throws when no direct hop exists; 'auto' falls
		// back to the relay (peer unchanged). The punch mechanism itself is covered end to end by the hole-punch test.
		const srv3 = net.createServer(() => {}); await new Promise((r) => srv3.listen(0, '127.0.0.1', r)); const port3 = srv3.address().port;
		const relayMode = await Vault.preferReachableUrl({ url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port: port3 }] }, { mode: 'relay' });
		ok('relay mode returns the stored address with no direct attempt (even if a candidate is reachable)', relayMode.url === 'https://relay:1/' && !relayMode.viaDirect);
		srv3.close();
		let threw = false; try { await Vault.preferReachableUrl({ url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port: 1 }] }, { mode: 'direct' }); } catch (e) { threw = !!e.noDirect; }
		ok('direct-only mode throws when no direct hop is available (no relay fallback)', threw);
		const autoFb = await Vault.preferReachableUrl({ url: 'https://relay:1/', ca: 'x', cand: [{ host: '127.0.0.1', port: 1 }] }, { mode: 'auto' });
		ok('auto mode falls back to the relay when no direct hop is reachable', autoFb.url === 'https://relay:1/');
	}

	// 7. Source pins: serveVault's LAN mode announces on the LAN, and the connect paths prefer a reachable address.
	{
		const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
		ok('serveVault has a LAN mode that announces via LanDiscovery', /const lanMode = /.test(src) && /LanDiscovery\.announce\(\{ nodeId:/.test(src));
		ok('a LAN serve uses a cert covering the LAN IPs (Cert.ensureLanCert)', /Cert\.ensureLanCert\(/.test(src));
		ok('testPeer and mirror prefer the LAN address (preferLanUrl)', (src.match(/await preferLanUrl\(/g) || []).length >= 2);
		// A failed punch is put on cooldown so a symmetric-NAT peer does not cost the full punch budget every sync.
		ok('preferReachableUrl uses a punch cooldown (not re-attempted every sync)', /punchOnCooldown\(sig\.node\)/.test(src) && /notePunchFailed\(sig\.node\)/.test(src));
		// The serving node bounds concurrent punch answers AND live tunnels, and tears the tunnels down when it stops.
		ok('a serving node bounds punch answers and live tunnels and tears them down on stop', /punchAnswers >= MAX_PUNCH_ANSWERS \|\| nodeTunnels\.size >= MAX_NODE_TUNNELS/.test(src) && /for \(const h of nodeTunnels\) \{ try \{ h\.stop\(\)/.test(src));
		// The signal credential is decrypted only at use, so it is never held in the clear beyond the moment of connect.
		ok('the signal credential is stored encrypted and decrypted only at use', /decCred\(sig\.cred, await machineCredKey\(\)\)/.test(src));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL VAULT-LAN CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
