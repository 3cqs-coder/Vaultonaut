'use strict';
// lib/test/lanaddresses.js — the LAN address ranking that decides the phone QR's preferred host. The operating
// system's interface order is not meaningful: macOS lists VM and Internet-Sharing bridges before the real Wi-Fi
// interface, which produced a QR address no phone could route to. The ranker must put physical Wi-Fi/Ethernet first,
// keep virtual/VPN/container addresses as alternatives, and push link-local last. Pure and synthetic, so it runs
// identically on macOS, Linux, and Windows with no network or mount driver.
//
// Run:  node -r ./lib/test/_setup.js lib/test/lanaddresses.js

const fs = require('fs');
const path = require('path');
const Lan = require('../net/LanAddresses');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL LAN-ADDRESS CHECKS PASSED')); process.exit(failures ? 1 : 0); }

function main() {
	const mac = [
		{ family: 'IPv4', internal: false, address: '10.211.55.2', iface: 'bridge100' },
		{ family: 'IPv4', internal: false, address: '192.168.1.54', iface: 'en0' },
		{ family: 'IPv4', internal: false, address: '10.241.100.205', iface: 'feth3147' },
		{ family: 'IPv4', internal: false, address: '10.8.0.2', iface: 'utun3' },
		{ family: 'IPv4', internal: false, address: '169.254.10.20', iface: 'en5' },
		{ family: 'IPv4', internal: true, address: '127.0.0.1', iface: 'lo0' },
	];
	const r = Lan.rank(mac);
	ok('a physical Wi-Fi/Ethernet address ranks first', r[0].address === '192.168.1.54' && r[0].iface === 'en0');
	ok('link-local addresses rank last', r[r.length - 1].address === '169.254.10.20');
	ok('a VM bridge follows the physical address', r.findIndex(x => x.iface === 'bridge100') > 0);
	ok('a VM/emulated interface follows the physical address', r.findIndex(x => x.iface === 'feth3147') > 0);
	ok('a VPN tunnel follows the physical address', r.findIndex(x => x.iface === 'utun3') > 0);
	ok('an internal address is never offered', !r.some(x => x.address === '127.0.0.1'));

	const win = [
		{ family: 'IPv4', internal: false, address: '172.20.0.1', iface: 'vethernet0' },
		{ family: 'IPv4', internal: false, address: '192.168.0.20', iface: 'Wi-Fi' },
		{ family: 'IPv4', internal: false, address: '10.0.0.5', iface: 'vmnet8' },
		{ family: 'IPv4', internal: false, address: '192.168.56.1', iface: 'vboxnet0' },
	];
	const wr = Lan.rank(win);
	ok('Windows Wi-Fi ranks above the virtual adapters', wr[0].address === '192.168.0.20' && wr.slice(1).every(x => x.iface !== 'Wi-Fi'));
	ok('a Windows Ethernet adapter ranks as physical', Lan.score('Ethernet', '192.168.1.10') > Lan.score('vethernet0', '172.20.0.1'));

	const linux = [
		{ family: 'IPv4', internal: false, address: '172.17.0.1', iface: 'docker0' },
		{ family: 'IPv4', internal: false, address: '192.168.1.30', iface: 'enp3s0' },
		{ family: 'IPv4', internal: false, address: '10.0.0.1', iface: 'wlp2s0' },
	];
	const lr = Lan.rank(linux);
	ok('Linux physical enp/wlp interfaces rank above docker', lr[0].iface !== 'docker0' && lr[1].iface !== 'docker0' && lr[2].iface === 'docker0');

	const dup = Lan.rank([
		{ family: 'IPv4', internal: false, address: '192.168.1.54', iface: 'en0' },
		{ family: 'IPv4', internal: false, address: '192.168.1.54', iface: 'bridge100' },
	]);
	ok('the same address on two interfaces appears once', dup.length === 1 && dup[0].iface === 'en0');

	const byObject = Lan.fromNetworkInterfaces({
		en0: [{ family: 'IPv4', internal: false, address: '192.168.1.54' }],
		bridge100: [{ family: 'IPv4', internal: false, address: '10.211.55.2' }],
	});
	ok('fromNetworkInterfaces carries the interface name', byObject[0].iface === 'en0' && byObject[1].iface === 'bridge100');

	const certSrc = fs.readFileSync(path.join(__dirname, '..', 'net', 'Cert.js'), 'utf8');
	ok('the certificate address set uses the one ranked source', /LanAddresses\.rankedIPv4s\(\)/.test(certSrc) && /lanAddressDetails/.test(certSrc));
	const webSrc = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('the mobile-start route returns interface-labelled hosts from the same ranked source', /out\.hostDetails = detailsFor/.test(webSrc) && /Cert\.lanAddressDetails\(\)/.test(webSrc));
	return done();
}
main();
