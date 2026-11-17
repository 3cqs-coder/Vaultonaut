'use strict';
// lib/net/LanAddresses.js — rank this machine's non-internal IPv4 addresses by how likely a phone on the same local
// network can reach them. The operating system's order is not meaningful: macOS commonly lists VM and Internet-Sharing
// bridges before the real Wi-Fi/Ethernet interface, which produced a QR address no phone could route to. The ranker
// puts physical Wi-Fi/Ethernet first, keeps VM/VPN/container addresses as alternatives, and pushes link-local last.
// The UI also lets the user choose an address, so a multi-homed machine (Wi-Fi + Ethernet + VPN) is never a guess.
//
// Pure and deterministic: the caller passes os.networkInterfaces() (or synthetic entries in a test), so the ranking is
// unit-testable on every platform with no network or OS calls.
const os = require('os');

// Physical LAN interfaces across macOS, Linux, and Windows. Windows keys are friendly names such as "Wi-Fi" and
// "Ethernet"; macOS uses en0/en1; Linux uses eth0/wlan0 or similar.
const PHYSICAL = /^(en\w*|eth\w*|wl\w*|wlan\w*|wireless|wi-?fi|ethernet|local area connection)/i;
// Virtual, bridged, VPN, container, and cellular interfaces. They stay in the list as alternatives, but never win by
// default over a real Wi-Fi/Ethernet address.
const VIRTUAL = /^(bridge|feth|vmnet|vboxnet|vethernet|hyper-?v|loopback|utun|tun\d|tap\d|ppp\d|awdl|llw|anpi|pdp_ip|gif|stf|docker|veth|br-|virbr|lxcbr|cni|flannel|cali|kube|ham\d+|wintun|ipsec|vpn)/i;
const LINK_LOCAL = /^169\.254\./;

function score(name, address) {
	let s = 0;
	if (PHYSICAL.test(name)) s += 100;
	if (/^en0$/i.test(name)) s += 20;                 // macOS primary Wi-Fi/Ethernet
	if (/^(eth0|wlan0)$/i.test(name)) s += 15;        // common Linux primary
	if (VIRTUAL.test(name)) s -= 100;
	if (LINK_LOCAL.test(address)) s -= 300; // always below a virtual bridge: a 169.254 address is not routable off-link
	return s;
}

// Normalize os.networkInterfaces() (or a synthetic list) into ranked { address, iface, score } records. Only
// non-internal IPv4 addresses are considered; duplicates (the same address on two interfaces) keep the best-ranked
// interface. The order is stable across calls, so a certificate's address set and the phone QR agree.
function rank(entries) {
	const rows = (entries || [])
		.filter(e => e && e.family === 'IPv4' && !e.internal && e.address)
		.map(e => ({ address: String(e.address), iface: String(e.iface || e.name || ''), score: score(String(e.iface || e.name || ''), String(e.address)) }))
		.sort((a, b) => b.score - a.score || a.iface.localeCompare(b.iface) || a.address.localeCompare(b.address));
	const seen = new Set();
	return rows.filter(r => (seen.has(r.address) ? false : (seen.add(r.address), true)));
}

// Build the ranked records from an interfaces object, defaulting to this machine.
function fromNetworkInterfaces(ifs) {
	const source = ifs || os.networkInterfaces();
	const entries = [];
	for (const [iface, list] of Object.entries(source || {})) {
		for (const a of list || []) entries.push({ ...a, iface });
	}
	return rank(entries);
}

function rankedIPv4s(ifs) { return fromNetworkInterfaces(ifs).map(r => r.address); }

module.exports = { rank, fromNetworkInterfaces, rankedIPv4s, score };
