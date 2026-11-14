'use strict';
// lib/DnsOrder.js — choose the DNS result order for all outbound connections, applied at startup BEFORE any
// network-using module is loaded, so every later request inherits it.
//
// Why this exists: Node 17+ resolves DNS "verbatim" by default, which often tries a host's IPv6 address first.
// On a machine whose IPv6 routing is broken or intermittently flapping — common on VPS and cloud hosts — that
// first attempt hangs or fails (ETIMEDOUT / ECONNREFUSED) and surfaces as a generic "fetch failed", taking
// outbound features down (downloading the bundled engine, reaching a cloud vault, a trusted-timestamp request, a
// relay hop) even though IPv4 works perfectly. Preferring IPv4 makes those resilient to flaky IPv6 WITHOUT
// disabling it: on an IPv6-only host the resolver still returns and uses IPv6 addresses.
//
// It affects only OUTBOUND resolution (dns.lookup), never how the local web interface binds. Configured by a
// command-line argument only, never an environment variable, like everything else here:
//   --dns-order <ipv4first | ipv6first | verbatim>   (default: ipv4first)
function prefer(argv) {
	try {
		let order = 'ipv4first';
		const a = Array.isArray(argv) ? argv : [];
		for (let i = 0; i < a.length; i++) {
			if (a[i] === '--dns-order' && a[i + 1]) order = String(a[i + 1]).toLowerCase();
			else if (String(a[i]).startsWith('--dns-order=')) order = String(a[i]).split('=')[1].toLowerCase();
		}
		if (order === 'ipv4first' || order === 'ipv6first' || order === 'verbatim') require('dns').setDefaultResultOrder(order);
	} catch (_) { /* an older runtime without setDefaultResultOrder, or a bad value: keep the runtime's default order */ }
}

module.exports = { prefer };
