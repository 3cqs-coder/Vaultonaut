'use strict';
// lib/test/dnsorder.js — DnsOrder.prefer(argv) runs at the very top of startup, before any network module loads, to
// pick the outbound DNS result order (default ipv4first, so a host with flaky IPv6 does not take outbound features
// down). A parse regression could throw at boot (breaking the crash-proof start) or silently mis-set the resolver.
// It had no test. This pins the parse and the fail-safe, by stubbing dns.setDefaultResultOrder to capture the value.
// Pure and offline; it restores the real dns function afterward.
//
// Run:  node lib/test/dnsorder.js

const dns = require('dns');
const DnsOrder = require('../DnsOrder');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Capture what prefer() would set, without actually changing the process resolver order.
const real = dns.setDefaultResultOrder;
let captured;
function run(argv) { captured = undefined; dns.setDefaultResultOrder = (v) => { captured = v; }; try { DnsOrder.prefer(argv); } finally { dns.setDefaultResultOrder = real; } }

try {
	run(['--dns-order', 'ipv6first']);
	ok('a separate --dns-order value is applied', captured === 'ipv6first');

	run(['--dns-order=verbatim']);
	ok('the --dns-order=value form is applied', captured === 'verbatim');

	run([]);
	ok('the default when unset is ipv4first', captured === 'ipv4first');

	run(['--dns-order', 'IPv4First']);
	ok('the value is case-insensitive', captured === 'ipv4first');

	run(['--dns-order', 'nonsense']);
	ok('an unknown value is ignored (resolver order left untouched)', captured === undefined);

	// A trailing flag with no value must not throw and must keep the safe default.
	let threw = false;
	try { run(['--dns-order']); } catch (_) { threw = true; }
	ok('a --dns-order flag with no value does not throw and keeps ipv4first', !threw && captured === 'ipv4first');

	// argv-only: an environment variable must never influence the order (config is CLI-only across the project).
	const savedEnv = process.env.DNS_ORDER;
	process.env.DNS_ORDER = 'ipv6first';
	run([]);
	ok('an environment variable does not influence the order', captured === 'ipv4first');
	if (savedEnv === undefined) delete process.env.DNS_ORDER; else process.env.DNS_ORDER = savedEnv;
} finally {
	dns.setDefaultResultOrder = real; // belt-and-suspenders: never leave the stub installed
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DNS-ORDER CHECKS PASSED'));
process.exit(failures ? 1 : 0);
