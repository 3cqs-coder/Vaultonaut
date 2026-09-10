'use strict';
// lib/test/ipmatch.js — the IP allow/deny matcher for the exposed web interface's optional access list. Covers
// exact addresses, CIDR ranges, IPv4 wildcards, IPv6 (including IPv4-mapped and zone ids), the deny-wins and
// empty-allow-means-all rules, the loopback exemption, and the rule-list parser's rejection of junk. No engine
// or network needed.
//
// Run:  node lib/test/ipmatch.js

const M = require('../IpMatch');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const allowed = (ip, allow, deny, allowLoopback) => M.evaluate(ip, { allow: allow || [], deny: deny || [] }, { allowLoopback: !!allowLoopback }).allowed;

console.log('[normalization]');
ok('an IPv6 zone id is stripped', M.normalizeIp('fe80::1%eth0') === 'fe80::1');
ok('an IPv4-mapped IPv6 folds to IPv4', M.normalizeIp('::ffff:1.2.3.4') === '1.2.3.4');
ok('junk normalizes to empty', M.normalizeIp(12345) === '' && M.normalizeIp(null) === '');

console.log('[exact + CIDR + wildcard matching]');
ok('an exact IPv4 matches', allowed('192.168.1.5', ['192.168.1.5']));
ok('an exact IPv4 that differs does not match', !allowed('192.168.1.6', ['192.168.1.5']));
ok('a CIDR range matches an address inside it', allowed('10.4.4.4', ['10.0.0.0/8']));
ok('a CIDR range does not match an address outside it', !allowed('11.4.4.4', ['10.0.0.0/8']));
ok('an IPv4 wildcard matches', allowed('192.168.1.99', ['192.168.1.*']));
ok('an IPv4 wildcard does not match another subnet', !allowed('192.168.2.99', ['192.168.1.*']));
ok('a trailing-dot partial works like a wildcard', allowed('192.168.1.7', ['192.168.1.']));

console.log('[IPv6]');
ok('an IPv6 CIDR matches', allowed('2001:db8::1', ['2001:db8::/32']));
ok('an IPv6 CIDR does not match outside it', !allowed('2001:dead::1', ['2001:db8::/32']));
ok('an IPv4-mapped client matches an IPv4 rule', allowed('::ffff:10.1.2.3', ['10.0.0.0/8']));
ok('the HEX-compressed IPv4-mapped form also matches an IPv4 rule (folded, not slipped past)', allowed('::ffff:0a01:0203', ['10.0.0.0/8']));
ok('a hex-mapped client is caught by an IPv4 DENY rule', !M.evaluate('::ffff:cb00:7105', { deny: ['203.0.113.5'] }, {}).allowed); // ::ffff:cb00:7105 == 203.0.113.5
ok('a hex-mapped loopback folds and is exempt when allowLoopback is on', M.evaluate('::ffff:7f00:1', { deny: ['203.0.113.5'] }, { allowLoopback: true }).allowed === true);
ok('families do not cross-match (v4 rule vs v6 client)', !allowed('2001:db8::1', ['10.0.0.0/8']));

console.log('[fail closed on an unparseable peer]');
ok('an unparseable peer is DENIED when a deny-only list is in force (does not slip through)', M.evaluate('not-an-ip', { deny: ['203.0.113.5'] }, {}).allowed === false);
ok('an unparseable peer is DENIED when an allow list is in force', M.evaluate('not-an-ip', { allow: ['10.0.0.0/8'] }, {}).allowed === false);
ok('an unparseable peer is allowed only when NO list is configured (nothing to enforce)', M.evaluate('not-an-ip', {}, {}).allowed === true);

console.log('[allow/deny semantics]');
ok('a deny match always wins over an allow match', !allowed('10.0.0.5', ['10.0.0.0/8'], ['10.0.0.5']));
ok('an empty allow list means allow all (subject to deny)', allowed('8.8.8.8', [], []));
ok('an empty allow list still honors deny', !allowed('8.8.8.8', [], ['8.8.8.8']));
ok('a non-empty allow list rejects an address not in it', !allowed('8.8.8.8', ['10.0.0.0/8'], []));

console.log('[loopback exemption]');
ok('loopback IPv4 is exempt when allowLoopback is on', allowed('127.0.0.1', ['10.0.0.0/8'], [], true));
ok('loopback IPv6 is exempt when allowLoopback is on', allowed('::1', ['10.0.0.0/8'], [], true));
ok('loopback is NOT exempt when allowLoopback is off', !allowed('127.0.0.1', ['10.0.0.0/8'], [], false));
ok('a whole 127/8 address is treated as loopback', M.isLoopback('127.5.6.7') === true);

console.log('[rule-list parsing rejects junk, never silently widening]');
const pl = M.parseList('10.0.0.0/8, 192.168.1.*, not-an-ip, ::1 2001:db8::/32');
ok('valid rules are kept', pl.list.length === 4 && pl.list.includes('10.0.0.0/8') && pl.list.includes('2001:db8::/32'));
ok('an invalid rule is dropped and reported, not kept', pl.dropped.length === 1 && pl.dropped[0] === 'not-an-ip');
ok('an empty spec yields no rules', M.parseList('').list.length === 0 && M.parseList(null).list.length === 0);
// A malformed CIDR must not be accepted (it would otherwise widen access unexpectedly).
ok('a malformed CIDR prefix is rejected', M.parseList('10.0.0.0/999').list.length === 0);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL IP-MATCH CHECKS PASSED'));
process.exit(failures ? 1 : 0);
