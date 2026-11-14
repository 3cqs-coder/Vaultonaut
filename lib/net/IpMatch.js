'use strict';
// lib/IpMatch.js — a small, dependency-free IP allow/deny matcher for the web interface's optional access list.
//
// When the interface is exposed to a network (an explicit --bind, which already forces a password and TLS), an
// operator can further restrict which client addresses may even reach it. This matches a client IP against allow
// and deny lists of exact addresses, CIDR ranges, and simple IPv4 wildcards, for both IPv4 and IPv6.
//
// It is applied to the REAL socket address only, never a forwarded header a client could forge, and loopback is
// always exempt so a mistake in the list can never lock the local user out of their own machine.
//
//   evaluate(ip, { allow, deny }, { allowLoopback }) -> { allowed, reason }
//
// Rules: a deny match always wins; an empty allow list means "allow all" (still subject to deny). Accepted rule
// forms: exact IPv4/IPv6, CIDR for either family ("10.0.0.0/8", "2001:db8::/32"), and an IPv4 wildcard/partial
// ("192.168.1.*", "192.168.", "10.*"). An unparseable address or rule simply never matches (fail-closed).

// Strip an IPv6 zone id and fold an IPv4-mapped IPv6 address to its IPv4 form, so an address compares equal
// regardless of the form it arrives in. Returns '' for anything that is not a string.
function normalizeIp(ip) {
	if (typeof ip !== 'string') return '';
	let s = ip.trim().toLowerCase();
	const pct = s.indexOf('%');
	if (pct > -1) s = s.slice(0, pct);                                   // drop fe80::1%eth0 zone id
	if (s.startsWith('::ffff:')) {
		if (s.indexOf('.') > -1) return s.slice(7);                      // dotted mapped form: ::ffff:1.2.3.4 -> 1.2.3.4
		// Hex-compressed mapped form (::ffff:7f00:1): fold it to dotted IPv4 too, so an IPv4 rule (or the loopback
		// exemption) applies to it exactly as it would to the dotted form. Without this, the hex form parses as a
		// distinct 128-bit value and slips past a version-4 allow/deny rule. Parse the whole address and, only when
		// the top 96 bits are the v4-mapped prefix (::ffff:), re-encode the low 32 bits as dotted.
		const big = ipv6ToBig(s);
		if (big !== null && (big >> 32n) === 0xffffn) {
			const lo = big & 0xffffffffn;
			return [(lo >> 24n) & 0xffn, (lo >> 16n) & 0xffn, (lo >> 8n) & 0xffn, lo & 0xffn].join('.');
		}
	}
	return s;
}

// Parse an IPv4 string to a BigInt in [0, 2^32), or null.
function ipv4ToBig(s) {
	const parts = s.split('.');
	if (parts.length !== 4) return null;
	let n = 0n;
	for (const p of parts) {
		if (!/^\d{1,3}$/.test(p)) return null;
		const v = Number(p);
		if (v > 255) return null;
		n = (n << 8n) + BigInt(v);
	}
	return n;
}

// Parse an IPv6 string to a BigInt in [0, 2^128), or null. Handles "::" expansion and a trailing IPv4 tail.
function ipv6ToBig(s) {
	if (s.indexOf(':') === -1) return null;
	let str = s;
	const lastColon = str.lastIndexOf(':');
	const tail = str.slice(lastColon + 1);
	if (tail.indexOf('.') > -1) {                                        // a dotted IPv4 tail -> two hex groups
		const v4 = ipv4ToBig(tail);
		if (v4 === null) return null;
		str = str.slice(0, lastColon + 1) + ((v4 >> 16n) & 0xffffn).toString(16) + ':' + (v4 & 0xffffn).toString(16);
	}
	const halves = str.split('::');
	if (halves.length > 2) return null;                                  // at most one "::"
	const head = halves[0] ? halves[0].split(':') : [];
	const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;
	let groups;
	if (back === null) { groups = head; }                                // no "::" -> must be exactly 8 groups
	else {
		const missing = 8 - (head.length + back.length);
		if (missing < 1) return null;                                    // "::" must stand for at least one zero group
		groups = head.concat(Array(missing).fill('0')).concat(back);
	}
	if (groups.length !== 8) return null;
	let n = 0n;
	for (const g of groups) {
		if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
		n = (n << 16n) + BigInt(parseInt(g, 16));
	}
	return n;
}

// Parse an address of either family -> { version, big } or null.
function parseIp(ip) {
	const s = normalizeIp(ip);
	if (!s) return null;
	if (s.indexOf(':') > -1) { const big = ipv6ToBig(s); return big === null ? null : { version: 6, big }; }
	const big = ipv4ToBig(s); return big === null ? null : { version: 4, big };
}

// Parse a CIDR rule -> { version, network, prefix, bits } or null.
function parseCidr(rule) {
	if (typeof rule !== 'string' || rule.indexOf('/') === -1) return null;
	const [base, lenStr] = rule.trim().split('/');
	const ip = parseIp(base);
	if (!ip || !/^\d{1,3}$/.test(lenStr)) return null;
	const prefix = Number(lenStr), bits = ip.version === 4 ? 32 : 128;
	if (prefix < 0 || prefix > bits) return null;
	return { version: ip.version, network: ip.big, prefix, bits };
}

// Convert an IPv4 wildcard/partial ("192.168.1.*", "192.168.", "10.*") to a CIDR string, or null. Only leading
// concrete octets are allowed; four concrete octets is an exact address, returned unchanged.
function v4PartialToCidr(rule) {
	let s = rule.trim().toLowerCase();
	if (s.endsWith('.')) s = s.slice(0, -1);
	const octets = s.split('.');
	if (octets.length < 1 || octets.length > 4) return null;
	const concrete = [];
	let seenWild = false;
	for (const o of octets) {
		if (o === '*' || o === '') { seenWild = true; continue; }
		if (seenWild) return null;                                       // a concrete octet after a wildcard
		if (!/^\d{1,3}$/.test(o) || Number(o) > 255) return null;
		concrete.push(o);
	}
	if (!concrete.length) return null;
	if (concrete.length === 4) return concrete.join('.');               // fully specified -> exact address
	return concrete.concat(Array(4 - concrete.length).fill('0')).join('.') + '/' + (concrete.length * 8);
}

// Expand any accepted rule to a canonical rule string (an exact IP or a CIDR), or null.
function expandRule(rule) {
	if (typeof rule !== 'string' || rule.trim() === '') return null;
	const r = rule.trim().toLowerCase();
	if (r.indexOf('/') > -1) return parseCidr(r) ? r : null;
	if (r.indexOf(':') === -1 && (r.indexOf('*') > -1 || r.endsWith('.') || r.split('.').length < 4)) return v4PartialToCidr(r);
	return parseIp(r) ? r : null;
}

// True if a single rule matches the address.
function matchOne(ip, rule) {
	const addr = parseIp(ip);
	const canonical = expandRule(rule);
	if (!addr || !canonical) return false;
	if (canonical.indexOf('/') > -1) {
		const cidr = parseCidr(canonical);
		if (!cidr || cidr.version !== addr.version) return false;
		if (cidr.prefix === 0) return true;                             // prefix 0 matches all; avoid a full-width shift
		const shift = BigInt(cidr.bits - cidr.prefix);
		return (addr.big >> shift) === (cidr.network >> shift);
	}
	const other = parseIp(canonical);
	return !!other && other.version === addr.version && other.big === addr.big;
}

// True if the address matches ANY rule in the list.
function matchesAny(ip, list) { return Array.isArray(list) && list.some(r => matchOne(ip, r)); }

// Loopback (127.0.0.0/8 or ::1) — always exempt so a bad list can never lock out local access.
function isLoopback(ip) { return matchOne(ip, '127.0.0.0/8') || matchOne(ip, '::1'); }
// Whether an address parses at all as IPv4 or IPv6 (after normalization). Used to fail CLOSED on garbage input.
function isParseable(ip) { const s = normalizeIp(ip); return ipv4ToBig(s) !== null || ipv6ToBig(s) !== null; }

// Decide whether an address is allowed given { allow, deny }. A deny match always wins; an empty allow list means
// "allow all" (still subject to deny); opts.allowLoopback short-circuits loopback to allowed.
function evaluate(ip, rules, opts) {
	rules = rules || {}; opts = opts || {};
	const allow = rules.allow || [], deny = rules.deny || [];
	if (opts.allowLoopback && isLoopback(ip)) return { allowed: true, reason: 'loopback' };
	// Fail CLOSED on a peer address that does not parse, whenever a filter is in force: a deny-only list would
	// otherwise let an unparseable address through (it matches no deny rule), which defeats the point of the list.
	// With no rules configured at all there is nothing to enforce, so this does not change the unfiltered case.
	if ((allow.length || deny.length) && !isParseable(ip)) return { allowed: false, reason: 'unparseable' };
	if (matchesAny(ip, deny)) return { allowed: false, reason: 'denied' };
	if (allow.length && !matchesAny(ip, allow)) return { allowed: false, reason: 'not-allowed' };
	return { allowed: true, reason: 'ok' };
}

// Parse a comma/space-separated rule string (a CLI argument) into a clean list; every entry that is not a valid
// rule is dropped, so a typo can never silently widen access. Returns { list, dropped } for caller feedback.
function parseList(spec) {
	const list = [], dropped = [];
	for (const raw of String(spec == null ? '' : spec).split(/[,\s]+/)) {
		const r = raw.trim();
		if (!r) continue;
		if (expandRule(r)) list.push(r); else dropped.push(r);
	}
	return { list, dropped };
}

module.exports = { normalizeIp, parseIp, matchOne, matchesAny, isLoopback, evaluate, parseList, expandRule };
