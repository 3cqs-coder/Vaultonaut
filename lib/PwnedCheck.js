'use strict';
// lib/PwnedCheck.js — a privacy-preserving "has this password appeared in a breach?" lookup, using the public
// Pwned Passwords range API with k-anonymity. Only the FIRST 5 HEX CHARACTERS of the password's SHA-1 (20 bits)
// ever leave this machine; the password and its full hash never do. The server returns every hash suffix under
// that prefix, and the match is completed HERE, locally. `Add-Padding: true` makes every response a random size
// so a passive network observer cannot fingerprint the requested bucket from the encrypted response length.
//
// SHA-1 here is only a non-secret dictionary index into the breach corpus (that is what the corpus is keyed by),
// not a security primitive — so its cryptographic weakness is irrelevant. The destination is a FIXED https host,
// never caller-supplied, so this is not an SSRF lever. The lookup is best-effort: any network error yields 0
// (treated as "not known to be breached") rather than throwing, so a breach check can never wedge a health scan.

const crypto = require('crypto');
const Common = require('./Common');

const HIBP_BASE = 'https://api.pwnedpasswords.com/range/';
const MAX_RESPONSE_BYTES = 1024 * 1024; // a padded bucket is ~800-1000 short lines; cap generously and reject anything absurd

// How many times a password appears in the breach corpus (0 = not found / unknown). `cache` (a Map) memoizes the
// per-prefix response for a scan so many items sharing a prefix cost one request; a FAILED lookup is deliberately
// NOT cached, so a transient error never poisons the whole scan into false "not breached" for a shared prefix — a
// later item retries. `onFail()` (optional) is called when a lookup could not complete, so the caller can report the
// scan as incomplete rather than silently downgrade the result. `base` is overridable for tests.
async function count(password, { cache = null, timeoutMs = 6000, base = HIBP_BASE, onFail = null } = {}) {
	const sha1 = crypto.createHash('sha1').update(String(password == null ? '' : password), 'utf8').digest('hex').toUpperCase();
	const prefix = sha1.slice(0, 5), suffix = sha1.slice(5);
	let body = cache ? cache.get(prefix) : null;
	if (body == null) {
		try {
			body = await Common.fetchWithTimeout(base + prefix, { headers: { 'Add-Padding': 'true', 'User-Agent': 'vaultonaut-health' } }, Math.max(1000, timeoutMs), (res) => Common.readCappedText(res, MAX_RESPONSE_BYTES));
		} catch (_) { body = null; }
		if (body == null) { if (onFail) { try { onFail(); } catch (_) {} } return 0; } // failed: report incomplete, do NOT cache (retryable), treat as "unknown"
		if (cache) cache.set(prefix, body);
	}
	// Each line is "SUFFIX:COUNT". Padded (fake) rows carry count 0 and must be ignored, or a random suffix could
	// look like a hit. Compare the suffix case-insensitively (the corpus is upper-case, and so is ours).
	for (const line of body.split('\n')) {
		const t = line.trim(); if (!t) continue;
		const idx = t.indexOf(':'); if (idx < 0) continue;
		if (t.slice(0, idx).toUpperCase() === suffix) { const n = parseInt(t.slice(idx + 1), 10) || 0; return n; }
	}
	return 0;
}

module.exports = { count, HIBP_BASE };
