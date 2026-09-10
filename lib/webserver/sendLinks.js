'use strict';
// lib/webserver/sendLinks.js — an in-memory holder for "Send" links: a way to hand ONE item to someone with a
// link that expires, can be opened only a limited number of times, and (optionally) needs a link password. It
// mirrors the kitView pattern (a small typed store plus a handler a test can drive), and shares nothing with the
// vault's own keys.
//
// Zero-knowledge for the recipient: what is stored here is CIPHERTEXT, sealed under a fresh random key that lives
// ONLY in the link's URL fragment (never sent to the server) and is discarded here the instant the ciphertext is
// stored. So this process cannot read a stored send back — only someone holding the link can. The store is bounded,
// everything is swept on expiry, and each read is counted so a "view once" link really opens once.

const crypto = require('crypto');

const MAX_ENTRIES = 200;                 // a generous ceiling so a local user cannot grow the store without bound
const MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024; // a Send holds one small item; refuse anything larger (no memory blowup)

function createSendStore({ now = () => Date.now() } = {}) {
	const sends = new Map(); // id -> { ciphertext, meta, exp, maxViews, views, pwHash }

	function sweep() { const t = now(); for (const [k, v] of sends) if (v.exp <= t) sends.delete(k); }

	// Stash one sealed item and return its id. `ciphertext` is base64 (iv|ct|tag) sealed under the caller's random
	// key; `meta` is small, non-secret display info (a label + kind) shown before decrypting. `ttlMs` and `maxViews`
	// bound the link; `pwHash` (optional) is the SHA-256 of a link password the recipient must supply.
	function create({ ciphertext, meta = {}, ttlMs, maxViews, pwHash = null } = {}) {
		sweep();
		const ct = String(ciphertext == null ? '' : ciphertext);
		if (!ct) throw new Error('Nothing to send.');
		if (Buffer.byteLength(ct, 'utf8') > MAX_CIPHERTEXT_BYTES) throw new Error('This item is too large to send as a link.');
		if (sends.size >= MAX_ENTRIES) throw new Error('Too many active send links — let some expire, then try again.');
		const ttl = Math.max(60 * 1000, Math.min(30 * 24 * 60 * 60 * 1000, Number(ttlMs) || 7 * 24 * 60 * 60 * 1000)); // 1 min … 30 days, default 7 days
		const views = Math.max(1, Math.min(1000, Number(maxViews) || 1)); // default: open once
		const id = crypto.randomBytes(16).toString('base64url');
		sends.set(id, { ciphertext: ct, meta: meta && typeof meta === 'object' ? meta : {}, exp: now() + ttl, maxViews: views, views: 0, pwHash: pwHash ? String(pwHash) : null });
		return { id, expiresAt: now() + ttl, maxViews: views };
	}

	function info(id) { sweep(); const e = sends.get(String(id || '')); if (!e) return null; return { needsPassword: !!e.pwHash, meta: e.meta, remaining: Math.max(0, e.maxViews - e.views), expiresAt: e.exp }; }

	// Redeem one view. Fail-closed: unknown/expired/exhausted -> { gone:true }; wrong password -> { badPassword:true }.
	// A correct redemption returns the ciphertext + meta and counts the view, deleting the entry once exhausted so a
	// "view once" link cannot be replayed and nothing lingers past its useful life.
	function redeem(id, password) {
		sweep();
		const e = sends.get(String(id || ''));
		if (!e || e.exp <= now() || e.views >= e.maxViews) { if (e) sends.delete(String(id)); return { gone: true }; }
		if (e.pwHash) {
			const got = crypto.createHash('sha256').update(String(password == null ? '' : password), 'utf8').digest('hex');
			// constant-time compare so a wrong link password cannot be guessed by timing
			if (got.length !== e.pwHash.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(e.pwHash))) return { badPassword: true };
		}
		e.views += 1;
		const out = { ciphertext: e.ciphertext, meta: e.meta, remaining: Math.max(0, e.maxViews - e.views) };
		if (e.views >= e.maxViews) sends.delete(String(id));
		return out;
	}

	function revoke(id) { return sends.delete(String(id || '')); }
	function clearAll() { sends.clear(); }

	return { create, info, redeem, revoke, clearAll, sweep, _size: () => sends.size, MAX_CIPHERTEXT_BYTES };
}

module.exports = { createSendStore };
