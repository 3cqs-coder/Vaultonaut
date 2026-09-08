'use strict';
// lib/UiAuth.js — authentication for the local web interface, used only when a UI password is set
// (see the web server). Dependency-free: the session cookie is a compact signed token (HMAC-SHA256
// over a JSON payload, the same construction as a JWT) verified with pure Node crypto, and the
// password itself is hashed with the vault's own memory-hard key-derivation so no new primitive is
// introduced. The password verifier and the signing secret are persisted by the caller; this module
// is stateless and only does the crypto.
//
// The default web interface still requires no login at all — it binds to loopback and is single-user.
// This module activates only when the operator sets a password (mandatory before binding to a
// network address), so a machine that exposes the UI beyond its own loopback is never left open.

const crypto = require('crypto');
const Kdf = require('./Kdf');
const Common = require('./Common');

const COOKIE_NAME = 'vd_session';
const SESSION_TTL_SEC = 12 * 3600; // a login lasts 12 hours, then the browser must sign in again

// ── Password hashing (delegates to the vault's Argon2id KDF) ──────────────────
// Stored shape: { params, verifier } — params carry the random salt and cost, verifier is the
// base64 derived value. Verification is constant-time. Reusing the vault KDF means the UI password
// gets the same memory-hard treatment as a vault password, with no second implementation to trust.
async function hashPassword(plain) {
	const params = Kdf.defaultParams('standard');
	const verifier = await Kdf.deriveSecret(String(plain), params);
	return { params, verifier };
}
async function verifyPassword(plain, stored) {
	if (!stored || !stored.params || !stored.verifier) return false;
	let derived;
	try { derived = await Kdf.deriveSecret(String(plain), stored.params); }
	catch (_) { return false; }
	return Common.timingSafeEqual(derived, stored.verifier);
}

// A fresh random signing secret. Rotating it (on a password change or a log-out-everywhere) instantly
// invalidates every outstanding session, because their signatures no longer verify.
function newSecret() { return crypto.randomBytes(32).toString('hex'); }

// ── Signed session token (HMAC-SHA256, no external dependency) ────────────────
function b64url(buf) {
	return (typeof buf === 'string' ? Buffer.from(buf) : buf).toString('base64url'); // padding-free base64url, the codebase's idiom
}
function signSession(secret, ttlSec = SESSION_TTL_SEC) {
	const now = Math.floor(Date.now() / 1000);
	const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
	const body = b64url(JSON.stringify({ iat: now, exp: now + ttlSec }));
	const sig = b64url(crypto.createHmac('sha256', secret).update(header + '.' + body).digest());
	return header + '.' + body + '.' + sig;
}
function verifySession(token, secret) {
	try {
		const [header, body, sig] = String(token || '').split('.');
		if (!header || !body || !sig) return null;
		const expected = b64url(crypto.createHmac('sha256', secret).update(header + '.' + body).digest());
		if (!Common.timingSafeEqual(sig, expected)) return null;
		const payload = JSON.parse(Buffer.from(body, 'base64url').toString()); // the body was encoded base64url; decode it the same way (Node's base64 is lenient, but match the encoding exactly)
		if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
		return payload;
	} catch (_) { return null; }
}

// ── Cookie helpers ────────────────────────────────────────────────────────────
function parseCookies(header) {
	const out = {};
	if (!header) return out;
	for (const part of String(header).split(';')) {
		const i = part.indexOf('=');
		if (i === -1) continue;
		const k = part.slice(0, i).trim();
		if (!k) continue;
		// A malformed percent-escape (e.g. "%zz") makes decodeURIComponent throw. Never let a bad cookie value
		// crash request parsing (which would surface as a 500 instead of a clean "unauthenticated") — skip it.
		// The session cookie itself is base64url with no percent-escapes, so a real session is never affected.
		try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch (_) {}
	}
	return out;
}
// The session cookie is HttpOnly (unreadable to script, so an injected script can't steal it),
// SameSite=Strict (never sent on a cross-site request, so it can't be used for CSRF), and Secure
// whenever the connection is TLS (so it never travels in the clear).
function setCookieHeader(token, { secure } = {}) {
	const flags = [COOKIE_NAME + '=' + encodeURIComponent(token), 'HttpOnly', 'Path=/', 'SameSite=Strict', 'Max-Age=' + SESSION_TTL_SEC];
	if (secure) flags.push('Secure');
	return flags.join('; ');
}
function clearCookieHeader({ secure } = {}) {
	const flags = [COOKIE_NAME + '=', 'HttpOnly', 'Path=/', 'SameSite=Strict', 'Max-Age=0'];
	if (secure) flags.push('Secure');
	return flags.join('; ');
}
function sessionFromRequest(req, secret) {
	const token = parseCookies(req.headers && req.headers.cookie)[COOKIE_NAME];
	return token ? verifySession(token, secret) : null;
}

module.exports = {
	COOKIE_NAME, SESSION_TTL_SEC,
	hashPassword, verifyPassword, newSecret,
	signSession, verifySession,
	parseCookies, setCookieHeader, clearCookieHeader, sessionFromRequest
};
