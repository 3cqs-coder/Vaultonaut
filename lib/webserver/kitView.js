'use strict';
// lib/webserver/kitView.js — a short-lived, in-memory holder and endpoint for a just-generated Recovery Kit.
//
// The kit can carry a one-time recovery key, so it is NEVER written to disk and NEVER returned in the API JSON. The
// POST that builds it stashes the HTML here and returns only a random token; the kit is then served at
// GET /kit-view?token=… for a short window and dropped. It is deliberately viewable more than once within that
// window — a few minutes is enough to print it and to re-print or re-save if the first attempt is cancelled — after
// which its TTL elapses and it is pruned from memory. Serving it from a real URL (rather than the API JSON) lets it
// render under its OWN kit-appropriate CSP: the kit is a self-contained page with inline styles, which the app's
// strict style-src would strip inside a srcdoc/blob frame (those inherit the embedder's CSP; a document loaded from a
// URL uses its own response CSP). One token URL therefore serves BOTH a normal browser window and the desktop app's
// in-app viewer — a WebView cannot open a separate window — from one code path. The short-lived random token is the
// capability, so the route is mounted BEFORE the login gate and works even from a browser window that has no session cookie.
//
// Factored out so a test drives the exact same handler the web server mounts.

const crypto = require('crypto');

function createKitView({ ttlMs = 5 * 60 * 1000, now = () => Date.now() } = {}) {
	const views = new Map(); // token -> { html, exp }

	// Hold a kit and return its token. The kit is viewable until its short TTL elapses — a few minutes is enough to
	// print it, and to print or re-save more than once — after which it is pruned. Opportunistically prunes anything
	// already past its TTL on each new stash, so nothing lingers in memory beyond the window.
	function stash(html) {
		const t = now();
		for (const [k, v] of views) if (v.exp <= t) views.delete(k);
		const token = crypto.randomBytes(32).toString('base64url');
		views.set(token, { html: String(html == null ? '' : html), exp: t + ttlMs });
		return token;
	}

	// Drop every entry past its TTL. stash() already prunes opportunistically, but a kit stashed and then never
	// followed by another stash would otherwise hold its HTML (which can carry a one-time recovery key) in memory past
	// the window. The web server calls this on its periodic health tick so nothing sensitive lingers on a quiet service.
	function sweep() { const t = now(); for (const [k, v] of views) if (v.exp <= t) views.delete(k); }

	// Is this token still valid (present and unexpired)? Used to gate the desktop "open in browser" action so it only
	// ever opens one of our own live kit URLs — never an arbitrary caller-supplied address.
	function has(token) { const e = token ? views.get(token) : null; return !!(e && e.exp > now()); }

	// Serve the kit under a restrictive, kit-appropriate CSP, or a friendly expired page once its window has passed.
	function handler(req, res) {
		const token = String((req.query && req.query.token) || '');
		const entry = token ? views.get(token) : null;
		res.setHeader('Cache-Control', 'no-store');
		if (!entry || entry.exp <= now()) {
			if (entry) views.delete(token); // drop an expired entry when we notice it
			return res.status(410).type('html').send('<!doctype html><meta charset="utf-8"><body style="font:15px/1.5 system-ui,sans-serif;padding:2rem;color:#333">This Recovery Kit view has expired. Create the kit again from the app.</body>');
		}
		// The kit is self-contained: inline styles, images as data URIs, no scripts and no outbound requests.
		res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:");
		res.setHeader('X-Content-Type-Options', 'nosniff');
		res.setHeader('Referrer-Policy', 'no-referrer');
		res.type('html').send(entry.html);
	}

	return { stash, has, handler, sweep, _size: () => views.size };
}

module.exports = { createKitView };
