'use strict';
// lib/webserver/kitView.js — a one-time, in-memory holder and endpoint for a just-generated Recovery Kit.
//
// The kit can carry a one-time recovery key, so it is NEVER written to disk and NEVER returned in the API JSON. The
// POST that builds it stashes the HTML here and returns only a random token; the kit is then served exactly ONCE at
// GET /kit-view?token=… and dropped. Serving it from a real URL (rather than the API JSON) lets it render under its
// OWN kit-appropriate CSP: the kit is a self-contained page with inline styles, which the app's strict style-src
// would strip inside a srcdoc/blob frame (those inherit the embedder's CSP; a document loaded from a URL uses its own
// response CSP). One token URL therefore serves BOTH a normal browser window and the desktop app's in-app viewer —
// a WebView cannot open a separate window — from one code path. The single-use token is the capability, so the route
// is mounted BEFORE the login gate and works even from a browser window that has no session cookie.
//
// Factored out so a test drives the exact same handler the web server mounts.

const crypto = require('crypto');

function createKitView({ ttlMs = 5 * 60 * 1000, now = () => Date.now() } = {}) {
	const views = new Map(); // token -> { html, exp }

	// Hold a kit for a single view and return its token. Opportunistically prunes anything left unopened past its TTL,
	// so an abandoned kit never lingers in memory.
	function stash(html) {
		const t = now();
		for (const [k, v] of views) if (v.exp <= t) views.delete(k);
		const token = crypto.randomBytes(32).toString('base64url');
		views.set(token, { html: String(html == null ? '' : html), exp: t + ttlMs });
		return token;
	}

	// Serve the kit ONCE under a restrictive, kit-appropriate CSP, or a friendly expired page. The token is consumed
	// (deleted) whether or not it was valid, so a guessed or replayed token reveals nothing and a real one works once.
	function handler(req, res) {
		const token = String((req.query && req.query.token) || '');
		const entry = token ? views.get(token) : null;
		views.delete(token);
		res.setHeader('Cache-Control', 'no-store');
		if (!entry || entry.exp <= now()) {
			return res.status(410).type('html').send('<!doctype html><meta charset="utf-8"><body style="font:15px/1.5 system-ui,sans-serif;padding:2rem;color:#333">This Recovery Kit view has expired or was already opened. Create the kit again from the app.</body>');
		}
		// The kit is self-contained: inline styles, images as data URIs, no scripts and no outbound requests.
		res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:");
		res.setHeader('X-Content-Type-Options', 'nosniff');
		res.setHeader('Referrer-Policy', 'no-referrer');
		res.type('html').send(entry.html);
	}

	return { stash, handler, _size: () => views.size };
}

module.exports = { createKitView };
