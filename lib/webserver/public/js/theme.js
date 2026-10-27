'use strict';
/* js/theme.js — the ONE theme model for every Vaultonaut surface.
   It owns the storage key, the four-choice cycle, the labels, the pre-paint application of the saved choice, and the
   browser-chrome color. The desktop interface and the phone viewer both load this file, so their theme behavior cannot
   drift. It runs in the <head> before the stylesheets paint, so a pinned light, dark, or sepia choice never flashes the
   wrong theme. The color tokens themselves live in css/theme.css; a drift test compares this file's CHROME map with
   that stylesheet. */
(function () {
	var root = typeof window !== 'undefined' ? window : this;
	var doc = typeof document !== 'undefined' ? document : null;
	var KEY = 'vdisk-theme';
	var ORDER = ['auto', 'light', 'dark', 'sepia'];
	var LABELS = { auto: 'Theme: match system', light: 'Theme: light', dark: 'Theme: dark', sepia: 'Theme: sepia' };
	// The page background each resolved theme paints. Must match --bg in css/theme.css; the themedrift test proves it.
	var CHROME = { light: '#f4f6fb', dark: '#0e1117', sepia: '#f4ecdf' };

	function normalize(t) { return ORDER.indexOf(t) >= 0 ? t : 'auto'; }
	function saved() {
		try { return normalize(localStorage.getItem(KEY)); } catch (_) { return 'auto'; } // private mode or blocked storage
	}
	function systemDark() {
		try { return !!(root.matchMedia && root.matchMedia('(prefers-color-scheme: dark)').matches); } catch (_) { return false; }
	}
	function resolved(t) { t = normalize(t); return t === 'auto' ? (systemDark() ? 'dark' : 'light') : t; }
	function apply(t) { if (doc && doc.documentElement) doc.documentElement.setAttribute('data-theme', normalize(t)); }
	// Keep the browser/OS chrome color in step with the resolved theme. The computed body background is authoritative
	// once the stylesheet has loaded; before that (the pre-paint call) use the CHROME map. The Apple status-bar style is
	// reset on every change too, so a switch from dark to light does not leave white glyphs over a light bar.
	function syncChrome() {
		if (!doc) return;
		var t = resolved(doc.documentElement ? (doc.documentElement.getAttribute('data-theme') || saved()) : saved());
		var color = CHROME[t] || CHROME.light;
		try {
			var bg = root.getComputedStyle && doc.body ? root.getComputedStyle(doc.body).backgroundColor : '';
			if (bg && bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') color = bg;
		} catch (_) {}
		try { var meta = doc.querySelector('meta[name="theme-color"]'); if (meta) meta.setAttribute('content', color); } catch (_) {}
		try {
			var bar = doc.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
			if (bar) bar.setAttribute('content', t === 'dark' ? 'black-translucent' : 'default');
		} catch (_) {}
	}
	function boot() { apply(saved()); syncChrome(); }
	function cycle() {
		var cur = normalize(doc && doc.documentElement ? (doc.documentElement.getAttribute('data-theme') || saved()) : saved());
		var next = ORDER[(ORDER.indexOf(cur) + 1) % ORDER.length];
		apply(next);
		try { localStorage.setItem(KEY, next); } catch (_) {} // persist is best-effort
		syncChrome();
		return next;
	}
	// Follow a live light/dark system flip while the saved choice is "auto". addListener is the older-Safari fallback.
	function watchSystem() {
		try {
			var mq = root.matchMedia && root.matchMedia('(prefers-color-scheme: dark)');
			if (!mq) return;
			if (mq.addEventListener) mq.addEventListener('change', syncChrome);
			else if (mq.addListener) mq.addListener(syncChrome);
		} catch (_) {}
	}

	root.VaultTheme = { KEY: KEY, ORDER: ORDER, LABELS: LABELS, CHROME: CHROME, normalize: normalize, saved: saved, resolved: resolved, apply: apply, syncChrome: syncChrome, boot: boot, cycle: cycle, watchSystem: watchSystem };
	boot();
})();
