/* Apply the saved theme before first paint, so a pinned light/dark/sepia choice does not flash the wrong theme on
   load. The mobile viewer uses the SAME theme model and the same 'vdisk-theme' key as the desktop interface (each
   device keeps its own choice in its own browser storage). A same-origin script, allowed by the strict
   script-src 'self' policy; the main script re-applies the same value idempotently. */
(function () {
	var t = 'auto';
	try {
		var saved = localStorage.getItem('vdisk-theme');
		if (saved === 'light' || saved === 'dark' || saved === 'sepia' || saved === 'auto') {
			t = saved;
			document.documentElement.setAttribute('data-theme', t);
		}
	} catch (e) { /* private mode or blocked storage — fall back to the default data-theme in the markup */ }
	// Set the browser-chrome color (status bar / task switcher) to match the resolved theme BEFORE first paint, so a
	// light or sepia choice does not flash the dark default. These backgrounds mirror the --bg tokens in app.css; the
	// main script re-syncs the meta from the computed background after load and on a system light/dark change. 'auto'
	// follows the OS setting. Kept as literals so this runs with no dependency on the stylesheet being parsed yet.
	try {
		var dark = false;
		try { dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches; } catch (e2) {}
		var resolvedDark = t === 'dark' || (t === 'auto' && dark);
		var color = t === 'dark' ? '#0e1117' : t === 'sepia' ? '#f4ecdf' : t === 'light' ? '#f4f6fb' : (dark ? '#0e1117' : '#f4f6fb');
		var meta = document.querySelector('meta[name="theme-color"]');
		if (meta) meta.setAttribute('content', color);
		// On an installed iOS home-screen app, a dark theme reads best with the edge-to-edge translucent status bar
		// (white glyphs over the dark app); light and sepia keep the 'default' opaque bar with dark glyphs, which the
		// translucent style would render illegible over their near-white background. iOS reads this at launch, and this
		// runs before first paint, so the installed app gets the right bar for its current theme.
		var barMeta = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
		if (barMeta && resolvedDark) barMeta.setAttribute('content', 'black-translucent');
	} catch (e3) { /* leave the markup default */ }
})();
