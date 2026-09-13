/* Apply the saved theme before first paint.
   Without this, a user who pinned light, dark, or sepia while their system is set the other way sees a brief flash of
   the wrong theme on every load, because the main script only runs at the end of the body. This runs in the <head>
   (a same-origin script, allowed by the strict script-src 'self' policy) and sets data-theme up front. It is
   deliberately tiny and self-contained, and the main script re-applies the same value idempotently. */
(function () {
	var t = 'auto';
	try {
		var saved = localStorage.getItem('vdisk-theme');
		if (saved === 'light' || saved === 'dark' || saved === 'sepia' || saved === 'auto') {
			t = saved;
			document.documentElement.setAttribute('data-theme', t);
		}
	} catch (e) { /* private mode or blocked storage — fall back to the default data-theme in the markup */ }
	// When this interface is opened from a PHONE on the network, set the browser-chrome color to match the resolved
	// theme BEFORE first paint, so a light or sepia choice does not flash the dark default. These literals mirror the
	// --bg tokens in app.css; app.js re-syncs the meta from the computed background after load. Harmless in the desktop
	// app's own window (no browser chrome). 'auto' follows the OS setting.
	try {
		var dark = false;
		try { dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches; } catch (e2) {}
		var color = t === 'dark' ? '#0e1117' : t === 'sepia' ? '#f4ecdf' : t === 'light' ? '#f4f6fb' : (dark ? '#0e1117' : '#f4f6fb');
		var meta = document.querySelector('meta[name="theme-color"]');
		if (meta) meta.setAttribute('content', color);
	} catch (e3) { /* leave the markup default */ }
})();
