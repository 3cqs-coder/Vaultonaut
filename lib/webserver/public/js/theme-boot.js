/* Apply the saved theme before first paint.
   Without this, a user who pinned light, dark, or sepia while their system is set the other way sees a brief flash of
   the wrong theme on every load, because the main script only runs at the end of the body. This runs in the <head>
   (a same-origin script, allowed by the strict script-src 'self' policy) and sets data-theme up front. It is
   deliberately tiny and self-contained, and the main script re-applies the same value idempotently. */
(function () {
	try {
		var t = localStorage.getItem('vdisk-theme');
		if (t === 'light' || t === 'dark' || t === 'sepia' || t === 'auto') {
			document.documentElement.setAttribute('data-theme', t);
		}
	} catch (e) { /* private mode or blocked storage — fall back to the default data-theme in the markup */ }
})();
