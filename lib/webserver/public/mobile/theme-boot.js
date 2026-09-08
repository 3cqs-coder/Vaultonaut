/* Apply the saved theme before first paint, so a pinned light/dark/sepia choice does not flash the wrong theme on
   load. The mobile viewer uses the SAME theme model and the same 'vdisk-theme' key as the desktop interface (each
   device keeps its own choice in its own browser storage). A same-origin script, allowed by the strict
   script-src 'self' policy; the main script re-applies the same value idempotently. */
(function () {
	try {
		var t = localStorage.getItem('vdisk-theme');
		if (t === 'light' || t === 'dark' || t === 'sepia' || t === 'auto') {
			document.documentElement.setAttribute('data-theme', t);
		}
	} catch (e) { /* private mode or blocked storage — fall back to the default data-theme in the markup */ }
})();
