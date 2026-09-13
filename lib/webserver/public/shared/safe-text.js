'use strict';
// Shared front-end text sanitizer — the single HTML-escape used by every browser bundle (desktop and mobile), so the
// clients can never drift to different sanitizing. A divergence could let one client under-escape an injected file name
// or label and open a cross-site-scripting hole the other does not have. There is no bundler here (the app serves
// static files and the mobile client is a PWA), so this attaches one tiny global that each page loads with a <script>
// tag BEFORE its app code. Written in ES5 (var, function expressions — no arrow functions) so it runs on the oldest
// browser the mobile client supports.
(function (root) {
	// Replace control and bidi/format characters that could hide or spoof text in a rendered name with the Unicode
	// replacement character, THEN escape the five markup-significant characters. The strip runs FIRST so a stripped
	// character can never reintroduce markup. Living here once keeps every client's escaping identical.
	var UNSAFE_DISPLAY = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
	var MARKUP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
	function escapeHtml(s) {
		return String(s == null ? '' : s).replace(UNSAFE_DISPLAY, '\uFFFD').replace(/[&<>"']/g, function (c) { return MARKUP[c]; });
	}
	root.VaultSafe = { escapeHtml: escapeHtml, UNSAFE_DISPLAY: UNSAFE_DISPLAY };
})(typeof window !== 'undefined' ? window : this);
