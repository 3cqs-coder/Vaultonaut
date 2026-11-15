'use strict';
// Shared, language-agnostic text helpers used by the pure UI models (dashboard, devices, fleet) so they never build a
// sentence with "+" or assume English pluralization. A string is a whole template with {var} placeholders, and a count
// chooses a plural form by the LOCALE's rule (via Intl.PluralRules, with an ES5 n===1 fallback), so word order and
// pluralization are per-language. English-only catalogs ship today, but adding a language is just adding a key to a
// catalog — the models do not change. One source of these helpers for the frontend and the backend (Node tests).
// ES5 only (var, function expressions) so it runs on the oldest supported browser.
(function (root) {
	var LANGS = ['en'];

	// Replace {name} placeholders from vars; a missing var is left as-is (visible, never a crash). Non-destructive.
	function interp(tmpl, vars) {
		if (vars == null) return String(tmpl == null ? '' : tmpl);
		return String(tmpl == null ? '' : tmpl).replace(/\{(\w+)\}/g, function (m, k) { return (vars[k] != null) ? String(vars[k]) : m; });
	}

	// The plural CATEGORY for a count in a language: 'zero'|'one'|'two'|'few'|'many'|'other'. Uses Intl.PluralRules
	// where available; falls back to the English rule (one vs other) so it still runs where Intl is absent.
	function plural(lang, n) {
		n = Number(n); if (!isFinite(n)) n = 0;
		try { if (typeof Intl !== 'undefined' && Intl.PluralRules) return new Intl.PluralRules(lang || 'en').select(Math.abs(n)); } catch (e) {}
		return Math.abs(n) === 1 ? 'one' : 'other';
	}

	// Resolve a key from a catalog shaped { lang: { key: template } }, then interpolate. When vars.n is given, the key
	// is a plural base: it looks up "<key>_<category>" (e.g. vaults_one / vaults_other), falling back to "<key>_other"
	// then the bare key. A missing string returns the key itself, so it is visible in the UI rather than throwing.
	function t(cat, lang, key, vars) {
		var dict = (cat && (cat[lang] || cat.en)) || {};
		var tmpl = null;
		if (vars && vars.n != null) {
			var ctg = plural(lang, vars.n);
			tmpl = dict[key + '_' + ctg];
			if (tmpl == null) tmpl = dict[key + '_other'];
		}
		if (tmpl == null) tmpl = dict[key];
		if (tmpl == null) return key;
		return interp(tmpl, vars);
	}

	root.VaultI18n = { LANGS: LANGS, interp: interp, plural: plural, t: t };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultI18n;
