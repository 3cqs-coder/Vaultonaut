'use strict';
// Shared catalog for the desktop interface's enumerable UI vocabulary — the small, fixed label maps app.js would
// otherwise hardcode (starting with the field-kind names in the item editor). It exists so these strings live in ONE
// place, translation-ready through the same shared i18n helper the pure models use, instead of scattered English
// literals that drift. Pure data + a resolver: no DOM, no network. Loaded with a <script> tag BEFORE app.js, and it
// also exports for require() in tests. ES5 (var, function expressions — no arrow functions) so it runs on the oldest
// supported browser. A string that is owned by a domain model (dashboard/devices/fleet) belongs in THAT model's
// catalog, not here; this is only for cross-cutting interface vocabulary with no single domain home.
(function (root) {
	var I18n = (typeof require === 'function') ? require('./i18n') : (root.VaultI18n || null);

	var STRINGS = {
		en: {
			// Field-kind display names for the item editor's type dropdown. The SET of kinds is owned by
			// secret-schema.js (its KINDS map); these are only the human labels, keyed by the same kind token.
			kind_text: 'Text', kind_secret: 'Secret', kind_password: 'Password', kind_multiline: 'Multi-line',
			kind_pin: 'PIN', kind_totp: 'One-time code (2FA)', kind_url: 'Website', kind_email: 'Email',
			kind_phone: 'Phone', kind_date: 'Date', 'kind_month-year': 'Month / year', kind_boolean: 'Yes / no',
			kind_number: 'Number',
			// Key-slot kind badges in the Keys dialog. The CSS class token stays in app.js (it styles the badge and is
			// not translatable); these are only the words shown on the badge, keyed by the slot's raw kind.
			keyKind_recovery: 'recovery', keyKind_device: 'device', keyKind_keyfile: 'keyfile',
			keyKind_readonly: 'read-only', keyKind_password: 'password',
			// Phone pairing: the address chooser and the reach guidance. The address values and interface names are
			// language-neutral data; only these labels are translated. The first address is the computer's main
			// Wi-Fi/Ethernet, which is what a phone on the same network needs.
			mobileNetworkAddress: 'Network address',
			mobileAddressHint: 'Choose the address for the network your phone is on. The first is this computer’s main Wi-Fi or Ethernet.',
			mobileReachSecure: 'Your phone can open this over your network — scan the code or enter the address above. Because it is a secure (https) address, it can also be added to the home screen and used offline. (It uses a self-signed certificate, so the phone shows a one-time warning to accept.)',
			mobileReachPlain: 'Your phone can open this over your network while connected — scan the code or enter the address above. For an offline, home-screen app, reach it over a secure https address (a reverse proxy, VPN, or tunnel with a real certificate).',
			mobileReachAlt: 'If the phone can’t connect, choose the address for the network it is on above. The first address is this computer’s main Wi-Fi or Ethernet; virtual machine, VPN, and container addresses follow.',
			// A short in-app helper, not a second guide: it points at the built-in guide (the README) for the full
			// paths. It deliberately names no port; the dialog shows the live address, so a port change cannot drift here.
			mobileOutsideHint: 'From outside this network, use a VPN, tunnel, or reverse proxy you run. To share a vault with family, use a team vault or a read link.',
			mobileOutsideHelp: 'Open the guide for remote access'
		}
	};
	function T(lang, key, vars) { return I18n ? I18n.t(STRINGS, lang, key, vars) : key; }
	function text(key, vars, lang) { return T(lang || 'en', key, vars); }

	// The display label for a field kind — one source, so the editor dropdown and any future surface agree and a locale
	// translates it in the catalog. An unknown kind falls back to the kind token itself (never a crash, never a raw
	// catalog key): i18n.t returns the key string when a label is missing, so a missing 'kind_x' is detected and the
	// bare kind is shown instead.
	function fieldKindLabel(kind, lang) {
		var key = 'kind_' + String(kind == null ? '' : kind);
		var s = T(lang, key);
		return (s === key) ? String(kind == null ? '' : kind) : s;
	}

	// The badge word for a key-slot kind. An unrecognized kind reads as "password" (its plain read-write meaning), the
	// same fallback the dialog has always shown — never a raw catalog key.
	function keyKindLabel(kind, lang) {
		var key = 'keyKind_' + String(kind == null ? '' : kind);
		var s = T(lang, key);
		return (s === key) ? T(lang, 'keyKind_password') : s;
	}

	root.VaultUIStrings = { fieldKindLabel: fieldKindLabel, keyKindLabel: keyKindLabel, text: text, STRINGS: STRINGS };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultUIStrings;
