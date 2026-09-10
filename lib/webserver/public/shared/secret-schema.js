/* secret-schema.js — the single source of truth for TYPED SECRET ITEMS, shared by the desktop editor and the
 * read-only viewer (in-app and phone) so the two can never drift. It defines the field-kind vocabulary, the
 * built-in templates (as DATA, so a new template is a data entry, not code), the otpauth/TOTP code generator,
 * and the copy-to-clipboard-with-auto-clear helper.
 *
 * Design (matches how mature managers stay future-proof): an item is a small stable core plus an ORDERED list
 * of typed fields. The `type` and each field `kind` are RENDER HINTS with graceful fallback — an unknown type
 * renders its fields generically, and an unknown kind renders as text (masked if the field's `secret` flag is
 * set) — so a newer item never breaks an older client and fields are never silently dropped. Masking is a
 * per-field flag defaulted from the kind, so any custom field can be concealed. Dates, PINs, and card numbers
 * are stored as STRINGS to avoid lossy coercion (leading zeros, locale). TOTP stores the otpauth secret, never
 * the momentary code, and the code is derived on the device with the browser's own audited HMAC (Web Crypto).
 *
 * Pure browser code: no dependencies, no Node. Runs the same in the desktop page and the mobile viewer. */
(function (root) {
	'use strict';

	// ---- field-kind vocabulary ----
	// secretDefault: masked unless the field overrides. The other traits drive input type and rendering.
	var KINDS = {
		text: { secretDefault: false },
		secret: { secretDefault: true },
		password: { secretDefault: true },
		multiline: { secretDefault: false, multiline: true },
		pin: { secretDefault: true, numeric: true },
		totp: { secretDefault: true, totp: true },
		url: { secretDefault: false, link: true },
		email: { secretDefault: false, email: true },
		phone: { secretDefault: false, tel: true },
		date: { secretDefault: false, date: true },
		'month-year': { secretDefault: false, month: true },
		boolean: { secretDefault: false, bool: true },
		number: { secretDefault: false, numeric: true }
	};
	function kindInfo(kind) { return KINDS[kind] || KINDS.text; } // unknown kind -> behave as text (forward-compatible)
	// A field is masked when it explicitly says so, else by the kind's default. One place so the editor and the
	// viewer always agree on what to conceal.
	function isSecret(field) { if (!field) return false; if (field.secret === true) return true; if (field.secret === false) return false; return !!kindInfo(field.kind).secretDefault; }

	// ---- templates (data, not code) ----
	// Each: { type, label, icon, fields: [ {kind, label, secret?} ] }. `note` (a free-text body) is always
	// available on every item, so it is not listed as a field. Ordering here is the on-screen order.
	var TEMPLATES = [
		{ type: 'login', label: 'Login', icon: '🔑', fields: [
			{ kind: 'text', label: 'Username' },
			{ kind: 'password', label: 'Password' },
			{ kind: 'totp', label: 'One-time code (2FA)' },
			{ kind: 'url', label: 'Website' } ] },
		{ type: 'note', label: 'Secure note', icon: '🗒️', fields: [] },
		{ type: 'card', label: 'Payment card', icon: '💳', fields: [
			{ kind: 'text', label: 'Cardholder name' },
			{ kind: 'secret', label: 'Card number' },
			{ kind: 'month-year', label: 'Expires' },
			{ kind: 'pin', label: 'Security code (CVV)' },
			{ kind: 'pin', label: 'Card PIN' } ] },
		{ type: 'identity', label: 'Identity', icon: '🪪', fields: [
			{ kind: 'text', label: 'Full name' },
			{ kind: 'email', label: 'Email' },
			{ kind: 'phone', label: 'Phone' },
			{ kind: 'text', label: 'Address' },
			{ kind: 'date', label: 'Date of birth' } ] },
		{ type: 'crypto', label: 'Crypto wallet', icon: '🪙', fields: [
			{ kind: 'text', label: 'Wallet address' },
			{ kind: 'multiline', label: 'Recovery phrase', secret: true },
			{ kind: 'pin', label: 'PIN' } ] },
		{ type: 'apikey', label: 'API credential', icon: '🔌', fields: [
			{ kind: 'text', label: 'Username / key ID' },
			{ kind: 'secret', label: 'API key / secret' },
			{ kind: 'url', label: 'Endpoint' },
			{ kind: 'date', label: 'Expires' } ] },
		{ type: 'ssh', label: 'SSH key', icon: '🖥️', fields: [
			{ kind: 'multiline', label: 'Private key', secret: true },
			{ kind: 'multiline', label: 'Public key' },
			{ kind: 'text', label: 'Fingerprint' },
			{ kind: 'secret', label: 'Passphrase' } ] },
		{ type: 'wifi', label: 'Wi-Fi network', icon: '📶', fields: [
			{ kind: 'text', label: 'Network name (SSID)' },
			{ kind: 'secret', label: 'Password' },
			{ kind: 'text', label: 'Security type' } ] },
		{ type: 'bank', label: 'Bank account', icon: '🏦', fields: [
			{ kind: 'text', label: 'Bank name' },
			{ kind: 'text', label: 'Account holder' },
			{ kind: 'text', label: 'Routing / sort code' },
			{ kind: 'secret', label: 'Account number' },
			{ kind: 'text', label: 'SWIFT / IBAN' },
			{ kind: 'pin', label: 'PIN' } ] },
		{ type: 'server', label: 'Server / database', icon: '🗄️', fields: [
			{ kind: 'text', label: 'Host' },
			{ kind: 'text', label: 'Port' },
			{ kind: 'text', label: 'Username' },
			{ kind: 'password', label: 'Password' },
			{ kind: 'url', label: 'Connection URL' } ] },
		{ type: 'license', label: 'Software license', icon: '🧾', fields: [
			{ kind: 'secret', label: 'License key' },
			{ kind: 'text', label: 'Version' },
			{ kind: 'email', label: 'Registered email' },
			{ kind: 'url', label: 'Download' } ] },
		{ type: 'passport', label: 'Passport / ID', icon: '📘', fields: [
			{ kind: 'secret', label: 'Document number' },
			{ kind: 'text', label: 'Full name' },
			{ kind: 'text', label: 'Nationality' },
			{ kind: 'date', label: 'Issued' },
			{ kind: 'date', label: 'Expires' } ] },
		{ type: 'membership', label: 'Membership', icon: '🎫', fields: [
			{ kind: 'text', label: 'Organization' },
			{ kind: 'text', label: 'Member ID' },
			{ kind: 'pin', label: 'PIN' } ] },
		{ type: 'medical', label: 'Medical record', icon: '➕', fields: [
			{ kind: 'text', label: 'Provider' },
			{ kind: 'text', label: 'Policy / member number' },
			{ kind: 'multiline', label: 'Details', secret: true } ] }
	];
	var TEMPLATE_BY_TYPE = {}; for (var i = 0; i < TEMPLATES.length; i++) TEMPLATE_BY_TYPE[TEMPLATES[i].type] = TEMPLATES[i];
	function templateFor(type) { return TEMPLATE_BY_TYPE[type] || null; }
	function iconFor(type) { var t = TEMPLATE_BY_TYPE[type]; return t ? t.icon : '🔒'; } // unknown type -> a neutral lock
	function labelFor(type) { var t = TEMPLATE_BY_TYPE[type]; return t ? t.label : (type ? String(type) : 'Item'); }

	function genId() { // stable per-field id; hex from crypto when present, else a timestamped fallback
		try { var b = new Uint8Array(6); (root.crypto || {}).getRandomValues(b); return Array.prototype.map.call(b, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
		catch (_) { return 'f' + Date.now().toString(16) + Math.floor(Math.random() * 1e6).toString(16); }
	}
	// A blank item for a chosen template: the template's field stubs expanded into empty, editable fields.
	function blankItem(type) {
		var tpl = templateFor(type) || templateFor('note');
		return {
			id: null, title: '', type: tpl.type, note: '',
			fields: (tpl.fields || []).map(function (f) { return { id: genId(), kind: f.kind, label: f.label, value: '', secret: f.secret === true ? true : (f.secret === false ? false : undefined) }; })
		};
	}

	// ---- base32 + TOTP (RFC 4226 / 6238), derived on the device ----
	function base32Decode(s) {
		var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		var clean = String(s || '').toUpperCase().replace(/[=\s-]/g, '');
		var bits = 0, val = 0, out = [];
		for (var i = 0; i < clean.length; i++) { var idx = A.indexOf(clean[i]); if (idx < 0) continue; val = (val << 5) | idx; bits += 5; if (bits >= 8) { bits -= 8; out.push((val >>> bits) & 0xff); } }
		return new Uint8Array(out);
	}
	// Accept a full otpauth:// URI or a bare base32 secret. Returns the parameters needed to derive a code.
	function parseTotp(value) {
		var v = String(value || '').trim();
		var cfg = { secret: '', algorithm: 'SHA1', digits: 6, period: 30, issuer: '', account: '' };
		if (/^otpauth:\/\//i.test(v)) {
			try {
				var u = new URL(v);
				var label = decodeURIComponent((u.pathname || '').replace(/^\/+/, ''));
				if (label.indexOf(':') >= 0) { cfg.issuer = label.split(':')[0]; cfg.account = label.split(':').slice(1).join(':'); } else { cfg.account = label; }
				var q = u.searchParams;
				cfg.secret = q.get('secret') || '';
				if (q.get('issuer')) cfg.issuer = q.get('issuer');
				if (q.get('algorithm')) cfg.algorithm = q.get('algorithm').toUpperCase();
				if (q.get('digits')) cfg.digits = Math.max(6, Math.min(10, parseInt(q.get('digits'), 10) || 6));
				if (q.get('period')) cfg.period = Math.max(5, Math.min(300, parseInt(q.get('period'), 10) || 30));
			} catch (_) { cfg.secret = ''; }
		} else { cfg.secret = v; }
		return cfg;
	}
	var HMAC_HASH = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
	// Compute the current TOTP code and how many seconds remain in its window. Async (Web Crypto HMAC). Rejects
	// if the secret is unusable or Web Crypto is unavailable (a non-secure context) — the caller shows a hint.
	function totpCode(cfg, nowMs) {
		var subtle = (root.crypto || {}).subtle;
		if (!subtle) return Promise.reject(new Error('secure context needed'));
		var key = base32Decode(cfg.secret);
		if (!key.length) return Promise.reject(new Error('no secret'));
		var period = cfg.period || 30, digits = cfg.digits || 6;
		var now = Math.floor((nowMs != null ? nowMs : Date.now()) / 1000);
		var counter = Math.floor(now / period);
		var msg = new Uint8Array(8);
		var c = counter;
		for (var i = 7; i >= 0; i--) { msg[i] = c & 0xff; c = Math.floor(c / 256); }
		var hash = HMAC_HASH[cfg.algorithm] || 'SHA-1';
		return subtle.importKey('raw', key, { name: 'HMAC', hash: hash }, false, ['sign'])
			.then(function (k) { return subtle.sign('HMAC', k, msg); })
			.then(function (sig) {
				var h = new Uint8Array(sig);
				var offset = h[h.length - 1] & 0x0f;
				var bin = ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
				var code = (bin % Math.pow(10, digits)).toString();
				while (code.length < digits) code = '0' + code;
				return { code: code, secondsRemaining: period - (now % period), period: period };
			});
	}

	// ---- copy to clipboard, then auto-clear ----
	// Copy a value and wipe the clipboard after a timeout so a secret does not linger. Best-effort: a browser
	// cannot read the clipboard back without a permission prompt, so it clears unconditionally after the delay;
	// and it cannot mark the entry "concealed" (macOS org.nspasteboard.ConcealedType) from a web page, so a
	// clipboard-history app may still capture it — a native path would be needed to prevent that.
	function copyToClipboard(text, opts) {
		opts = opts || {};
		var clearMs = opts.clearMs == null ? 20000 : opts.clearMs;
		if (!root.navigator || !navigator.clipboard || !navigator.clipboard.writeText) return Promise.reject(new Error('clipboard unavailable'));
		return navigator.clipboard.writeText(String(text == null ? '' : text)).then(function () {
			if (clearMs > 0) setTimeout(function () { try { navigator.clipboard.writeText('').catch(function () {}); } catch (_) {} }, clearMs);
			return true;
		});
	}

	// ---- generic AES-GCM open (Web Crypto) ----
	// Decrypt base64/base64url of iv(12)|ciphertext|tag(16) — the layout Kdf.wrapSecret writes — with a raw key.
	// Shared so the notes viewer, the Send page, and anything else open the same sealed shape one way.
	function b64ToBytes(b64) { var s = atob(String(b64 || '').replace(/-/g, '+').replace(/_/g, '/')); var out = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
	function aesGcmOpen(sealedB64, keyBytes) {
		var subtle = (root.crypto || {}).subtle;
		if (!subtle) return Promise.reject(new Error('This browser needs Web Crypto over a secure connection.'));
		var blob = b64ToBytes(sealedB64);
		if (blob.length < 12 + 16) return Promise.reject(new Error('malformed'));
		return subtle.importKey('raw', keyBytes instanceof Uint8Array ? keyBytes : b64ToBytes(keyBytes), { name: 'AES-GCM' }, false, ['decrypt'])
			.then(function (k) { return subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, k, blob.slice(12)); })
			.then(function (pt) { return new TextDecoder().decode(new Uint8Array(pt)); });
	}

	// ---- read-only item rendering (shared DOM) ----
	// One stylesheet, injected once, so every surface that renders an item (the Send page, and any other reader)
	// looks identical with no duplicated CSS. Theme-token driven with safe fallbacks.
	function injectStyleOnce() {
		if (typeof document === 'undefined' || document.getElementById('vs-item-css')) return;
		var css = '.vs-field{border:1px solid var(--border,#e2e6ef);border-radius:10px;padding:8px 10px;margin:0 0 8px;background:var(--panel,#fff)}'
			+ '.vs-label{font-size:12px;font-weight:700;color:var(--muted,#5b6475);margin-bottom:4px}'
			+ '.vs-value{display:flex;align-items:center;gap:8px}'
			+ '.vs-val{flex:1;min-width:0;overflow-wrap:anywhere;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}'
			+ '.vs-val.vs-masked{letter-spacing:.1em}.vs-val a{color:var(--accent,#2f6bff)}'
			+ '.vs-tools{display:flex;gap:4px;flex:0 0 auto}'
			+ '.vs-btn{padding:5px 10px;background:var(--panel-2,#f0f2f8);color:var(--text,#1a2233);border:1px solid var(--border,#e2e6ef);border-radius:999px;font-size:12px;cursor:pointer}'
			+ '.vs-totp{display:flex;align-items:center;gap:10px}.vs-totp .vs-code{font:700 20px/1 ui-monospace,Menlo,monospace;letter-spacing:.1em;color:var(--accent,#2f6bff)}.vs-totp .vs-secs{font-size:12px;color:var(--muted,#5b6475)}'
			+ '.vs-note{white-space:pre-wrap;word-break:break-word;font:14px/1.6 ui-monospace,Menlo,monospace;margin:6px 0 0}';
		var el = document.createElement('style'); el.id = 'vs-item-css'; el.textContent = css; document.head.appendChild(el);
	}
	// Render an item ({ title, type, fields, note }) read-only into `container`. Masked secrets reveal on toggle,
	// every field copies (through the auto-clearing clipboard), URLs are launchable only when http(s), and a totp
	// field shows a live rolling code. Values go in via textContent, never innerHTML, so a value cannot inject markup.
	// Returns a cleanup function that stops any live TOTP timers — call it when the view closes.
	function renderItem(container, item, opts) {
		opts = opts || {}; injectStyleOnce();
		var timers = [];
		var toast = opts.toast || function () {};
		function copy(v) { if (!v) return; copyToClipboard(v).then(function () { toast('Copied — clipboard clears shortly'); }, function () { toast('Could not copy'); }); }
		function btn(txt, fn) { var b = document.createElement('button'); b.type = 'button'; b.className = 'vs-btn'; b.textContent = txt; b.addEventListener('click', fn); return b; }
		container.innerHTML = '';
		(item && item.fields || []).forEach(function (f) {
			if (!f) return;
			var info = kindInfo(f.kind), secret = isSecret(f);
			var wrap = document.createElement('div'); wrap.className = 'vs-field';
			var lab = document.createElement('div'); lab.className = 'vs-label'; lab.textContent = f.label || (f.kind || 'Field'); wrap.appendChild(lab);
			if (info.totp) {
				var box = document.createElement('div'); box.className = 'vs-totp'; wrap.appendChild(box);
				var tick = function () { var cfg = parseTotp(f.value || ''); if (!cfg.secret) { box.textContent = ''; return; } totpCode(cfg).then(function (r) { box.innerHTML = ''; var c = document.createElement('span'); c.className = 'vs-code'; c.textContent = r.code.replace(/(\d{3})(\d+)/, '$1 $2'); var s = document.createElement('span'); s.className = 'vs-secs'; s.textContent = r.secondsRemaining + 's'; box.appendChild(c); box.appendChild(s); box.appendChild(btn('Copy', function () { copy(r.code); })); }, function () { box.textContent = ''; }); };
				tick(); timers.push(setInterval(tick, 1000));
				container.appendChild(wrap); return;
			}
			var rowEl = document.createElement('div'); rowEl.className = 'vs-value';
			var val = document.createElement('span'); val.className = 'vs-val' + (secret ? ' vs-masked' : ''); val.setAttribute('dir', 'auto');
			var shown = false;
			function paint() { if (secret && !shown) { val.textContent = '••••••••'; } else if (info.link && f.value && /^https?:\/\//i.test(f.value)) { val.innerHTML = ''; var a = document.createElement('a'); a.href = f.value; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = f.value; val.appendChild(a); } else { val.textContent = f.value || ''; } }
			paint(); rowEl.appendChild(val);
			var tools = document.createElement('div'); tools.className = 'vs-tools';
			if (secret) tools.appendChild(btn('Show', function (e) { shown = !shown; e.target.textContent = shown ? 'Hide' : 'Show'; paint(); }));
			if (f.value) tools.appendChild(btn('Copy', function () { copy(f.value); }));
			rowEl.appendChild(tools); wrap.appendChild(rowEl); container.appendChild(wrap);
		});
		if (item && item.note) { var lab2 = document.createElement('div'); lab2.className = 'vs-label'; lab2.textContent = 'Note'; container.appendChild(lab2); var pre = document.createElement('div'); pre.className = 'vs-note'; pre.setAttribute('dir', 'auto'); pre.textContent = item.note; container.appendChild(pre); }
		return function cleanup() { timers.forEach(function (t) { clearInterval(t); }); timers = []; };
	}

	root.VaultSecret = {
		KINDS: KINDS, kindInfo: kindInfo, isSecret: isSecret,
		TEMPLATES: TEMPLATES, templateFor: templateFor, iconFor: iconFor, labelFor: labelFor,
		genId: genId, blankItem: blankItem,
		parseTotp: parseTotp, totpCode: totpCode, base32Decode: base32Decode,
		copyToClipboard: copyToClipboard, aesGcmOpen: aesGcmOpen, b64ToBytes: b64ToBytes, renderItem: renderItem,
		CLIPBOARD_CLEAR_MS: 20000
	};
})(typeof self !== 'undefined' ? self : this);
