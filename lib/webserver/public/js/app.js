'use strict';
// app.js — the browser client for the Vaultonaut UI. Vanilla JS, no build step.
// It calls the loopback JSON API, renders the vault list, and handles create,
// mount (with a password prompt), unmount, add, remove and reveal.

const $ = (sel) => document.querySelector(sel);

// The product name, supplied by the server (see Brand.js) so the client never hardcodes it.
// The product name comes from a data attribute the server renders (see Brand.js), read without any
// inline script so the strict CSP (script-src 'self') is never violated.
const APP_NAME = (document.body && document.body.dataset.appName) || 'Vaultonaut';
const APP_CLI = (document.body && document.body.dataset.cli) || 'vdisk'; // the command name, for accurate "run this" hints

// Every API call carries the X-Vdisk header. Cross-origin pages cannot set it
// without a CORS preflight the server refuses, so this blocks CSRF.
const api = async (path, body) => {
	const opts = { headers: { 'X-Vdisk': '1' } };
	if (body) { opts.method = 'POST'; opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
	const res = await fetch(path, opts);
	const data = await res.json().catch(() => ({ ok: false, error: 'Bad response' }));
	if (data && data.login) { location.href = '/login'; throw new Error('Session expired'); } // signed-out — back to the login page
	if (!data.ok) {
		if (data.passwordRequired && body && body.path && !body.password) return retryWithVaultPassword(path, body, api); // exposed-mode copy/serve op: ask for the vault password and retry
		throw Object.assign(new Error(data.error || 'Request failed'), { install: data.install, locked: data.locked, holder: data.holder, flushing: data.flushing, busy: data.busy });
	}
	return data;
};

// When a copy/serve operation on a network-exposed interface needs the vault password (the server answers
// passwordRequired), ask for it once and retry the same request with it added. Kept out of the everyday flow: it is
// requested only when the server actually requires it, never on the loopback default where these ops need no password.
async function retryWithVaultPassword(path, body, call) {
	const password = await uiConfirm({ title: 'Vault password needed', message: 'Doing this over a network connection needs this vault’s password, to confirm you can open it.', confirmLabel: 'Continue', requirePassword: true });
	if (!password) throw new Error('Canceled — no password entered.');
	return call(path, { ...body, password });
}

// Like api(), but for a streaming (newline-delimited JSON) endpoint that reports progress. onProgress
// receives { percent, label } as the operation runs; the resolved value is the final result. Same
// X-Vdisk CSRF header as api(). Realtime, single request, no dependency.
const apiStream = async (path, body, onProgress) => {
	const res = await fetch(path, { method: 'POST', headers: { 'X-Vdisk': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
	if (!res.ok || !res.body) { // a non-streaming error response (e.g. blocked/forbidden) — surface it
		let msg = 'Request failed (' + res.status + ')';
		try { const j = await res.json(); if (j && j.login) { location.href = '/login'; throw new Error('Session expired'); } if (j && j.error) msg = j.error; } catch (_) {}
		throw new Error(msg);
	}
	const reader = res.body.getReader();
	const dec = new TextDecoder();
	let buf = '', result = null, sawDone = false;
	for (;;) {
		const { value, done } = await reader.read();
		if (value) buf += dec.decode(value, { stream: true });
		let nl;
		while ((nl = buf.indexOf('\n')) >= 0) {
			const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
			if (!line) continue;
			let msg; try { msg = JSON.parse(line); } catch (_) { continue; }
			if (msg.error) { if (msg.passwordRequired && body && body.path && !body.password) return retryWithVaultPassword(path, body, (p, b) => apiStream(p, b, onProgress)); const err = new Error(msg.error); err.clash = !!msg.clash; throw err; }
			if (msg.done) { result = msg.result; sawDone = true; }
			else if (msg.progress && onProgress) onProgress(msg.progress);
		}
		if (done) break;
	}
	// If the stream ended without a terminating result (server restart, a worker crash, or a dropped
	// connection mid-operation), fail with a clear, actionable message instead of returning null and letting
	// every caller throw a bare "Cannot read properties of null".
	if (!sawDone) throw new Error('The operation was interrupted before it finished. Make sure ' + APP_NAME + ' is still running, then try again.');
	return result;
};

// While an action is in flight, suppress the periodic refresh so it cannot rebuild
// the list and wipe an in-progress button state (or invite a double action). A DEPTH
// counter, not a boolean: a quick action finishing must not clear the pause while a
// slower overlapping action is still running (which would resume the poll mid-operation).
let busyDepth = 0;
function isBusy() { return busyDepth > 0; }
async function withBusy(fn) { busyDepth++; try { return await fn(); } finally { busyDepth = Math.max(0, busyDepth - 1); } }

// Re-entry guard for a consequential button. withBusy only PAUSES the background refresh; it does not stop a
// second click from launching a DUPLICATE operation while the first is still running (two concurrent mirror
// syncs, reindexes, or disperse runs against the same target — a real data-integrity hazard). This does: while
// the wrapped async handler runs, it ignores further invocations AND disables the clicked button, re-enabling it
// when the action settles. Wrap a click handler as: el.addEventListener('click', guarded(async (ev) => { … })).
function guarded(fn) {
	let running = false;
	return async function (ev) {
		if (running) return;
		running = true;
		const btn = ev && ev.currentTarget && ev.currentTarget.tagName === 'BUTTON' ? ev.currentTarget : null;
		if (btn) btn.disabled = true;
		try { return await fn.call(this, ev); }
		finally { running = false; if (btn) { btn.disabled = false; if (document.activeElement === document.body) { try { btn.focus(); } catch (_) {} } } } // restore keyboard focus: disabling a focused button moves focus to <body>, so a keyboard user who pressed Enter would otherwise lose their place

	};
}

// A whole-vault re-encryption (key rotation, or removing a member/device with rotate) is a single heavy operation:
// only ONE may run at a time. Rotate, member-remove, and member-remove-device all trigger it, so one shared flag
// guards them all — while one is streaming, a second attempt (which re-opens the password prompt) is refused rather
// than launching a concurrent re-encrypt. Mirrors the guarded() pattern used for the dedicated heavy buttons.
let vaultReencrypting = false;

// The scroll behavior to use, honoring the OS "reduce motion" setting: 'auto' (instant) when reduced motion is
// requested, otherwise 'smooth'. Single-sourced so every programmatic scroll respects the preference the same way.
function scrollBehavior() { return (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) ? 'auto' : 'smooth'; }

// Latest per-vault state, keyed by path (so dialogs can read a vault's enrolled devices etc.).
let vaultsByPath = {};
let lastState = { sftpDests: [] };
let lastCardsHtml = null; // the vault-list HTML last written to the DOM, so a poll that changes nothing skips the rebuild
const vaultSizes = {}; // path -> human-readable storage-used string (or '…' while computing); filled on demand, never on the poll
// Human-readable byte size (1024-based), one decimal below 100 units. Shared by any UI that shows a size.
function fmtBytes(n) {
	n = Number(n); if (!Number.isFinite(n) || n < 0) return '';
	if (n < 1024) return n + ' B';
	const units = ['KB', 'MB', 'GB', 'TB', 'PB']; let i = -1;
	do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
	return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
}

// Hide the toast, however it was shown (popover or plain). Safe to call at any time.
function hideToast() { const t = $('#toast'); if (!t) return; clearTimeout(toast._t); try { t.hidePopover(); } catch (_) {} t.hidden = true; if (t.parentNode !== document.body) document.body.appendChild(t); } // re-home to <body> so the no-Popover re-parent into a dialog never leaves the toast stranded in a closed one
// Show a toast. `isError` styles it and makes it interrupt screen readers. `opts.sticky` keeps it up until the user
// dismisses it (for "write this down" messages); `opts.duration` overrides the timeout in ms. Otherwise the duration
// scales with how much there is to read, so a long message stays long enough to read instead of a fixed 3 seconds.
// Every toast is click-to-dismiss, so nothing is ever stuck on screen.
function toast(msg, isError, opts = {}) {
	const t = $('#toast');
	t.classList.toggle('error', !!isError);
	t.classList.toggle('sticky', !!opts.sticky);
	t.setAttribute('aria-live', isError ? 'assertive' : 'polite'); // assertive for an error so it interrupts
	clearTimeout(toast._t);
	// Show as a manual popover when the browser supports it, so the toast renders in the top layer ABOVE any open
	// modal dialog (a plain element cannot beat showModal()'s top layer with z-index). Re-show on each toast so it
	// is re-added to the top layer on top of whatever opened since. Fall back to plain visibility otherwise.
	let asPopover = false;
	if (typeof t.showPopover === 'function' && t.hasAttribute('popover')) {
		t.hidden = false; // the [hidden] attribute would otherwise beat the popover's own display
		try { t.hidePopover(); } catch (_) {}
		try { t.showPopover(); asPopover = true; } catch (_) {}
	}
	if (!asPopover) {
		// No Popover API (older WebKitGTK / Safari): a fixed element cannot beat an open modal dialog's top layer
		// with z-index, so a toast fired from inside a dialog would render behind it. Re-parent the toast INTO the
		// open dialog (itself in the top layer) while one is open, and back to <body> otherwise, so it is always seen.
		(document.querySelector('dialog[open]') || document.body).appendChild(t);
		t.hidden = false;
	}
	// Set the text AFTER it is visible/in the a11y tree, so the live region actually announces the message.
	t.textContent = msg;
	t.title = 'Click to dismiss';
	if (!toast._wired) { t.addEventListener('click', hideToast); toast._wired = true; } // click anywhere on it to dismiss
	// A single shared element, so toasts never stack — each replaces the last. Sticky ones stay until clicked;
	// otherwise the on-screen time scales with how much there is to read (~260ms/word, bounded 3.5–20s) so a long
	// message is not gone in a fixed 3 seconds. opts.duration overrides.
	if (!opts.sticky) {
		const words = String(msg == null ? '' : msg).trim().split(/\s+/).filter(Boolean).length;
		const dur = opts.duration != null ? opts.duration : Math.min(20000, Math.max(isError ? 6000 : 3500, words * 260));
		toast._t = setTimeout(hideToast, dur);
	}
}
// When the no-Popover fallback parked the toast INSIDE a dialog (so it could sit above the modal), closing that
// dialog would hide the toast along with it — cutting a sticky "write this down" message short. On any dialog close,
// re-home a visible toast that lives inside it back to <body> so it stays up until its own timer or a click. `close`
// does not bubble, so listen in the capture phase. A no-op when the Popover API is used (the toast lives in the top
// layer, not inside the dialog).
document.addEventListener('close', (ev) => {
	try { const t = $('#toast'); if (t && !t.hidden && ev.target instanceof HTMLElement && ev.target !== t && ev.target.contains(t)) document.body.appendChild(t); } catch (_) {}
}, true);

// Escape for HTML. Single quotes are escaped too (not just double), so a value placed in a single-quoted attribute is
// as safe as one in a double-quoted attribute — every attribute in this file uses double quotes today, but this keeps
// a future single-quoted one from becoming an injection point. It ALSO neutralizes invisible bidi-formatting and
// control characters (replacing each with U+FFFD): a file or note name written in a team/shared vault could otherwise
// embed a right-to-left override (U+202E) or similar to SPOOF how the name reads in the list (e.g. make "photo<RLO>gpj.exe"
// display as a .jpg). Strong RTL letters themselves are left alone, so a genuine Arabic or Hebrew name still renders
// correctly; only the override/embedding/isolate FORMAT characters and non-whitespace C0/C1 controls are removed.
const UNSAFE_DISPLAY = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
function esc(s) { return String(s == null ? '' : s).replace(UNSAFE_DISPLAY, '\uFFFD').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// Re-show a dialog only if it isn't already open. The folder/SFTP/peer pickers stack ON TOP of their
// caller dialog without closing it, so a callback that re-shows the caller would call showModal() on an
// already-open <dialog>, which throws InvalidStateError. This makes that re-show a safe no-op.
function reopen(sel) { const d = $(sel); if (d && !d.open) d.showModal(); }

// Show an HTML result inside a `.tamper-result` panel (shared by the Keys and Tamper-check dialogs).
function showResult(el, kind, html) { const label = kind === 'ok' ? 'Success: ' : kind === 'bad' ? 'Error: ' : kind === 'warn' ? 'Warning: ' : ''; el.className = 'tamper-result ' + (kind || ''); el.setAttribute('aria-live', 'polite'); el.hidden = false; el.innerHTML = (label ? '<span class="sr-only">' + label + '</span>' : '') + html; } // live region + content set while visible, so a screen reader announces the result — prefixed with a visually-hidden status word so success/failure is not signaled by panel color alone
// Bind showResult to one panel's result element, so each dialog gets a one-line show(kind, html) helper without
// repeating the selector wiring — and without the copy-paste risk of a wrapper pointing at the wrong #...Result.
const makeShow = (sel) => (kind, html) => showResult($(sel), kind, html);

// Wire a dialog form's submit: a plain Cancel/Close button submits with value "cancel" and just
// closes the dialog, so ignore those; for the primary button (or Enter) prevent the default submit
// and run `handler`. Folds the guard every dialog handler would otherwise repeat.
function onDialogSubmit(formSel, handler) {
	let running = false;
	$(formSel).addEventListener('submit', async (ev) => {
		if (ev.submitter && ev.submitter.value === 'cancel') return;
		ev.preventDefault();
		// Ignore a second submit (a double Enter or click) while the first is still in flight, and disable the
		// submit button meanwhile, so a form can't fire its action twice — e.g. mounting a vault twice.
		if (running) return;
		running = true;
		const submitBtn = ev.submitter && ev.submitter.tagName === 'BUTTON' && ev.submitter.value !== 'cancel' ? ev.submitter : null;
		if (submitBtn) submitBtn.disabled = true;
		try { return await handler(ev); }
		finally { running = false; if (submitBtn) submitBtn.disabled = false; }
	});
}

// A keyfile is read with crypto.subtle, which exists ONLY in a secure context (https, or localhost). When the app is
// opened over a plain-http LAN address it is absent, so keyfile actions cannot work there. One predicate, used both
// to gate keyfileDigest and to hide the keyfile controls, so the promise the UI makes matches what it can deliver.
function secureContext() { return !!(window.isSecureContext && window.crypto && crypto.subtle); }
// Show or hide every keyfile control according to secureContext() — a keyfile UI that cannot function is worse than
// none, since it fails only after the user picks a file. Called on load and whenever the relevant dialogs open.
function renderKeyfileControls() {
	const ok = secureContext();
	for (const sel of ['#keysAddKeyfile']) { const el = $(sel); if (el) el.hidden = !ok; }
}
// The base64 SHA-256 of a chosen file's bytes — a keyfile's unlock secret. Computed entirely in the
// browser (the file never leaves the machine) and matches the command line's digest exactly.
async function keyfileDigest(file) {
	// crypto.subtle exists only in a secure context (https or localhost). The app can be served over plain http on a
	// LAN address, where it is undefined — fail with a clear message instead of a cryptic "cannot read digest of
	// undefined". The UI also HIDES the keyfile controls on such an origin (see secureContext()/renderKeyfileControls);
	// this is the belt-and-suspenders in case one is reached another way.
	if (!secureContext()) throw new Error('Keyfiles need a secure address (https, or localhost on this computer). This page is on a plain http address, so it cannot read a keyfile here — open it on the computer itself, or use a password.');
	const buf = await file.arrayBuffer();
	const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
	let s = ''; for (const b of hash) s += String.fromCharCode(b);
	return btoa(s);
}
// Prompt for a file with a hidden <input type=file> and resolve with the selected File (or null).
function pickFile(inputId) {
	return new Promise((resolve) => {
		const el = $('#' + inputId);
		if (!el) return resolve(null);
		el.value = '';
		const onChange = () => { el.removeEventListener('change', onChange); resolve(el.files && el.files[0] ? el.files[0] : null); };
		el.addEventListener('change', onChange);
		el.click();
	});
}

// ---- Biometric unlock (Touch ID / Windows Hello) via WebAuthn PRF ----
// The device's platform authenticator releases a stable 32-byte secret (the PRF extension),
// gated by the fingerprint/face check; that secret becomes a vault key slot. All native browser
// API — no dependencies, no native code. WebAuthn needs the page opened as "localhost" (not
// 127.0.0.1) as its relying-party id.
const BIO_RP_ID = 'localhost';
let bioOK = false;    // a PLATFORM authenticator (Touch ID / Windows Hello) is available on a localhost origin
let secKeyOK = false; // WebAuthn is available on a localhost origin at all — a roaming SECURITY KEY (e.g. a YubiKey) needs no platform authenticator, so this is the broader capability that gates security-key enroll and every device unlock
async function bioSupported() {
	try {
		if (!window.PublicKeyCredential || location.hostname !== BIO_RP_ID) return false;
		return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
	} catch (_) { return false; }
}
function webauthnSupported() { try { return !!window.PublicKeyCredential && location.hostname === BIO_RP_ID; } catch (_) { return false; } }
// A friendly name for the enrolled unlock method, adapting to what this machine can do: a platform authenticator
// reads as "Touch ID", otherwise a roaming key reads as "security key". The unlock ceremony is identical either way.
function deviceUnlockLabel() { return bioOK ? 'Touch ID' : 'security key'; }
// The base64url codec and the PRF assertion ceremony live in the shared webauthn.js (window.WebAuthnUtil), loaded
// before this script, so the login page and the app never keep two copies of credential-handling code.
function b64uEncode(buf) { return WebAuthnUtil.b64uEncode(buf); }
function b64uDecode(str) { return WebAuthnUtil.b64uDecode(str); }
function randBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// Derive the device key from an assertion (used at unlock, and as the enrollment fallback if create() did not
// return the PRF result directly). Prompts the platform authenticator. The app's descriptors name the credential
// id `credentialId`, so map it to the shared helper's `id` shape.
async function bioDerive(descriptors) {
	return WebAuthnUtil.derivePrfSecret(BIO_RP_ID, descriptors.map(d => ({ id: d.credentialId, prfSalt: d.prfSalt })));
}

// Enroll an authenticator (a platform passkey, or a roaming security key) as a device-key slot: create a
// credential with PRF, derive the device key from it, and register it (authorized by the current password). The
// two enroll flavors below differ only in the authenticator selection, an optional hint, and the slot label —
// everything else (the per-vault PRF salt, deriving the secret, and the add-device-key POST) is shared here. The
// derived secret only ever wraps a capability, never the master, so it is safe to reuse this one path.
async function enrollWebAuthn(vaultPath, vaultName, currentPassword, opts) {
	const prfSalt = randBytes(32);
	const publicKey = {
		rp: { name: APP_NAME, id: BIO_RP_ID },
		user: { id: randBytes(16), name: vaultName + ' · ' + APP_NAME, displayName: vaultName },
		challenge: randBytes(32), timeout: 60000,
		pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
		authenticatorSelection: opts.authenticatorSelection,
		extensions: { prf: { eval: { first: prfSalt } } }
	};
	if (opts.hints) publicKey.hints = opts.hints;
	const cred = await navigator.credentials.create({ publicKey });
	if (!cred) throw new Error('Enrollment was canceled.');
	const descriptor = { credentialId: b64uEncode(cred.rawId), prfSalt: b64uEncode(prfSalt) };
	// Prefer the PRF result from create() (one tap); otherwise derive it via an assertion.
	const prf = cred.getClientExtensionResults && cred.getClientExtensionResults().prf;
	const deviceKey = (prf && prf.results && prf.results.first) ? b64uEncode(prf.results.first) : await bioDerive([descriptor]);
	const body = { path: vaultPath, password: currentPassword, deviceKey, webauthn: descriptor };
	if (opts.label) body.label = opts.label;
	await api('/api/add-device-key', body);
}
// Enroll THIS device's built-in authenticator (Touch ID / Windows Hello).
function bioEnroll(vaultPath, vaultName, currentPassword) {
	return enrollWebAuthn(vaultPath, vaultName, currentPassword, { authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' } });
}
// Enroll a roaming SECURITY KEY (a USB/NFC key such as a YubiKey). Cross-platform so the browser targets a
// security key, no discoverable credential consumed (one key backs unlimited vaults via the per-vault PRF salt),
// and user verification required so a stolen key alone (without its PIN/biometric) can never unlock. Works on
// desktop Chrome/Edge/Firefox; Safari/iOS do not expose PRF for roaming keys (a browser limit, surfaced to the
// user, not something the code can work around).
function securityKeyEnroll(vaultPath, vaultName, currentPassword) {
	return enrollWebAuthn(vaultPath, vaultName, currentPassword, { authenticatorSelection: { authenticatorAttachment: 'cross-platform', residentKey: 'discouraged', userVerification: 'required' }, hints: ['security-key'], label: 'Security key' });
}

// Reusable confirmation dialog. Resolves true only if the user confirms.
// A shared confirm dialog. By default it resolves to a boolean (OK vs cancel). With `requirePassword: true` it shows a
// vault-password field, keeps the OK button disabled until one is entered, and resolves to the entered password on OK
// or null on cancel — so a destructive/standing-security action can prove read-write access at the point of use. The
// field is always cleared on close, so a password is never left sitting in the DOM.
// The shared confirm modal, and the one place a password is collected. Options:
//   requirePassword  — show the first (authorizing) field; resolve the entered password (string) or null on cancel.
//   passwordLabel    — label for that first field (default "Vault password").
//   second: {label}  — also show a SECOND masked field (a NEW password to set, with a strength meter); the resolve
//                      value then becomes { password, second } (or null on cancel) instead of a bare string.
// With neither, it is a plain confirm resolving true/false. This is what lets every Keys action prompt for exactly
// the credentials it needs at the moment of the action, so nothing is ever left "armed" in an ambient field.
function uiConfirm({ title = 'Confirm', message = '', confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, requirePassword = false, passwordLabel = 'Vault password', second = null } = {}) {
	return new Promise((resolve) => {
		$('#confirmTitle').textContent = title;
		$('#confirmMsg').textContent = message;
		const okBtn = $('#confirmOk');
		okBtn.textContent = confirmLabel;
		const cancelBtn = $('#confirmCancel'); if (cancelBtn) cancelBtn.textContent = cancelLabel; // honor a custom Cancel label (callers pass one for clarity, e.g. "Keep it")
		okBtn.className = danger ? 'primary-btn danger' : 'primary-btn';
		const pwField = $('#confirmPwField'), pw = $('#confirmPw'), pwLabel = $('#confirmPwLabel');
		const pw2Field = $('#confirmPw2Field'), pw2 = $('#confirmPw2'), pw2Label = $('#confirmPw2Label'), pw2Meter = $('#confirmPw2Meter');
		pw.value = ''; pw2.value = ''; if (pw2Meter) pw2Meter.hidden = true;
		if (pwLabel) pwLabel.textContent = passwordLabel;
		pwField.hidden = !requirePassword;
		pw2Field.hidden = !second;
		if (second && pw2Label) pw2Label.textContent = second.label || 'New password';
		const gate = requirePassword || !!second;
		const need = () => (requirePassword && !pw.value) || (second && !pw2.value);
		okBtn.disabled = gate && need();
		const oninput = () => { okBtn.disabled = need(); };
		pw.oninput = gate ? oninput : null;
		pw2.oninput = second ? oninput : null;
		const dlg = $('#confirmDialog');
		const onClose = () => {
			dlg.removeEventListener('close', onClose);
			const ok = dlg.returnValue === 'ok';
			const password = pw.value, secondVal = pw2.value;
			pw.value = ''; pw2.value = ''; if (pw2Meter) pw2Meter.hidden = true; okBtn.disabled = false; // never leave a password in the DOM
			if (second) return resolve(ok ? { password, second: secondVal } : null);
			resolve(requirePassword ? (ok ? password : null) : ok);
		};
		dlg.addEventListener('close', onClose);
		dlg.showModal();
		if (gate) setTimeout(() => (requirePassword ? pw : pw2).focus(), 50);
	});
}

// ---- Theme ----
function initTheme() {
	const saved = localStorage.getItem('vdisk-theme') || 'auto';
	document.documentElement.setAttribute('data-theme', saved);
	$('#themeToggle').addEventListener('click', () => {
		const order = ['auto', 'light', 'dark', 'sepia'];
		const cur = document.documentElement.getAttribute('data-theme') || 'auto';
		const next = order[(order.indexOf(cur) + 1) % order.length];
		document.documentElement.setAttribute('data-theme', next);
		localStorage.setItem('vdisk-theme', next);
		const label = { auto: 'Theme: match system', light: 'Theme: light', dark: 'Theme: dark', sepia: 'Theme: sepia (calm)' };
		toast(label[next] || 'Theme: ' + next);
	});
	const logout = $('#logoutBtn');
	if (logout) logout.addEventListener('click', async () => { try { await api('/api/logout', {}); } catch (_) {} location.href = '/login'; });
}

// ---- Rendering ----
function renderEnv(doctor) {
	const el = $('#env');
	const engineOk = doctor.engine && doctor.engine.ok;
	const driverOk = doctor.driver && doctor.driver.ok;
	const driverWarn = doctor.driver && doctor.driver.warn;
	if (engineOk && driverOk && !driverWarn) { if (renderEnv._sig !== 'clean') { el.hidden = true; el.innerHTML = ''; renderEnv._sig = 'clean'; } return; }
	let msg = '';
	if (!engineOk) msg += (doctor.engine && doctor.engine.downloading
		? 'Setting up the encryption engine (downloading it now)… This happens once, and the page updates automatically when it is ready.\n'
		: 'The encryption engine is not set up yet. It downloads automatically on first use (requires an internet connection).\n');
	if (!driverOk) msg += (doctor.driver ? doctor.driver.detail + '\n' + (doctor.driver.install || '') : 'A mount driver is required.');
	else if (driverWarn) msg += doctor.driver.warn + '\n' + (doctor.driver.install || '');
	msg = msg.trim();
	const needBtn = !driverOk || driverWarn;
	// An in-progress first-run engine download is informational, not a problem — tint it neutrally. Anything with an
	// actionable fix (a missing or incompatible mount driver) keeps the amber warning treatment.
	const cls = (doctor.engine && doctor.engine.downloading && !needBtn) ? 'info' : 'warn';
	// This is an aria-live region: rewriting its subtree makes a screen reader RE-ANNOUNCE, so skip the write when
	// nothing changed since the last render (the 5-second poll would otherwise re-read the whole message every tick).
	const sig = cls + '\n' + (needBtn ? 'btn\n' : '') + msg;
	if (renderEnv._sig === sig) return;
	renderEnv._sig = sig;
	el.hidden = false;
	el.className = 'banner ' + cls;
	el.innerHTML = '<div class="banner-msg"></div>';
	el.querySelector('.banner-msg').textContent = msg;
	if (needBtn) {
		const btn = document.createElement('button');
		btn.className = 'primary-btn mt-2';
		btn.dataset.act = 'install-driver';
		btn.textContent = 'Install the mount driver';
		el.appendChild(btn);
	}
}

// Surface the boot-time integrity self-check, but only when it has something to report — a clean
// install shows nothing. Each finding pairs a plain-language message with how to fix it. The banner
// can be MINIMIZED to a one-line chip (so it stays visible and is never forgotten, just out of the
// way); the collapsed state is remembered per finding-set, so a NEW or changed finding re-opens it.
const INTEGRITY_COLLAPSE_KEY = 'vdisk-integrity-collapsed';
let lastSelfCheck = null; // the latest self-check payload, so the Minimize/Show buttons can re-render
// A stable signature of the current findings; the minimized state is keyed to it so it re-expands
// automatically whenever the findings change rather than hiding something new.
function integritySig(findings) { return findings.map(f => (f.level || '') + ':' + f.message).join('|'); }
function renderIntegrity(sc) {
	const el = $('#integrity'); if (!el) return;
	lastSelfCheck = sc;
	// The environment banner already surfaces the engine and mount-driver readiness (with the install button), so
	// drop those two self-check findings here — otherwise a fresh machine shows the same issue in two stacked banners.
	const findings = ((sc && sc.findings) || []).filter(f => f.check !== 'engine' && f.check !== 'driver');
	if (!findings.length) { if (renderIntegrity._key !== 'empty') { el.hidden = true; el.innerHTML = ''; try { localStorage.removeItem(INTEGRITY_COLLAPSE_KEY); } catch (_) {} renderIntegrity._key = 'empty'; } return; }
	const level = findings.some(f => f.level === 'error') ? 'bad' : 'warn';
	const sig = integritySig(findings);
	let collapsed = false;
	try { collapsed = localStorage.getItem(INTEGRITY_COLLAPSE_KEY) === sig; } catch (_) {}
	// This is an aria-live region: only rewrite it when the findings or the collapsed state actually changed, so the
	// 5-second poll does not make a screen reader re-read the whole list every tick.
	const key = level + '|' + collapsed + '|' + sig;
	if (renderIntegrity._key === key) return;
	renderIntegrity._key = key;
	el.hidden = false;
	el.className = 'banner ' + level + (collapsed ? ' collapsed' : '');
	const n = findings.length, count = n + (n === 1 ? ' item' : ' items');
	if (collapsed) {
		el.innerHTML = '<div class="banner-row"><span class="banner-msg">⚠ System check: ' + count + ' to look at</span>'
			+ '<button type="button" class="banner-toggle" data-act="integrity-expand">Show</button></div>';
	} else {
		// The message reads in the normal weight (the banner's own tint already sets it apart), with the fix
		// muted beneath it — bolding the whole multi-sentence message was heavy, especially on a phone.
		const items = findings.map(f => '<li>' + esc(f.message) + (f.fix ? '<br><span class="muted">' + esc(f.fix) + '</span>' : '') + '</li>').join('');
		el.innerHTML = '<div class="banner-row"><span class="banner-msg">System integrity check found ' + count + ' to look at:</span>'
			+ '<button type="button" class="banner-toggle" data-act="integrity-collapse">Minimize</button></div>'
			+ '<ul class="integrity-list">' + items + '</ul>';
	}
}

// The small self-heal badge on a vault's name: a live "updating" state while recovery data is being
// rebuilt in the background, otherwise a quiet marker that protection is present.
function recoveryBadge(v) {
	const r = v.recovery;
	if (!r) return '';
	if (r.refreshing) return ` <span class="badge updating" title="Rebuilding recovery data after changes">updating ${r.refreshPercent != null ? r.refreshPercent + '%' : '…'}</span>`;
	if (r.protected) return ' <span class="badge protected" title="Self-healing recovery data is present">self-heal</span>';
	return '';
}
// The mirror badge: a live "syncing" state during a background sync, otherwise a quiet marker that a
// two-way mirror is set up (with a dot when the last sync left conflicts to resolve).
function mirrorBadge(v) {
	const m = v.mirror;
	if (!m || !m.configured) return '';
	if (m.syncing) return ' <span class="badge updating" title="Syncing the mirror">syncing…</span>';
	const warn = m.lastConflicts ? ' •' : '';
	return ` <span class="badge mirror" title="Two-way mirror is set up">mirror${warn}</span>`;
}
// The node/serve badge: shown when this machine is serving the vault so another can mirror to it.
function servingBadge(v) { return (v.serving && v.serving.serving) ? ' <span class="badge serving" title="Serving as a node for another machine to mirror to">serving</span>' : ''; }
// Build one More-menu button. An action tagged { needsUnmount } is rendered disabled with an "unmount first"
// hint while the vault is mounted (kept visible for discoverability); the click delegator turns a click on such
// a blocked button into a plain hint instead of running it. The server is the real guard (assertUnmounted).
function moreBtn(v, act, label, opts = {}) {
	// needsLocal actions (the data lives on this machine) can never work on a cloud vault, whose encrypted files
	// live at the provider — the server refuses them outright — so omit them entirely rather than offer a dead click.
	if (opts.needsLocal && v.cloud) return '';
	const blocked = !!opts.needsUnmount && v.mounted;
	const cls = 'link-btn' + (opts.danger ? ' danger' : '') + (blocked ? ' disabled' : '');
	const extra = blocked ? ' data-blocked="unmount" aria-disabled="true" title="Unmount this vault first to use this"' : '';
	return `<button class="${cls}" data-act="${act}" data-path="${esc(v.path)}" data-name="${esc(v.name)}"${extra}>${label}</button>`;
}
function vaultCard(v) {
	const stuck = v.mounted && v.responsive === false; // wedged or engine-dead but still mounted
	const isServing = !!(v.serving && v.serving.serving);
	const badge = !v.valid ? '<span class="badge invalid" title="The vault folder can’t be read right now — it may have been moved or renamed, or its drive isn’t connected">unreachable</span>'
		: stuck ? '<span class="badge notresponding">not responding</span>'
			: v.mounted ? '<span class="badge mounted">mounted</span>'
				: '<span class="badge idle">idle</span>';
	// Two tiers keep the card uncluttered: the handful of actions people reach for daily stay in view,
	// while the occasional and advanced ones tuck into a "More" menu. Every button still routes through the
	// same delegated click handler, so nesting them in the menu changes nothing about how they work.
	const actions = [];
	const more = [];
	if (v.valid && stuck) {
		// Recovery is one click and needs no reboot: force-release the wedged drive.
		actions.push(`<button class="primary-btn" data-act="force-unmount" data-target="${esc(v.mountpoint)}" data-name="${esc(v.name)}">Force unmount</button>`);
	} else if (v.valid && v.mounted) {
		actions.push(`<button class="ghost-btn" data-act="reveal" data-path="${esc(v.mountpoint)}">Reveal</button>`);
		actions.push(`<button class="ghost-btn" data-act="add-files" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Add files</button>`);
		actions.push(`<button class="ghost-btn" data-act="notes" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Notes</button>`);
		actions.push(`<button class="ghost-btn" data-act="search" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Search</button>`);
		actions.push(`<button class="ghost-btn danger" data-act="unmount" data-target="${esc(v.mountpoint)}" data-name="${esc(v.name)}">Unmount</button>`);
	} else if (v.valid && isServing) {
		// While serving, the vault is offered to other machines, not mounted here — offer to stop.
		actions.push(`<button class="primary-btn danger" data-act="serve" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Stop serving</button>`);
	} else if (v.valid) {
		// A favorite with a device key (Touch ID / Windows Hello / a security key) enrolled opens in one tap.
		const oneTap = v.favorite && v.biometric && v.biometric.length && secKeyOK;
		if (oneTap) actions.push(`<button class="primary-btn" data-act="bio-mount" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Unlock with ${deviceUnlockLabel()}</button>`);
		actions.push(`<button class="${oneTap ? 'ghost-btn' : 'primary-btn'}" data-act="mount" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Mount</button>`);
	}
	if (v.valid) actions.push(`<button class="link-btn" data-act="keys" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Keys</button>`);
	// Everything below is occasional or advanced, so it lives in the More menu. Actions that need a settled
	// (unmounted) vault — the server enforces this with assertUnmounted — are shown DISABLED with an "unmount
	// first" hint while the vault is mounted, rather than vanishing, so the menu stays complete and the user can
	// see what is available and why. The ones without needsUnmount read the encrypted store or a key slot and work
	// mounted or not: Password and Share are instant key-slot operations; View files decrypts in the browser.
	if (v.valid) {
		more.push(moreBtn(v, 'passwd', 'Password'));
		more.push(moreBtn(v, 'share', 'Share'));
		more.push(moreBtn(v, 'members', 'Members', { needsUnmount: true }));
		more.push(moreBtn(v, 'mobile', 'View files & notes', { needsLocal: true }));
		more.push(moreBtn(v, 'tamper', 'Tamper check', { needsUnmount: true }));
		more.push(moreBtn(v, 'protect', 'Self-heal', { needsUnmount: true, needsLocal: true }));
		more.push(moreBtn(v, 'mirror', 'Mirror', { needsUnmount: true, needsLocal: true }));
		if (!isServing) more.push(moreBtn(v, 'serve', 'Serve', { needsUnmount: true, needsLocal: true }));
		more.push(moreBtn(v, 'backup', 'Back up', { needsUnmount: true, needsLocal: true }));
		more.push(moreBtn(v, 'versions', 'Versions', { needsUnmount: true }));
		more.push(moreBtn(v, 'disperse', 'Split', { needsUnmount: true, needsLocal: true }));
		// Permanent delete lives in the More menu, apart from the always-visible Remove, so it cannot be
		// fat-fingered — it destroys the keys and erases the data for good, gated by a typed-name confirmation.
		more.push(moreBtn(v, 'destroy', 'Delete permanently', { needsUnmount: true, danger: true }));
	}
	// Remove stays visible — it is destructive, but people expect to find it without hunting.
	actions.push(`<button class="link-btn danger" data-act="remove" data-path="${esc(v.path)}" data-name="${esc(v.name)}">Remove</button>`);
	const moreItems = more.filter(Boolean); // drop entries a helper chose to omit (e.g. cloud-only-unavailable actions)
	const moreMenu = moreItems.length ? `<details class="more"><summary class="more-toggle">More</summary><div class="more-menu">${moreItems.join('')}</div></details>` : '';
	const note = stuck ? `<div class="path stuck-note">This drive stopped responding. Click “Force unmount” to recover it — no reboot needed.</div>`
		: (!v.valid ? `<div class="path invalid-note">This vault can’t be read right now. Its folder may have been moved or renamed, or its drive may be disconnected — reconnect it, or add the vault again from its new location. “Remove” only forgets it here; your files are not deleted.</div>` : '');
	return `<div class="card${stuck ? ' card-stuck' : ''}" role="listitem">
		<div class="info">
			<div class="name"><button class="star-btn${v.favorite ? ' on' : ''}" data-act="favorite" data-path="${esc(v.path)}" data-on="${v.favorite ? '0' : '1'}" aria-pressed="${v.favorite ? 'true' : 'false'}" title="${v.favorite ? 'Remove from favorites' : 'Add to favorites'}" aria-label="${v.favorite ? 'Remove from favorites' : 'Add to favorites'}">${v.favorite ? '★' : '☆'}</button> <span dir="auto">${esc(v.name)}</span> ${badge}${v.sealed ? ' <span class="badge sealed" title="Strict tamper tripwire is active">sealed</span>' : ''}${v.worm ? ` <span class="badge" title="Tamper-proof: every saved version is locked for ${esc(String(v.worm.retainDays))} days and cannot be deleted or overwritten (Object Lock)">tamper-proof</span>` : ''}${recoveryBadge(v)}${mirrorBadge(v)}${servingBadge(v)}</div>
			<div class="path" dir="auto">${esc(v.mounted ? v.mountpoint + '  ←  ' + v.path : v.path)}</div>
			${sizeCell(v)}
			${note}
		</div>
		<div class="actions">${actions.join('')}${moreMenu}</div>
	</div>`;
}

// The "storage used" line under a vault's path. Offered ONLY while the vault is mounted, which keeps decoys
// deniable: an unmounted vault never shows a footprint. When the decoy feature is in use the server measures the
// MOUNTED contents, so a decoy unlock reports the decoy's size; otherwise, for a local vault, it measures the
// on-disk ciphertext store (the same size, but reliable on every platform — a mount walk can read 0 B on Windows).
// On-demand: a full walk, so it never runs on
// the status poll. The figure it shows is a snapshot from the last click; the shown value stays clickable so it can
// be rechecked after files change (with a ↻ cue), rather than silently going stale.
function sizeCell(v) {
	if (!v.valid || !v.mounted) return '';
	const s = vaultSizes[v.path];
	if (s === '…') return '<div class="path vault-size">Storage used: calculating…</div>';
	const p = esc(v.path);
	if (s) return '<div class="path vault-size"><button type="button" class="link-btn size-btn" data-act="size" data-path="' + p + '" title="Recheck — this is a snapshot, not live">Storage used: ' + esc(s) + ' <span class="size-recheck" aria-hidden="true">↻</span></button></div>';
	return '<div class="path vault-size"><button type="button" class="link-btn size-btn" data-act="size" data-path="' + p + '">Show storage used</button></div>';
}

// Render the vault list from the latest state. Factored out of refresh() so an in-place update (e.g. a computed
// storage size) can redraw the cards without a fresh network poll. Favorites first; the DOM is written only when
// the HTML actually changed, and never while a "More" menu OR a dialog is open (rebuilding then would detach the
// card button a dialog was opened from, so the dialog's focus-return lands on nothing — a keyboard/reader user loses
// their place). The vaultsByPath/size bookkeeping above still refreshes; only the DOM write is deferred.
function renderVaults() {
	const vaults = (lastState && lastState.vaults) || [];
	vaultsByPath = {};
	vaults.forEach(v => { vaultsByPath[v.path] = v; });
	// Drop a cached storage size once its vault is unmounted or gone, so a re-mount recomputes rather than showing a
	// stale figure (and nothing lingers for a removed vault).
	for (const p of Object.keys(vaultSizes)) { const v = vaultsByPath[p]; if (!v || !v.mounted) delete vaultSizes[p]; }
	const list = $('#vaults'); if (!list) return;
	const ordered = vaults.slice().sort((a, b) => (Number(!!b.favorite) - Number(!!a.favorite)));
	if (!list.querySelector('details.more[open]') && !document.querySelector('dialog[open]')) {
		const html = ordered.map(vaultCard).join('');
		if (html !== lastCardsHtml) { list.innerHTML = html; lastCardsHtml = html; }
	}
	const nv = $('#noVaults'); if (nv) nv.hidden = vaults.length > 0;
	const count = $('#vaultCount'); if (count) count.textContent = vaults.length ? String(vaults.length) : '';
}

let refreshing = false;
let lastPollError = null; // the last poll-failure message shown, so a briefly-unreachable service is announced ONCE, not every 5s
async function refresh() {
	if (isBusy() || refreshing) return; // skip while an action is in flight, or while a previous (slow) poll is still outstanding — so a late response can't overwrite a newer render
	refreshing = true;
	try {
		const { state } = await api('/api/state');
		renderEnv(state.doctor);
		renderIntegrity(state.selfCheck);
		lastState = state;
		try { renderCloudSelect(); } catch (_) {}
		// Per-vault decoy protection needs no session gate: the vault list is always the real list, and a decoy
		// is resolved only at mount time when a vault's own unlock fails. Which vaults are protected is hidden.
		const logout = $('#logoutBtn'); if (logout) logout.hidden = !(state.auth && state.auth.enabled); // shown only when a login is in force
		renderVaults();
		const al = $('#autoLock');
		if (al && document.activeElement !== al) al.value = String((state.settings && state.settings.autoLockMinutes) || 0);
		const aa = $('#autoAttest');
		if (aa && document.activeElement !== aa) aa.checked = !!(state.settings && state.settings.autoAttest);
		const los = $('#lockOnSleep');
		if (los && document.activeElement !== los) los.checked = !!(state.settings && state.settings.lockOnSleep);
		const auc = $('#autoUpdateCheck');
		if (auc && document.activeElement !== auc) auc.checked = !!(state.settings && state.settings.autoUpdateCheck);
		// Only overwrite the version line from the poll when the user is not mid-manual-check and a stored status
		// exists; a null status leaves the default prompt (or a just-shown manual result) in place. The in-flight
		// manual check sets a dataset latch (see the Check-now handler), which is language- and wording-independent
		// where the previous exact-text compare was not.
		const ust = $('#updateStatusText');
		if (state.settings && state.settings.updateStatus && ust && ust.dataset.checking !== '1') renderUpdateStatus(state.settings.updateStatus);
		const bw = $('#bwLimit'), bwp = $('#bwPreset');
		if (bw && bwp && document.activeElement !== bw && document.activeElement !== bwp) applyBwToUI((state.settings && state.settings.bwlimit) || '');
		const hint = $('#createHint');
		if (hint && state.vaultsDir) hint.textContent = 'Enter a name to store it in ' + state.vaultsDir + ', or type a full path. Copy a vault folder to any machine to take it with you.';
		lastPollError = null; // a successful poll clears the "announced" latch, so a later, genuinely new failure is shown again
	} catch (e) {
		// The background poll runs every 5 seconds. When the local service is briefly unreachable — which the app
		// itself can trigger by installing start-at-login or updating — an unconditional toast would fire every 5s
		// and, because an error toast is an assertive live region, interrupt a screen reader each time with a cryptic
		// "Failed to fetch." Announce a given failure only ONCE (until it changes or a poll succeeds), and phrase a
		// connection loss plainly. A user-initiated action still surfaces its own errors through its own handler.
		const raw = (e && e.message) || 'Something went wrong.';
		const connLost = /failed to fetch|networkerror|load failed|fetch/i.test(raw);
		const msg = connLost ? 'Lost contact with the app — it may be restarting. Retrying…' : raw;
		if (msg !== lastPollError) { lastPollError = msg; toast(msg, true); }
	}
	finally { refreshing = false; }
}

// Force-release a mount to recover a stuck or wedged drive (no reboot). Shared by the
// "not responding" card action and the fallback offered when a normal unmount fails.
// Returns 'ok', 'declined', or 'failed'.
async function forceUnmount(target, name, { message, success = 'Recovered', btn } = {}) {
	const okd = await uiConfirm({ title: 'Force unmount', message, confirmLabel: 'Force unmount', danger: true });
	if (!okd) return 'declined';
	try {
		if (btn) btn.disabled = true;
		const r = await withBusy(() => api('/api/unmount', { target, force: true }));
		// A force unmount usually succeeds. If the drive is STILL mounted (r.ok === false) it is wedged — on macOS a
		// file server that stopped responding. Offer the explicit last-resort recovery, which stops the drive's
		// process and releases it, usually avoiding a restart.
		if (r && r.ok === false) { if (btn) btn.disabled = false; return await recoverWedged(target, name, btn); }
		toast(success); refresh(); return 'ok';
	} catch (e) { toast(e.message, true); if (btn) btn.disabled = false; return 'failed'; }
}
// The last resort for a wedged drive a plain force could not release. Confirmed separately because it forcibly stops
// the drive's file-server process; on the rare occasion even this cannot free it, the app says a restart is the last
// option. Nothing in the vault is lost either way (a wedged drive holds no un-flushed writes this can save).
async function recoverWedged(target, name, btn) {
	const okd = await uiConfirm({ title: 'Recover wedged drive', message: 'The drive "' + name + '" is stuck and a normal force could not release it. Recovery will stop its file-server process and release it, usually without a restart. Nothing in the vault is lost. Continue?', confirmLabel: 'Recover', danger: true }); // message is set via textContent (uiConfirm), which escapes on its own — passing esc(name) here would double-escape
	if (!okd) return 'declined';
	try {
		if (btn) btn.disabled = true;
		const r = await withBusy(() => api('/api/unmount', { target, recover: true }));
		if (r && r.stuck) { toast('The drive is wedged and could not be released — restarting the computer is the last option. Nothing in the vault is lost.', true); refresh(); return 'failed'; }
		toast(r && r.recovered ? 'Recovered the wedged drive — no restart needed.' : 'Recovered'); refresh(); return 'ok';
	} catch (e) { toast(e.message, true); if (btn) btn.disabled = false; return 'failed'; }
}

// Cancel buttons are plain (non-submit) buttons so that pressing Enter in a dialog triggers the
// PRIMARY action (Mount, Change password, Confirm) instead of Cancel. Close the dialog here, with
// returnValue 'cancel' so confirm()/submit handlers still see it as a cancel.
document.addEventListener('click', (ev) => {
	const cancel = ev.target.closest('button[value="cancel"]');
	if (cancel) { const dlg = cancel.closest('dialog'); if (dlg) dlg.close('cancel'); }
});

// Keep only one card's "More" menu open at a time, and close it when the click lands elsewhere. Native
// <details> does the toggling; this just tidies up so menus never stack or linger over the page.
document.addEventListener('click', (ev) => {
	const open = document.querySelectorAll('details.more[open]');
	if (!open.length) return;
	const inside = ev.target.closest('details.more');
	open.forEach((d) => { if (d !== inside) d.removeAttribute('open'); });
});
document.addEventListener('keydown', (ev) => {
	if (ev.key !== 'Escape') return;
	// Return focus to the summary that owns a menu we close, so a keyboard user is not dropped to <body> and loses
	// their place. Focus the one that currently contains focus (or the last open menu) before removing [open].
	const openMenus = [...document.querySelectorAll('details.more[open]')];
	if (!openMenus.length) return;
	const owner = openMenus.find((d) => d.contains(document.activeElement)) || openMenus[openMenus.length - 1];
	openMenus.forEach((d) => d.removeAttribute('open'));
	const summary = owner && owner.querySelector('summary'); if (summary) summary.focus();
});

// ---- Actions (event delegation) ----
document.addEventListener('click', async (ev) => {
	const btn = ev.target.closest('button[data-act]');
	if (!btn) return;
	// A More-menu action that needs a settled vault is shown disabled while mounted; a click just explains why,
	// so the hint reaches touch users too (no hover tooltip there) without ever starting the action.
	if (btn.dataset.blocked === 'unmount') { toast('Unmount this vault first to use this.', true); return; }
	const act = btn.dataset.act;
	// Minimize the self-check banner to a chip (remembered for this finding-set), or expand it again.
	if (act === 'integrity-collapse') { try { localStorage.setItem(INTEGRITY_COLLAPSE_KEY, integritySig((lastSelfCheck && lastSelfCheck.findings) || [])); } catch (_) {} renderIntegrity(lastSelfCheck); return; }
	if (act === 'integrity-expand') { try { localStorage.removeItem(INTEGRITY_COLLAPSE_KEY); } catch (_) {} renderIntegrity(lastSelfCheck); return; }
	if (act === 'mount') { openMount(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'add-files') { openImport(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'notes') { openNotes(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'search') { openSearch(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'versions') { openVersions(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'members') { openMembers(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'favorite') { toggleFavorite(btn.dataset.path, btn.dataset.on === '1'); return; }
	if (act === 'bio-mount') { quickBioMount(btn.dataset.path); return; }
	if (act === 'passwd') { openPasswd(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'tamper') { openTamper(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'protect') { openProtect(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'mirror') { openMirror(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'serve') { openServe(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'keys') { openKeys(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'share') { openShare(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'mobile') { openMobile(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'disperse') { openDisperse(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'destroy') { openDestroy(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'size') {
		const p = btn.dataset.path;
		vaultSizes[p] = '…'; renderVaults(); // show "calculating…" at once
		try { const r = await api('/api/vault-size', { path: p }); vaultSizes[p] = fmtBytes(r.bytes) + (r.truncated ? ' or more' : ''); }
		catch (e) { vaultSizes[p] = undefined; toast(e.message, true); }
		renderVaults();
		return;
	}
		if (act === 'backup') { openBackup(btn.dataset.path, btn.dataset.name); return; }
	if (act === 'remove') {
		const rv = vaultsByPath[btn.dataset.path] || {};
		let message = 'Remove "' + btn.dataset.name + '" from this list? This only forgets it here — your encrypted files are NOT deleted, and you can add it back anytime by its folder.';
		message += rv.cloud
			? ' Its encrypted data stays in the cloud, and the provider may keep versions or backups even after a later delete. To make it truly unrecoverable, use “Delete permanently” in this vault’s More menu instead — that destroys the keys, so the cloud data can never be decrypted again.'
			: ' To permanently destroy the keys so this copy can never be opened again, use “Delete permanently” in this vault’s More menu instead.';
		message += ' Either way, any Recovery Kit, recovery key, threshold shares, or emergency seal you exported still holds a working key — destroy those too, or the data can be brought back.';
		const okd = await uiConfirm({ title: 'Remove vault', message, confirmLabel: 'Remove', danger: true });
		if (!okd) return;
		try { await withBusy(() => api('/api/remove-vault', { path: btn.dataset.path })); toast('Removed from the list'); refresh(); }
		catch (e) { toast(e.message, true); }
		return;
	}
	if (act === 'force-unmount') {
		await forceUnmount(btn.dataset.target, btn.dataset.name, {
			message: 'Force-release “' + btn.dataset.name + '”? This recovers a drive that stopped responding immediately — no reboot needed. Any writes still in progress may be lost.',
			btn
		});
		return;
	}
	if (act === 'unmount') {
		const okd = await uiConfirm({
			title: 'Unmount vault',
			message: 'Unmount "' + btn.dataset.name + '"? Make sure no apps are still using the drive. Any writes are flushed before it locks.',
			confirmLabel: 'Unmount', danger: true
		});
		if (!okd) return;
		try { btn.disabled = true; await withBusy(() => api('/api/unmount', { target: btn.dataset.target })); toast('Unmounted'); refresh(); }
		catch (e) {
			btn.disabled = false;
			// "flushing" means the vault is still safely saving buffered changes and was left mounted so nothing is
			// lost — NOT a stuck drive. Tell the user to wait and retry, and never offer force here (force would
			// discard the very writes still being saved).
			if (e.flushing) { toast('Still saving buffered changes — nothing is lost. Wait a moment, then unmount again.', true); refresh(); return; }
			// A normal unmount can fail if the drive is stuck (an app still holding it, or a
			// stale mount left by a crashed engine). Offer a force-release as an override.
			const r = await forceUnmount(btn.dataset.target, btn.dataset.name, {
				message: '“' + btn.dataset.name + '” did not unmount (' + e.message + '). Force-release it now? This skips the flush, so writes still in progress may be lost.',
				success: 'Force-unmounted', btn
			});
			if (r === 'declined') toast(e.message, true); // keep the original reason visible if they don't force
		}
		return;
	}
	try {
		await withBusy(async () => {
			if (act === 'reveal') { await api('/api/reveal', { path: btn.dataset.path }); }
			else if (act === 'install-driver') {
				btn.disabled = true; toast('Downloading the driver installer…');
				const r = await api('/api/install-driver', {});
				if (r.launched) toast('Installer opened — complete it, then click Refresh.');
				// A command the user has to read and run — keep it up (dismiss by clicking) instead of on a timer.
				else if (r.instructions) toast('Run this to install the driver: ' + r.instructions + '  (click to dismiss)', false, { sticky: true });
				btn.disabled = false;
			}
		});
		refresh();
	} catch (e) { toast(e.message, true); btn.disabled = false; }
});

// ---- Mount dialog ----
let mountTarget = null, mountBiometric = [];
function openMount(path, name) {
	mountTarget = path;
	mountBiometric = (vaultsByPath[path] && vaultsByPath[path].biometric) || [];
	$('#mountName').textContent = name;
	$('#mountPass').value = '';
	if ($('#mountReadCap')) $('#mountReadCap').value = '';
	// Prefill the mount options this vault was last mounted with (favorites), so a repeat mount is
	// one click with your preferred settings. Defaults to all-off for a vault mounted here before.
	const prefs = (vaultsByPath[path] && vaultsByPath[path].mountPrefs) || {};
	$('#mountReadOnly').checked = !!prefs.readOnly;
	if ($('#mountWorkingDisk')) $('#mountWorkingDisk').checked = !!prefs.workingDisk;
	if ($('#mountStreaming')) $('#mountStreaming').checked = !!prefs.streaming;
	if ($('#mountFuseBackend')) $('#mountFuseBackend').checked = prefs.fuseBackend === 'smb';
	// Offer device-key unlock (Touch ID / Windows Hello / a security key) only when this vault is enrolled and the
	// browser can do WebAuthn on localhost. Gated on secKeyOK (the broader capability) so a security key works even
	// on a machine with no platform authenticator; the label adapts to what this machine has.
	const bioBtn = $('#mountBio');
	if (bioBtn) { bioBtn.hidden = !(secKeyOK && mountBiometric.length); bioBtn.textContent = 'Unlock with ' + deviceUnlockLabel(); }
	// Offer keyfile unlock only when this vault has a keyfile slot.
	const kfBtn = $('#mountKeyfileBtn');
	const hasKeyfile = !!(vaultsByPath[path] && vaultsByPath[path].keyfile);
	if (kfBtn) kfBtn.hidden = !hasKeyfile || !secureContext(); // a keyfile unlock needs a secure context; hide it on plain http rather than fail after the file is picked
	// A threshold key is stored as a keyfile slot, so offer share-unlock whenever the vault has one.
	const sw = $('#mountSharesWrap'); if (sw) { sw.hidden = !hasKeyfile; sw.open = false; if ($('#mountShares')) $('#mountShares').value = ''; }
	$('#mountDialog').showModal();
	setTimeout(() => $('#mountPass').focus(), 50);
}
// Mark or unmark a vault as a favorite (surfaced first, one-tap unlock).
async function toggleFavorite(path, on) {
	try { await api('/api/favorite', { path, on }); refresh(); }
	catch (e) { toast(e.message, true); }
}
// One-tap unlock for a favorite with biometric enrolled: derive the device key from the platform
// authenticator and mount directly, no dialog and no typed password. Reuses the same WebAuthn path the
// mount dialog uses; the tool still stores no password — the device authenticator releases the key.
async function quickBioMount(path) {
	const descriptors = (vaultsByPath[path] && vaultsByPath[path].biometric) || [];
	if (!descriptors.length) return toast('No device unlock is set up for this vault yet — open Keys to add Touch ID or a security key.', true);
	try {
		toast('Waiting for your device — touch your key or sensor…');
		const deviceKey = await bioDerive(descriptors);
		toast('Mounting…');
		const r = await withBusy(() => api('/api/mount', { path, password: deviceKey }));
		toast('Mounted at ' + r.mountpoint);
		refresh();
	} catch (e) { toast(e.message || 'Biometric unlock failed', true); }
}
// Perform the mount with a given secret (a typed password or a biometric device key).
async function doMount(password, over = {}) {
	const readOnly = over.readOnly != null ? over.readOnly : $('#mountReadOnly').checked;
	const force = !!over.force;
	const workingDisk = $('#mountWorkingDisk') ? $('#mountWorkingDisk').checked : false;
	const streaming = $('#mountStreaming') ? $('#mountStreaming').checked : false;
	// A read link (read capability) or threshold-key shares can stand in for a typed password.
	const readCap = $('#mountReadCap') ? $('#mountReadCap').value.trim() : '';
	const sharesRaw = $('#mountShares') ? $('#mountShares').value.trim() : '';
	const keyShares = sharesRaw ? sharesRaw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean) : null;
	if (!password && !keyShares && !readCap) { toast('Enter the password, paste threshold-key shares, or a read link.', true); return; }
	try {
		toast('Mounting…');
		const body = { path: mountTarget, readOnly, workingDisk, streaming, force };
		if ($('#mountFuseBackend') && $('#mountFuseBackend').checked) body.fuseBackend = 'smb'; // macOS: SMB transport
		if (readCap) body.readCap = readCap; else if (keyShares) body.keyShares = keyShares; else body.password = password;
		const r = await withBusy(() => api('/api/mount', body));
		$('#mountDialog').close();
		// Surface read-only up front: a share recipient (or anyone who unlocked with a read-only key) otherwise sees an
		// ordinary mounted drive and only discovers the limit when their first save fails with a bare OS write error.
		const cacheNote = r.mode === 'off' ? ' (streaming — no cache)' : (r.inRam ? ' (buffer in memory)' : '');
		const note = (r.readOnly ? ' — read-only' : '') + cacheNote;
		toast('Mounted at ' + r.mountpoint + note);
		if (r.ramDowngraded) toast('You asked for a working disk, but no in-memory RAM disk could be set up, so it fell back to streaming (in-place editing is off). On Windows, install the ImDisk driver to enable it.', true);
		refresh();
		// Automatic tamper detection. An interrupted-session change is the owner's own writes from a
		// session that ended abnormally (crash / hard kill / power loss); they have already been accepted
		// into the baseline, so present it as a plain, non-alarming notice rather than a tamper warning.
		if (r.tamper && r.tamper.kind === 'interrupted') {
			await uiConfirm({
				title: 'Vault wasn’t closed cleanly last time',
				message: 'Changes from that interrupted session (' + changeCounts(r.tamper).join(' · ') + ') have been accepted into the baseline. Nothing to do — this is expected after a crash or power loss.',
				confirmLabel: 'OK'
			});
		} else if (r.tamper) {
			const t = r.tamper, parts = [];
			if (t.tamper && t.tamper.length) parts.push(t.tamper.join(' '));
			parts.push(...changeCounts(t));
			await uiConfirm({
				title: '⚠ This vault changed since it was last used',
				message: parts.join(' · ') + '. Unmount, then use “Tamper check” to see the full list. If the change was intentional, take a snapshot there to accept it as the new baseline — otherwise this warning keeps showing.',
				confirmLabel: 'OK', danger: true
			});
		}
	} catch (e) {
		// The vault is mounted for writing on another machine. Offer a safe read-only mount or a forced
		// writable one (which may create sync-conflict copies), rather than just failing.
		if (e.locked && !force) {
			const go = await uiConfirm({ title: 'In use on another machine', message: e.message + '  Tip: you can also tick “Read only” to view it safely without any risk of conflicts.', confirmLabel: 'Force a writable mount', cancelLabel: 'Cancel', danger: true });
			if (go) return doMount(password, { force: true });
			return;
		}
		toast(e.message, true);
	}
}
// The form only submits via the primary button or Enter (Cancel is a plain button that closes the
// dialog); onDialogSubmit handles that guard.
onDialogSubmit('#mountForm', () => doMount($('#mountPass').value));
// Unlock with Touch ID / Windows Hello: derive the device key from the platform authenticator,
// then mount with it as the password.
$('#mountBio').addEventListener('click', async () => {
	try {
		toast('Waiting for your device — touch your key or sensor…');
		const deviceKey = await bioDerive(mountBiometric);
		await doMount(deviceKey);
	} catch (e) { toast(e.message || 'Biometric unlock failed', true); }
});
$('#mountKeyfileBtn').addEventListener('click', async () => {
	const file = await pickFile('mountKeyfile');
	if (!file) return;
	try {
		toast('Unlocking with the keyfile…');
		await doMount(await keyfileDigest(file)); // the keyfile's digest is the unlock secret
	} catch (e) { toast(e.message || 'Keyfile unlock failed', true); }
});

// ---- Change-password dialog ----
let passwdTarget = null;
function openPasswd(path, name) {
	passwdTarget = path;
	$('#passwdName').textContent = name;
	$('#passwdOld').value = '';
	$('#passwdNew').value = '';
	$('#passwdNew2').value = '';
	$('#passwdDialog').showModal();
	setTimeout(() => $('#passwdOld').focus(), 50);
}
onDialogSubmit('#passwdForm', async () => {
	const oldPassword = $('#passwdOld').value;
	const newPassword = $('#passwdNew').value;
	if (newPassword !== $('#passwdNew2').value) return toast('New passwords do not match', true);
	try {
		await withBusy(() => api('/api/change-password', { path: passwdTarget, oldPassword, newPassword }));
		$('#passwdDialog').close();
		toast('Password changed');
	} catch (e) { toast(e.message, true); }
});

// ---- Version history dialog (prior file versions kept at the backup destination) ----
let versionsTarget = null;
function openVersions(path, name) {
	versionsTarget = path;
	$('#versionsName').textContent = name;
	$('#versionsPw').value = '';
	$('#versionsList').innerHTML = '<div class="muted">Enter your password and load the history.</div>';
	$('#versionsResult').hidden = true;
	$('#versionsDialog').showModal();
	setTimeout(() => $('#versionsPw').focus(), 50);
}
onDialogSubmit('#versionsForm', async () => {
	const password = $('#versionsPw').value;
	if (!password) return toast('Enter your password', true);
	$('#versionsList').innerHTML = '<div class="muted">Loading…</div>'; $('#versionsResult').hidden = true;
	try {
		const rep = await withBusy(() => api('/api/versions', { path: versionsTarget, password }));
		if (!rep.hasStore) { $('#versionsList').innerHTML = '<div class="muted">This vault has no backup or mirror yet, so it has no version history. Back it up or set up a mirror first.</div>'; return; }
		if (!rep.snapshots.length) { $('#versionsList').innerHTML = '<div class="muted">No prior versions yet — they are captured each time a backup or mirror runs after a file changes.</div>'; return; }
		$('#versionsList').innerHTML = rep.snapshots.map(s => {
			const files = (s.files || []).map(f => '<li>' + esc(f) + ' <button type="button" class="link-btn" data-restore-ts="' + esc(s.timestamp) + '" data-restore-origin="' + esc(s.origin || '') + '" data-restore-file="' + esc(f) + '">Restore</button></li>').join('');
			const src = s.originLabel ? ' <span class="badge">' + esc(s.originLabel) + '</span>' : '';
			return '<div class="tamper-group"><strong>' + esc(s.at ? new Date(s.at).toLocaleString() : s.timestamp) + '</strong>' + src + '<ul>' + (files || '<li class="muted">(no files)</li>') + '</ul></div>';
		}).join('');
	} catch (e) { $('#versionsList').innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; }
});
document.addEventListener('click', async (e) => {
	const btn = e.target.closest('#versionsList [data-restore-ts]');
	if (!btn) return;
	const password = $('#versionsPw').value;
	if (!password) return toast('Enter your password', true);
	try {
		const r = await withBusy(() => api('/api/restore-version', { path: versionsTarget, password, origin: btn.dataset.restoreOrigin || undefined, timestamp: btn.dataset.restoreTs, file: btn.dataset.restoreFile }));
		showResult($('#versionsResult'), 'ok', 'Restored as <code>' + esc(r.restoredAs) + '</code> inside the vault — the current file was not touched. Open the vault to find it.');
	} catch (err) { showResult($('#versionsResult'), 'bad', esc(err.message)); }
});

// ---- Members dialog (team / multi-user vaults) ----
let membersTarget = null;
const membersShow = makeShow('#membersResult');
function openMembers(path, name) {
	membersTarget = path;
	$('#membersName').textContent = name;
	$('#membersResult').hidden = true;
	$('#membersBody').innerHTML = '<div class="muted">Loading…</div>';
	$('#membersDialog').showModal();
	loadMembers().catch(e => { $('#membersBody').innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; });
}
async function loadMembers() {
	const target = membersTarget; // capture so a late response for a vault the dialog moved on from does not render into it
	const r = await api('/api/members', { path: target });
	if (membersTarget !== target) return;
	if (!r.team) {
		$('#membersBody').innerHTML =
			'<p class="hint">This vault is not a team vault yet. Enter your password to enable team access — you become the owner.</p>' +
			'<label class="field"><span>Your password</span><input type="text" class="mask" id="teamEnablePw" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" data-1p-ignore data-lpignore="true"></label>' +
			'<div class="key-actions-close actions-left"><button type="button" class="primary-btn" id="teamEnableBtn">Enable team access</button></div>';
		return;
	}
	const rows = r.members.map(m => {
		const devs = (m.deviceCount > 1) ? ('<ul class="device-list">' + m.devices.map(d => '<li class="muted fs-12">' + esc(d.label || 'device') + ' · ' + esc(d.fingerprint) + ' <button type="button" class="link-btn danger" data-remove-device="' + esc(d.slotId) + '">revoke device</button></li>').join('') + '</ul>') : '';
		const idLine = (m.deviceCount > 1) ? ('<span class="muted fs-12">' + m.deviceCount + ' devices</span>') : ('<span class="muted fs-12">' + esc(m.fingerprint) + '</span>');
		return '<li><span class="nm" dir="auto">' + esc(m.label || 'Member') + '</span> <span class="badge">' + (m.owner ? 'owner' : (m.role === 'write' ? 'read-write' : 'read-only')) + '</span> ' + idLine +
			' <button type="button" class="link-btn" data-member-owner="' + esc(m.memberId) + '" data-make="' + (m.owner ? '0' : '1') + '">' + (m.owner ? 'Demote' : 'Make owner') + '</button>' +
			' <button type="button" class="link-btn" data-add-device="' + esc(m.memberId) + '">Add device</button>' +
			' <button type="button" class="link-btn danger" data-member-remove="' + esc(m.memberId) + '">Remove</button>' + devs + '</li>';
	}).join('');
	const rec = r.recovery ? ('Owner recovery: any ' + r.recovery.k + ' of ' + r.recovery.n + ' trustees can restore owner access.' + (r.recovery.stale ? ' <strong>It was set up before the last key rotation and no longer works — re-run owner-recovery.</strong>' : '')) : 'Owner recovery is not set up. Set it up from the command line (<code>vdisk owner-recovery</code>) so a lost owner can be recovered by trusted people.';
	$('#membersBody').innerHTML =
		'<p class="hint">Owner ' + esc(r.ownerFingerprint) + ' · roster ' + (r.rosterValid ? 'signed and valid' : '<strong>INVALID — the member list was altered</strong>') + ' · ' + rec + '</p>' +
		'<ul class="scroll-list short">' + (rows || '<li class="muted">No members yet.</li>') + '</ul>' +
		'<hr><p class="hint">Add a member by their public key (verify its fingerprint with them first):</p>' +
		'<label class="field"><span>Member public key</span><textarea id="memberPub" rows="2" spellcheck="false" class="w-full"></textarea></label>' +
		'<label class="field"><span>Name (optional)</span><input type="text" id="memberLabel"></label>' +
		'<label class="radio-row"><input type="checkbox" id="memberWrite"> <span><strong>Read-write</strong> — can change files. Leave off for read-only (recommended).</span></label>' +
		'<label class="field"><span>Your owner password</span><input type="text" class="mask" id="memberOwnerPw" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" data-1p-ignore data-lpignore="true"></label>' +
		'<div class="key-actions-close actions-left"><button type="button" class="primary-btn" id="memberAddBtn">Add member</button></div>';
}
document.addEventListener('click', async (e) => {
	if (!$('#membersDialog') || !$('#membersDialog').open) return;
	if (e.target.id === 'teamEnableBtn') {
		const password = $('#teamEnablePw').value; if (!password) return toast('Enter your password', true);
		try { await withBusy(() => api('/api/team-enable', { path: membersTarget, password })); membersShow('ok', 'Team access enabled — you are the owner.'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		return;
	}
	if (e.target.id === 'memberAddBtn') {
		const memberPub = $('#memberPub').value.trim(); const password = $('#memberOwnerPw').value;
		if (!memberPub) return toast('Paste the member\'s public key', true);
		if (!password) return toast('Enter your owner password', true);
		try { const r = await withBusy(() => api('/api/member-add', { path: membersTarget, password, memberPub, role: $('#memberWrite').checked ? 'write' : 'read', label: $('#memberLabel').value.trim() })); membersShow('ok', 'Added member (fingerprint ' + esc(r.fingerprint) + ').'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		return;
	}
	const ad = e.target.closest('[data-add-device]');
	if (ad) {
		const memberId = ad.dataset.addDevice;
		const devicePub = ($('#memberPub') && $('#memberPub').value.trim()) || '';
		const password = ($('#memberOwnerPw') && $('#memberOwnerPw').value) || '';
		if (!devicePub) { membersShow('bad', 'Paste the new device\'s public key in the "Member public key" field below, then click Add device.'); return; }
		if (!password) { membersShow('bad', 'Enter your owner password in the field below first.'); return; }
		try { await withBusy(() => api('/api/member-add-device', { path: membersTarget, password, memberId, devicePub })); membersShow('ok', 'Device enrolled for this member.'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		return;
	}
	const rd = e.target.closest('[data-remove-device]');
	if (rd) {
		const slotId = rd.dataset.removeDevice;
		const pwEl = $('#memberOwnerPw'); const password = (pwEl && pwEl.value) || '';
		if (!password) { membersShow('bad', 'Enter your owner password in the field below, then revoke the device.'); return; }
		const okd = await uiConfirm({ title: 'Revoke device', message: 'Revoking this device re-encrypts the vault so it can never open future content; the member\'s other devices keep working. It also invalidates every other password, read link, recovery key, keyfile, and security-key sign-in — re-add the ones you still need afterward. Continue?', confirmLabel: 'Revoke and re-encrypt', danger: true });
		if (!okd) return;
		if (vaultReencrypting) { membersShow('bad', 'A re-encryption is already running — let it finish before starting another.'); return; }
		vaultReencrypting = true;
		try { await apiStream('/api/member-remove-device', { path: membersTarget, password, slotId, rotate: true }, (p) => { if (p && (p.label || p.percent != null)) membersShow('', esc((p.percent != null ? p.percent + '% — ' : '') + (p.label || 'Re-encrypting…'))); }); membersShow('ok', 'Device revoked — the vault was re-encrypted.'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		finally { vaultReencrypting = false; }
		return;
	}
	const own = e.target.closest('[data-member-owner]');
	if (own) {
		const memberId = own.dataset.memberOwner; const makeOwner = own.dataset.make === '1';
		const pwEl = $('#memberOwnerPw'); const password = (pwEl && pwEl.value) || '';
		if (!password) { membersShow('bad', 'Enter your owner password in the field below, then change the role.'); return; }
		if (!makeOwner) { const okd = await uiConfirm({ title: 'Demote owner', message: 'Demote this owner to a plain member? They lose the ability to manage membership going forward. Note: because they held the owner key, being fully certain they can no longer manage membership means rotating owner access (remove and re-add owners).', confirmLabel: 'Demote', danger: true }); if (!okd) return; }
		try { await withBusy(() => api('/api/member-owner', { path: membersTarget, password, memberId, owner: makeOwner })); membersShow('ok', makeOwner ? 'Promoted to owner.' : 'Demoted to a plain member.'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		return;
	}
	const rm = e.target.closest('[data-member-remove]');
	if (rm) {
		const memberId = rm.dataset.memberRemove;
		const pwEl = $('#memberOwnerPw'); const password = (pwEl && pwEl.value) || '';
		if (!password) { membersShow('bad', 'Enter your owner password in the field below, then remove.'); return; }
		const okd = await uiConfirm({ title: 'Remove member', message: 'Fully removing a member re-encrypts the whole vault under a new key (this needs about twice the vault size in free space), so the removed member can never open future content. It also invalidates every other password, read link, recovery key, keyfile, and security-key sign-in — re-add the ones you still need afterward. The rest of the team keeps working. Continue?', confirmLabel: 'Remove and re-encrypt', danger: true });
		if (!okd) return;
		if (vaultReencrypting) { membersShow('bad', 'A re-encryption is already running — let it finish before starting another.'); return; }
		vaultReencrypting = true;
		try { await apiStream('/api/member-remove', { path: membersTarget, password, memberId, rotate: true }, (p) => { if (p && (p.label || p.percent != null)) membersShow('', esc((p.percent != null ? p.percent + '% — ' : '') + (p.label || 'Re-encrypting…'))); }); membersShow('ok', 'Member removed and revoked — the vault was re-encrypted.'); await loadMembers(); }
		catch (err) { membersShow('bad', esc(err.message)); }
		finally { vaultReencrypting = false; }
		return;
	}
});

// ---- Secure notes dialog (encrypted notes stored inside the open vault) ----
let notesTarget = null, notesCurrentId = null;
const notesShow = makeShow('#notesResult');
let notesAll = [];       // the latest listing, so the filter box can narrow it without re-fetching
const VS = window.VaultSecret || null; // the shared typed-secret schema (templates, field kinds, TOTP, clipboard)
async function loadNotesList() {
	const target = notesTarget;
	const { notes } = await api('/api/notes-list', { path: notesTarget });
	if (notesTarget !== target) return; // a late response for a vault the user navigated away from must not paint its item titles into another vault's Notes dialog (mirrors the members/keys/share loaders)
	notesAll = notes || [];
	if ($('#notesFilter')) $('#notesFilter').hidden = notesAll.length < 6; // the filter box only earns its space once there are several items
	if ($('#notesHealthBar')) $('#notesHealthBar').hidden = notesAll.length < 1; // health check is offered as soon as there is anything to check
	renderNotesList();
}
function renderNotesList() {
	const el = $('#notesList');
	// Normalize to NFC before comparing, matching the server-side search: a title stored decomposed (NFD, as macOS
	// produces) must still match an accented query typed in the browser (NFC), so the filter never misses a note.
	const q = (($('#notesFilter') && $('#notesFilter').value) || '').trim().normalize('NFC').toLowerCase();
	const icon = (t) => VS ? VS.iconFor(t) : '🔒';
	const shown = q ? notesAll.filter(n => (n.title || '').normalize('NFC').toLowerCase().indexOf(q) >= 0 || (n.type || '').normalize('NFC').toLowerCase().indexOf(q) >= 0) : notesAll;
	if (!notesAll.length) { el.innerHTML = '<div class="muted">No items yet. Start a new one below and Save.</div>'; return; }
	el.innerHTML = shown.length
		? shown.map(n => `<button type="button" class="note-item${n.id === notesCurrentId ? ' active' : ''}" data-note-id="${esc(n.id)}"><span class="note-ic" aria-hidden="true">${icon(n.type)}</span> <span class="note-nm" dir="auto">${esc(n.title || '(untitled)')}</span></button>`).join('')
		: '<div class="muted">No items match.</div>';
}
// Render the password-health report. Shows only item titles and their issue tags — never any password value — and
// each row opens that item. All checks run on this computer; the optional breach check sends only a short hash prefix.
function renderHealthPanel(r) {
	const p = $('#notesHealthPanel'); if (!p) return;
	if (!r) { p.hidden = true; p.innerHTML = ''; return; }
	const c = r.counts || {}, clean = !r.items || !r.items.length;
	const tag = (kind, txt) => `<span class="hb hb-${kind}">${txt}</span>`;
	const head = clean
		? '<span class="hb hb-ok">✓ No password issues found</span>'
		: [c.exposed ? tag('bad', c.exposed + ' exposed') : '', c.weak ? tag('warn', c.weak + ' weak') : '', c.reused ? tag('warn', c.reused + ' reused') : ''].filter(Boolean).join(' ');
	let html = `<div class="health-head">${head} <span class="fine">${r.scanned} login${r.scanned === 1 ? '' : 's'} checked${r.breachChecked ? ', incl. breaches' : ''}</span></div>`;
	if (!clean) {
		html += '<ul class="health-items">' + r.items.map(it => {
			const tags = [it.issues.exposed ? tag('bad', 'exposed') : '', it.issues.weak ? tag('warn', 'weak') : '', it.issues.reused ? tag('warn', 'reused') : ''].filter(Boolean).join(' ');
			return `<li><button type="button" class="note-item health-open" data-note-id="${esc(it.id)}"><span class="note-nm" dir="auto">${esc(it.title || '(untitled)')}</span></button> ${tags}</li>`;
		}).join('') + '</ul>';
	}
	html += '<p class="fine">Every check runs on this computer. Following NIST guidance, weak means easy to guess and we never nag you to rotate on a timer.' + (r.breachChecked ? ' “Exposed” means the password appears in a public breach list, not that your account was hacked.' : ' Tick “also check for breaches online” to compare against known breach lists — only a short, anonymized hash prefix ever leaves this computer, never your password.') + '</p>';
	if (r.breachIncomplete) html += '<p class="fine hb-bad-note">The breach check could not reach the service for some passwords, so those were not checked. Try again when you are online.</p>';
	p.innerHTML = html; p.hidden = false;
}
// Populate the template picker once, from the shared schema, so the desktop editor and the viewer share one list.
function fillNoteTypeOptions() {
	const sel = $('#noteType'); if (!sel || sel.dataset.filled) return;
	const tpls = VS ? VS.TEMPLATES : [{ type: 'note', label: 'Secure note', icon: '🗒️' }];
	sel.innerHTML = tpls.map(t => `<option value="${esc(t.type)}">${esc(t.icon + '  ' + t.label)}</option>`).join('');
	sel.dataset.filled = '1';
}
// A friendly name for each field kind in the per-field kind picker.
const KIND_LABELS = { text: 'Text', secret: 'Secret', password: 'Password', multiline: 'Multi-line', pin: 'PIN', totp: 'One-time code (2FA)', url: 'Website', email: 'Email', phone: 'Phone', date: 'Date', 'month-year': 'Month / year', boolean: 'Yes / no', number: 'Number' };
let totpTimers = []; // live-code refresh intervals for any TOTP fields on screen; cleared on rebuild and on close
function clearTotpTimers() { totpTimers.forEach(t => clearInterval(t)); totpTimers = []; }

// Build one editable field row. Uniform model — every field has a kind, an editable label, and a value control
// appropriate to its kind — so template fields and custom fields share one code path and stay consistent.
function buildFieldRow(field) {
	const f = field || { id: (VS ? VS.genId() : String(Math.random()).slice(2)), kind: 'text', label: '', value: '' };
	const secret = VS ? VS.isSecret(f) : !!f.secret;
	const row = document.createElement('div'); row.className = 'secret-field'; row.dataset.fid = f.id; row.dataset.kind = f.kind;
	// Head: editable label + kind picker + remove.
	const head = document.createElement('div'); head.className = 'sf-head';
	const label = document.createElement('input'); label.className = 'sf-label'; label.type = 'text'; label.maxLength = 200; label.value = f.label || ''; label.placeholder = 'Label'; label.setAttribute('aria-label', 'Field label');
	const kindSel = document.createElement('select'); kindSel.className = 'sf-kind'; kindSel.setAttribute('aria-label', 'Field type');
	const kinds = VS ? Object.keys(VS.KINDS) : ['text'];
	// Preserve an unknown (forward-compatible) kind rather than silently narrowing it to "text" on save: if the stored
	// field's kind is not one this build knows, include it as its own selected option so an editor round-trip keeps it.
	// The typed-secret schema is forward-compatible by design (a newer field must survive an older client), and the
	// value is escaped because an unknown kind is untrusted stored data, not a fixed vocabulary key.
	if (f.kind && !kinds.includes(f.kind)) kinds.push(f.kind);
	kindSel.innerHTML = kinds.map(k => `<option value="${esc(k)}"${k === f.kind ? ' selected' : ''}>${esc(KIND_LABELS[k] || k)}</option>`).join('');
	const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'sf-remove'; rm.title = 'Remove field'; rm.setAttribute('aria-label', 'Remove field'); rm.textContent = '✕';
	rm.addEventListener('click', () => { clearRowTotp(row); row.remove(); }); // stop any live 2FA timer before dropping the row
	head.appendChild(label); head.appendChild(kindSel); head.appendChild(rm);
	// Value area, rebuilt when the kind changes.
	const valWrap = document.createElement('div'); valWrap.className = 'sf-value';
	function paintValue(kind, value) {
		clearRowTotp(row);
		valWrap.innerHTML = '';
		const info = VS ? VS.kindInfo(kind) : {};
		const isSec = VS ? VS.isSecret({ kind, secret: f.secret }) : false;
		let input;
		if (info.multiline) { input = document.createElement('textarea'); input.rows = 3; }
		else { input = document.createElement('input'); input.type = isSec ? 'password' : (info.email ? 'email' : info.tel ? 'tel' : info.date ? 'date' : info.month ? 'month' : info.numeric ? 'text' : info.link ? 'url' : 'text'); }
		input.className = 'sf-input' + (isSec ? ' masked' : ''); input.value = value || ''; input.setAttribute('autocomplete', 'off'); input.setAttribute('autocorrect', 'off'); input.setAttribute('autocapitalize', 'off'); input.setAttribute('spellcheck', 'false');
		valWrap.appendChild(input);
		const tools = document.createElement('div'); tools.className = 'sf-tools';
		if (isSec && !info.multiline) { const eye = mkBtn('👁', 'Show or hide', () => { input.type = input.type === 'password' ? 'text' : 'password'; }); tools.appendChild(eye); }
		const copy = mkBtn('Copy', 'Copy to clipboard', () => copySecretValue(input.value)); copy.classList.add('sf-copy'); tools.appendChild(copy);
		valWrap.appendChild(tools);
		if (info.totp) { const t = document.createElement('div'); t.className = 'sf-totp'; valWrap.appendChild(t); wireTotp(row, () => input.value, t); input.addEventListener('input', () => wireTotp(row, () => input.value, t)); }
	}
	paintValue(f.kind, f.value);
	kindSel.addEventListener('change', () => { row.dataset.kind = kindSel.value; f.secret = undefined; paintValue(kindSel.value, currentRowValue(row)); });
	row.appendChild(head); row.appendChild(valWrap);
	return row;
}
function mkBtn(text, title, onclick) { const b = document.createElement('button'); b.type = 'button'; b.className = 'sf-btn'; b.textContent = text; b.title = title; b.setAttribute('aria-label', title); b.addEventListener('click', onclick); return b; }
function currentRowValue(row) { const el = row.querySelector('.sf-input'); return el ? el.value : ''; }
function clearRowTotp(row) { if (row._totpTimer) { clearInterval(row._totpTimer); const i = totpTimers.indexOf(row._totpTimer); if (i >= 0) totpTimers.splice(i, 1); row._totpTimer = null; } }
// Show a live rolling 2FA code for a TOTP field, refreshed each second. Derived on the device (Web Crypto); the
// stored value is the otpauth secret, never the momentary code.
function wireTotp(row, getValue, box) {
	clearRowTotp(row); box.innerHTML = ''; // never stack timers; re-wiring (on input) always replaces the prior one
	// No secret yet (an empty or not-yet-filled 2FA field): show nothing and start NO interval, so an empty field —
	// including the blank editor shown when the dialog is closed/reset — never leaves a timer ticking.
	if (!VS || !VS.parseTotp(getValue()).secret) { return; }
	// Build the code, seconds, and Copy nodes ONCE and only UPDATE their text each tick, so focus on the Copy button
	// is never thrown away by a per-second DOM rebuild (a keyboard/screen-reader user can actually use it).
	let cur = '';
	const code = document.createElement('span'); code.className = 'totp-code';
	const ring = document.createElement('span'); ring.className = 'totp-secs';
	const cp = mkBtn('Copy', 'Copy code', () => copySecretValue(cur));
	box.appendChild(code); box.appendChild(ring); box.appendChild(cp);
	async function tick() {
		try { const r = await VS.totpCode(VS.parseTotp(getValue())); cur = r.code; code.textContent = r.code.replace(/(\d{3})(\d+)/, '$1 $2'); ring.textContent = r.secondsRemaining + 's'; }
		catch (_) { /* unusable secret or no secure context — leave the last shown code rather than thrash the DOM */ }
	}
	tick(); row._totpTimer = setInterval(tick, 1000); totpTimers.push(row._totpTimer);
}
// Copy a value, then auto-clear the clipboard (via the shared helper) so a secret does not linger.
function copySecretValue(v) {
	if (!v) return;
	if (VS && VS.copyToClipboard) { VS.copyToClipboard(v).then(() => toast('Copied — clipboard clears shortly')).catch(() => toast('Could not copy', true)); return; }
	try { navigator.clipboard.writeText(v).then(() => toast('Copied'), () => toast('Could not copy', true)); } catch (_) {}
}
// Load an item into the editor. `item` is null (or a type string) for a new item.
function noteEditor(item) {
	fillNoteTypeOptions();
	clearTotpTimers();
	const it = (item && typeof item === 'object') ? item : (VS ? VS.blankItem(typeof item === 'string' ? item : 'login') : { id: null, title: '', type: 'note', fields: [], note: '' });
	notesCurrentId = it.id || null;
	if ($('#noteType')) $('#noteType').value = it.type || 'note';
	$('#noteTitle').value = it.title || '';
	$('#noteBody').value = it.note || '';
	$('#noteDelete').hidden = !it.id;
	if ($('#noteSend')) $('#noteSend').hidden = !it.id; // Send is offered only for a saved item (it needs an id to seal)
	const box = $('#noteFields'); box.innerHTML = '';
	(it.fields || []).forEach(f => box.appendChild(buildFieldRow(f)));
	const m = $('#noteMeta');
	if (m) {
		const fmt = (t) => { try { return new Date(t).toLocaleString(); } catch (_) { return ''; } };
		const parts = [];
		if (it.createdAt) parts.push('Created ' + fmt(it.createdAt));
		if (it.updatedAt) parts.push('Updated ' + fmt(it.updatedAt));
		m.textContent = parts.join(' · ');
		m.hidden = parts.length === 0;
	}
}
// Read the editor back into an item object for saving.
function collectNote() {
	const fields = [];
	$('#noteFields').querySelectorAll('.secret-field').forEach(row => {
		const label = row.querySelector('.sf-label'), kind = row.querySelector('.sf-kind'), val = row.querySelector('.sf-input');
		const f = { id: row.dataset.fid, kind: kind ? kind.value : 'text', label: label ? label.value : '', value: val ? val.value : '' };
		if (!f.label && !f.value) return; // drop a wholly empty field
		fields.push(f);
	});
	return { id: notesCurrentId, type: ($('#noteType') && $('#noteType').value) || 'note', title: $('#noteTitle').value, fields, note: $('#noteBody').value };
}
// Auto-close the notes dialog after a stretch of no interaction, so a note left open on screen (a password, a
// secret) does not stay revealed if you walk away. Any typing or clicking inside the dialog resets the timer.
let notesIdleTimer = null;
let notesIdleGen = 0; // bumped on every reset; the timer captures its generation so a save-await that overlaps fresh user activity aborts the close
const NOTES_IDLE_MS = 3 * 60 * 1000;
function notesResetIdle() {
	if (notesIdleTimer) { clearTimeout(notesIdleTimer); notesIdleTimer = null; }
	const dlg = $('#notesDialog'); if (!dlg || !dlg.open) return;
	const gen = ++notesIdleGen; // this armed timer's generation; any later reset (a keystroke or click) makes gen stale
	notesIdleTimer = setTimeout(async () => {
		try {
			const d = $('#notesDialog'); if (!d || !d.open) return;
			// The close below wipes the editor (so a secret is never left revealed). Before it does, PRESERVE any
			// unsaved work: if there is content, save it first — saving is non-destructive (it creates or updates the
			// note), so an idle timeout while a note is being composed can never silently lose it.
			const it = collectNote();
			const hasContent = it.title || it.note || (it.fields && it.fields.length);
			if (hasContent) {
				try { const r = await api('/api/note-save', { path: notesTarget, id: it.id, type: it.type, title: it.title, fields: it.fields, note: it.note }); notesCurrentId = r.id; }
				catch (_) { toast('An item in progress could not be auto-saved', true); return; } // save failed — leave the dialog open so the user can retry rather than lose the text
			}
			// The save may have taken a moment. If the user came back and interacted during it, notesResetIdle armed a
			// newer timer (a newer generation), so this stale one must NOT yank the dialog closed and wipe what they are
			// now typing — bail out and let the fresh timer own the idle close. Re-check open state too.
			if (gen !== notesIdleGen || !d.open) return;
			noteEditor(null); d.close();
			toast(hasContent ? 'Items closed after inactivity — your changes were saved' : 'Items closed after inactivity');
		} catch (_) {}
	}, NOTES_IDLE_MS);
}
async function openNotes(path, name) {
	notesTarget = path;
	$('#notesName').textContent = name;
	const r = $('#notesResult'); r.hidden = true; r.innerHTML = '';
	noteEditor(null);
	if ($('#notesFilter')) { $('#notesFilter').value = ''; $('#notesFilter').hidden = true; }
	renderHealthPanel(null); if ($('#notesHealthBar')) $('#notesHealthBar').hidden = true; if ($('#notesHealthBreach')) $('#notesHealthBreach').checked = false;
	$('#notesList').innerHTML = '<div class="muted">Loading…</div>';
	const dlg = $('#notesDialog');
	dlg.showModal();
	notesResetIdle();
	try { await loadNotesList(); } catch (e) { $('#notesList').innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; }
	setTimeout(() => $('#noteTitle').focus(), 50);
}
// Keep the note editor from lingering: reset the idle timer on interaction, and clear it (and the editor) on close.
(function wireNotesIdle() {
	const dlg = document.getElementById('notesDialog'); if (!dlg) return;
	['input', 'keydown', 'click'].forEach(t => dlg.addEventListener(t, notesResetIdle));
	dlg.addEventListener('close', () => { if (notesIdleTimer) { clearTimeout(notesIdleTimer); notesIdleTimer = null; } clearTotpTimers(); noteEditor(null); });
	// Filter the item list as you type (client-side over the already-loaded titles/types — no re-fetch, no plaintext).
	// Debounced so a very large list is re-rendered at most every ~120ms rather than on every keystroke.
	if ($('#notesFilter')) { let ft = null; $('#notesFilter').addEventListener('input', () => { clearTimeout(ft); ft = setTimeout(renderNotesList, 120); }); }
	// Changing the type on a NEW, still-empty item swaps in that template's starter fields; on a saved item it just
	// retags the type, so existing fields are never wiped.
	if ($('#noteType')) $('#noteType').addEventListener('change', () => {
		if (notesCurrentId) return; // editing a saved item — leave its fields alone
		const box = $('#noteFields');
		const untouched = [...box.querySelectorAll('.secret-field')].every(r => !currentRowValue(r));
		if (untouched && VS) { const it = VS.blankItem($('#noteType').value); it.title = $('#noteTitle').value; noteEditor(it); }
	});
	// Run the password-health report on demand (opt-in breach check via the checkbox).
	if ($('#notesHealthBtn')) $('#notesHealthBtn').addEventListener('click', async () => {
		const breach = !!($('#notesHealthBreach') && $('#notesHealthBreach').checked);
		const p = $('#notesHealthPanel'); if (p) { p.hidden = false; p.innerHTML = '<div class="muted">' + (breach ? 'Checking passwords and breach lists…' : 'Checking passwords…') + '</div>'; }
		try { const r = await withBusy(() => api('/api/notes-health', { path: notesTarget, breach })); renderHealthPanel(r); }
		catch (err) { if (p) { p.innerHTML = '<div class="muted">' + esc(err.message) + '</div>'; } }
	});
	// Add a custom field (defaults to a plain text field; change its type with the per-row picker).
	if ($('#noteAddField')) $('#noteAddField').addEventListener('click', () => {
		const row = buildFieldRow(VS ? { id: VS.genId(), kind: 'text', label: '', value: '' } : null);
		$('#noteFields').appendChild(row);
		const lbl = row.querySelector('.sf-label'); if (lbl) lbl.focus();
	});
})();

// ---- Send this item (an expiring, view-limited link) ----
const sendShow = makeShow('#sendResult');
let lastSendId = null; // the id of the just-created Send link, so it can be revoked from the done view
function openSend() {
	if (!notesCurrentId) return toast('Save the item first', true);
	$('#sendName').textContent = $('#noteTitle').value || '(untitled)';
	$('#sendStart').hidden = false; $('#sendDone').hidden = true; $('#sendResult').hidden = true;
	if ($('#sendPassword')) $('#sendPassword').value = '';
	if ($('#sendRevokedNote')) $('#sendRevokedNote').hidden = true;
	lastSendId = null;
	// Pause the Notes dialog's idle auto-save/close while the Send dialog is stacked on top, so the Notes dialog
	// cannot auto-close underneath while the user is composing a link. It re-arms when the Send dialog closes.
	if (notesIdleTimer) { clearTimeout(notesIdleTimer); notesIdleTimer = null; }
	$('#sendDialog').showModal();
}
if ($('#sendDialog')) $('#sendDialog').addEventListener('close', () => { if ($('#notesDialog') && $('#notesDialog').open) notesResetIdle(); }); // re-arm the Notes idle timer once Send closes
if ($('#noteSend')) $('#noteSend').addEventListener('click', openSend);
// guarded so a fast double-click can't mint two share links: the second would overwrite lastSendId/#sendUrl and
// orphan the first (a still-valid capability link the user can no longer see or revoke). Same hazard, and the same
// guard, as mobileStart minting two one-time phone sessions.
if ($('#sendCreate')) $('#sendCreate').addEventListener('click', guarded(async () => {
	try {
		const ttlMinutes = Number($('#sendTtl').value) || 10080, maxViews = Number($('#sendViews').value) || 1;
		const linkPassword = ($('#sendPassword') && $('#sendPassword').value) || '';
		const r = await withBusy(() => api('/api/send-create', { path: notesTarget, id: notesCurrentId, ttlMinutes, maxViews, linkPassword }));
		lastSendId = r.id;
		const url = location.origin + '/s/' + r.id + '#' + r.key; // the key rides in the fragment — it never went to the server and never will
		$('#sendUrl').value = url;
		const when = (() => { try { return new Date(r.expiresAt).toLocaleString(); } catch (_) { return ''; } })();
		$('#sendDoneNote').textContent = 'Opens ' + (maxViews === 1 ? 'once' : 'up to ' + maxViews + ' times') + ', expires ' + when + (linkPassword ? '. Send the password separately.' : '.') + ' Anyone with this exact link can open it, so share it carefully.';
		$('#sendStart').hidden = true; $('#sendDone').hidden = false;
		setTimeout(() => { try { $('#sendUrl').focus(); $('#sendUrl').select(); } catch (_) {} }, 50);
	} catch (e) { sendShow('bad', esc(e.message)); }
}));
if ($('#sendCopy')) $('#sendCopy').addEventListener('click', () => {
	const v = $('#sendUrl').value; if (!v) return;
	if (window.VaultSecret && window.VaultSecret.copyToClipboard) window.VaultSecret.copyToClipboard(v, { clearMs: 0 }).then(() => toast('Link copied'), () => toast('Could not copy', true));
	else try { navigator.clipboard.writeText(v).then(() => toast('Link copied'), () => toast('Could not copy', true)); } catch (_) {}
});
// Cancel a just-created link (a mis-send). The link stops working at once; the recipient sees "expired or used".
if ($('#sendRevoke')) $('#sendRevoke').addEventListener('click', async () => {
	if (!lastSendId) return;
	try { await api('/api/send-revoke', { id: lastSendId }); $('#sendUrl').value = ''; showResult($('#sendRevokedNote'), 'ok', 'This link has been revoked — it will no longer open.'); lastSendId = null; }
	catch (e) { showResult($('#sendRevokedNote'), 'bad', esc(e.message)); }
});

// ---- Search: by file name (no password when mounted) or INSIDE files (an encrypted in-vault index) ----
let searchTarget = null;
const searchProgress = stepProgress('#searchProgress', '#searchBarFill', '#searchBarText');
function searchScope() { const el = document.querySelector('input[name="searchScope"]:checked'); return el ? el.value : 'names'; }
function updateSearchScope() {
	const content = searchScope() === 'content';
	$('#searchHintNames').hidden = content; $('#searchHintContent').hidden = !content; $('#searchIndexBtn').hidden = !content;
	$('#searchQuery').placeholder = content ? 'a word inside your files' : 'part of a file or folder name';
	$('#searchResults').innerHTML = ''; $('#searchResult').hidden = true;
}
function openSearch(path, name) {
	searchTarget = path;
	$('#searchName').textContent = name;
	$('#searchQuery').value = '';
	$('#searchResults').innerHTML = '';
	const r = $('#searchResult'); r.hidden = true; r.innerHTML = '';
	const names = document.querySelector('input[name="searchScope"][value="names"]'); if (names) names.checked = true;
	$('#searchProgress').hidden = true; updateSearchScope();
	$('#searchDialog').showModal();
	setTimeout(() => $('#searchQuery').focus(), 50);
}
document.querySelectorAll('input[name="searchScope"]').forEach(el => el.addEventListener('change', updateSearchScope));
$('#searchIndexBtn').addEventListener('click', guarded(async (ev) => {
	$('#searchResults').innerHTML = ''; $('#searchProgress').hidden = false; searchProgress({ indeterminate: true, label: 'Indexing' });
	try {
		const r = await withBusy(() => apiStream('/api/content-reindex', { path: searchTarget }, searchProgress));
		$('#searchProgress').hidden = true;
		showResult($('#searchResult'), 'ok', 'Indexed ' + r.indexed + ' file' + (r.indexed === 1 ? '' : 's') + '. The index is stored inside the vault, so take a new tamper snapshot afterward.');
	} catch (e) { $('#searchProgress').hidden = true; showResult($('#searchResult'), 'bad', esc(e.message)); }
}));
onDialogSubmit('#searchForm', async () => {
	const query = $('#searchQuery').value.trim();
	if (!query) return;
	const results = $('#searchResults');
	results.innerHTML = '<div class="muted">Searching…</div>';
	try {
		if (searchScope() === 'names') {
			const { matches, mounted } = await api('/api/search-names', { path: searchTarget, query });
			if (!matches.length) { results.innerHTML = '<div class="muted">No matches.</div>'; $('#searchResult').hidden = true; return; }
			results.innerHTML = matches.map(m => '<div class="search-hit" dir="auto" title="' + esc(m) + '">' + esc(m) + '</div>').join('');
			showResult($('#searchResult'), 'ok', matches.length + ' match' + (matches.length === 1 ? '' : 'es') + (mounted ? '' : ' (unmounted)') + '.');
		} else {
			const res = await api('/api/content-search', { path: searchTarget, query });
			if (res.noIndex) { results.innerHTML = '<div class="muted">No search index yet — choose “Update index” to build one.</div>'; $('#searchResult').hidden = true; return; }
			if (res.stale) { results.innerHTML = '<div class="muted">The index needs rebuilding — choose “Update index”.</div>'; $('#searchResult').hidden = true; return; }
			if (!res.results.length) { results.innerHTML = '<div class="muted">No matches.</div>'; $('#searchResult').hidden = true; return; }
			results.innerHTML = res.results.map(m => '<div class="search-hit" dir="auto" title="' + esc(m.path) + '">' + esc(m.path) + '</div>').join('');
			showResult($('#searchResult'), 'ok', res.results.length + ' file' + (res.results.length === 1 ? '' : 's') + ' matched.');
		}
	} catch (e) { results.innerHTML = ''; showResult($('#searchResult'), 'bad', esc(e.message)); }
});
// Open a saved note into the editor.
document.addEventListener('click', async (e) => {
	const item = e.target.closest('#notesList .note-item, #notesHealthPanel .health-open');
	if (!item) return;
	try { const { note } = await api('/api/note-get', { path: notesTarget, id: item.dataset.noteId }); noteEditor(note); $('#notesResult').hidden = true; renderNotesList(); }
	catch (err) { notesShow('bad', esc(err.message)); }
});
$('#noteNew').addEventListener('click', () => { noteEditor('login'); renderNotesList(); $('#noteTitle').focus(); });
onDialogSubmit('#notesForm', async () => {
	const it = collectNote();
	if (!it.title && !it.note && !it.fields.length) return toast('Add a title, a field, or some text first', true);
	try {
		const r = await withBusy(() => api('/api/note-save', { path: notesTarget, id: it.id, type: it.type, title: it.title, fields: it.fields, note: it.note }));
		notesCurrentId = r.id; $('#noteDelete').hidden = false;
		// Re-fetch the saved item so the editor reflects exactly what was stored (sanitized fields, fresh timestamps).
		try { const { note } = await api('/api/note-get', { path: notesTarget, id: r.id }); noteEditor(note); } catch (_) {}
		notesShow('ok', 'Saved.');
		await loadNotesList();
	} catch (err) { notesShow('bad', esc(err.message)); }
});
$('#noteDelete').addEventListener('click', async () => {
	if (!notesCurrentId) return;
	// Deleting a note is permanent and has no undo, so confirm first (the project's standard for consequential,
	// irreversible actions), rather than removing it on a single click.
	const okd = await uiConfirm({ title: 'Delete item', message: 'Permanently delete this item? This cannot be undone.', confirmLabel: 'Delete', danger: true });
	if (!okd) return;
	try { await withBusy(() => api('/api/note-delete', { path: notesTarget, id: notesCurrentId })); noteEditor(null); notesShow('ok', 'Deleted.'); await loadNotesList(); }
	catch (err) { notesShow('bad', esc(err.message)); }
});

// ---- Keys dialog (multiple passwords + recovery key) ----
let keysTarget = null;
const keysShow = makeShow('#keysResult');
async function loadKeys() {
	const target = keysTarget; // capture: if a slow response resolves after the dialog was reopened for a different vault, bail rather than write the wrong vault's slots into the live dialog
	const { slots, level, recoveryReminder } = await api('/api/keys', { path: target });
	if (keysTarget !== target) return;
	const KIND = { recovery: 'recovery', device: 'device', keyfile: 'keyfile', readonly: 'read-only' };
	const rows = slots.map((s) => {
		const kind = KIND[s.kind] || 'password';
		const badge = '<span class="key-kind ' + (KIND[s.kind] || '') + '">' + kind + '</span>';
		const label = s.kind === 'keyfile' ? (s.keyfileName || s.label || 'keyfile') : (s.label || '');
		const rm = slots.length > 1 ? `<button type="button" class="link-btn danger" data-remove-key="${esc(s.id)}">Remove</button>` : '';
		return `<div class="key-row"><span class="key-info">${badge} ${esc(label)} <span class="key-id">${esc(s.id)}</span></span>${rm}</div>`;
	}).join('');
	const levelNote = level ? `<div class="hint key-level">Security level: <strong>${esc(level)}</strong> (set when the vault was created).</div>` : '';
	// After a rotation drops the recovery key, nudge the user to add a fresh one so a forgotten password is not a lockout.
	const reminder = recoveryReminder ? '<div class="banner warn key-recovery-reminder">This vault has no recovery key since it was last rotated. If you forget its password, there is no way back in — add a recovery key below and store it safely.</div>' : '';
	$('#keysList').innerHTML = reminder + levelNote + (rows || '<div class="muted">No key slots.</div>');
}
async function openKeys(path, name) {
	keysTarget = path;
	$('#keysName').textContent = name;
	const r = $('#keysResult'); r.hidden = true; r.innerHTML = ''; r.className = 'tamper-result';
	$('#keysList').innerHTML = '<div class="muted">Loading…</div>';
	if ($('#keysBio')) $('#keysBio').hidden = !bioOK;       // Touch ID / Windows Hello enrollment — needs a platform authenticator
	if ($('#keysSecKey')) $('#keysSecKey').hidden = !secKeyOK; // security-key enrollment — needs only WebAuthn on localhost
	renderKeyfileControls();                               // hide "Add keyfile" on a plain-http origin, where a keyfile cannot be read
	$('#keysDialog').showModal();
	try { await loadKeys(); } catch (e) { $('#keysList').innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; }
}
// Enroll THIS device for Touch ID / Windows Hello unlock of the current vault.
$('#keysBio').addEventListener('click', async () => {
	const password = await uiConfirm({ title: 'Set up Touch ID / Windows Hello', message: 'Enter this vault’s password to authorize enrolling this device for unlock.', confirmLabel: 'Continue', requirePassword: true });
	if (!password) return;
	try {
		keysShow('', 'Follow the Touch ID / Windows Hello prompt…');
		await bioEnroll(keysTarget, $('#keysName').textContent || 'Vault', password);
		keysShow('ok', 'This device is set up — you can now unlock this vault with Touch ID / Windows Hello.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message || 'Enrollment failed')); }
});
// Enroll a roaming SECURITY KEY (YubiKey and the like) for unlock of the current vault.
$('#keysSecKey').addEventListener('click', async () => {
	const password = await uiConfirm({ title: 'Add a security key', message: 'Enter this vault’s password to authorize enrolling a roaming security key (YubiKey and the like).', confirmLabel: 'Continue', requirePassword: true });
	if (!password) return;
	try {
		keysShow('', 'Insert your security key and follow the browser prompt (touch the key, enter its PIN)…');
		await securityKeyEnroll(keysTarget, $('#keysName').textContent || 'Vault', password);
		keysShow('ok', 'Your security key is set up — you can now unlock this vault by inserting it. Keep a password or recovery key as a backup, so a lost key never locks you out.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message || 'Enrollment failed. On Safari and iOS, roaming security keys are not supported for this — use Chrome, Edge, or Firefox on a computer.')); }
});
$('#keysAdd').addEventListener('click', async () => {
	const r = await uiConfirm({ title: 'Add a password', message: 'The vault will open with either password. Enter your current password to authorize, then the new one to add.', confirmLabel: 'Add password', requirePassword: true, passwordLabel: 'Current password', second: { label: 'New password to add' } });
	if (!r) return;
	try {
		await withBusy(() => api('/api/add-key', { path: keysTarget, password: r.password, newPassword: r.second }));
		keysShow('ok', 'Added — the vault now opens with this password too.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
});
$('#keysAddRecovery').addEventListener('click', guarded(async (ev) => {
	const password = await uiConfirm({ title: 'Add a recovery key', message: 'A new one-time recovery key will be generated and shown once — store it somewhere safe and separate. Enter your current password to authorize it.', confirmLabel: 'Generate recovery key', requirePassword: true });
	if (!password) return;
	try {
		const r = await withBusy(() => api('/api/add-recovery', { path: keysTarget, password }));
		keysShow('ok', 'Recovery key — store it safely, it is shown once:<div class="tamper-fp"><code>' + esc(r.recoveryKey) + '</code></div>');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
}));
// Recovery Kit: shows the vault's recovery VALUES natively in the app (reliable in every WebView, cross-browser, and
// in the desktop app, and it keeps the app's own feel), and prints the full one-page kit through a REAL browser — the
// one dependable way to print, since a desktop WebView has no working in-place print. "Recovery Kit" includes a spare
// recovery key and needs the current password; "Identity-only kit" records just the identity and fingerprint.
let kitToken = null, kitDesktop = false; // the current kit's print token, and whether we are running as the desktop app
async function openRecoveryKit(addKey) {
	let password = '';
	if (addKey) {
		password = await uiConfirm({ title: 'Recovery Kit', message: 'The kit includes a spare recovery key, so it needs your current password to authorize it. (Use “Identity‑only kit” for a no‑key record.)', confirmLabel: 'Create kit', requirePassword: true });
		if (!password) return;
	}
	try {
		const r = await withBusy(() => api('/api/recovery-kit', { path: keysTarget, password, addKey }));
		renderKitDialog(r);
		keysShow('ok', addKey
			? 'Recovery Kit ready — record the recovery key shown, then use Print or save as PDF to keep a copy somewhere safe and private.'
			: 'Identity‑only Recovery Kit ready — it records the vault’s identity and fingerprint but no key, so it changes nothing.');
		if (addKey) await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
}
// First-run safety net: a vault created with only a password has NO way back in if that password is forgotten. Offer
// — never force — to set up a Recovery Kit (a spare recovery key) right after creation, while the user is here and
// still knows the password. Declining is fine; the vault is created either way. Re-entering the password to authorize
// the kit also gently confirms the user actually remembers it, while recovery is still possible if they do not.
async function offerRecoveryKit(vaultPath, vaultName) {
	const go = await uiConfirm({
		title: 'Set up a Recovery Kit?',
		message: 'Your vault is protected by this password alone. If you ever forget it, there is no way back in unless you set up a recovery method now. A Recovery Kit gives you a spare recovery key to use in place of the password. Set one up now? You can also do this any time from the vault’s Keys.',
		confirmLabel: 'Set up Recovery Kit',
		cancelLabel: 'Not now',
	});
	if (!go) return;
	keysTarget = vaultPath;
	if ($('#keysName')) $('#keysName').textContent = vaultName || 'Vault';
	await openRecoveryKit(true);
}
// Build the kit view from its values with the app's own styling, so it renders reliably everywhere (no iframe, no
// external window). Every value is set via textContent (never innerHTML), so a key or identity can never inject markup.
function renderKitDialog(r) {
	const dlg = $('#kitDialog'), body = $('#kitBody'), note = $('#kitNote');
	if (!dlg || !body) return;
	kitToken = r.token || null; kitDesktop = !!r.desktop;
	if (note) note.textContent = r.addKey
		? 'This kit includes a spare recovery key. Note it or save a copy now, then store it somewhere safe and private. It is shown only here — closing this clears it.'
		: 'This records the vault’s identity and fingerprint only — no key. Save a copy for your records.';
	body.textContent = '';
	const field = (label, value, extraClass) => {
		const wrap = document.createElement('div'); wrap.className = 'kit-field' + (extraClass ? ' ' + extraClass : '');
		const l = document.createElement('div'); l.className = 'kit-label'; l.textContent = label;
		const v = document.createElement('div'); v.className = 'kit-value'; v.textContent = value == null ? '' : value;
		wrap.append(l, v); return wrap;
	};
	if (r.addKey && r.recoveryKey) body.append(field('Recovery key', r.recoveryKey, 'kit-key'));
	if (r.identity) body.append(field('Vault identity', r.identity));
	if (r.fingerprint) body.append(field('Content fingerprint', r.fingerprint));
	const steps = document.createElement('ul'); steps.className = 'kit-steps';
	const step = (t) => { const li = document.createElement('li'); li.textContent = t; steps.append(li); };
	if (r.addKey) { step('Keep the recovery key somewhere safe and private, separate from the vault.'); step('To recover access, open the vault and enter the recovery key in place of the password.'); }
	else { step('Record the identity above from a source you trust — it never changes.'); step('Later, use it to confirm that a copy is genuinely this vault.'); }
	body.append(steps);
	dlg.showModal(); // consistent with every other dialog open (all shipped WebViews support <dialog>.showModal)
}
function closeKitDialog() {
	const dlg = $('#kitDialog'), body = $('#kitBody');
	if (body) body.textContent = ''; // drop the values (and any recovery key) from the page the moment it is closed
	kitToken = null;
	if (dlg) { if (typeof dlg.close === 'function') dlg.close(); else dlg.removeAttribute('open'); }
}
// Print or save the FULL printable kit. A WebView cannot print in place, so open the kit in the user's REAL browser:
// in the desktop app the backend launches it (the WebView cannot open a window); in a normal browser we open a tab.
// The app window is untouched either way, so the kit dialog and the main app are still right there to return to.
if ($('#kitPrint')) $('#kitPrint').addEventListener('click', async () => {
	if (!kitToken) return;
	if (kitDesktop) {
		try { await api('/api/recovery-kit-open', { token: kitToken }); toast('Opening the kit in your browser to print…'); }
		catch (e) { toast((e && e.message) || 'Could not open the browser to print.', true); }
	} else if (!window.open(location.origin + '/kit-view?token=' + encodeURIComponent(kitToken), '_blank', 'noopener')) {
		toast('Your browser blocked the print window — allow pop-ups for this page, then try again.', true);
	}
});
if ($('#kitClose')) $('#kitClose').addEventListener('click', closeKitDialog);
if ($('#kitDialog')) $('#kitDialog').addEventListener('cancel', (ev) => { ev.preventDefault(); closeKitDialog(); }); // Escape closes and clears the values too
$('#keysKit').addEventListener('click', () => openRecoveryKit(true));
if ($('#keysKitId')) $('#keysKitId').addEventListener('click', () => openRecoveryKit(false));
// Add a read-only password: the current (read-write) password authorizes it; the "new password" field
// becomes the read-only password. Someone who unlocks with it can read the vault but never change it.
$('#keysAddReadOnly').addEventListener('click', guarded(async (ev) => {
	const r = await uiConfirm({ title: 'Add a read-only password', message: 'Someone unlocking with it can read the vault but never change it, add keys, or take snapshots. Enter your current read-write password to authorize, then the new read-only password.', confirmLabel: 'Add read-only password', requirePassword: true, passwordLabel: 'Current read-write password', second: { label: 'New read-only password' } });
	if (!r) return;
	try {
		await withBusy(() => api('/api/add-readonly', { path: keysTarget, password: r.password, readOnlyPassword: r.second }));
		keysShow('ok', 'Read-only password added. Unlocking with it opens the vault read-only — it can read the contents but cannot change them, add keys, or take snapshots.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
}));
// Mint a shareable read capability (a token that opens a copy of the vault read-only, no password).
$('#keysReadCap').addEventListener('click', async () => {
	const expiryDays = parseInt($('#keysReadCapExpiry') && $('#keysReadCapExpiry').value, 10) || 0;
	const password = await uiConfirm({ title: 'Create a read link', message: 'A read link opens a copy of the vault read-only, with no password. Enter your current password to authorize it.', confirmLabel: 'Create read link', requirePassword: true });
	if (!password) return;
	try {
		const r = await withBusy(() => api('/api/read-cap', { path: keysTarget, password, expiryDays }));
		const expNote = r.exp ? ' It expires on ' + new Date(r.exp).toLocaleString() + '.' : '';
		keysShow('ok', 'Read link — share it with a <em>copy</em> of the vault folder. The recipient opens it read-only (Mount → “Unlock with a read link”). It carries the read key, so treat it like a password.' + esc(expNote)
			+ '<div class="conn-row mt-1"><code class="conn-val" id="keysReadCapVal">' + esc(r.token) + '</code><button type="button" class="copy-btn" data-copy="#keysReadCapVal">Copy</button></div>'
			+ '<p class="hint">Share id <code>' + esc(r.sid) + '</code>. Revoking ends any live in-app viewer session and marks the share revoked, but it cannot stop a node already serving the vault or recall a link someone already holds. To cut off a leaked read key for good, re-encrypt the vault.</p>');
		loadShares().catch(() => {});
	} catch (e) { keysShow('bad', esc(e.message)); }
});
// Who has access: the signed roster of read links handed out, with expiry and a revoke button each.
async function loadShares() {
	const target = keysTarget; // capture so a slow response can't populate a different vault's reopened dialog
	let rep; try { rep = await api('/api/shares', { path: target }); } catch (_) { return; }
	if (keysTarget !== target) return;
	const shares = (rep && rep.shares) || [];
	if (!shares.length) { keysShow('ok', 'No read links have been handed out for this vault yet.'); return; }
	const rows = shares.map(s => {
		const state = s.revoked ? '<span class="share-key-caution">revoked</span>' : s.expired ? '<span class="muted">expired</span>' : '<span class="txt-good">active</span>';
		const exp = s.exp ? ' · expires ' + esc(new Date(Number(s.exp)).toLocaleDateString()) : '';
		const rm = (!s.revoked) ? '<button type="button" class="link-btn danger" data-revoke-sid="' + esc(s.sid) + '">Revoke</button>' : '';
		return '<div class="key-row"><span class="key-info">' + state + ' ' + esc(s.label || '(read link)') + ' <span class="key-id">' + esc(s.sid) + '</span>' + exp + '</span>' + rm + '</div>';
	}).join('');
	const sigWarn = rep.rolledBack ? '<p class="share-key-caution">⚠ This access list is an older version than this device last saw — it may have been rolled back to undo a revocation.</p>'
		: (rep.sigOk ? '' : '<p class="share-key-caution">⚠ The access list signature did not verify — it may have been altered.</p>');
	// Revoked/expired entries stay in the list until cleaned up (they document what was cut off). Offer to remove
	// the dead ones so the list does not grow without bound — it only tidies, never changes who can open the vault.
	const dead = shares.filter(s => s.revoked || s.expired).length;
	const cleanup = dead ? '<div class="key-row"><button type="button" class="link-btn" data-prune-shares="1">Remove ' + dead + ' revoked/expired entr' + (dead === 1 ? 'y' : 'ies') + '</button></div>' : '';
	keysShow('ok', '<div class="tamper-group"><strong>Who has access (' + shares.length + ')</strong>' + rows + cleanup + '</div>' + sigWarn
		+ 'Revoking blocks a share on a served node and marks it here; it cannot recall a copy someone already downloaded.');
}
$('#keysShares').addEventListener('click', () => { loadShares().catch(e => keysShow('bad', esc(e.message))); });
// Rotate keys + re-encrypt the whole vault — true, cryptographic revocation of a leaked read link.
$('#keysRotate').addEventListener('click', async () => {
	const password = await uiConfirm({
		title: 'Rotate keys and re-encrypt everything?',
		message: 'This re-encrypts EVERY file under a new key and changes the vault’s identity — the way to cut off a leaked read link for good. Every OTHER password, key, and read link is invalidated (you re-add the ones you keep). It needs about double the vault size in free space temporarily, can take a while, and is safe to interrupt — the vault is untouched unless it finishes. A mirror or backup still holds old-key data until you re-encrypt or delete it.',
		confirmLabel: 'Rotate and re-encrypt', danger: true, requirePassword: true
	});
	if (!password) return;
	if (vaultReencrypting) { keysShow('bad', 'A re-encryption is already running — let it finish before starting another.'); return; }
	vaultReencrypting = true;
	try {
		keysShow('', 'Re-encrypting… this can take a while.');
		const r = await apiStream('/api/rotate', { path: keysTarget, password }, (p) => { if (p && p.label) keysShow('', esc((p.percent != null ? p.percent + '% — ' : '') + p.label)); });
		keysShow('ok', 'Done — the vault was re-encrypted and its identity rotated to <code>' + esc(r.newIdentity) + '</code>. Record the new identity (or make a fresh Recovery Kit), and re-add any keys or read links you want to keep.' + (r.recoveryDropped ? ' <strong>This vault no longer has a recovery key — add one below so a forgotten password is not a lockout.</strong>' : ''));
		try { await loadKeys(); } catch (_) {} // refresh the slot list and surface the no-recovery-key reminder banner
		refresh();
	} catch (e) { keysShow('bad', esc(e.message)); }
	finally { vaultReencrypting = false; }
});
document.addEventListener('click', async (e) => {
	const btn = e.target.closest('#keysResult [data-revoke-sid]');
	if (!btn) return;
	// Revoking cuts off access — confirm it (reusing the shared modal, which also collects the authorizing password) so a stray click can't do it by accident.
	const password = await uiConfirm({ title: 'Revoke access', message: 'Revoke this access going forward? The link or mobile session using it stops working, and a served node refuses it. It cannot recall a copy someone already downloaded — to cut off a leaked key for good, rotate the vault’s keys. Enter your current password to authorize.', confirmLabel: 'Revoke', danger: true, requirePassword: true });
	if (!password) return;
	try { await withBusy(() => api('/api/revoke-share', { path: keysTarget, password, sid: btn.dataset.revokeSid })); toast('Share revoked'); await loadShares(); }
	catch (err) { keysShow('bad', esc(err.message)); }
});
// Clean up the access list: permanently remove the revoked and expired (dead) entries. Same password gate and
// confirm as revoke; it only tidies the list and never changes who can open the vault.
document.addEventListener('click', async (e) => {
	const btn = e.target.closest('#keysResult [data-prune-shares]');
	if (!btn) return;
	const password = await uiConfirm({ title: 'Remove revoked & expired', message: 'Permanently remove the revoked and expired entries from this vault’s access list? Active access is untouched — this only tidies the list and does not change who can open the vault. Enter your current password to authorize.', confirmLabel: 'Remove', danger: true, requirePassword: true });
	if (!password) return;
	try { const r = await withBusy(() => api('/api/prune-shares', { path: keysTarget, password })); toast('Removed ' + r.removed + ' entr' + (r.removed === 1 ? 'y' : 'ies')); await loadShares(); }
	catch (err) { keysShow('bad', esc(err.message)); }
});
$('#keysAddKeyfile').addEventListener('click', guarded(async (ev) => {
	const file = await pickFile('keysKeyfile'); // opens the file picker on the click gesture (a file dialog needs that gesture)
	if (!file) return;
	const password = await uiConfirm({ title: 'Add a keyfile', message: 'Use the file “' + file.name + '” as a key that unlocks the vault on its own. Enter your current password to authorize.', confirmLabel: 'Add keyfile', requirePassword: true });
	if (!password) return;
	try {
		keysShow('', 'Fingerprinting the keyfile…');
		const digest = await keyfileDigest(file);
		await withBusy(() => api('/api/add-keyfile', { path: keysTarget, password, keyfileDigest: digest, keyfileName: file.name }));
		keysShow('ok', 'Added — this vault now opens with the keyfile "' + esc(file.name) + '" as well. Keep that file safe; anyone who has it can unlock the vault.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
}));
$('#keysList').addEventListener('click', async (ev) => {
	const btn = ev.target.closest('button[data-remove-key]');
	if (!btn) return;
	// You must authorize with a DIFFERENT key than the one being removed — a vault always keeps at least one way in.
	const password = await uiConfirm({ title: 'Remove key', message: 'Remove this key? The vault will no longer open with it. Enter a DIFFERENT password or key that still opens the vault to authorize.', confirmLabel: 'Remove', danger: true, requirePassword: true, passwordLabel: 'A different password that still opens the vault' });
	if (!password) return;
	try {
		await withBusy(() => api('/api/remove-key', { path: keysTarget, password, slotId: btn.dataset.removeKey }));
		keysShow('ok', 'Key removed.');
		await loadKeys();
	} catch (e) { keysShow('bad', esc(e.message)); }
});

// ---- Share dialog (group password + hand-off) ----
// A guided layer over the same building blocks as Keys: it adds a read-only OR read-write password for a
// group (reusing /api/add-readonly and /api/add-key), then helps hand the vault over — packed into one file,
// or via a shared folder. No new sharing mechanism; just a simple flow for "share this with a group."
let shareTarget = null, shareGroupSlotId = null;
const shareShow = makeShow('#shareResult');
function shareAccess() { const el = document.querySelector('input[name="shareAccess"]:checked'); return el ? el.value : 'ro'; }
// ---- Mobile access: mint a one-time code + QR so a phone can open the vault and decrypt locally ----
let mobileTarget = null;
function openMobile(path, name) {
	mobileTarget = path;
	$('#mobileName').textContent = name;
	$('#mobilePassword').value = '';
	$('#mobileStart').hidden = false; $('#mobilePaired').hidden = true;
	$('#mobileQr').innerHTML = ''; $('#mobileCode').textContent = ''; $('#mobileUrl').value = ''; $('#mobileReach').hidden = true;
	$('#mobileDialog').showModal();
	setTimeout(() => $('#mobilePassword').focus(), 50);
}
function renderQr(box, text) {
	box.innerHTML = '';
	try { const q = window.qrcode(0, 'M'); q.addData(text); q.make(); box.innerHTML = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true }); }
	catch (e) { box.textContent = 'QR unavailable — use the address below.'; }
}
// Mint a one-time read-only access session for the target vault from the typed password. Shared by both
// ways to open the viewer — in this browser, or via a code/QR on a phone — so the two paths stay in step.
// `local` true is the in-app viewer opened in this browser: an ephemeral session that leaves no entry in the
// vault's access list. The phone path (local false) records a revocable grant, as a handed-out device should.
async function mobileMintSession(local) {
	const password = $('#mobilePassword').value;
	if (!password) { toast('Enter the vault password', true); return null; }
	return withBusy(() => api('/api/mobile-start', { path: mobileTarget, password, local: !!local }));
}
// Open the vault in the built-in viewer in THIS browser — the low-residue path: files decrypt in the page,
// with no mount, no external app, and no OS preview cache. The viewer auto-pairs from the code in the URL
// hash. The blank tab is opened synchronously, before the await, so the click still counts as a user
// gesture and a pop-up blocker cannot swallow it; on failure the stray tab is closed.
async function mobileOpenHere() {
	if (!$('#mobilePassword').value) return toast('Enter the vault password', true);
	const tab = window.open('', '_blank');
	let r; try { r = await mobileMintSession(true); } catch (e) { if (tab && !tab.closed) tab.close(); return toast(e.message, true); }
	if (!r) { if (tab && !tab.closed) tab.close(); return; }
	const url = location.origin + r.path + '#' + r.code;
	if (tab && !tab.closed) tab.location = url; else if (!window.open(url, '_blank', 'noopener')) location.href = url;
	$('#mobileDialog').close();
}
// Get a one-time code + QR to open the vault on a phone instead (files decrypt on the phone there).
async function mobileStart() {
	let r; try { r = await mobileMintSession(); } catch (e) { return toast(e.message, true); }
	if (!r) return;
	const url = location.origin + r.path + '#' + r.code;
	$('#mobileUrl').value = url;
	$('#mobileCode').textContent = r.code;
	renderQr($('#mobileQr'), url);
	// Honest reach note. A LOOPBACK address (localhost / 127.* / ::1) is reachable ONLY on this computer, so a phone
	// can never open it — say so plainly and give the exact steps to put the interface on the network, rather than
	// implying "same network" works. A network (https) address is phone-reachable and can also install offline.
	const host = location.hostname.replace(/^\[|\]$/g, '');
	const loopback = host === 'localhost' || /^127\./.test(host) || host === '::1';
	const reach = $('#mobileReach'); reach.hidden = false; reach.className = 'tamper-result ' + (loopback ? 'bad' : (location.protocol === 'https:' ? 'ok' : 'warn'));
	reach.innerHTML = loopback
		? 'This address works only on this computer, so no phone or other device can open it.'
			+ '<br><br>To open a vault on your phone, first put the interface on your network:'
			+ '<br>1. Set a login: <code>' + esc(APP_CLI) + ' web-password set</code>'
			+ '<br>2. Restart it on your network: <code>' + esc(APP_CLI) + ' ui --bind 0.0.0.0</code>'
			+ '<br>3. On this computer, open the <strong>https</strong> address it prints, then get a phone code again from there.'
			+ '<br>Your phone then opens that same https address.'
			+ '<br><br>To have it start this way every time, turn on <strong>Start at login</strong> in Settings and choose <strong>my other devices</strong>.'
		: location.protocol === 'https:'
			? 'Your phone needs to reach this computer at this address — on the same network, or through a VPN or tunnel you run. Because it is a secure (https) address, it can also be added to the home screen and used offline. (This is a self-signed certificate, so the phone shows a one-time warning to accept.)'
			: 'Your phone needs to reach this computer at this address, over your own network or VPN. For an offline, home-screen app, reach it over a secure <strong>https</strong> address (a reverse proxy, VPN, or tunnel with a real certificate) — plain http can view while connected but cannot install offline.';
	$('#mobileStart').hidden = true; $('#mobilePaired').hidden = false;
}
onDialogSubmit('#mobileForm', mobileOpenHere);
if ($('#mobileGetCode')) $('#mobileGetCode').addEventListener('click', guarded(mobileStart)); // guarded so a fast double-click can't mint two one-time phone sessions (two revocable grants to clean up)
if ($('#mobileAnother')) $('#mobileAnother').addEventListener('click', () => { $('#mobileStart').hidden = false; $('#mobilePaired').hidden = true; setTimeout(() => $('#mobilePassword').focus(), 50); });

function openShare(path, name) {
	shareTarget = path; shareGroupSlotId = null;
	$('#shareName').textContent = name;
	$('#shareCurrent').value = ''; $('#sharePassword').value = ''; $('#shareConfirm').value = '';
	const ro = document.querySelector('input[name="shareAccess"][value="ro"]'); if (ro) ro.checked = true;
	const r = $('#shareResult'); r.hidden = true; r.innerHTML = ''; r.className = 'tamper-result';
	$('#shareDeliver').hidden = true; $('#shareKeyList').innerHTML = ''; $('#shareCreate').hidden = false;
	$('#shareDialog').showModal();
	setTimeout(() => $('#shareCurrent').focus(), 50);
}
// List the vault's keys as checkboxes so the sharer chooses which ones go into the packed file. The group
// key just created is ticked; every other key (the owner's own password, other keys) starts unticked, so by
// default the shared copy opens ONLY with the group password. Device (biometric) keys are machine-bound and
// cannot open a copy elsewhere, so they are never offered.
async function loadShareKeys() {
	const box = $('#shareKeyList'); if (!box) return;
	box.innerHTML = '<div class="muted">Loading…</div>';
	const target = shareTarget; // capture so a late response can't render into a reopened dialog for another vault
	let data; try { data = await api('/api/keys', { path: target }); } catch (e) { box.innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; return; }
	if (shareTarget !== target) return;
	// Device (biometric) keys are machine-bound and can't open a copy elsewhere, so they are never offered.
	const slots = (data.slots || []).filter(s => s.kind !== 'device');
	if (!slots.length) { box.innerHTML = '<div class="muted">This vault has no shareable keys.</div>'; return; }
	box.innerHTML = slots.map(s => {
		const isGroup = s.id === shareGroupSlotId;
		const tag = (s.kind && s.kind !== 'password') ? ' <span class="key-kind ' + esc(s.kind) + '">' + esc(s.kind) + '</span>' : '';
		// Spell out what each key IS so the user can tell their own password apart from the group's.
		const note = isGroup ? ' <span class="mine">— the group password (tick this)</span>'
			: s.kind === 'recovery' ? ' <span class="mine">— your recovery key (best left out)</span>'
			: s.kind === 'readonly' ? ' <span class="mine">— an existing read‑only password</span>'
			: ' <span class="mine">— your own password (leave unticked to keep it out)</span>';
		return '<label class="radio-row"><input type="checkbox" class="share-key-cb" data-kind="' + esc(s.kind || 'password') + '" value="' + esc(s.id) + '"' + (isGroup ? ' checked' : '') + '> <span>' + esc(s.label || 'Password') + tag + note + '</span></label>';
	}).join('') + '<div id="shareKeyCaution" class="share-key-caution" hidden></div>';
	updateShareKeyCaution();
}
// Warn if the user ticks something risky to hand out: a recovery key, or a read‑write password other than the
// group one (which would let it open the shared copy too).
function updateShareKeyCaution() {
	const c = $('#shareKeyCaution'); if (!c) return;
	const ticked = [...document.querySelectorAll('.share-key-cb:checked')];
	const rec = ticked.some(cb => cb.dataset.kind === 'recovery');
	const ownRw = ticked.some(cb => cb.dataset.kind === 'password' && cb.value !== shareGroupSlotId);
	if (rec) { c.hidden = false; c.textContent = '⚠ A recovery key is ticked — including it gives the group your recovery ability. Untick it unless you mean to.'; }
	else if (ownRw) { c.hidden = false; c.textContent = '⚠ A read‑write password other than the group’s is ticked — the shared copy will also open with it.'; }
	else c.hidden = true;
}
document.addEventListener('change', (e) => { if (e.target && e.target.classList && e.target.classList.contains('share-key-cb')) updateShareKeyCaution(); });
// Digit-only inputs (marked data-digits) and select-all-on-focus fields (data-selectall), bound by delegation
// here instead of inline on* attributes — the app's Content-Security-Policy forbids inline handlers, which
// silently disabled the old attribute versions. Stripping non-digits on 'input' also covers paste, which the
// former keypress guard did not.
document.addEventListener('input', (e) => { const t = e.target; if (t && t.dataset && t.dataset.digits) { const c = t.value.replace(/\D+/g, ''); if (c !== t.value) t.value = c; } });
function selectAllField(e) { const t = e.target; if (t && t.dataset && t.dataset.selectall) { try { t.select(); } catch (_) {} } }
document.addEventListener('focusin', selectAllField);
document.addEventListener('click', selectAllField);
onDialogSubmit('#shareForm', async () => {
	const password = $('#shareCurrent').value, group = $('#sharePassword').value, confirm = $('#shareConfirm').value;
	if (!password) return toast('Enter your current password', true);
	if (!group) return toast('Enter a group password', true);
	if (group !== confirm) return shareShow('bad', 'The two group passwords do not match.');
	const ro = shareAccess() === 'ro';
	try {
		const res = ro
			? await withBusy(() => api('/api/add-readonly', { path: shareTarget, password, readOnlyPassword: group, label: 'Group share (read-only)' }))
			: await withBusy(() => api('/api/add-key', { path: shareTarget, password, newPassword: group, label: 'Group share' }));
		shareGroupSlotId = (res && res.slotId) || null;
		shareShow('ok', 'Group password created — the vault now also opens with it, '
			+ (ro ? '<strong>read-only</strong> (the group can view but not change it).' : '<strong>read-write</strong> (the group can view and change it).')
			+ ' You can change or remove it any time from <strong>Keys</strong>, instantly and without re‑encrypting.');
		$('#shareDeliver').hidden = false;
		$('#shareCreate').hidden = true; // password made — the next step is now "Pack to a file" (promoted below)
		await loadShareKeys();
	} catch (e) { shareShow('bad', esc(e.message)); }
});
// Pack the vault to one portable file inside a folder the user picks, to hand to the group.
const shareProgress = stepProgress('#shareProgress', '#shareBarFill', '#shareBarText');
function shareSelectedKeys() { return [...document.querySelectorAll('.share-key-cb:checked')].map(cb => cb.value); }
async function sharePackTo(folder, overwrite, keepSlots) {
	shareShow('', 'Packing the vault into one file. This can take a moment for a large vault — keep ' + APP_NAME + ' running.');
	shareProgress({ indeterminate: true, label: 'Starting' });
	try {
		const r = await withBusy(() => apiStream('/api/pack', { path: shareTarget, destFolder: folder, overwrite, keepSlots }, shareProgress));
		shareShow('ok', 'Saved a single shareable file:<div class="tamper-fp"><code>' + esc(r.file) + '</code></div>'
			+ 'It opens only with the ' + keepSlots.length + ' key' + (keepSlots.length === 1 ? '' : 's') + ' you chose. Send this file and the group password. Each member opens it in one step with <strong>Open a shared file…</strong> above the vault list (or <code>vdisk unpack</code>), then mounts it with the group password.');
	} finally { shareProgress(null); }
}
$('#sharePack').addEventListener('click', () => {
	const keepSlots = shareSelectedKeys();
	if (!keepSlots.length) return shareShow('bad', 'Tick at least one password that should open the shared file (otherwise no one could open it).');
	openBrowse({ title: 'Choose where to save the file', useLabel: 'Save here', onChoose: async (folder) => {
		try { await sharePackTo(folder, false, keepSlots); }
		catch (e) {
			if (/already exists/i.test(e.message)) {
				if (await uiConfirm({ title: 'Overwrite?', message: 'A file with that name is already in that folder. Overwrite it?', confirmLabel: 'Overwrite', danger: true })) {
					try { await sharePackTo(folder, true, keepSlots); } catch (e2) { shareShow('bad', esc(e2.message)); }
				}
			} else shareShow('bad', esc(e.message));
		}
	} });
});

// ---- Tamper-check dialog ----
let tamperTarget = null;
function openTamper(path, name) {
	tamperTarget = path;
	$('#tamperName').textContent = name;
	$('#tamperPass').value = '';
	const res = $('#tamperResult');
	res.hidden = true; res.innerHTML = ''; res.className = 'tamper-result';
	// The Seal button doubles as Unseal when the vault is already sealed.
	const sealed = !!(vaultsByPath[path] && vaultsByPath[path].sealed);
	const sealBtn = $('#tamperSeal');
	sealBtn.textContent = sealed ? 'Unseal' : 'Seal';
	sealBtn.dataset.mode = sealed ? 'unseal' : 'seal';
	$('#tamperDialog').showModal();
	setTimeout(() => $('#tamperPass').focus(), 50);
}
const tamperShow = makeShow('#tamperResult');

// Permanent delete (crypto-erase). The Delete button unlocks only when the typed text is the vault's
// exact name, so this can never fire on a stray click — the same absolute confirmation the command line asks for.
let destroyTarget = null;
function openDestroy(path, name) {
	destroyTarget = path;
	$('#destroyName').textContent = name;
	$('#destroyExpect').textContent = name;
	const rv = vaultsByPath[path] || {};
	// A cloud vault keeps its ciphertext at the provider; destroying the local keys makes it undecryptable,
	// but the provider may still hold the data and old versions, so surface that caveat.
	$('#destroyCloudNote').hidden = !rv.cloud;
	const input = $('#destroyConfirm');
	const pw = $('#destroyPassword');
	const go = $('#destroyGo');
	input.value = '';
	pw.value = '';
	go.disabled = true;
	// Both are required: the typed name guards against erasing the wrong vault, and the password proves the person can
	// actually open this one. The server verifies the password regardless, so this only gates the button.
	const sync = () => { go.disabled = input.value.trim() !== name || !pw.value; };
	input.oninput = sync;
	pw.oninput = sync;
	$('#destroyDialog').showModal();
	setTimeout(() => input.focus(), 50);
}
onDialogSubmit('#destroyForm', async () => {
	const name = $('#destroyName').textContent;
	const password = $('#destroyPassword').value;
	// Never erase on a mismatch, even though the button is disabled until the name matches — defense in depth.
	if ($('#destroyConfirm').value.trim() !== name || !password) return;
	const path = destroyTarget;
	try {
		const res = await withBusy(() => api('/api/secure-remove', { path, confirmName: name, password }));
		$('#destroyDialog').close();
		// On rare partial cleanup (a lock on Windows kept a now-meaningless file) the keys are still destroyed —
		// say so plainly rather than implying failure, and note the harmless leftover the user can delete by hand.
		// Make that leftover case sticky (dismiss by clicking): it asks the user to do something, so it should not
		// vanish on a timer; the clean case is a brief confirmation.
		if (res && res.leftover) toast('Deleted “' + name + '” — its keys are destroyed; a few now-unreadable leftover files could not be removed and can be deleted by hand. Click to dismiss.', false, { sticky: true });
		else toast('Permanently deleted “' + name + '”');
		refresh();
	} catch (e) { toast(e.message, true); }
});
function fileList(label, arr) {
	if (!arr.length) return '';
	return '<div class="tamper-group"><strong>' + label + ' (' + arr.length + ')</strong><ul>' +
		arr.slice(0, 200).map(p => '<li>' + esc(p) + '</li>').join('') +
		(arr.length > 200 ? '<li>… and ' + (arr.length - 200) + ' more</li>' : '') + '</ul></div>';
}
// The "Tampering" block (rollback / forged-or-removed baseline notes) — like fileList but unnumbered.
function tamperGroup(items) {
	if (!items || !items.length) return '';
	return '<div class="tamper-group"><strong>Tampering</strong><ul>' + items.map(t => '<li>' + esc(t) + '</li>').join('') + '</ul></div>';
}
// Cloud-sync leftovers (conflicted copies, partial uploads) found in the store — shown so a sync
// artifact reads as a sync issue to resolve, not as tampering. Groups by the plain-language reason.
function syncGroup(issues) {
	if (!issues || !issues.length) return '';
	const byWhy = {};
	for (const s of issues) (byWhy[s.why] = byWhy[s.why] || []).push(s.file);
	const groups = Object.keys(byWhy).map(why => '<div><em>' + esc(why) + '</em><ul>' +
		byWhy[why].slice(0, 50).map(f => '<li>' + esc(f) + '</li>').join('') +
		(byWhy[why].length > 50 ? '<li>… and ' + (byWhy[why].length - 50) + ' more</li>' : '') + '</ul></div>').join('');
	return '<div class="tamper-group"><strong>Cloud-sync leftovers (' + issues.length + ') — not tampering</strong>' + groups + '</div>';
}
// A compact "N modified · N removed · N added" summary of a change set (shared by the mount warning
// and the tamper-history rows).
function changeCounts(e) {
	const parts = [];
	if (e.modified && e.modified.length) parts.push(e.modified.length + ' modified');
	if (e.removed && e.removed.length) parts.push(e.removed.length + ' removed');
	if (e.added && e.added.length) parts.push(e.added.length + ' added');
	// Foreign/undecryptable files sitting in the encrypted store — added from outside without the password.
	if (e.foreign && e.foreign.length) parts.push(e.foreign.length + ' unrecognized');
	// Files present with a valid name but unreadable content — a damaged/corrupt blob, or a loss beyond self-healing.
	if (e.damaged && e.damaged.length) parts.push(e.damaged.length + ' damaged');
	return parts;
}
// The vault's version + short fingerprint, shown so a user can record it and later confirm the
// vault is the exact version they left (a rollback anchor that works across machines).
function fingerprintLine(r) {
	if (!r || !r.fingerprint) return '';
	return '<div class="tamper-fp">Version ' + esc(String(r.seq)) + ' · fingerprint <code>' + esc(r.fingerprint) + '</code></div>';
}
// The vault's STABLE identity, plus a paste-to-verify box. The identity is the fingerprint of the vault's
// write‑authority key — it never changes as you edit, and a hacker's recreation has a different one they
// cannot reproduce. The user records it once; to confirm a vault is genuinely theirs they paste that value
// and the COMPUTER compares it exactly (people miss look‑alike fingerprints, and attackers exploit that).
function identityBlock(r) {
	if (!r || !r.identity) return '';
	return '<div class="identity-box">'
		+ '<div class="identity-head">Vault identity <span class="muted">— which vault this is (stays the same as you edit)</span></div>'
		+ '<div class="conn-row"><code class="conn-val" id="vaultIdentityVal">' + esc(r.identity) + '</code><button type="button" class="copy-btn" data-copy="#vaultIdentityVal">Copy</button></div>'
		+ '<div class="identity-verify"><input type="text" id="identityCheck" placeholder="Paste the identity you recorded to confirm this is your vault" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"><button type="button" class="ghost-btn" id="identityCheckBtn">Check</button></div>'
		+ '<div id="identityCheckResult" class="identity-result hint"></div>'
		+ '</div>';
}
// Compare the pasted identity to the vault's, ignoring spacing/case/hyphens (so a value copied by hand still
// matches). Done for the user so a near‑match a hacker crafted can't slip past the eye.
function normId(s) { return String(s || '').replace(/[^a-z0-9]/gi, '').toUpperCase(); }
document.addEventListener('click', (e) => {
	if (!e.target.closest('#identityCheckBtn')) return;
	const res = $('#identityCheckResult'), valEl = $('#vaultIdentityVal'), inEl = $('#identityCheck');
	if (!res || !valEl || !inEl) return;
	const got = normId(inEl.value);
	if (!got) { res.className = 'identity-result hint'; res.textContent = 'Paste the identity you recorded above, then Check.'; return; }
	if (got === normId(valEl.textContent)) { res.className = 'identity-result ok'; res.innerHTML = '✓ Match — this is the vault you recorded. (Make sure the check above also reports no tampering.)'; }
	else { res.className = 'identity-result bad'; res.innerHTML = '✗ Does NOT match — this is not the vault you recorded. Treat it as a different or recreated vault and do not trust it.'; }
});
// Establish a new baseline — a plain snapshot or a strict seal — always as a REVIEWED, deliberate
// act. First audits the vault: if changes are outstanding, it shows exactly what would be accepted
// and requires an explicit confirmation; if the vault is already clean, it still confirms, because
// writing a baseline redefines "trusted" and should never be a stray click. `opts` supplies the
// endpoint and the wording for each surface; both Take snapshot and Seal go through here.
async function writeBaselineReviewed(opts) {
	const password = $('#tamperPass').value;
	if (!password) return toast('Enter the password', true);
	try {
		tamperShow('', 'Checking what would be recorded…');
		const chk = await withBusy(() => api('/api/audit', { path: tamperTarget, password }));
		// A vault with no baseline yet is not an error here — it is the normal first-time case, so
		// fall through to the plain confirmation. Any other error (wrong password, unreadable) stops.
		if (chk.errors && chk.errors.length && !chk.noSnapshot) { tamperShow('bad', esc(chk.errors.join(' '))); return; }
		let accept = null, okd;
		if (!chk.clean && !chk.noSnapshot) {
			accept = { modified: chk.modified || [], removed: chk.removed || [], added: chk.added || [] };
			const n = accept.modified.length + accept.removed.length + accept.added.length;
			const tamper = tamperGroup(chk.tamper);
			// A tamper-only report (n === 0 but a note present) means the baseline record itself was
			// removed or forged — describe that, not "0 changes".
			const lead = (n === 0 && chk.tamper && chk.tamper.length)
				? 'The baseline record itself is missing or altered. Continuing writes a fresh ' + opts.noun + ' from the current contents:'
				: 'These ' + n + ' change' + (n === 1 ? '' : 's') + ' would be accepted as the new ' + opts.noun + ':';
			tamperShow('bad', lead + tamper +
				fileList('Modified', accept.modified) + fileList('Removed', accept.removed) + fileList('Added', accept.added));
			okd = await uiConfirm({
				title: opts.dirtyTitle,
				message: (n === 0 && chk.tamper && chk.tamper.length)
					? 'This vault’s baseline record is missing or altered. Continuing writes a fresh ' + opts.noun + ' from the current contents — review the note behind this dialog first. Continue?' + (opts.dirtySuffix || '')
					: 'This vault has ' + n + ' change' + (n === 1 ? '' : 's') + ' since its last trusted state. Continuing accepts the current contents as the new ' + opts.noun + ' — review the list behind this dialog first. Continue?' + (opts.dirtySuffix || ''),
				confirmLabel: opts.dirtyConfirm, danger: true
			});
		} else {
			okd = await uiConfirm({ title: opts.cleanTitle, message: opts.cleanMessage, confirmLabel: opts.cleanConfirm, danger: !!opts.cleanDanger });
		}
		if (!okd) { tamperShow('', opts.canceled); return; }
		tamperShow('', opts.working);
		// The user has confirmed; `force` authorizes the server-side sealed-vault gate (snapshot only).
		const r = await withBusy(() => api(opts.endpoint, { path: tamperTarget, password, accept, force: !!opts.force }));
		tamperShow('ok', opts.success(r) + fingerprintLine(r));
		refresh(); // update the sealed badge and the Seal/Unseal button on next open
	} catch (e) { tamperShow('bad', esc(e.message)); }
}
$('#tamperSnapshot').addEventListener('click', () => {
	// A snapshot writes an unsealed baseline. If the vault is currently sealed, taking one removes
	// the tripwire, so say so plainly and require the user to accept that before it happens.
	const sealed = !!(vaultsByPath[tamperTarget] && vaultsByPath[tamperTarget].sealed);
	const warn = sealed ? ' This vault is sealed — taking a snapshot removes the seal and returns it to automatic tracking.' : '';
	writeBaselineReviewed({
		endpoint: '/api/snapshot', noun: 'baseline', force: sealed, // authorize the server-side seal-removal gate once confirmed
		cleanTitle: sealed ? 'Remove seal and snapshot' : 'Take snapshot', cleanConfirm: sealed ? 'Remove seal and snapshot' : 'Take snapshot', cleanDanger: sealed,
		cleanMessage: 'Record the vault’s current contents as its trusted baseline? Any file added, removed, or changed after this is then reported by an audit.' + warn,
		dirtyTitle: sealed ? 'Remove seal and snapshot' : 'Accept changes and snapshot', dirtyConfirm: sealed ? 'Remove seal and snapshot' : 'Accept and snapshot',
		dirtySuffix: warn,
		working: 'Recording the snapshot…', canceled: 'Snapshot canceled — nothing was changed.',
		success: (r) => 'Snapshot recorded — ' + r.count + ' file' + (r.count === 1 ? '' : 's') + ' fingerprinted. Run an audit later to detect any changes.'
	});
});
onDialogSubmit('#tamperForm', async () => {
	const password = $('#tamperPass').value;
	if (!password) return toast('Enter the password', true);
	try {
		tamperShow('', 'Comparing the vault to its baseline…');
		const r = await withBusy(() => api('/api/audit', { path: tamperTarget, password }));
		if (r.errors && r.errors.length) { tamperShow('bad', esc(r.errors.join(' '))); return; }
		const sync = syncGroup(r.syncIssues);
		if (r.clean) { tamperShow(sync ? 'warn' : 'ok', 'No changes — the vault matches its baseline from ' + esc(r.snapshotAt) + '.' + fingerprintLine(r) + identityBlock(r) + sync); return; }
		const tamper = tamperGroup(r.tamper);
		const noFileDiff = !(r.modified.length || r.removed.length || r.added.length);
		// Damaged files (corrupt content) get their OWN group with a plain caption — they are an integrity problem to
		// fix, not an attack, so they are NOT shown under "Tampering". The caption carries the actionable guidance.
		const damaged = (r.damaged && r.damaged.length)
			? fileList('Damaged — present, but their content could not be read', r.damaged)
				+ '<div class="fine">Restore these from a backup or a saved version. If a file is gone for good, delete it, then take a new snapshot.</div>'
			: '';
		// When there is no ordinary add/remove/modify but there IS a tamper note or a damaged file, lead with the
		// integrity-problem wording rather than "Changes detected since <date>", which would read as an ordinary edit.
		const lead = (noFileDiff && (((r.tamper && r.tamper.length)) || (r.damaged && r.damaged.length)))
			? 'The vault’s integrity check found a problem:'
			: 'Changes detected since ' + esc(r.snapshotAt) + ':';
		tamperShow('bad', lead + tamper +
			fileList('Modified', r.modified) + fileList('Removed', r.removed) + fileList('Added', r.added) + fileList('Unrecognized — added from outside the vault', r.foreign) + damaged + fingerprintLine(r) + identityBlock(r) + sync);
	} catch (e) { tamperShow('bad', esc(e.message)); }
});
// Seal / Unseal. Sealing writes a strict deep baseline that is never auto-refreshed, so any later
// change is flagged until the user seals again; unsealing returns to automatic tracking.
$('#tamperSeal').addEventListener('click', async () => {
	if (($('#tamperSeal').dataset.mode || 'seal') === 'unseal') {
		const password = $('#tamperPass').value;
		if (!password) return toast('Enter the password', true);
		try {
			tamperShow('', 'Removing the seal…');
			await withBusy(() => api('/api/unseal', { path: tamperTarget, password }));
			tamperShow('ok', 'Unsealed — this vault is back to automatic tracking.');
			refresh();
		} catch (e) { tamperShow('bad', esc(e.message)); }
		return;
	}
	writeBaselineReviewed({
		endpoint: '/api/seal', noun: 'sealed baseline',
		cleanTitle: 'Seal vault', cleanConfirm: 'Seal',
		cleanMessage: 'Seal the vault at its current contents? Any file added, removed, or changed after this is flagged on every mount and audit until you seal again.',
		dirtyTitle: 'Accept changes and seal', dirtyConfirm: 'Accept and seal',
		working: 'Sealing the vault…', canceled: 'Sealing canceled — nothing was changed.',
		success: (r) => 'Sealed — ' + r.count + ' file' + (r.count === 1 ? '' : 's') + ' locked in. Any added, removed, or changed file is now flagged until you seal again — on every mount, and (for a same-size content swap) on a deep audit.'
	});
});
// Timestamp proof (RFC 3161 attestation) — no password; only a hash of the vault's state is sent to a
// trusted authority, which signs it together with the time. Proof that this exact state existed by then.
$('#tamperAttest').addEventListener('click', async () => {
	// Creating a proof reaches out to a public authority and appends a permanent entry to this vault's proof
	// chain, so confirm first (and show what it does) rather than firing on every click.
	const okd = await uiConfirm({ title: 'Create a timestamp proof', message: 'This sends a hash of the vault’s recorded state (its identity, content fingerprint, and version) to a public timestamp authority, which signs it with the current time. Only the hash is sent — your files, their names, and your password never leave this computer. The signed proof is saved beside the vault as evidence this exact state existed by then.', confirmLabel: 'Create proof' });
	if (!okd) return;
	try {
		tamperShow('', 'Requesting a trusted timestamp…');
		const r = await withBusy(() => api('/api/attest', { path: tamperTarget }));
		tamperShow('ok', 'Timestamp proof created for version ' + esc(String(r.seq)) + '.<div class="tamper-fp">Certified time <code>' + esc(r.genTime || '(unknown)') + '</code> · via ' + esc(r.tsaUrl) + '</div>It proves this exact state existed at the certified time. Stored beside the vault, it travels with your backups, and anyone can verify it.');
	} catch (e) { tamperShow('bad', esc(e.message)); }
});
// List and verify a vault's timestamp proofs — no password. Each token is re-checked and the certified
// time is read back out of the signed proof itself.
$('#tamperAttestList').addEventListener('click', async () => {
	try {
		tamperShow('', 'Loading timestamp proofs…');
		const r = await withBusy(() => api('/api/attestations', { path: tamperTarget }));
		const items = (r && r.items) || [];
		if (!items.length) { tamperShow('ok', 'No timestamp proofs yet. Use “Timestamp proof” to create one (take a snapshot first).'); return; }
		const rows = items.slice().reverse().map(it => {
			const badge = it.verified ? (it.matchesCurrent ? '✓ verified · current state' : '✓ verified') : '⚠ ' + esc(it.reason || 'unverified');
			const link = it.chained ? '' : ' <span class="share-key-caution">⚠ chain break</span>';
			return '<li>Version ' + esc(String(it.seq)) + ' — <code>' + esc(it.genTime || it.at) + '</code> <span class="muted">(' + badge + ')</span>' + link + '</li>';
		}).join('');
		const chainNote = r.chainOk ? '<p class="muted">✓ Proof chain intact — tamper-evident as a whole.</p>'
			: '<p class="share-key-caution"><strong>⚠ The proof chain is broken</strong> — a proof was reordered, inserted, or altered.</p>';
		const rollNote = r.rolledBack ? '<p class="share-key-caution"><strong>⚠ Possible rollback</strong> — this vault presents an older version (' + esc(String(r.currentSeq)) + ') than its own attested history (up to ' + esc(String(r.maxAttestedSeq)) + ').</p>' : '';
		const headNote = r.head ? '<p class="muted">Chain head (record it out of band, or keep the Recovery Kit, to detect a rollback later): version ' + esc(String(r.head.seq)) + ' · <code>' + esc(String(r.head.chain).slice(0, 16)) + '…</code></p>' : '';
		tamperShow(r.chainOk && !r.rolledBack ? 'ok' : 'bad', '<div class="tamper-group"><strong>Timestamp proofs (' + items.length + ')</strong><ul>' + rows + '</ul></div>' + chainNote + rollNote + headNote + 'Each proof certifies the vault’s exact state at the signed time, and anyone can verify it.');
	} catch (e) { tamperShow('bad', esc(e.message)); }
});
// Tamper history — the local, persistent record of every detection (survives even if the vault or
// its baseline is deleted). No password: the log holds no secrets.
$('#tamperLogBtn').addEventListener('click', async () => {
	try {
		tamperShow('', 'Loading tamper history…');
		const r = await withBusy(() => api('/api/tamper-log', { path: tamperTarget }));
		const events = (r && r.events) || [];
		const history = r && r.history;
		if (!events.length) { tamperShow('ok', 'No tampering has been recorded for this vault.'); return; }
		// Whether the history RECORD itself is intact: it is hash-chained and anchored (and signed by a
		// read-write session), so an altered record is reported before the entries are listed.
		let histNote = ''; // verdict decided once server-side (history.verdict); this only maps it to markup
		if (history && history.verdict === 'altered') histNote = '<p class="share-key-caution"><strong>⚠ This history has itself been altered</strong> (' + esc(history.reason || 'inconsistent') + ') — the entries below cannot be fully trusted.</p>';
		else if (history && history.verdict === 'signed') histNote = '<p class="muted">✓ History verified — hash-chained and signed by the vault’s write key.</p>';
		else if (history && history.verdict === 'chained') histNote = '<p class="muted">✓ History verified — hash-chained.</p>';
		const sevLabel = { critical: 'critical', high: 'high', medium: 'medium', info: 'note' };
		const rows = events.map(e => {
			const parts = [];
			if (e.notes && e.notes.length) parts.push(esc(e.notes.join('; ')));
			parts.push(...changeCounts(e));
			const when = e.at ? new Date(e.at).toLocaleString() : '';
			const sev = e.severity || 'info';
			const chip = '<span class="sev sev-' + esc(sev) + '">' + esc(sevLabel[sev] || sev) + '</span> ';
			return '<li>' + chip + '<strong>' + esc(when) + '</strong> — ' + esc(e.kind || 'change') + (parts.length ? ': ' + parts.join(' · ') : '') + '</li>';
		}).join('');
		tamperShow('bad', '<div class="tamper-group"><strong>Tamper history (' + events.length + ')</strong>' + histNote + '<ul class="tamper-history">' + rows + '</ul></div>');
	} catch (e) { tamperShow('bad', esc(e.message)); }
});

// ---- Self-healing dialog ----
let protectTarget = null;
const protectShow = makeShow('#protectResult');
function openProtect(path, name) {
	protectTarget = path;
	$('#protectName').textContent = name;
	const rec = (vaultsByPath[path] && vaultsByPath[path].recovery) || { protected: false };
	const statusEl = $('#protectStatus');
	if (rec.unreadable) {
		statusEl.textContent = rec.message || 'This vault has recovery data this version cannot read.';
		$('#protectTier').value = 'medium';
		$('#protectHeal').hidden = true;
		$('#protectRemove').hidden = false;
		$('#protectGo').textContent = 'Rebuild protection';
	} else if (rec.protected) {
		statusEl.textContent = 'Protected at the ' + rec.tier + ' level (about ' + rec.redundancyPercent + '% recovery data), added ' + (rec.createdAt ? new Date(rec.createdAt).toLocaleString() : '') + '.';
		$('#protectTier').value = rec.tier || 'medium';
		$('#protectHeal').hidden = false;
		$('#protectRemove').hidden = false;
		$('#protectGo').textContent = 'Update protection';
	} else {
		statusEl.textContent = 'This vault has no recovery data yet.';
		$('#protectTier').value = 'medium';
		$('#protectHeal').hidden = true;
		$('#protectRemove').hidden = true;
		$('#protectGo').textContent = 'Add protection';
	}
	$('#protectThorough').checked = !!rec.thorough;
	// Scheduled integrity scrub — only meaningful once the vault has recovery data to check. Hide the control
	// until then; otherwise load and reflect the current schedule.
	const scrubProtected = rec.protected && !rec.unreadable;
	const scrubField = $('#scrubMode').closest('.field');
	if (scrubField) scrubField.hidden = !scrubProtected;
	$('#scrubHealRow').hidden = true;
	if ($('#scrubNowRow')) { $('#scrubNowRow').hidden = !scrubProtected; if ($('#scrubNowResult')) $('#scrubNowResult').textContent = ''; }
	if (scrubProtected) api('/api/scrub-schedule', { path }).then(r => {
		if (protectTarget !== path) return; // a late response for a vault the user already navigated away from must not populate another vault's (shared) controls
		const s = (r && r.schedule) || { mode: 'off' };
		$('#scrubMode').value = s.mode === 'daily' ? 'daily' : (s.mode === 'interval' ? 'weekly' : 'off');
		$('#scrubHeal').checked = !!s.autoHeal;
		$('#scrubHealRow').hidden = $('#scrubMode').value === 'off';
	}).catch(() => {});
	// If a background refresh is running on this vault, say so — an action here will queue behind it.
	if (rec.refreshing) statusEl.textContent += ' Its recovery data is updating in the background right now (' + (rec.refreshPercent != null ? rec.refreshPercent + '%' : 'in progress') + ') — an action will start once that finishes.';
	const res = $('#protectResult'); res.hidden = true; res.innerHTML = '';
	protectProgress(null); protectBusy(false);
	$('#protectDialog').showModal();
}
// Drive the dialog's progress bar (shared factory; passing null hides it when the operation finishes).
const protectProgress = stepProgress('#protectProgress', '#protectBarFill', '#protectBarText');
// Disable the dialog's action buttons while an operation runs (so it can't be double-fired or the
// vault touched mid-write), then restore them.
function protectBusy(on) {
	['#protectGo', '#protectHeal', '#protectRemove'].forEach(sel => { const b = $(sel); if (b) b.disabled = on; });
}
// Save the scheduled-scrub choice. Daily maps to a set time; Weekly to a 7-day interval; Off clears it.
function saveScrubSchedule() {
	const m = $('#scrubMode').value;
	$('#scrubHealRow').hidden = m === 'off';
	let schedule = { mode: 'off' };
	if (m === 'daily') schedule = { mode: 'daily', hour: 3, minute: 0, autoHeal: $('#scrubHeal').checked };
	else if (m === 'weekly') schedule = { mode: 'interval', intervalHours: 168, autoHeal: $('#scrubHeal').checked };
	api('/api/scrub-schedule', { path: protectTarget, schedule })
		.then(() => toast(m === 'off' ? 'Scheduled check off' : 'Scheduled check: ' + m + ($('#scrubHeal').checked ? ', auto-repair' : ', check only')))
		.catch(e => toast(e.message, true));
}
if ($('#scrubMode')) $('#scrubMode').addEventListener('change', saveScrubSchedule);
if ($('#scrubHeal')) $('#scrubHeal').addEventListener('change', saveScrubSchedule);
// Run one integrity scrub right now — the same password-less check (and optional repair) the schedule runs,
// giving the web interface the CLI's on-demand `scrub`. Best-effort and self-contained: it reports its verdict
// in place and never disturbs the rest of the dialog.
if ($('#scrubNow')) $('#scrubNow').addEventListener('click', async () => {
	const btn = $('#scrubNow'), out = $('#scrubNowResult');
	btn.disabled = true; if (out) out.textContent = 'Checking…';
	try {
		const r = await api('/api/scrub-now', { path: protectTarget });
		const repaired = r && r.healed ? ', repaired' : '';
		if (out) out.textContent = r && r.clean === false ? 'Damage found' + (r.healed ? ' and repaired.' : ' — click “Check & repair” below to fix it now from the recovery data.') : 'No damage found' + repaired + '.';
	} catch (e) { if (out) out.textContent = e.message; }
	finally { btn.disabled = false; }
});
$('#protectGo').addEventListener('click', async () => {
	const tier = $('#protectTier').value;
	const thorough = $('#protectThorough').checked;
	// Rebuilding existing protection replaces the current recovery data with a fresh set over the
	// vault's CURRENT contents — so confirm first (a first-time "Add protection" needs no confirmation).
	const rec = (vaultsByPath[protectTarget] && vaultsByPath[protectTarget].recovery) || {};
	if (rec.protected || rec.unreadable) {
		const go = await uiConfirm({
			title: 'Update recovery protection',
			message: 'This rebuilds the self-healing recovery data over the vault’s current contents, replacing the existing set. It reads the whole vault, so it can take a while on a large one — and it re-bases recovery on the vault as it is now. Continue?',
			confirmLabel: 'Update protection', cancelLabel: 'Cancel'
		});
		if (!go) return;
	}
	try {
		protectBusy(true); protectShow('', 'Building recovery data. Keep ' + APP_NAME + ' running until this finishes.'); protectProgress({ percent: 0, label: 'Starting' });
		const r = await withBusy(() => apiStream('/api/protect', { path: protectTarget, tier, thorough }, protectProgress));
		protectProgress(null);
		if (r.deferred) { protectShow('warn', esc(r.message)); refresh(); return; } // signed vault, no unlocked session to re-sign — left signed rather than downgraded
		protectShow('ok', 'Protected — ' + r.parityBlocks + ' recovery blocks over ' + r.dataBlocks + ' data blocks (' + r.stripes + ' stripe' + (r.stripes === 1 ? '' : 's') + '). Use "Check &amp; repair" any time to detect and fix corruption.');
		$('#protectHeal').hidden = false; $('#protectRemove').hidden = false; $('#protectGo').textContent = 'Update protection';
		refresh();
	} catch (e) { protectProgress(null); protectShow('bad', esc(e.message)); }
	finally { protectBusy(false); }
});
// Run a check-and-repair. allowUnverified is the explicit "repair anyway" override, offered only after the server
// has refused an unverified (possibly-forged) recovery signature — so the default stays fail-closed. force is the
// explicit "repair the same-size changes anyway" override, offered only after a run reported same-size changes it
// preserved (they could be edits) — so an edit is never silently reverted unless the user asks for it.
async function runHeal(allowUnverified, force) {
	try {
		protectBusy(true); protectShow('', 'Checking every block against the recovery data. Keep ' + APP_NAME + ' running until this finishes.'); protectProgress({ percent: 0, label: 'Starting' });
		const r = await withBusy(() => apiStream('/api/heal', { path: protectTarget, allowUnverified: !!allowUnverified, force: !!force }, protectProgress));
		protectProgress(null);
		const v = r.verify || {};
		if (!v.protected) { protectShow('bad', 'This vault has no recovery data.'); return; }
		const auth = v.authenticity || {};
		// Recovery data whose signature is present but invalid may have been forged — repairing from it could
		// corrupt files, so the server refuses by default and returns refused:'authenticity'. Gate on THAT signal
		// alone (not auth.state): a forced "Repair anyway" run still reports state 'tampered' because a passwordless
		// heal never re-signs the index, so also checking auth.state here would wrongly re-refuse the override.
		if (r.refused === 'authenticity') {
			protectShow('bad', '<strong>Repair refused — the recovery data may have been tampered with.</strong> Its authenticity signature did not verify. Rebuild the recovery data from a trusted read-write session (unlock the vault, then “Update protection”), or remove its recovery folder and rebuild. <button type="button" id="healAnyway" class="link-btn danger">Repair anyway</button>');
			const b = $('#healAnyway'); if (b) b.addEventListener('click', () => runHeal(true));
			return;
		}
		const authNote = auth.state === 'downgrade' ? ' <span class="share-key-caution">The recovery data is not signed, though a signed version was seen before — if you did not just rebuild it without unlocking, treat it with suspicion.</span>'
			: auth.state === 'verified' ? ' <span class="muted">✓ Recovery data signed by the vault’s write key and verified.</span>' : '';
		if (!r.heal) { protectShow('ok', 'No corruption found — every block matches the recovery data.' + authNote); return; }
		const h = r.heal;
		const nFiles = (h.repairedFiles || []).length;
		const filesNote = nFiles ? ' Across ' + nFiles + ' encrypted file' + (nFiles === 1 ? '' : 's') + '.' : '';
		const sizeNote = h.repairedSize ? ' and trimmed ' + h.repairedSize + ' over-long file' + (h.repairedSize === 1 ? '' : 's') : '';
		const writeNote = h.writeErrors ? ' ' + h.writeErrors + ' repair' + (h.writeErrors === 1 ? '' : 's') + ' could not be written — check free space and that the files are not read-only or locked, then heal again.' : '';
		const unverifiedNote = h.repairedUnverified ? ' <span class="share-key-caution">Repaired despite an unverified recovery signature — rebuild the recovery data from a read-write session to restore trust.</span>' : '';
		const changedNote = h.changedSkipped ? ' <span class="share-key-caution">' + h.changedSkipped + ' file' + (h.changedSkipped === 1 ? '' : 's') + ' changed since protection was last updated and ' + (h.changedSkipped === 1 ? 'was' : 'were') + ' left exactly as ' + (h.changedSkipped === 1 ? 'it is' : 'they are') + ' — those changes are your data, not damage. Use "Update protection" to record the current contents.</span>' : '';
		// Same-size changes were PRESERVED, not repaired: a same-length change is indistinguishable from a same-length
		// edit without opening the vault, so it is never reverted by default. Offer an explicit repair for the case
		// where it truly is bit-rot; if it is an edit, "Update protection" records it.
		const inPlaceNote = (h.inPlaceDeferred && !force) ? ' <span class="share-key-caution">' + h.inPlaceDeferred + ' file' + (h.inPlaceDeferred === 1 ? '' : 's') + ' changed at the same size and ' + (h.inPlaceDeferred === 1 ? 'was' : 'were') + ' left exactly as ' + (h.inPlaceDeferred === 1 ? 'it is' : 'they are') + '. A same-size change can be your edit or corruption, and the two cannot be told apart without opening the vault, so it is preserved. If it is your edit, use "Update protection"; if you are sure it is damage, <button type="button" id="healSameSize" class="link-btn danger">repair it anyway</button>.</span>' : '';
		// A genuine DATA loss larger than the recovery budget (h.unrecoverable) cannot be healed — say so and point at a
		// backup. A parity-only shortfall (h.unrecoverableStripes with no lost data file) leaves the files intact but
		// reduces protection, so steer to "Update protection" instead of alarming about a restore.
		const tail = h.unrecoverable
			? ' ' + h.unrecoverable + ' file' + (h.unrecoverable === 1 ? '' : 's') + ' could not be fully recovered — the loss is larger than the recovery data can rebuild. Restore ' + (h.unrecoverable === 1 ? 'it' : 'them') + ' from a backup or a saved version; a tamper check will name ' + (h.unrecoverable === 1 ? 'it' : 'them') + '.'
			: (h.unrecoverableStripes ? ' Your files are intact, but some recovery data could not be rebuilt, so protection is reduced — use "Update protection" to refresh it.' : (h.writeErrors ? '' : ' Open the vault to confirm.'));
		protectShow((h.unrecoverable || h.writeErrors) ? 'bad' : 'ok', 'Repaired ' + h.repairedData + ' data block' + (h.repairedData === 1 ? '' : 's') + (h.repairedParity ? ' and ' + h.repairedParity + ' recovery block' + (h.repairedParity === 1 ? '' : 's') : '') + sizeNote + '.' + filesNote + writeNote + changedNote + inPlaceNote + tail + authNote + unverifiedNote);
		const bss = $('#healSameSize'); if (bss) bss.addEventListener('click', () => runHeal(allowUnverified, true)); // "repair it anyway" -> force the same-size repair
	} catch (e) { protectProgress(null); protectShow('bad', esc(e.message)); }
	finally { protectBusy(false); }
}
$('#protectHeal').addEventListener('click', () => runHeal(false));
$('#protectRemove').addEventListener('click', async () => {
	const password = await uiConfirm({ title: 'Remove protection', message: 'Remove this vault’s recovery data? It will no longer be able to repair corruption until you add protection again. Your files are not affected. Enter the vault password to confirm.', confirmLabel: 'Remove', danger: true, requirePassword: true });
	if (!password) return;
	try {
		await withBusy(() => api('/api/unprotect', { path: protectTarget, password }));
		protectShow('', 'Recovery data removed.');
		$('#protectHeal').hidden = true; $('#protectRemove').hidden = true; $('#protectGo').textContent = 'Add protection';
		$('#protectStatus').textContent = 'This vault has no recovery data yet.';
		refresh();
	} catch (e) { protectShow('bad', esc(e.message)); }
});

// ---- Create / Add forms ----
$('#createForm').addEventListener('submit', async (ev) => {
	ev.preventDefault();
	const path = $('#createPath').value.trim();
	const password = $('#createPass').value;
	const password2 = $('#createPass2').value;
	const level = $('#createLevel') ? $('#createLevel').value : undefined;
	const sourceDir = $('#createImport') ? $('#createImport').value.trim() : '';
	const cloudId = $('#createCloud') ? $('#createCloud').value : '';
	const cloud = cloudId ? { remoteId: cloudId, remotePath: ($('#createCloudPath') ? $('#createCloudPath').value.trim() : '') } : undefined;
	if (password !== password2) return toast('Passwords do not match', true);
	if (cloud && sourceDir) return toast('Importing into a cloud vault is not supported yet — create the cloud vault, then add files after mounting it.', true);
	try {
		const newName = String(path).split(/[\\/]/).filter(Boolean).pop() || 'Vault';
		if (sourceDir) {
			toast('Creating the vault and importing…');
			const r = await withBusy(() => api('/api/import', { path, password, level, sourceDir }));
			resetCreateForm();
			toast('Imported ' + r.count + ' file' + (r.count === 1 ? '' : 's') + ' — your originals are unchanged');
		} else {
			const worm = (cloud && $('#createWorm') && $('#createWorm').checked) ? { mode: 'governance', retainDays: Math.max(1, parseInt(($('#createWormDays') && $('#createWormDays').value) || '30', 10) || 30) } : undefined;
			toast(cloud ? (worm ? 'Creating the tamper-proof cloud vault…' : 'Creating the cloud vault…') : 'Creating…');
			const cr = await withBusy(() => api('/api/create', { path, password, level, cloud, worm }));
			resetCreateForm();
			// One sticky toast (dismiss by clicking it), so the identity to write down stays up until the user has it,
			// instead of vanishing on a timer. If there is no identity to record, a brief confirmation is enough.
			if (cr && cr.identity) toast('Vault created. Identity: ' + cr.identity + ' — record it somewhere safe (it never changes; a Recovery Kit saves it for you). It confirms a copy is genuinely this vault. Click to dismiss.', false, { sticky: true });
			else toast('Vault created');
		}
		refresh();
		// Nudge toward a recovery method now, so a forgotten password never becomes an unrecoverable lockout. Offered
		// once, right after creation; the vault is already made and listed whether or not the user sets one up.
		await offerRecoveryKit(path, newName);
	} catch (e) { toast(e.message, true); }
});
// Reset the create form fully, including the import field and its Clear button.
function resetCreateForm() {
	$('#createForm').reset();
	if ($('#createImport')) $('#createImport').value = '';
	if ($('#createImportClear')) $('#createImportClear').hidden = true;
	if ($('#createPassMeter')) $('#createPassMeter').hidden = true;
	if ($('#createCloudPathRow')) $('#createCloudPathRow').hidden = true;
	if ($('#createWormRow')) $('#createWormRow').hidden = true;
	if ($('#createWormDaysRow')) $('#createWormDaysRow').hidden = true;
}

// ---- Cloud storage (backends for cloud-backed vaults) ----
let lastCloudSig = null; // signature of the last cloud-remote list rendered, so an unchanged 5s poll skips the rebuild
function renderCloudSelect() {
	const sel = $('#createCloud'); if (!sel) return;
	const remotes = (lastState && lastState.cloudRemotes) || [];
	// The cloud-remote list almost never changes, so only rebuild the <select> when it actually did — otherwise the
	// poll churns the options (and re-runs updateCreateCloudRows) every 5s for no reason.
	const sig = JSON.stringify(remotes.map(r => [r.id, r.type, r.label]));
	if (sig === lastCloudSig) return;
	lastCloudSig = sig;
	const cur = sel.value;
	sel.innerHTML = '<option value="">This computer (a normal local vault)</option>' +
		remotes.map(r => '<option value="' + esc(r.id) + '" data-type="' + esc(r.type) + '">' + esc(r.label || r.type) + ' (' + esc(r.type) + ')</option>').join('');
	if (remotes.some(r => r.id === cur)) sel.value = cur;
	updateCreateCloudRows();
}
// Show the cloud folder row when a remote is chosen, and the tamper-proof (Object Lock) rows only for an S3 or
// S3-compatible remote (the only backend that supports it). Governance mode is the safe default; compliance
// (irreversible) is left to the deliberate command-line path.
function updateCreateCloudRows() {
	const sel = $('#createCloud'); if (!sel) return;
	const opt = sel.selectedOptions && sel.selectedOptions[0];
	const isS3 = !!(opt && opt.getAttribute('data-type') === 's3');
	if ($('#createCloudPathRow')) $('#createCloudPathRow').hidden = !sel.value;
	if ($('#createWormRow')) $('#createWormRow').hidden = !isS3;
	if (!isS3 && $('#createWorm')) $('#createWorm').checked = false;
	if ($('#createWormDaysRow')) $('#createWormDaysRow').hidden = !(isS3 && $('#createWorm') && $('#createWorm').checked);
}
document.addEventListener('change', (e) => { if (e.target && (e.target.id === 'createCloud' || e.target.id === 'createWorm')) updateCreateCloudRows(); });
if ($('#createCloudManage')) $('#createCloudManage').addEventListener('click', openCloud);
function openCloud() {
	$('#cloudResult').hidden = true; $('#cloudLabel').value = ''; $('#cloudOpts').value = '';
	renderCloudList();
	$('#cloudDialog').showModal();
}
function renderCloudList() {
	const el = $('#cloudList'); const remotes = (lastState && lastState.cloudRemotes) || [];
	if (!remotes.length) { el.innerHTML = '<p class="hint">No cloud storage saved yet.</p>'; return; }
	el.innerHTML = remotes.map(r => '<div class="row-between">'
		+ '<span>' + esc(r.label || r.type) + ' <span class="muted">(' + esc(r.type) + ')</span></span>'
		+ '<span><button type="button" class="ghost-btn" data-cloud-test="' + esc(r.id) + '">Test</button> '
		+ '<button type="button" class="ghost-btn danger" data-cloud-remove="' + esc(r.id) + '">Remove</button></span></div>').join('');
	el.querySelectorAll('[data-cloud-test]').forEach(b => b.addEventListener('click', async () => {
		try { const r = await withBusy(() => api('/api/cloud-test', { id: b.getAttribute('data-cloud-test') })); showResult($('#cloudResult'), r.ok ? 'ok' : 'bad', r.ok ? 'Reachable — ' + esc(r.detail) : 'Not reachable — ' + esc(r.detail)); }
		catch (e) { showResult($('#cloudResult'), 'bad', esc(e.message)); }
	}));
	el.querySelectorAll('[data-cloud-remove]').forEach(b => b.addEventListener('click', async () => {
		try { await withBusy(() => api('/api/cloud-remote-remove', { id: b.getAttribute('data-cloud-remove') })); await refresh(); renderCloudList(); }
		catch (e) { showResult($('#cloudResult'), 'bad', esc(e.message)); }
	}));
}
onDialogSubmit('#cloudForm', async () => {
	const type = $('#cloudType').value, label = $('#cloudLabel').value.trim();
	const OBSCURE = new Set(['pass', 'password', 'key_file_pass']);
	const PLAINSEC = new Set(['secret_access_key', 'key', 'token', 'sas_url', 'client_secret', 'account']);
	const opts = {}, secretsPlain = {}, secretsObscure = {};
	for (const line of $('#cloudOpts').value.split(/\r?\n/)) {
		const t = line.trim(); if (!t) continue; const i = t.indexOf('='); if (i < 0) continue;
		const k = t.slice(0, i).trim(), v = t.slice(i + 1).trim();
		if (OBSCURE.has(k)) secretsObscure[k] = v; else if (PLAINSEC.has(k)) secretsPlain[k] = v; else opts[k] = v;
	}
	if (!Object.keys(opts).length && !Object.keys(secretsPlain).length && !Object.keys(secretsObscure).length) return showResult($('#cloudResult'), 'bad', 'Enter at least one key=value setting.');
	try {
		await withBusy(() => api('/api/cloud-remote', { remote: { type, label, opts, secretsPlain, secretsObscure } }));
		showResult($('#cloudResult'), 'ok', 'Cloud storage added. Choose it under “Store on cloud storage” when you create a vault.');
		$('#cloudLabel').value = ''; $('#cloudOpts').value = '';
		await refresh(); renderCloudList(); renderCloudSelect();
	} catch (e) { showResult($('#cloudResult'), 'bad', esc(e.message)); }
});
// Connect a browser-OAuth account (Google Drive / Dropbox): the engine opens its sign-in page, we open the
// URL it hands back, and it captures the token once the user consents.
if ($('#cloudConnectBtn')) $('#cloudConnectBtn').addEventListener('click', async () => {
	const type = $('#cloudOAuthType').value, label = $('#cloudOAuthLabel').value.trim();
	const status = $('#cloudConnectStatus'); status.hidden = false; status.textContent = 'Opening the sign-in page…';
	$('#cloudResult').hidden = true;
	try {
		await withBusy(() => apiStream('/api/cloud-connect', { type, label }, (p) => {
			if (p && p.url) {
				// In the desktop app the server already opened the sign-in page in the real browser (p.opened), because
				// the WebView cannot. Do NOT call window.open there — it would fail and the fallback link would navigate
				// the whole app window away. On the web, open the URL ourselves as before.
				if (p.opened) { status.textContent = 'Finish signing in in your browser, then come back here.'; return; }
				let opened = null; try { opened = window.open(p.url, '_blank', 'noopener'); } catch (_) {}
				if (opened) { status.textContent = 'Finish signing in on the new browser tab, then come back here…'; }
				else {
					// Some embedded windows block window.open, so surface the URL as a visible, selectable link the
					// user can open or copy — otherwise the sign-in page would silently never appear. Only an
					// http(s) link is made clickable; anything else is shown as plain text.
					const safe = /^https?:\/\//i.test(p.url);
					status.innerHTML = 'Open this sign-in link in your browser, finish signing in, then return here: ' +
						(safe ? '<a href="' + esc(p.url) + '" target="_blank" rel="noopener" class="conn-val">' + esc(p.url) + '</a>' : '<span class="conn-val">' + esc(p.url) + '</span>');
				}
			}
		}));
		status.hidden = true; $('#cloudOAuthLabel').value = '';
		showResult($('#cloudResult'), 'ok', 'Account connected. Choose it under “Store on cloud storage” when you create a vault.');
		await refresh(); renderCloudList(); if (typeof renderCloudSelect === 'function') renderCloudSelect();
	} catch (e) { status.hidden = true; showResult($('#cloudResult'), 'bad', esc(e.message)); }
});
$('#createImportBrowse').addEventListener('click', () => openBrowse({
	title: 'Choose a folder to import', useLabel: 'Import this folder', start: $('#createImport').value || '', pickVaults: false,
	onChoose: (p) => { $('#createImport').value = p; $('#createImportClear').hidden = false; }
}));
$('#createImportClear').addEventListener('click', () => { $('#createImport').value = ''; $('#createImportClear').hidden = true; });

async function addVaultPath(p) {
	p = (p || '').trim();
	if (!p) return;
	try { await withBusy(() => api('/api/add-vault', { path: p })); $('#addForm').reset(); toast('Added'); refresh(); }
	catch (e) { toast(e.message, true); }
}

$('#addForm').addEventListener('submit', (ev) => { ev.preventDefault(); addVaultPath($('#addPath').value); });

// ---- In-page folder browser (pick a folder; no native dialog) ----
// Generic: the caller passes an onChoose(path) callback, so it serves both "add a vault" and
// "choose a backup folder". pickVaults=true makes clicking a vault folder select it directly.
let browseCur = null, browseOnChoose = null, browsePickVaults = false, browsePickFileExt = null;
// pickFileExt (e.g. '.vdisk') switches the picker to choosing a FILE with that extension instead of a folder —
// files are listed and selectable, and the "Use this folder" button is hidden. Reuses the same dialog.
function openBrowse({ title = 'Choose a vault folder', useLabel = 'Use this folder', start = '', pickVaults = false, pickFileExt = null, onChoose } = {}) {
	browseOnChoose = onChoose || null;
	browsePickVaults = !!pickVaults;
	browsePickFileExt = pickFileExt ? String(pickFileExt).toLowerCase() : null;
	if ($('#browseTitle')) $('#browseTitle').textContent = title;
	$('#browseUse').textContent = useLabel;
	$('#browseUse').hidden = !!browsePickFileExt; // in file mode you pick a file, not "this folder"
	loadBrowse(start);
	$('#browseDialog').showModal();
}
function addVaultBrowse() { openBrowse({ pickVaults: true, onChoose: (p) => { $('#addPath').value = p; addVaultPath(p); } }); }
$('#browseBtn').addEventListener('click', addVaultBrowse);

// Open a shared packed file in one step: pick the file, then unpack-and-register it into the vaults folder.
const PACK_EXT = (document.body && document.body.dataset.packExt) || '.vdisk';
const openSharedProgress = stepProgress('#openSharedProgress', '#openSharedBarFill', '#openSharedBarText');
if ($('#openSharedBtn')) $('#openSharedBtn').addEventListener('click', () => {
	openBrowse({ title: 'Choose a shared vault file', pickFileExt: PACK_EXT, onChoose: async (file) => {
		const res = $('#openSharedResult');
		showResult(res, '', 'Opening the shared file — this can take a moment for a large vault.');
		openSharedProgress({ indeterminate: true, label: 'Starting' });
		try {
			await withBusy(() => apiStream('/api/unpack', { file }, openSharedProgress));
			openSharedProgress(null);
			showResult(res, 'ok', 'Imported — the vault is now in your list. Open it with the group password.');
			refresh();
		} catch (e) { openSharedProgress(null); showResult(res, 'bad', esc(e.message)); }
	} });
});

async function loadBrowse(p) {
	let data;
	try { data = await api('/api/browse', { path: p || '', includeFiles: !!browsePickFileExt }); }
	catch (e) { toast(e.message, true); return; }
	browseCur = data.path;
	$('#browsePath').textContent = data.path;
	$('#browseUp').disabled = !data.parent;
	$('#browseUp').dataset.path = data.parent || '';
	// Quick places: Home + mounted volumes / external drives.
	$('#browsePlaces').innerHTML = (data.places || [])
		.map(pl => `<button type="button" class="ghost-btn" data-path="${esc(pl.path)}">${esc(pl.name)}</button>`).join('');
	// Sub-folders; a vault folder is selectable directly, a normal folder opens.
	const folderHtml = data.folders.map(f => `<button type="button" class="browse-item${f.isVault ? ' vault' : ''}" data-path="${esc(f.path)}" data-vault="${f.isVault ? 1 : 0}"><span class="bi-name" dir="auto">${esc(f.name)}</span>${f.isVault ? '<span class="vault-tag">vault</span>' : ''}</button>`).join('');
	// In file-pick mode, list files with the wanted extension as selectable items.
	const wantFiles = browsePickFileExt ? (data.files || []).filter(f => f.name.toLowerCase().endsWith(browsePickFileExt)) : [];
	const fileHtml = wantFiles.map(f => `<button type="button" class="browse-item file" data-file="${esc(f.path)}"><span class="bi-name" dir="auto">${esc(f.name)}</span><span class="vault-tag file">file</span></button>`).join('');
	$('#browseList').innerHTML = (folderHtml + fileHtml) || `<p class="muted browse-empty">${browsePickFileExt ? 'No matching files or sub-folders here.' : 'No sub-folders here.'}</p>`;
}
$('#browseUp').addEventListener('click', () => loadBrowse($('#browseUp').dataset.path));
$('#browsePlaces').addEventListener('click', (e) => { const b = e.target.closest('[data-path]'); if (b) loadBrowse(b.dataset.path); });
$('#browseList').addEventListener('click', (e) => {
	const item = e.target.closest('.browse-item'); if (!item) return;
	if (browsePickFileExt && item.dataset.file) return browseSelect(item.dataset.file);   // a matching file → choose it
	if (browsePickVaults && item.dataset.vault === '1') return browseSelect(item.dataset.path); // a vault → choose it
	if (item.dataset.path) loadBrowse(item.dataset.path);                                  // otherwise → open the folder
});
$('#browseUse').addEventListener('click', () => browseSelect(browseCur));
function browseSelect(p) { $('#browseDialog').close(); if (browseOnChoose) browseOnChoose(p); }

// ---- Add files to a mounted vault (streaming import) ----
// Streams the chosen files into the mounted vault via the server, which copies with plain read/write
// (no OS copy call), so a large file lands reliably even where the macOS Finder hits the FUSE-T "-36"
// bug. Reuses the in-page browser (folders to navigate, files to tick).
let importVaultPath = null;
const importSel = new Map(); // full path -> name of each ticked file/folder to add
function openImport(vaultPath, name) {
	importVaultPath = vaultPath;
	importSel.clear();
	$('#importName').textContent = name || '';
	importProgress(null);
	updateImportCount();
	loadImportBrowse('');
	$('#importDialog').showModal();
}
async function loadImportBrowse(p) {
	let data;
	try { data = await api('/api/browse', { path: p || '', includeFiles: true }); }
	catch (e) { toast(e.message, true); return; }
	$('#importPath').textContent = data.path;
	$('#importUp').disabled = !data.parent;
	$('#importUp').dataset.path = data.parent || '';
	$('#importPlaces').innerHTML = (data.places || []).map(pl => `<button type="button" class="ghost-btn" data-path="${esc(pl.path)}">${esc(pl.name)}</button>`).join('');
	const rows = [];
	for (const f of (data.folders || [])) {
		const on = importSel.has(f.path) ? ' checked' : '';
		rows.push(`<div class="pick-row"><input type="checkbox" class="pick-box" data-path="${esc(f.path)}" data-name="${esc(f.name)}"${on}><button type="button" class="pick-open" data-open="${esc(f.path)}"><span class="pick-folder">${esc(f.name)}</span><span class="pick-hint">open</span></button></div>`);
	}
	for (const f of (data.files || [])) {
		const on = importSel.has(f.path) ? ' checked' : '';
		rows.push(`<label class="pick-row"><input type="checkbox" class="pick-box" data-path="${esc(f.path)}" data-name="${esc(f.name)}"${on}><span class="pick-file"><span class="pick-fname">${esc(f.name)}</span><span class="pick-size">${esc(f.size == null ? '' : fmtBytes(f.size))}</span></span></label>`);
	}
	$('#importList').innerHTML = rows.length ? rows.join('') : '<p class="muted browse-empty">This folder is empty.</p>';
}
function updateImportCount() {
	const n = importSel.size;
	$('#importCount').textContent = n ? (n + ' selected') : '';
	$('#importGo').disabled = !n;
}
$('#importUp').addEventListener('click', () => loadImportBrowse($('#importUp').dataset.path));
$('#importPlaces').addEventListener('click', (e) => { const b = e.target.closest('[data-path]'); if (b) loadImportBrowse(b.dataset.path); });
$('#importList').addEventListener('click', (e) => { const open = e.target.closest('[data-open]'); if (open) loadImportBrowse(open.dataset.open); });
$('#importList').addEventListener('change', (e) => {
	const box = e.target.closest('.pick-box'); if (!box) return;
	if (box.checked) importSel.set(box.dataset.path, box.dataset.name); else importSel.delete(box.dataset.path);
	updateImportCount();
});
const importProgress = stepProgress('#importProgress', '#importBarFill', '#importBarText');
async function runImport(force) {
	const sources = [...importSel.keys()];
	if (!sources.length) return;
	$('#importGo').disabled = true; $('#importUp').disabled = true;
	importProgress({ percent: 0, label: 'Starting' });
	try {
		const r = await apiStream('/api/import-files', { path: importVaultPath, sources, force: !!force }, importProgress);
		importProgress(null);
		const n = (r && r.added != null) ? r.added : sources.length;
		toast('Added ' + n + (n === 1 ? ' file' : ' files') + ' to the vault.');
		$('#importDialog').close();
		refresh();
	} catch (e) {
		importProgress(null);
		if (e.clash) { const go = await uiConfirm({ title: 'Some files already exist', message: e.message + ' Replace them?', confirmLabel: 'Replace', cancelLabel: 'Cancel', danger: true }); if (go) return runImport(true); }
		else toast(e.message, true);
	} finally {
		$('#importGo').disabled = importSel.size === 0; $('#importUp').disabled = !$('#importUp').dataset.path;
	}
}
$('#importGo').addEventListener('click', () => runImport(false));

// Drag-and-drop a .vault folder onto the add box. Browsers do NOT expose a dropped
// folder's path via the File API, but the OS also puts a file:// URL on the drop, which
// we can decode into a real path.
const addZone = $('#addForm');
['dragenter', 'dragover'].forEach(ev => addZone.addEventListener(ev, (e) => { e.preventDefault(); addZone.classList.add('dragging'); }));
['dragleave', 'dragend'].forEach(ev => addZone.addEventListener(ev, () => addZone.classList.remove('dragging')));
addZone.addEventListener('drop', (e) => {
	e.preventDefault();
	addZone.classList.remove('dragging');
	// Reference the dropped vault IN PLACE if the environment reveals its real path — some
	// (Electron / native webviews) expose it on the File, and the OS sometimes attaches a
	// file:// URL. Vaults always run from where they live; they are never copied here.
	let p = null;
	const f0 = e.dataTransfer.files && e.dataTransfer.files[0];
	if (f0 && f0.path) p = f0.path;
	if (!p) for (const type of ['text/uri-list', 'text/plain']) {
		const raw = e.dataTransfer.getData(type);
		if (!raw) continue;
		for (const line of raw.split(/[\r\n]+/).map(s => s.trim()).filter(Boolean)) {
			if (line.indexOf('file://') === 0) { try { p = decodeURIComponent(new URL(line).pathname); } catch (_) {} }
			else if (line.charAt(0) === '/' || /^[A-Za-z]:[\\/]/.test(line)) p = line;
			if (p) break;
		}
		if (p) break;
	}
	if (p) { p = p.replace(/\/+$/, ''); $('#addPath').value = p; addVaultPath(p); return; }
	// A standard browser hides a dropped folder's real location, so we cannot reference it
	// from the drop. Open the picker (which reaches external drives) to choose it in place.
	addVaultBrowse();
});

// ---- Backup dialog (destination + back up now + automatic schedule) ----
// Wire a destination <select> that mixes real destinations with "＋ add…" ACTION rows. A native <select> fires
// 'change' ONLY when the value changes, so an action row must never be the resting value — otherwise re-picking the
// already-selected action does nothing and its picker never opens (a real bug when no destination is saved yet). This
// puts a disabled placeholder first, and after an action fires resets the select to the previously-committed value so
// the action can always be re-triggered. `actions` maps an action value (for example '__folder__') to its handler.
// Returns { fill(rows, selected), value() }: rows are { v, t } option objects, and value() is the committed real
// destination or '' for none. Shared by the backup and mirror dialogs so the two behave identically.
function destSelect(selectId, actions) {
	const sel = $('#' + selectId);
	let committed = '';
	function fill(rows, selected) {
		const opts = [{ v: '', t: 'Choose a destination…', ph: true }, ...rows];
		sel.innerHTML = opts.map(o => `<option value="${esc(o.v)}"${o.ph ? ' disabled' : ''}>${esc(o.t)}</option>`).join('');
		sel.value = (selected && opts.some(o => o.v === selected)) ? selected : '';
		committed = sel.value;
	}
	sel.addEventListener('change', () => {
		const v = sel.value;
		if (actions[v]) { sel.value = committed; actions[v](); return; } // reset first, so an action row is never the resting value
		committed = v;
	});
	return { fill: fill, value: () => committed };
}

let backupTarget = null, backupExtraFolder = null;
function tzLabel() { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'; } catch (_) { return 'local time'; } }
function pad2(n) { return String(n == null ? 0 : n).padStart(2, '0'); }
function backupFreqChanged() { $('#backupTimeRow').hidden = $('#backupFreq').value !== 'daily'; }
const backupDest = destSelect('backupDest', {
	__folder__: () => openBrowse({ title: 'Choose a backup folder', useLabel: 'Use this folder', start: backupExtraFolder || '', pickVaults: false, onChoose: (p) => { backupExtraFolder = p; fillBackupDest(p); reopen('#backupDialog'); } }),
	__sftp__: () => openSftp(null, (id) => { fillBackupDest('sftp:' + id); reopen('#backupDialog'); }),
});
// Rebuild the destination dropdown: a remembered/just-picked folder, every saved SFTP server, and two "add" actions.
function fillBackupDest(selected) {
	const rows = [];
	if (backupExtraFolder) rows.push({ v: backupExtraFolder, t: 'Folder: ' + backupExtraFolder });
	(lastState.sftpDests || []).forEach(d => rows.push({ v: 'sftp:' + d.id, t: 'SFTP: ' + (d.label || d.host) }));
	rows.push({ v: '__folder__', t: '＋ Choose a folder…' });
	rows.push({ v: '__sftp__', t: '＋ Add an SFTP server…' });
	backupDest.fill(rows, selected);
}
function openBackup(path, name) {
	backupTarget = path;
	const v = vaultsByPath[path] || {};
	const sch = v.backupSchedule || { mode: 'off' };
	const remembered = sch.dest || v.backupDest || null;
	backupExtraFolder = (remembered && !String(remembered).startsWith('sftp:')) ? remembered : null;
	$('#backupName').textContent = name;
	fillBackupDest(remembered);
	$('#backupFreq').value = sch.mode === 'daily' ? 'daily' : sch.mode === 'interval' ? String(sch.intervalHours || 24) : 'off';
	$('#backupTime').value = sch.mode === 'daily' ? pad2(sch.hour) + ':' + pad2(sch.minute) : '02:00';
	$('#backupTz').textContent = tzLabel();
	backupFreqChanged();
	const res = $('#backupResult'); res.hidden = true; res.textContent = ''; res.className = 'tamper-result';
	if (sch.lastRunAt) { res.hidden = false; res.className = 'tamper-result ' + (String(sch.lastResult).startsWith('error') ? 'bad' : 'ok'); res.textContent = 'Last backup: ' + new Date(sch.lastRunAt).toLocaleString() + (String(sch.lastResult).startsWith('error') ? ' — failed' : ''); }
	$('#backupDialog').showModal();
}
// The chosen destination string (a folder path or "sftp:<id>"), or null for none.
function backupDestValue() { return backupDest.value() || null; }
$('#backupFreq').addEventListener('change', backupFreqChanged);
$('#backupNow').addEventListener('click', guarded(async (ev) => {
	const dest = backupDestValue();
	if (!dest) return toast('Choose a destination first', true);
	try { toast('Backing up (encrypted)…'); const r = await withBusy(() => api('/api/backup', { path: backupTarget, dest })); toast('Backed up' + (String(r.dest).startsWith('sftp:') ? ' off-site' : ' to ' + r.dest)); refresh(); $('#backupDialog').close(); }
	catch (e) { toast(e.message, true); }
}));
// Restorability check: confirm the backup destination holds a complete copy of this vault (no password).
if ($('#backupCheck')) $('#backupCheck').addEventListener('click', async () => {
	const dest = backupDestValue() || undefined;
	const res = $('#backupResult'); res.hidden = false; res.className = 'tamper-result'; res.textContent = 'Checking the backup…';
	try {
		const r = await withBusy(() => api('/api/verify-backup', { path: backupTarget, dest }));
		const kind = r.verdict === 'RESTORABLE' ? 'ok' : 'bad';
		const head = { RESTORABLE: 'Backup is complete and restorable', INCOMPLETE: 'Backup is INCOMPLETE', DIFFERENT: 'That destination holds a DIFFERENT vault', UNREADABLE: 'Backup could not be read' }[r.verdict] || r.verdict;
		showResult(res, kind, '<strong>' + head + '.</strong> ' + esc(r.reason) + (r.total != null ? ' (' + r.present + ' of ' + r.total + ' files present)' : ''));
	} catch (e) { showResult(res, 'bad', esc(e.message)); }
});
$('#backupSave').addEventListener('click', async () => {
	const f = $('#backupFreq').value;
	let schedule;
	if (f === 'off') schedule = { mode: 'off' };
	else {
		const dest = backupDestValue();
		if (!dest) return toast('Choose a destination first', true);
		if (f === 'daily') { const [h, m] = ($('#backupTime').value || '02:00').split(':').map(Number); schedule = { mode: 'daily', hour: h, minute: m, dest }; }
		else schedule = { mode: 'interval', intervalHours: parseInt(f, 10), dest };
	}
	try { await withBusy(() => api('/api/backup-schedule', { path: backupTarget, schedule })); toast(f === 'off' ? 'Automatic backup turned off' : 'Automatic backup saved'); refresh(); $('#backupDialog').close(); }
	catch (e) { toast(e.message, true); }
});

// ---- Mirror dialog (Tier-1 two-way sync) ----
let mirrorTarget = null, mirrorExtraFolder = null;
const mirrorShow = makeShow('#mirrorResult');
const mirrorDest = destSelect('mirrorDest', {
	__folder__: () => openBrowse({ title: 'Choose a mirror folder', useLabel: 'Use this folder', start: mirrorExtraFolder || '', pickVaults: false, onChoose: (p) => { mirrorExtraFolder = p; fillMirrorDest(p); reopen('#mirrorDialog'); } }),
	__sftp__: () => openSftp(null, (id) => { fillMirrorDest('sftp:' + id); reopen('#mirrorDialog'); }),
	__peer__: () => openPeer(null, (id) => { fillMirrorDest('webdav:' + id); reopen('#mirrorDialog'); }),
});
// The destination dropdown mirrors the backup one: a picked folder, every saved SFTP server and peer, and the
// "add" actions — reusing the same folder browser, SFTP dialog, and peer dialog.
function fillMirrorDest(selected) {
	const rows = [];
	if (mirrorExtraFolder) rows.push({ v: mirrorExtraFolder, t: 'Folder: ' + mirrorExtraFolder });
	(lastState.sftpDests || []).forEach(d => rows.push({ v: 'sftp:' + d.id, t: 'SFTP: ' + (d.label || d.host) }));
	(lastState.peers || []).forEach(d => rows.push({ v: 'webdav:' + d.id, t: 'Peer: ' + (d.label || d.url) }));
	rows.push({ v: '__folder__', t: '＋ Choose a folder…' });
	rows.push({ v: '__sftp__', t: '＋ Add an SFTP server…' });
	rows.push({ v: '__peer__', t: '＋ Add a peer node…' });
	mirrorDest.fill(rows, selected);
}
function mirrorDestValue() { return mirrorDest.value() || null; }
function openMirror(path, name) {
	mirrorTarget = path;
	$('#mirrorName').textContent = name;
	const m = (vaultsByPath[path] && vaultsByPath[path].mirror) || { configured: false };
	mirrorExtraFolder = (m.dest && !String(m.dest).startsWith('sftp:')) ? m.dest : null;
	fillMirrorDest(m.dest || null);
	const statusEl = $('#mirrorStatus');
	if (m.configured && m.primed) {
		statusEl.textContent = 'Mirroring to ' + m.dest + (m.lastSyncAt ? ' — last synced ' + new Date(m.lastSyncAt).toLocaleString() : '') + (m.lastConflicts ? '. Some files differ on both sides; run a Tamper check to review the “sync‑conflict” copies.' : '.');
		$('#mirrorGo').textContent = 'Re-prime'; $('#mirrorSync').hidden = false; $('#mirrorRemove').hidden = false;
	} else if (m.configured) {
		statusEl.textContent = 'A destination is chosen but not primed yet. Set up the mirror to make the first copy.';
		$('#mirrorGo').textContent = 'Set up mirror'; $('#mirrorSync').hidden = true; $('#mirrorRemove').hidden = false;
	} else {
		statusEl.textContent = 'No mirror yet. Choose where to keep the two-way copy.';
		$('#mirrorGo').textContent = 'Set up mirror'; $('#mirrorSync').hidden = true; $('#mirrorRemove').hidden = true;
	}
	const res = $('#mirrorResult'); res.hidden = true; res.innerHTML = '';
	$('#mirrorDialog').showModal();
}
// ---- Peer node dialog (Tier-2 anywhere access, client side) ----
let peerOnSaved = null;
const peerMsg = makeShow('#peerResult');
function openPeer(id, onSaved) {
	peerOnSaved = onSaved || null;
	const d = id ? (lastState.peers || []).find(x => x.id === id) : null;
	$('#peerCode').value = '';
	$('#peerLabel').value = d ? (d.label || '') : '';
	$('#peerUrl').value = d ? d.url : '';
	$('#peerUser').value = d ? d.user : 'vd';
	$('#peerPass').value = '';
	const res = $('#peerResult'); res.hidden = true; res.textContent = ''; res.className = 'tamper-result';
	$('#peerDialog').showModal();
}
// A pasted connect code wins (it carries everything); otherwise the manual fields are used.
function peerFields() { const code = $('#peerCode').value.trim(); if (code) return { code, label: $('#peerLabel').value.trim() }; return { label: $('#peerLabel').value.trim(), url: $('#peerUrl').value.trim(), user: $('#peerUser').value.trim() || 'vd', password: $('#peerPass').value }; }
$('#peerSave').addEventListener('click', guarded(async (ev) => {
	const p = peerFields();
	if (!p.url && !p.code) return peerMsg('bad', 'Paste a connect code, or enter the address by hand.');
	try { const r = await withBusy(() => api('/api/peer', { peer: p })); await refresh(); $('#peerDialog').close(); if (peerOnSaved) peerOnSaved(r.id); }
	catch (e) { peerMsg('bad', esc(e.message)); }
}));
$('#peerTest').addEventListener('click', async () => {
	const p = peerFields();
	if (!p.url && !p.code) return peerMsg('bad', 'Paste a connect code, or enter the address first.');
	try {
		peerMsg('', 'Saving and testing the connection…');
		const r = await withBusy(() => api('/api/peer', { peer: p }));
		const t = await withBusy(() => api('/api/peer-test', { id: r.id }));
		peerMsg(t.ok ? 'ok' : 'bad', t.ok ? 'Connected — the peer is reachable and the login works.' : 'Could not connect: ' + esc(t.error || 'unknown') + '. Is the other machine serving this vault, and reachable?');
		await refresh();
	} catch (e) { peerMsg('bad', esc(e.message)); }
});
$('#mirrorGo').addEventListener('click', guarded(async (ev) => {
	const dest = mirrorDestValue();
	if (!dest) return toast('Choose a destination first', true);
	try {
		mirrorShow('', 'Setting up and priming the mirror… Keep ' + APP_NAME + ' running until this finishes.');
		await withBusy(() => api('/api/mirror-set', { path: mirrorTarget, dest }));
		const onProg = (p) => mirrorShow('', 'Priming the mirror' + (p && p.percent != null ? ' — ' + p.percent + '%' : '…') + ' Keep ' + APP_NAME + ' running until this finishes.');
		const r = await withBusy(() => apiStream('/api/mirror-sync', { path: mirrorTarget, prime: true }, onProg));
		mirrorShow(r.conflicts ? 'bad' : 'ok', r.conflicts ? 'Primed, but some files differed on both sides and were kept as “sync-conflict” copies — review them with a Tamper check.' : 'Mirror is set up and primed. It will sync both ways from now on, including automatically after you unmount.');
		$('#mirrorSync').hidden = false; $('#mirrorRemove').hidden = false; $('#mirrorGo').textContent = 'Re-prime';
		refresh();
	} catch (e) { mirrorShow('bad', esc(e.message)); }
}));
$('#mirrorSync').addEventListener('click', guarded(async (ev) => {
	try {
		mirrorShow('', 'Syncing both directions… Keep ' + APP_NAME + ' running until this finishes.');
		const onProg = (p) => mirrorShow('', 'Syncing both sides' + (p && p.percent != null ? ' — ' + p.percent + '%' : '…') + ' Keep ' + APP_NAME + ' running until this finishes.');
		const r = await withBusy(() => apiStream('/api/mirror-sync', { path: mirrorTarget }, onProg));
		mirrorShow(r.conflicts ? 'bad' : 'ok', r.conflicts ? 'Synced. Some files differed on both sides and were kept as “sync-conflict” copies — review them with a Tamper check.' : 'Synced both directions.');
		refresh();
	} catch (e) { mirrorShow('bad', esc(e.message)); }
}));
$('#mirrorRemove').addEventListener('click', guarded(async (ev) => {
	const okd = await uiConfirm({ title: 'Stop mirroring', message: 'Stop mirroring this vault? The copy already at the destination is left in place — nothing is deleted. You can set the mirror up again later.', confirmLabel: 'Stop mirroring', danger: true });
	if (!okd) return;
	try {
		await withBusy(() => api('/api/mirror-remove', { path: mirrorTarget }));
		mirrorShow('', 'Mirroring stopped. The copy at the destination was left in place.');
		$('#mirrorSync').hidden = true; $('#mirrorRemove').hidden = true; $('#mirrorGo').textContent = 'Set up mirror';
		refresh();
	} catch (e) { mirrorShow('bad', esc(e.message)); }
}));

// ---- Serve dialog (Tier-2: act as a node other machines mirror to) ----
let serveTarget = null;
const serveMsg = makeShow('#serveResult');
function serveShowConn(info) {
	$('#serveCode').textContent = info.code || '';
	$('#serveCodeRow').hidden = !info.code;
	$('#serveUrl').textContent = info.url || '';
	$('#serveUser').textContent = info.user || '';
	$('#servePass').textContent = info.pass || '';
	$('#serveSecNote').textContent = info.bind === 'relay'
		? (info.secure ? '🔒 The relay hop is encrypted end to end — the other machine pins this node’s certificate, so the hub only ever relays scrambled data.'
			: '⚠ Serving over plain HTTP: no TLS certificate could be made, so the relay hop is not encrypted. The vault contents are encrypted either way; try serving again.')
		: '';
	$('#serveConn').hidden = !info.url;
	$('#serveBindRow').hidden = true;
	$('#serveStop').hidden = false;
	$('#serveGo').hidden = true;
}
async function openServe(path, name) {
	serveTarget = path;
	$('#serveName').textContent = name;
	const res = $('#serveResult'); res.hidden = true; res.innerHTML = '';
	const v = vaultsByPath[path] || {};
	if (v.serving && v.serving.serving) {
		// Already serving — fetch the full details (including the password) to show.
		try { const info = await api('/api/serve-info', { path }); serveShowConn(info); }
		catch (e) { serveMsg('bad', esc(e.message)); }
	} else {
		$('#serveConn').hidden = true; $('#serveBindRow').hidden = false;
		$('#serveStop').hidden = true; $('#serveGo').hidden = false; $('#serveBind').value = 'relay';
		$('#serveRelayHost').value = ''; $('#serveRelayToken').value = ''; $('#serveRelayToken').placeholder = '';
		serveBindChanged();
		// Prefill a remembered relay so the user rarely re-enters it (the token stays saved server-side).
		try { const rc = await api('/api/relay-config', {}); if (rc.host) $('#serveRelayHost').value = rc.host; if (rc.hasToken) $('#serveRelayToken').placeholder = '(saved — leave blank to reuse)'; } catch (_) {}
	}
	$('#serveDialog').showModal();
}
function serveBindChanged() { $('#serveRelayRow').hidden = $('#serveBind').value !== 'relay'; }
$('#serveBind').addEventListener('change', serveBindChanged);
$('#serveGo').addEventListener('click', guarded(async (ev) => {
	const bind = $('#serveBind').value;
	if (bind === 'relay' && !$('#serveRelayHost').value.trim()) return serveMsg('bad', 'Enter the relay hub address (run “vdisk relay” on a public machine to get it).');
	try {
		serveMsg('', bind === 'relay' ? 'Connecting to the relay and starting the node…' : 'Starting the node…');
		const body = { path: serveTarget, bind };
		if (bind === 'relay') { body.relayHost = $('#serveRelayHost').value.trim(); body.relayToken = $('#serveRelayToken').value; }
		const info = await withBusy(() => api('/api/serve-start', body));
		serveMsg('ok', 'Serving. Copy the details below to the other machine.');
		serveShowConn(info);
		refresh();
	} catch (e) { serveMsg('bad', esc(e.message)); }
}));
$('#serveStop').addEventListener('click', async () => {
	try {
		await withBusy(() => api('/api/serve-stop', { path: serveTarget }));
		$('#serveDialog').close();
		toast('Stopped serving');
		refresh();
	} catch (e) { serveMsg('bad', esc(e.message)); }
});
// Copy the text of a referenced element to the clipboard. Most copied values here are secrets (a recovery key,
// a read link, a share, an identity), so a short time after copying we clear the clipboard again, so a secret is
// not left sitting there. This is BEST-EFFORT: a browser may block a clipboard write that is not tied to a user
// gesture, so it is a convenience, not a guarantee. A newer copy cancels the pending clear.
let lastCopied = null, clipClearTimer = null;
const CLIP_CLEAR_MS = 45000;
document.addEventListener('click', async (ev) => {
	const btn = ev.target.closest('.copy-btn'); if (!btn) return;
	const el = $(btn.dataset.copy); if (!el) return;
	const text = el.textContent;
	try {
		await navigator.clipboard.writeText(text);
		const t = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = t; }, 1200);
		lastCopied = text;
		if (clipClearTimer) clearTimeout(clipClearTimer);
		clipClearTimer = setTimeout(async () => {
			if (lastCopied !== text) return; // a newer in-app copy already superseded this one
			// Only clear if the clipboard STILL holds exactly what we put there. If the user copied something else
			// meanwhile, or the browser won't let us read the clipboard, leave it alone — never wipe unrelated content.
			try { if ((await navigator.clipboard.readText()) === text) { await navigator.clipboard.writeText(''); lastCopied = null; } } catch (_) {}
		}, CLIP_CLEAR_MS);
	}
	catch (_) { toast('Could not copy — select and copy manually', true); }
});

// ---- SFTP server dialog (add / edit an off-site destination) ----
let sftpEditId = null, sftpOnSaved = null;
function sftpAuthChanged() {
	const key = $('#sftpAuth').value === 'key';
	$('#sftpPwRow').hidden = key; $('#sftpKeyRow').hidden = !key; $('#sftpPassphraseRow').hidden = !key;
}
function openSftp(id, onSaved) {
	sftpEditId = id || null; sftpOnSaved = onSaved || null;
	const d = id ? (lastState.sftpDests || []).find(x => x.id === id) : null;
	$('#sftpHost').value = d ? d.host : '';
	$('#sftpPort').value = d ? d.port : '22';
	$('#sftpUser').value = d ? d.user : '';
	$('#sftpAuth').value = d ? d.authType : 'password';
	$('#sftpPass').value = ''; $('#sftpPassphrase').value = '';
	$('#sftpKeyFile').value = d ? d.keyFile : '';
	$('#sftpRemote').value = d ? d.remotePath : '';
	$('#sftpLabel').value = d ? d.label : '';
	// The pinned host key is never echoed back; show whether one is set and keep it unless replaced.
	const hk = $('#sftpHostKey');
	if (hk) { hk.value = ''; hk.placeholder = (d && d.hasHostKey) ? 'A host key is pinned — leave blank to keep it, or paste a new one to replace it.' : 'Paste the output of:  ssh-keyscan your-host'; }
	if ($('#sftpUnpin')) $('#sftpUnpin').hidden = !(d && d.hasHostKey); // only offer un-pinning when one is set
	$('#sftpDelete').hidden = !id;
	const res = $('#sftpResult'); res.hidden = true; res.textContent = '';
	sftpAuthChanged();
	$('#sftpDialog').showModal();
}
function sftpFormValue() {
	return {
		id: sftpEditId || undefined, label: $('#sftpLabel').value.trim(),
		host: $('#sftpHost').value.trim(), port: parseInt($('#sftpPort').value, 10) || 22, user: $('#sftpUser').value.trim(),
		remotePath: $('#sftpRemote').value.trim(), authType: $('#sftpAuth').value,
		password: $('#sftpPass').value, keyFile: $('#sftpKeyFile').value.trim(), passphrase: $('#sftpPassphrase').value,
		// Send the host key only when the user typed one; omitting it keeps any already pinned.
		hostKey: ($('#sftpHostKey') && $('#sftpHostKey').value.trim()) ? $('#sftpHostKey').value.trim() : undefined
	};
}
$('#sftpAuth').addEventListener('change', sftpAuthChanged);
// Remove a pinned host key — a security downgrade, so require an explicit confirmation. Sends an
// empty hostKey (an explicit clear, distinct from "leave blank to keep") and saves the destination.
$('#sftpUnpin').addEventListener('click', async () => {
	const okd = await uiConfirm({
		title: 'Remove pinned host key',
		message: 'Remove the pinned server host key? Future backups to this destination will no longer verify the server’s identity, so an impersonating server on an untrusted network could capture your login. Your uploaded data stays encrypted either way.',
		confirmLabel: 'Remove pinned key', danger: true
	});
	if (!okd) return;
	try {
		await withBusy(() => api('/api/sftp-dest', { dest: { ...sftpFormValue(), hostKey: '' } })); // '' explicitly clears it
		await refresh();
		$('#sftpUnpin').hidden = true;
		$('#sftpHostKey').placeholder = 'Paste the output of:  ssh-keyscan your-host';
		toast('Pinned host key removed');
	} catch (e) { toast(e.message, true); }
});
$('#sftpSave').addEventListener('click', guarded(async (ev) => {
	const dest = sftpFormValue();
	if (!dest.host || !dest.user) return toast('Enter at least a host and username', true);
	try {
		const r = await withBusy(() => api('/api/sftp-dest', { dest }));
		await refresh(); // pick up the new/updated dest into lastState
		toast('SFTP server saved');
		$('#sftpDialog').close();
		if (sftpOnSaved) sftpOnSaved(sftpEditId || r.id);
	} catch (e) { toast(e.message, true); }
}));
$('#sftpTest').addEventListener('click', async () => {
	const res = $('#sftpResult');
	// Save first (so the test uses the current form), then test by id.
	const dest = sftpFormValue();
	if (!dest.host || !dest.user) return toast('Enter at least a host and username', true);
	try {
		res.hidden = false; res.className = 'tamper-result'; res.textContent = 'Connecting…';
		const saved = await withBusy(() => api('/api/sftp-dest', { dest }));
		sftpEditId = sftpEditId || saved.id; $('#sftpDelete').hidden = false;
		await refresh();
		const t = await withBusy(() => api('/api/sftp-test', { id: sftpEditId }));
		if (t.ok) { res.className = 'tamper-result ok'; res.textContent = 'Connected — the server and login work.'; }
		else { res.className = 'tamper-result bad'; res.textContent = 'Could not connect: ' + (t.error || 'check the host, login, and that the folder exists'); } // textContent renders literally — do NOT esc() here or an error with & < > shows the entities
	} catch (e) { res.className = 'tamper-result bad'; res.textContent = e.message; }
});
$('#sftpDelete').addEventListener('click', async () => {
	if (!sftpEditId) return;
	if (!(await uiConfirm({ title: 'Delete SFTP server', message: 'Remove this off-site destination? Vaults set to back up here will need a new destination.', confirmLabel: 'Delete', danger: true }))) return;
	try { await withBusy(() => api('/api/sftp-dest-remove', { id: sftpEditId })); await refresh(); toast('SFTP server removed'); $('#sftpDialog').close(); }
	catch (e) { toast(e.message, true); }
});

$('#refreshBtn').addEventListener('click', refresh);

// Auto-lock timeout: persist the chosen minutes (0 = off).
$('#autoLock').addEventListener('change', async (ev) => {
	const minutes = parseInt(ev.target.value, 10) || 0;
	try { await api('/api/settings', { autoLockMinutes: minutes }); toast(minutes ? 'Auto-lock: ' + minutes + ' min of inactivity' : 'Auto-lock off'); }
	catch (e) { toast(e.message, true); }
});
// Auto-timestamp (opt-in): timestamp each new snapshot/seal so the proof chain stays current.
$('#autoAttest').addEventListener('change', async (ev) => {
	const on = !!ev.target.checked;
	try { await api('/api/settings', { autoAttest: on }); toast(on ? 'Auto-timestamp on — each new snapshot and seal is timestamped' : 'Auto-timestamp off'); }
	catch (e) { toast(e.message, true); }
});
// Lock on sleep: lock open vaults when the machine wakes.
const losEl = $('#lockOnSleep');
if (losEl) losEl.addEventListener('change', async (ev) => {
	const on = !!ev.target.checked;
	try { await api('/api/settings', { lockOnSleep: on }); toast(on ? 'Open vaults will lock when this computer wakes from sleep' : 'Lock on sleep off'); }
	catch (e) { toast(e.message, true); }
});
// Automatic update check: opt-in, off by default (it makes an outbound request).
const aucEl = $('#autoUpdateCheck');
if (aucEl) aucEl.addEventListener('change', async (ev) => {
	const on = !!ev.target.checked;
	try { await api('/api/settings', { autoUpdateCheck: on }); toast(on ? 'The app will check once a day for a newer version' : 'Automatic update checks off'); }
	catch (e) { toast(e.message, true); }
});
// Manual "Check now": a read-only version comparison. Never downloads; a failure is reported plainly and is harmless.
const ucBtn = $('#updateCheckBtn');
if (ucBtn) ucBtn.addEventListener('click', guarded(async () => {
	const out = $('#updateStatusText');
	// Latch a dataset flag while the manual check is in flight so the background state poll does not overwrite the
	// "Checking…" line (or the result) mid-request. A flag is robust where a text compare was not — it does not break
	// if the wording or language changes. Cleared in finally so the poll resumes ownership afterward.
	if (out) { out.dataset.checking = '1'; out.textContent = 'Checking…'; }
	try {
		const r = await api('/api/update-check', {});
		renderUpdateStatus(r && r.ok ? { current: r.current, latest: r.latest, updateAvailable: r.updateAvailable, ahead: r.ahead, releasesUrl: r.releasesUrl } : null, r && r.error);
	} catch (e) { if (out) out.textContent = 'Could not check for updates right now.'; }
	finally { if (out) delete out.dataset.checking; }
}));
// Render the version line from an update status (live from the state poll, or a just-run manual check). Kept in one
// place so the poll and the button show identical wording. `err` is only set on a failed manual check.
function renderUpdateStatus(st, err) {
	const out = $('#updateStatusText'); if (!out) return;
	if (err) { out.textContent = err + ' This check is optional — the app works normally without it.'; return; }
	if (!st) { out.textContent = 'Check whether a newer version has been published. Downloading stays your choice.'; return; }
	if (st.updateAvailable) {
		// Render the releases location as a real link so it is one click, not a copy-paste. Built with DOM nodes (not
		// innerHTML) so the URL and versions can never inject markup. Opens in a new tab; noopener/noreferrer keep the
		// opened page from reaching back into this one.
		out.textContent = 'Version ' + st.latest + ' is available (you have ' + st.current + '). Get it from ';
		if (st.releasesUrl && /^https?:\/\//i.test(st.releasesUrl)) {
			const a = document.createElement('a');
			a.href = st.releasesUrl; a.textContent = st.releasesUrl; a.target = '_blank'; a.rel = 'noopener noreferrer';
			out.appendChild(a);
			out.appendChild(document.createTextNode(' — downloading is manual, and the download is verified before you trust it.'));
		} else {
			out.appendChild(document.createTextNode((st.releasesUrl || 'the releases page') + ' — downloading is manual, and the download is verified before you trust it.'));
		}
	} else if (st.ahead) {
		out.textContent = 'This build (' + st.current + ') is newer than the latest published version (' + st.latest + ') — nothing to do.';
	} else {
		out.textContent = 'You are on the latest version (' + st.current + ').';
	}
}
// Sync bandwidth limit: applied to off-site backups and mirrors. Common speeds are one click in the preset
// dropdown; "Custom…" reveals a free-text field for advanced values (asymmetric "10M:1M" or an off-peak
// timetable). The dropdown keeps the everyday case fool-proof — you cannot type a bad rate — while the advanced
// syntax stays available. The set of preset values here must match the <option>s in the page.
const BW_PRESETS = ['', '256k', '512k', '1M', '2M', '5M', '10M'];
function applyBwToUI(v) {
	const bw = $('#bwLimit'), bwp = $('#bwPreset'), row = $('#bwCustomRow');
	if (!bw || !bwp) return;
	const val = String(v || '').trim();
	const isPreset = BW_PRESETS.indexOf(val) >= 0;
	bwp.value = isPreset ? val : 'custom';
	if (row) row.hidden = isPreset;             // the free-text row only shows for a non-preset (custom) value
	bw.value = isPreset ? '' : val;
}
async function saveBwlimit(v) {
	const val = String(v || '').trim();
	try { const r = await api('/api/settings', { bwlimit: val }); const set = (r.settings && r.settings.bwlimit) || ''; applyBwToUI(set); toast(set ? 'Sync speed limited to ' + set : 'Sync speed: no limit'); }
	catch (e) { toast(e.message, true); }
}
const bwPresetEl = $('#bwPreset');
if (bwPresetEl) bwPresetEl.addEventListener('change', (ev) => {
	if (ev.target.value === 'custom') {                 // reveal the free-text field and let the user type; nothing saved yet
		const row = $('#bwCustomRow'), bw = $('#bwLimit');
		if (row) row.hidden = false;
		if (bw) { bw.value = ''; bw.focus(); }
		return;
	}
	saveBwlimit(ev.target.value);                        // a preset is a complete, valid value — save it straight away
});
const bwEl = $('#bwLimit');
if (bwEl) bwEl.addEventListener('change', (ev) => saveBwlimit(ev.target.value));

// ---- Passwordless web-interface sign-in (Touch ID / Windows Hello / a security key) ----
// Reuses the same WebAuthn PRF as vault unlock: enroll derives a per-credential secret (released only after the
// device's user check) and stores its hash server-side; the login page later re-derives it to sign in without
// the password. The relying-party id is the current hostname, so a credential works on the origin it was added on.
async function loadSigninKeys() {
	const list = $('#signinKeysList');
	try {
		const { credentials } = await api('/api/webauthn-list', {});
		list.innerHTML = credentials.length
			? credentials.map(c => '<div class="note-item static row-between"><span>' + esc(c.label) + '</span><button type="button" class="link-btn danger" data-wa-remove="' + esc(c.id) + '">Remove</button></div>').join('')
			: '<div class="muted">No sign-in keys yet. Add this device to sign in without the password.</div>';
	} catch (e) { list.innerHTML = '<div class="muted">' + esc(e.message) + '</div>'; }
}
function openSigninKeys() {
	const r = $('#signinKeysResult'); r.hidden = true; r.innerHTML = '';
	$('#signinKeysList').innerHTML = '<div class="muted">Loading…</div>';
	$('#signinKeysDialog').showModal();
	loadSigninKeys();
}
if ($('#signinKeysBtn')) $('#signinKeysBtn').addEventListener('click', openSigninKeys);
if ($('#signinKeyAdd')) $('#signinKeyAdd').addEventListener('click', async () => {
	const res = $('#signinKeysResult');
	if (!window.PublicKeyCredential) { showResult(res, 'bad', 'This browser does not support Touch ID or security keys.'); return; }
	try {
		res.hidden = false; res.className = 'tamper-result'; res.textContent = 'Follow the prompt on your device…';
		const prfSalt = randBytes(32);
		const cred = await navigator.credentials.create({ publicKey: {
			rp: { name: APP_NAME, id: location.hostname },
			user: { id: randBytes(16), name: 'web-signin', displayName: 'Web sign-in' },
			challenge: randBytes(32), timeout: 60000,
			pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
			authenticatorSelection: { userVerification: 'required' },
			extensions: { prf: { eval: { first: prfSalt } } }
		} });
		const credentialId = b64uEncode(cred.rawId);
		// create() may return the PRF result directly; if not, a get() re-derives the same secret.
		let prf = cred.getClientExtensionResults().prf; let first = prf && prf.results && prf.results.first;
		if (!first) {
			const assertion = await navigator.credentials.get({ publicKey: {
				rpId: location.hostname, challenge: randBytes(32), timeout: 60000, userVerification: 'required',
				allowCredentials: [{ type: 'public-key', id: cred.rawId }],
				extensions: { prf: { evalByCredential: { [credentialId]: { first: prfSalt } } } }
			} });
			prf = assertion.getClientExtensionResults().prf; first = prf && prf.results && prf.results.first;
		}
		if (!first) throw new Error('This device does not support the required security-key extension, so it cannot be used for passwordless sign-in.');
		const label = (bioOK ? 'Touch ID' : 'Security key') + ' · ' + new Date().toLocaleDateString();
		// Enrolling a passwordless sign-in method requires the current web password: it stores a secret, so a session
		// alone must not be enough to plant a credential (a hijacked session could otherwise create a lasting backdoor).
		const pw = await uiConfirm({ title: 'Confirm it\'s you', message: 'Enter your web password to add ' + label + ' as a passwordless sign-in.', confirmLabel: 'Add', requirePassword: true, passwordLabel: 'Web password' }); // uiConfirm sets message via textContent (auto-escaping); esc(label) here would double-escape
		if (!pw) { showResult(res, '', 'Canceled — nothing was added.'); return; }
		await api('/api/webauthn-add', { secret: b64uEncode(first), credentialId, prfSalt: b64uEncode(prfSalt), label, password: pw });
		showResult(res, 'ok', 'Added. You can now sign in with ' + esc(label) + '.');
		loadSigninKeys();
	} catch (e) { showResult(res, 'bad', esc((e && e.message) || 'Could not add this device.')); }
});
if ($('#signinKeysList')) $('#signinKeysList').addEventListener('click', async (ev) => {
	const btn = ev.target.closest('[data-wa-remove]'); if (!btn) return;
	try { await api('/api/webauthn-remove', { id: btn.dataset.waRemove }); loadSigninKeys(); toast('Sign-in key removed'); }
	catch (e) { toast(e.message, true); }
});

// ---- Per-vault decoy (duress) protection (advanced) — hidden management ----
// A protected vault is paired with a separate decoy vault; opening the real vault with the decoy vault's
// password opens the decoy instead. Nothing marks a vault as protected; pairings are managed with a manager
// password. Both the pairing form and the reveal-existing section live in one dialog.
function decoyPwField(id, label, hint) { return '<label class="field"><span>' + label + '</span><input type="text" class="mask" id="' + id + '" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" data-1p-ignore data-lpignore="true">' + (hint ? '<span class="field-hint">' + hint + '</span>' : '') + '</label>'; }
// ---- Travel mode: hide all vaults under a travel password, restore with it ----
async function openTravel() {
	let active = false;
	try { active = (await api('/api/travel-status', {})).active; } catch (_) {}
	$('#travelEnable').hidden = active; $('#travelRestore').hidden = !active;
	$('#travelPassword').value = ''; $('#travelConfirm').value = ''; $('#travelRestorePassword').value = '';
	$('#travelResult').hidden = true; $('#travelRestoreResult').hidden = true;
	$('#travelDialog').showModal();
	setTimeout(() => (active ? $('#travelRestorePassword') : $('#travelPassword')).focus(), 50);
}
function travelShow(sel, kind, msg) { const r = $(sel); r.hidden = false; r.className = 'tamper-result ' + kind; r.innerHTML = msg; }
if ($('#travelBtn')) $('#travelBtn').addEventListener('click', openTravel);
onDialogSubmit('#travelForm', async () => {
	const pw = $('#travelPassword').value, confirm = $('#travelConfirm').value;
	if (!pw) return travelShow('#travelResult', 'bad', 'Enter a travel password.');
	if (pw !== confirm) return travelShow('#travelResult', 'bad', 'The two travel passwords do not match.');
	try { const r = await withBusy(() => api('/api/travel-start', { password: pw })); $('#travelDialog').close(); toast('Travel mode on — ' + r.hidden + ' vault' + (r.hidden === 1 ? '' : 's') + ' hidden and locked.'); refresh(); }
	catch (e) { travelShow('#travelResult', 'bad', esc(e.message)); }
});
if ($('#travelRestoreBtn')) $('#travelRestoreBtn').addEventListener('click', async () => {
	const pw = $('#travelRestorePassword').value;
	if (!pw) return travelShow('#travelRestoreResult', 'bad', 'Enter your travel password.');
	try { const r = await withBusy(() => api('/api/travel-restore', { password: pw })); $('#travelDialog').close(); toast('Restored ' + r.restored + ' vault' + (r.restored === 1 ? '' : 's') + '.'); refresh(); }
	catch (e) { travelShow('#travelRestoreResult', 'bad', esc(e.message)); }
});

// ---- Emergency / inheritance access (dead-man's switch) ----
async function openEmergency() {
	$('#emEnrollResult').hidden = true; $('#emManageResult').hidden = true; $('#emKeyOut').hidden = true;
	$('#emContactKey').value = ''; $('#emContactLabel').value = ''; $('#emArmPassword').value = '';
	if ($('#emAddKey')) $('#emAddKey').value = ''; if ($('#emAddLabel')) $('#emAddLabel').value = ''; if ($('#emAddKeyOut')) $('#emAddKeyOut').hidden = true;
	let s = { enrolled: false };
	try { s = await api('/api/emergency-status', {}); } catch (_) {}
	$('#emergencyEnroll').hidden = !!s.enrolled; $('#emergencyManage').hidden = !s.enrolled;
	if (s.enrolled) renderEmergencyStatus(s);
	$('#emergencyDialog').showModal();
}
let emContacts = [];
function renderEmergencyStatus(s) {
	emContacts = s.contacts || [];
	const phase = s.phase === 'released' ? '<strong>RELEASED</strong> on ' + esc(s.releasedAt) + ' — check in to withdraw it'
		: s.phase === 'grace' ? '<strong>in the grace period</strong> — check in now to stop the release'
		: 'active — about ' + s.daysUntilRelease + ' day(s) of no check-in until release';
	showResult($('#emStatus'), s.phase === 'released' || s.phase === 'grace' ? 'bad' : 'ok',
		esc(String(emContacts.length)) + ' beneficiar' + (emContacts.length === 1 ? 'y' : 'ies') + '. Check in every ' + s.inactivityDays + ' days (+' + s.graceDays + ' day grace). Status: ' + phase + '.');
	// The beneficiaries list: each with the vaults routed to them and a Remove button.
	const list = $('#emContactsList');
	if (list) {
		list.innerHTML = emContacts.length ? emContacts.map(c => {
			const vaults = (s.armed || []).filter(a => a.contactId === c.id).map(a => esc(a.name)).join(', ') || 'no vaults yet';
			return '<div class="em-contact"><span class="nm" dir="auto"><strong>' + esc(c.label) + '</strong> — ' + vaults + '</span> <button type="button" class="link-btn danger" data-act="em-remove-contact" data-id="' + esc(c.id) + '" data-label="' + esc(c.label) + '">Remove</button></div>';
		}).join('') : '<div class="muted">None yet.</div>';
	}
	// Fill the vault picker with valid, unmounted vaults, and the beneficiary picker with the enrolled contacts.
	const sel = $('#emArmVault'); const vaults = ((lastState && lastState.vaults) || []).filter(v => v.valid && !v.mounted);
	sel.innerHTML = vaults.length ? vaults.map(v => '<option value="' + esc(v.path) + '">' + esc(v.name || v.path) + '</option>').join('') : '<option value="">No unlocked-and-closed vaults to protect</option>';
	const csel = $('#emArmContact');
	if (csel) csel.innerHTML = emContacts.length ? emContacts.map(c => '<option value="' + esc(c.id) + '">' + esc(c.label) + '</option>').join('') : '<option value="">Add a beneficiary first</option>';
}
if ($('#emergencyBtn')) $('#emergencyBtn').addEventListener('click', openEmergency);
if ($('#emGenKey')) $('#emGenKey').addEventListener('click', async () => {
	try {
		const kp = await api('/api/emergency-keypair', {});
		$('#emContactKey').value = kp.publicKey; // convenience: the owner can generate on the contact's behalf
		showResult($('#emKeyOut'), 'ok', 'Give your contact BOTH of these; they keep the private key secret. The public key is filled in above.<br><br><strong>Public key:</strong><br><code class="break-all">' + esc(kp.publicKey) + '</code><br><br><strong>Private key (secret):</strong><br><code class="break-all">' + esc(kp.privateKey) + '</code>');
	} catch (e) { showResult($('#emKeyOut'), 'bad', esc(e.message)); }
});
onDialogSubmit('#emergencyForm', async () => {
	if (!$('#emergencyEnroll').hidden) {
		const contactPubKey = $('#emContactKey').value.trim();
		if (!contactPubKey) return showResult($('#emEnrollResult'), 'bad', 'Paste your contact\'s public key (or generate a keypair for them).');
		try {
			const r = await withBusy(() => api('/api/emergency-enroll', { contactPubKey, contactLabel: $('#emContactLabel').value.trim(), inactivityDays: Number($('#emInactive').value) || 30, graceDays: Number($('#emGrace').value) || 14 }));
			const s = await api('/api/emergency-status', {});
			$('#emergencyEnroll').hidden = true; $('#emergencyManage').hidden = false; renderEmergencyStatus(s);
			if (r && r.rearmNeeded) toast('Contact changed — ' + r.rearmNeeded + ' armed vault' + (r.rearmNeeded === 1 ? ' was' : 's were') + ' unarmed. Re-arm each one for the new contact.', true);
		} catch (e) { showResult($('#emEnrollResult'), 'bad', esc(e.message)); }
	}
});
if ($('#emArmBtn')) $('#emArmBtn').addEventListener('click', async () => {
	const path = $('#emArmVault').value, password = $('#emArmPassword').value;
	const contactId = ($('#emArmContact') && $('#emArmContact').value) || '';
	if (!path) return showResult($('#emManageResult'), 'bad', 'There is no unlocked, closed vault to protect. Close a vault first.');
	if (!contactId) return showResult($('#emManageResult'), 'bad', 'Add a beneficiary first, then choose who should receive this vault.');
	if (!password) return showResult($('#emManageResult'), 'bad', 'Enter the vault password.');
	try { const r = await withBusy(() => api('/api/emergency-arm', { path, password, contactId })); $('#emArmPassword').value = ''; const s = await api('/api/emergency-status', {}); renderEmergencyStatus(s); showResult($('#emManageResult'), 'ok', 'Routed. Its read access is sealed to ' + esc(r.contactLabel) + '.'); }
	catch (e) { showResult($('#emManageResult'), 'bad', esc(e.message)); }
});
// Generate a keypair for an additional beneficiary (in the manage view's Add section).
if ($('#emGenKey2')) $('#emGenKey2').addEventListener('click', async () => {
	try { const kp = await api('/api/emergency-keypair', {}); $('#emAddKey').value = kp.publicKey; showResult($('#emAddKeyOut'), 'ok', 'Give this beneficiary BOTH keys; they keep the private key secret. The public key is filled in above.<br><br><strong>Public key:</strong><br><code class="break-all">' + esc(kp.publicKey) + '</code><br><br><strong>Private key (secret):</strong><br><code class="break-all">' + esc(kp.privateKey) + '</code>'); }
	catch (e) { showResult($('#emAddKeyOut'), 'bad', esc(e.message)); }
});
if ($('#emAddBtn')) $('#emAddBtn').addEventListener('click', async () => {
	const pubKey = $('#emAddKey').value.trim(); if (!pubKey) return showResult($('#emManageResult'), 'bad', 'Paste the beneficiary\'s public key (or generate a keypair for them).');
	try { await withBusy(() => api('/api/emergency-add-contact', { pubKey, label: $('#emAddLabel').value.trim() })); $('#emAddKey').value = ''; $('#emAddLabel').value = ''; $('#emAddKeyOut').hidden = true; const s = await api('/api/emergency-status', {}); renderEmergencyStatus(s); showResult($('#emManageResult'), 'ok', 'Beneficiary added. Choose them when you route a vault.'); }
	catch (e) { showResult($('#emManageResult'), 'bad', esc(e.message)); }
});
// Remove a beneficiary (delegated, since the list is re-rendered). Confirms, since it drops their sealed grants.
document.addEventListener('click', async (ev) => {
	const btn = ev.target.closest('[data-act="em-remove-contact"]'); if (!btn) return;
	if (!(await uiConfirm({ title: 'Remove beneficiary', message: 'Remove "' + btn.dataset.label + '"? Any vaults routed to them are unrouted (their sealed access could never be opened by anyone else anyway). This does not affect access already released or copied — rotate a vault\'s keys for that.', confirmLabel: 'Remove', danger: true }))) return;
	try { await withBusy(() => api('/api/emergency-remove-contact', { contactId: btn.dataset.id })); const s = await api('/api/emergency-status', {}); renderEmergencyStatus(s); showResult($('#emManageResult'), 'ok', 'Beneficiary removed.'); }
	catch (e) { showResult($('#emManageResult'), 'bad', esc(e.message)); }
});
if ($('#emCheckinBtn')) $('#emCheckinBtn').addEventListener('click', async () => {
	try { await api('/api/emergency-checkin', {}); const s = await api('/api/emergency-status', {}); renderEmergencyStatus(s); showResult($('#emManageResult'), 'ok', 'Checked in — the timer is reset.'); }
	catch (e) { showResult($('#emManageResult'), 'bad', esc(e.message)); }
});
if ($('#emDisarmBtn')) $('#emDisarmBtn').addEventListener('click', async () => {
	if (!(await uiConfirm({ title: 'Turn off emergency access', message: 'Turn off emergency access? To be certain a released or copied sealed blob can never open a vault, also rotate that vault\'s keys.', confirmLabel: 'Turn off', danger: true }))) return;
	try { await api('/api/emergency-disarm', {}); $('#emergencyDialog').close(); toast('Emergency access turned off.'); }
	catch (e) { showResult($('#emManageResult'), 'bad', esc(e.message)); }
});

$('#decoyBtn').addEventListener('click', () => {
	const body = $('#decoyBody');
	$('#decoyResult').hidden = true;
	const vaults = (lastState && lastState.vaults) || [];
	const opts = vaults.map(v => '<option value="' + esc(v.path) + '">' + esc(v.name || v.path) + '</option>').join('');
	body.innerHTML =
		'<p class="hint">Pair a vault with a separate <strong>decoy</strong> vault. Opening the real vault with the <em>decoy vault\'s</em> own password then opens the decoy instead, so a forced unlock reveals only the decoy. Nothing marks a vault as protected.</p>'
		+ '<p class="share-key-caution">Read this first. This hides a vault\'s <em>contents</em> under a one-time compelled unlock. It does <em>not</em> hide:</p>'
		+ '<ul class="share-key-caution tight-list">'
			+ '<li>that the vault exists — its name stays in your list;</li>'
			+ '<li>that encrypted data exists, or your vault folders, file sizes, timestamps, backups, or OS indexes.</li>'
		+ '</ul>'
		+ '<details class="advanced"><summary>How it works, and its limits</summary>'
			+ '<p class="hint">The decoy is a real, separate vault, so give it believable contents. The trigger is the decoy vault\'s password as it is now — if you later change or rotate that password, re-pair so it matches. Someone who can watch your disk over time may still infer a hidden pairing, and in some places revealing a decoy can carry legal risk. Expert-only.</p>'
		+ '</details>'
		+ (vaults.length < 2 ? '<p class="hint">You need at least two vaults — one to protect and one to use as the decoy — before you can pair them.</p>' : '')
		+ '<label class="field"><span>Protect this vault</span><select id="decoyReal">' + opts + '</select></label>'
		+ '<label class="field"><span>Open this decoy instead</span><select id="decoyDecoy">' + opts + '</select></label>'
		+ decoyPwField('decoyPw', 'The decoy vault\'s password (this becomes the trigger)')
		+ decoyPwField('decoyMgr', 'Set a manager password (used only to manage decoys)', 'If you already have decoys, enter the same manager password you set before.')
		+ '<label class="checkfield"><input type="checkbox" id="decoyAck"> <span>I understand what this does and does not protect.</span></label>'
		+ '<details class="advanced mt-3"><summary>Manage existing pairings</summary>'
			+ '<p class="hint">Enter your manager password to reveal your pairings, then remove any you no longer want.</p>'
			+ decoyPwField('decoyMgrShow', 'Manager password (to view or remove pairings)')
			+ '<div class="my-1"><button type="button" id="decoyShowBtn" class="ghost-btn">Show pairings</button></div>'
			+ '<div id="decoyMappings"></div>'
		+ '</details>';
	$('#decoyShowBtn').addEventListener('click', decoyShowPairings);
	$('#decoyPrimary').disabled = vaults.length < 2; // can't pair without at least a real and a decoy vault
	$('#decoyDialog').showModal();
});
async function decoyShowPairings() {
	const managerPassword = $('#decoyMgrShow').value;
	if (!managerPassword) return;
	try {
		const { mappings } = await api('/api/decoy-list', { managerPassword });
		const el = $('#decoyMappings');
		const name = (p) => { const v = ((lastState && lastState.vaults) || []).find(x => x.path === p); return esc(v ? (v.name || p) : p); };
		if (!mappings.length) { el.innerHTML = '<p class="hint">No pairings yet.</p>'; return; }
		// A pairing can silently go stale (a vault moved or replaced, or the decoy's password changed) — its duress
		// redirect would then no longer trigger. The warning shows ONLY here, in this manager-password view, so it
		// never leaks that a pairing exists to anyone who has only a decoy password.
		el.innerHTML = mappings.map(m => '<div class="decoy-map">'
			+ '<div class="row-between"><span>' + name(m.realVault) + ' → decoy: ' + name(m.decoyVault) + '</span>'
			+ '<button type="button" class="ghost-btn danger" data-decoy-remove="' + esc(m.realVault) + '">Remove</button></div>'
			+ (m.warning ? '<div class="decoy-stale">⚠ ' + esc(m.warning) + '</div>' : '')
			+ '</div>').join('');
		el.querySelectorAll('[data-decoy-remove]').forEach(b => b.addEventListener('click', () => decoyRemovePairing(b.getAttribute('data-decoy-remove'), managerPassword)));
	} catch (e) { showResult($('#decoyResult'), 'bad', esc(e.message)); }
}
async function decoyRemovePairing(realVault, managerPassword) {
	// Removing a decoy pairing weakens this vault's duress protection, so confirm first — a consequential change,
	// not a one-click action.
	const okd = await uiConfirm({ title: 'Remove decoy pairing', message: 'Remove the decoy pairing for this vault? Its duress (decoy) protection will no longer apply until you pair one again.', confirmLabel: 'Remove pairing', danger: true });
	if (!okd) return;
	try { await withBusy(() => api('/api/decoy-remove', { realVault, managerPassword })); showResult($('#decoyResult'), 'ok', 'Pairing removed.'); decoyShowPairings(); refresh(); }
	catch (e) { showResult($('#decoyResult'), 'bad', esc(e.message)); }
}
onDialogSubmit('#decoyForm', async () => {
	if (!$('#decoyAck') || !$('#decoyAck').checked) return showResult($('#decoyResult'), 'bad', 'Please confirm you understand the limits first.');
	const realVault = ($('#decoyReal') || {}).value, decoyVault = ($('#decoyDecoy') || {}).value;
	const decoyPassword = $('#decoyPw').value, managerPassword = $('#decoyMgr').value;
	if (!realVault || !decoyVault) return showResult($('#decoyResult'), 'bad', 'Choose the vault to protect and a decoy vault.');
	if (realVault === decoyVault) return showResult($('#decoyResult'), 'bad', 'The decoy must be a different vault from the one you are protecting.');
	if (!decoyPassword || !managerPassword) return showResult($('#decoyResult'), 'bad', 'Enter the decoy vault’s password and a manager password.');
	try {
		await withBusy(() => api('/api/decoy-set', { realVault, decoyVault, decoyPassword, managerPassword }));
		// Clear the sensitive fields so the decoy and manager passwords do not linger on screen after pairing.
		$('#decoyPw').value = ''; $('#decoyMgr').value = ''; $('#decoyAck').checked = false;
		showResult($('#decoyResult'), 'ok', 'Paired. Opening the protected vault with the decoy password now opens the decoy.');
		refresh();
	} catch (e) { showResult($('#decoyResult'), 'bad', esc(e.message)); }
});

// Panic lock: unmount every mounted vault now (each is flushed first; any with a file open is
// left mounted and reported).
// Lock (unmount) every mounted vault. Each is flushed first, and unmounting evicts its keys from memory, so this
// is also the "panic" action. Shared by the button (which confirms) and the panic hotkey (which does not).
async function doLockAll() {
	const r = await withBusy(() => api('/api/lock-all', {}));
	toast(r.total === 0 ? 'No vaults were mounted' : 'Locked ' + r.locked + ' of ' + r.total + (r.busy ? ' — ' + r.busy + ' still in use' : ''), !!r.busy);
	refresh();
	return r;
}
$('#lockAllBtn').addEventListener('click', async () => {
	if (!(await uiConfirm({ title: 'Lock all', message: 'Lock (unmount) every mounted vault now? Each is flushed first; a vault with a file still open stays mounted.', confirmLabel: 'Lock all', danger: true }))) return;
	try { await doLockAll(); } catch (e) { toast(e.message, true); }
});
// Panic hotkey: Ctrl/Cmd + Shift + L locks everything INSTANTLY, with no confirmation — the point of a panic key
// is to slam the vault shut fast. It first closes anything on screen (dialogs and menus) so a shoulder-surfer sees
// nothing, then unmounts every vault (each flushed first; a vault with an open file is left mounted rather than
// risking data loss, exactly like Lock all). Cross-platform (metaKey on macOS, ctrlKey elsewhere) and
// layout-independent (ev.code). It never fires while typing a plain key, since it requires the modifier combo.
async function panicLock() {
	try { document.querySelectorAll('dialog[open]').forEach((d) => { try { d.close(); } catch (_) {} }); } catch (_) {}
	try { document.querySelectorAll('details.more[open]').forEach((d) => d.removeAttribute('open')); } catch (_) {}
	toast('Panic lock — locking every vault…');
	try { await doLockAll(); } catch (e) { toast(e.message, true); }
}
document.addEventListener('keydown', (ev) => {
	if ((ev.metaKey || ev.ctrlKey) && ev.shiftKey && (ev.code === 'KeyL' || (ev.key || '').toLowerCase() === 'l')) { ev.preventDefault(); panicLock(); }
});

// Repair: a manual self-heal. Releases stale (crashed) mounts and cleans up leftovers,
// then refreshes the list. Safe to run anytime — it only touches mounts whose engine is gone.
$('#repairBtn').addEventListener('click', async () => {
	const okd = await uiConfirm({
		title: 'Repair',
		message: 'Release any stale (crashed) mounts and clean up leftover files? Vaults that are still working are left untouched.',
		confirmLabel: 'Repair'
	});
	if (!okd) return;
	try { await withBusy(() => api('/api/repair', {})); toast('Repair complete'); refresh(); }
	catch (e) { toast(e.message, true); }
});

// ---- Settings dialog ----
// It gathers the persistent preferences and the advanced/maintenance actions that used to crowd the vault bar. Most
// controls (auto-lock, lock-on-sleep, auto-timestamp, sync limit) keep their existing IDs and change handlers, so
// they need no new code — the live poll keeps them current whether the dialog is open or not. Only start-at-login is
// not part of the poll, so its toggle is read on demand each time the dialog opens.
async function autostartSyncToggle() {
	const t = $('#autostartToggle'); if (!t) return;
	const note = $('#autostartState');
	t.disabled = true;
	try {
		const s = await api('/api/autostart-status', {});
		t.checked = !!(s.supported && s.installed); t.disabled = !s.supported;
		// Surface whether an installed autostart is network-reachable, so the notable case is visible at a glance
		// (a this-computer-only install needs no note — that is the default the row already describes).
		if (note) { const net = !!(s.installed && s.bind); note.hidden = !net; if (net) note.textContent = 'Currently reachable from your other devices on your network.'; }
	}
	catch (_) { t.disabled = false; } // leave the toggle as-is on a read error rather than misreport
}
if ($('#settingsBtn')) $('#settingsBtn').addEventListener('click', () => { $('#settingsDialog').showModal(); autostartSyncToggle(); });

// ---- In-app Help: the project README rendered in a searchable panel ------------------------------------------
// The guide is the SAME docs/README.md the project ships (served at /readme.md), rendered client-side with the
// vendored markdown library, so Help can never drift from the docs. Loaded once and cached. A simple client-side
// find highlights matches and jumps between them — no server round-trips, no AI, works offline.
let helpLoaded = false, helpBaseHTML = '', helpHits = [], helpHitIdx = -1;
// GitHub-style heading slug, so the README's own Table-of-Contents links resolve inside the panel.
function helpSlug(t) { return t.trim().toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-'); }
async function openHelp() {
	const dlg = $('#helpDialog'); if (!dlg) return;
	dlg.showModal();
	if (!helpLoaded) {
		const body = $('#helpBody');
		try {
			let md = await (await fetch('/readme.md', { cache: 'no-store' })).text();
			// The README opens with a centered banner image for the project's landing page. Strip that leading block
			// for the in-app guide: the app already shows its own branding, and the image is not served under the app
			// origin, so leaving it in would render a broken image at the top of Help.
			md = md.replace(/^\s*<p align="center">[\s\S]*?<\/p>\s*/i, '');
			helpBaseHTML = (window.marked && typeof window.marked.parse === 'function') ? window.marked.parse(md) : '<pre>' + esc(md) + '</pre>';
			body.innerHTML = helpBaseHTML;
			// Give headings ids (marked does not) so the in-doc TOC links jump, and keep those jumps inside the panel.
			body.querySelectorAll('h1,h2,h3,h4,h5,h6').forEach(h => { if (!h.id) h.id = helpSlug(h.textContent); });
			helpBaseHTML = body.innerHTML; // cache with ids in place
			helpLoaded = true;
		} catch (e) { body.innerHTML = '<p class="muted">Could not load the guide.</p>'; }
	}
	setTimeout(() => { const s = $('#helpSearch'); if (s) s.focus(); }, 50);
}
// Keep a TOC / anchor click scrolling WITHIN the panel instead of navigating the page URL.
if ($('#helpBody')) $('#helpBody').addEventListener('click', (ev) => {
	const a = ev.target.closest('a[href^="#"]'); if (!a) return;
	const id = decodeURIComponent(a.getAttribute('href').slice(1)); const target = id && document.getElementById(id);
	if (target && $('#helpBody').contains(target)) { ev.preventDefault(); target.scrollIntoView({ block: 'start', behavior: scrollBehavior() }); }
});
function helpJump(i) {
	if (!helpHits.length) return;
	if (helpHitIdx >= 0 && helpHits[helpHitIdx]) helpHits[helpHitIdx].classList.remove('help-hit-active');
	helpHitIdx = (i + helpHits.length) % helpHits.length;
	helpHits[helpHitIdx].classList.add('help-hit-active');
	helpHits[helpHitIdx].scrollIntoView({ block: 'center', behavior: scrollBehavior() });
	$('#helpSearchCount').textContent = (helpHitIdx + 1) + ' / ' + helpHits.length;
}
// Regex-safe pattern where any run of spaces/hyphens is interchangeable, so "read only" also finds "read-only"
// and vice versa — the wording a user types rarely matches the doc's hyphenation exactly.
function helpFlex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/[-\s]+/g, '[\\s\\-]+'); }
// Highlight every match of a /g regex in the guide body, skipping the Table of Contents (it repeats every section
// title, so searching a topic would otherwise count and cycle its index entry before the real content). Returns
// the created <mark> elements in document order. Do NOT pre-filter with rx.test(): rx is global, so .test()
// advances rx.lastIndex and that position carries into the next node, silently under-counting; instead run the
// exec loop with a per-node lastIndex reset and only replace nodes that actually matched.
function helpHighlight(body, rx) {
	const tocHead = [...body.querySelectorAll('h1,h2,h3,h4')].find(h => /^table of contents$/i.test(h.textContent.trim()));
	const tocList = tocHead ? tocHead.nextElementSibling : null;
	const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, null);
	const nodes = []; let n; while ((n = walker.nextNode())) { if (n.nodeValue && !(tocList && tocList.contains(n))) nodes.push(n); }
	const marks = [];
	nodes.forEach(node => {
		rx.lastIndex = 0; const s = node.nodeValue, frag = document.createDocumentFragment(); let last = 0, m, hit = false;
		while ((m = rx.exec(s))) {
			hit = true;
			if (m.index > last) frag.appendChild(document.createTextNode(s.slice(last, m.index)));
			const mark = document.createElement('mark'); mark.textContent = m[0]; frag.appendChild(mark); marks.push(mark);
			last = m.index + m[0].length; if (m.index === rx.lastIndex) rx.lastIndex++;
		}
		if (!hit) return; // no match in this text node — leave it untouched
		if (last < s.length) frag.appendChild(document.createTextNode(s.slice(last)));
		node.parentNode.replaceChild(frag, node);
	});
	return marks;
}
function helpSearch(q) {
	const body = $('#helpBody'); if (!helpLoaded) return;
	body.innerHTML = helpBaseHTML; helpHits = []; helpHitIdx = -1; // clear any prior marks
	const showNav = (on) => { if ($('#helpPrev')) $('#helpPrev').hidden = !on; if ($('#helpNext')) $('#helpNext').hidden = !on; };
	const clearChips = () => { const b = $('#helpMatches'); if (b) { b.hidden = true; b.innerHTML = ''; } };
	const query = (q || '').trim();
	if (!query) { $('#helpSearchCount').textContent = ''; showNav(false); clearChips(); return; }
	// First try the whole query as one phrase (the most precise result).
	let rx; try { rx = new RegExp(helpFlex(query), 'gi'); } catch (_) { $('#helpSearchCount').textContent = ''; showNav(false); clearChips(); return; } // never let an odd query throw
	helpHits = helpHighlight(body, rx);
	// If the exact phrase matched nothing but the query is several words, fall back to matching ANY of the words,
	// so a near miss (a different word order, an extra word, one mistyped word) still surfaces the relevant
	// sections instead of showing nothing.
	if (!helpHits.length && /\s/.test(query)) {
		body.innerHTML = helpBaseHTML;
		const terms = query.split(/\s+/).filter(Boolean).map(helpFlex);
		try { helpHits = helpHighlight(body, new RegExp(terms.join('|'), 'gi')); } catch (_) { helpHits = []; }
	}
	showNav(helpHits.length > 0);
	if (!helpHits.length) { $('#helpSearchCount').textContent = 'no matches'; clearChips(); return; }
	const ranked = helpRenderSections();
	// Land on the section that mentions the topic MOST (ranked first), not merely the earliest incidental mention.
	helpJump(ranked.length ? ranked[0].firstIdx : 0);
}
// Group the current matches by the section (nearest preceding heading) they fall in, and show a "Jump to:" bar of
// those sections RANKED by how many matches each holds (most first), each with its count — so a search shows WHERE
// a topic is covered most and one click goes straight there, instead of only cycling hit-by-hit. Hits and headings
// are both in document order, so one forward pass assigns each hit to a section. Returns the ranked list so the
// caller can land on the best section.
function helpRenderSections() {
	const bar = $('#helpMatches'); if (!bar) return [];
	const heads = [...$('#helpBody').querySelectorAll('h1,h2,h3,h4,h5,h6')];
	const sections = []; const byHead = []; let hi = 0;
	helpHits.forEach((mark, idx) => {
		while (hi + 1 < heads.length && (heads[hi + 1].compareDocumentPosition(mark) & Node.DOCUMENT_POSITION_FOLLOWING)) hi++;
		const head = heads[hi];
		if (!head || !(head.compareDocumentPosition(mark) & Node.DOCUMENT_POSITION_FOLLOWING)) return; // a hit before the first heading
		const pos = byHead.indexOf(head);
		if (pos === -1) { byHead.push(head); sections.push({ name: head.textContent, firstIdx: idx, count: 1 }); }
		else sections[pos].count++;
	});
	const ranked = sections.slice().sort((a, b) => b.count - a.count); // by match count desc; ties keep document order (stable sort)
	bar.innerHTML = ranked.map(c => `<button type="button" class="help-chip" data-hit="${c.firstIdx}" title="${esc(c.name)} — ${c.count} match${c.count === 1 ? '' : 'es'}">${esc(c.name)} <span class="help-chip-n">${c.count}</span></button>`).join('');
	bar.hidden = ranked.length === 0;
	return ranked;
}
if ($('#helpBtn')) $('#helpBtn').addEventListener('click', openHelp);
if ($('#helpPrev')) $('#helpPrev').addEventListener('click', () => helpJump(helpHitIdx - 1));
if ($('#helpNext')) $('#helpNext').addEventListener('click', () => helpJump(helpHitIdx + 1));
if ($('#helpMatches')) $('#helpMatches').addEventListener('click', (e) => { const b = e.target.closest('[data-hit]'); if (b) helpJump(parseInt(b.dataset.hit, 10)); });
// Press "/" (when not typing in a field and no other dialog is open) to open Help and start searching — the
// common docs shortcut; if Help is already open it just refocuses the search box. Reuses openHelp().
document.addEventListener('keydown', (e) => {
	if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
	const el = document.activeElement, tag = el && el.tagName;
	if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (el && el.isContentEditable)) return;
	const help = $('#helpDialog'), open = document.querySelector('dialog[open]');
	if (open && open !== help) return; // another dialog is up — leave "/" to normal typing
	e.preventDefault();
	if (help && help.open) { const s = $('#helpSearch'); if (s) { s.focus(); s.select(); } } else openHelp();
});
if ($('#helpSearch')) {
	let helpTimer = null;
	$('#helpSearch').addEventListener('input', (e) => { clearTimeout(helpTimer); const v = e.target.value; helpTimer = setTimeout(() => helpSearch(v), 140); });
	$('#helpSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); if (helpHits.length) helpJump(helpHitIdx + (e.shiftKey ? -1 : 1)); } });
}

// "New vault" jumps to the create form and focuses its first field, so the primary action is one tap away no matter
// how far the vault list has grown. The form already lives on the page — no dialog, no duplicated markup.
if ($('#newVaultBtn')) $('#newVaultBtn').addEventListener('click', () => {
	const input = $('#createPath');
	if (input) { input.scrollIntoView({ behavior: scrollBehavior(), block: 'center' }); input.focus({ preventScroll: true }); }
});

// Rail drawer (narrow screens): the hamburger slides the rail in over a scrim; the scrim, Escape, or tapping any rail
// action dismisses it. On wide screens the rail is always visible and these handlers simply never fire (the toggle is
// display:none), so there is one code path for both layouts.
(function () {
	const rail = $('#rail'), toggle = $('#railToggle'), scrim = $('#railScrim');
	if (!rail || !toggle || !scrim) return;
	const narrow = window.matchMedia('(max-width: 860px)');
	// When the drawer is off-screen on a narrow screen, mark it inert so a keyboard user can't tab into invisible
	// controls; on a wide screen the rail is always on-screen and fully interactive. Idempotent, safe to call anytime.
	const syncInert = () => { rail.inert = narrow.matches && !rail.classList.contains('open'); };
	const setOpen = (open, restoreFocus) => {
		rail.classList.toggle('open', open);
		scrim.hidden = !open;
		toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
		syncInert();
		if (open && narrow.matches) { const first = rail.querySelector('button.rail-item, a.rail-item'); if (first) first.focus(); }
		else if (!open && restoreFocus && narrow.matches) { toggle.focus(); } // return focus only on an explicit dismiss (scrim/Esc), not when a rail action opened a dialog
	};
	toggle.addEventListener('click', () => setOpen(!rail.classList.contains('open')));
	scrim.addEventListener('click', () => setOpen(false, true));
	document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && rail.classList.contains('open')) setOpen(false, true); });
	// Any actioned rail item closes the drawer so the result is visible; the passive "Vaults" label is already the page.
	rail.querySelectorAll('.rail-item').forEach(el => { if (el.tagName === 'BUTTON') el.addEventListener('click', () => setOpen(false)); });
	narrow.addEventListener('change', syncInert); // crossing the breakpoint (resize / rotate) re-evaluates focusability
	syncInert();
})();
// Start-at-login toggle. Turning ON opens a small dialog to choose the scope (this computer only, or reachable from
// other devices on the network — which needs a web login and serves over https); the dialog does the actual install,
// so the switch stays off until that succeeds. Turning OFF just confirms and uninstalls. A stray flip never changes
// anything on its own.
function autostartScope() { const r = document.querySelector('input[name="autostartScope"]:checked'); return r ? r.value : 'local'; }
function syncAutostartScope() {
	const network = autostartScope() === 'network';
	const hasPw = !!(lastState && lastState.auth && lastState.auth.enabled);
	const wantPass = network && !hasPw;
	const passWrap = $('#autostartPassWrap');
	const wasHidden = passWrap.hidden;
	passWrap.hidden = !wantPass;                          // ask for a login only when exposing and none is set yet
	$('#autostartPassHave').hidden = !(network && hasPw); // otherwise say the existing one will be used
	$('#autostartNetHint').hidden = !network;
	// When the password field first appears (network chosen, no login yet), move focus to it so the user can type
	// straight away rather than hunting for the newly revealed input.
	if (wantPass && wasHidden) setTimeout(() => $('#autostartPass').focus(), 50);
}
function openAutostartDialog() {
	const local = document.querySelector('input[name="autostartScope"][value="local"]'); if (local) local.checked = true;
	$('#autostartPass').value = ''; $('#autostartPassMeter').hidden = true;
	syncAutostartScope();
	$('#autostartDialog').showModal();
	if (local) setTimeout(() => local.focus(), 50); // match the other dialogs, which focus a sensible control on open
}
document.querySelectorAll('input[name="autostartScope"]').forEach(r => r.addEventListener('change', syncAutostartScope));
if ($('#autostartToggle')) $('#autostartToggle').addEventListener('change', async (ev) => {
	const t = ev.target, turnOn = t.checked;
	if (turnOn) { t.checked = false; openAutostartDialog(); return; } // the dialog turns it on only if the install succeeds
	const ok = await uiConfirm({ title: 'Turn off start at login?', message: 'Stop starting at login and remove the launcher icon? Your vaults, keys, and settings are untouched.', confirmLabel: 'Turn off', danger: true });
	if (!ok) { t.checked = true; return; } // reverted — still installed
	try { await withBusy(() => api('/api/autostart-uninstall', {})); toast('Start-at-login is off.'); }
	catch (e) { t.checked = true; toast(e.message, true); }
});
onDialogSubmit('#autostartForm', async () => {
	const network = autostartScope() === 'network';
	const hasPw = !!(lastState && lastState.auth && lastState.auth.enabled);
	try {
		if (network && !hasPw) {
			const pw = $('#autostartPass').value;
			if (!pw || pw.length < 8) return toast('Enter a web login password of at least 8 characters', true);
			await withBusy(() => api('/api/web-password-set', { password: pw }));
		}
		await withBusy(() => api('/api/autostart-install', network ? { bind: '0.0.0.0' } : {}));
		$('#autostartDialog').close();
		const toggle = $('#autostartToggle'); if (toggle) toggle.checked = true;
		toast(network
			? 'Start-at-login is on. At your next login, ' + APP_NAME + ' opens on your network at a secure address — get a phone code from this computer to connect.'
			: 'Start-at-login is on — ' + APP_NAME + ' will open when you log in.');
		if (network) refresh(); // a login is now set; refresh so the sign-out control and mobile note reflect it
	} catch (e) { toast(e.message, true); }
});
attachStrength('autostartPass', 'autostartPassMeter');

// Vault-password fields are type="text" masked with CSS so the browser's password manager
// never engages (no save-password or generate-password prompts). If the engine can't mask
// text that way, fall the fields back to real password inputs so the value is never shown.
// Many mask fields are injected into dialogs AFTER load (team, member-owner, decoy passwords), so a one-time sweep
// at startup would miss them and show their text in the clear on such an engine. Convert every existing mask field
// now AND watch for any inserted later, so the fallback covers the whole class, not just the static markup.
if (!(window.CSS && CSS.supports && CSS.supports('-webkit-text-security', 'disc'))) {
	const unmask = (el) => { if (el && el.matches && el.matches('input.mask') && el.type !== 'password') el.type = 'password'; };
	const unmaskWithin = (root) => { unmask(root); if (root && root.querySelectorAll) root.querySelectorAll('input.mask').forEach(unmask); };
	unmaskWithin(document);
	try {
		new MutationObserver((records) => {
			for (const r of records) for (const n of r.addedNodes) if (n.nodeType === 1) unmaskWithin(n);
		}).observe(document.documentElement, { childList: true, subtree: true });
	} catch (_) {} // no MutationObserver (very old engine): the startup sweep above still covers the static fields
}

// Live password-strength meter. Uses the shared estimator (served as /js/strength.js from the same
// lib/ module the CLI uses), so the browser and command line score a password identically. Attaches
// to each field where the user CHOOSES a password (create, change, add key) — not to unlock fields.
function attachStrength(inputId, meterId) {
	const input = $('#' + inputId), meter = $('#' + meterId);
	if (!input || !meter || !window.VdiskStrength) return;
	const barWrap = meter.querySelector('.strength-bar'), bar = meter.querySelector('.strength-bar i'), text = meter.querySelector('.strength-text');
	// Announce the strength to assistive tech: the bar is a progressbar (0–4) and the text is a polite live region, so
	// its label ("Fair — add another word") is read as the user types. Each of these password inputs carries an
	// aria-labelledby pointing at its own visible label span, so this meter — a sibling inside the same <label> — never
	// becomes part of the field's accessible name (which would otherwise mutate on every keystroke).
	if (barWrap) { barWrap.setAttribute('role', 'progressbar'); barWrap.setAttribute('aria-valuemin', '0'); barWrap.setAttribute('aria-valuemax', '4'); barWrap.setAttribute('aria-label', 'Password strength'); }
	if (text) text.setAttribute('aria-live', 'polite');
	const update = () => {
		const v = input.value;
		if (!v) { meter.hidden = true; return; }
		const r = window.VdiskStrength.estimate(v);
		meter.hidden = false;
		meter.dataset.score = r.score;
		bar.style.width = ((r.score / 4) * 100) + '%';
		const label = r.label + (r.hint ? ' — ' + r.hint : '');
		text.textContent = label;
		if (barWrap) { barWrap.setAttribute('aria-valuenow', String(r.score)); barWrap.setAttribute('aria-valuetext', label); }
	};
	input.addEventListener('input', update);
}
attachStrength('createPass', 'createPassMeter');
attachStrength('passwdNew', 'passwdNewMeter');
attachStrength('confirmPw2', 'confirmPw2Meter'); // the shared confirm modal's "new password" field

initTheme();
// Give every modal dialog an accessible name from its own heading. A native <dialog> does not derive its name from
// a child heading, so without this a screen reader announces a nameless "dialog"; aria-labelledby fixes that. Done
// once here and applied uniformly, so every current dialog — and any added later — is named without per-dialog markup.
function nameDialogs() {
	document.querySelectorAll('dialog').forEach((d, i) => {
		if (d.getAttribute('aria-label') || d.getAttribute('aria-labelledby')) return; // respect an explicit name (e.g. the Help dialog)
		const h = d.querySelector('h1, h2, h3, h4, legend'); if (!h) return;
		if (!h.id) h.id = 'dlgTitle' + i;
		d.setAttribute('aria-labelledby', h.id);
	});
}
nameDialogs();
// Give every labelled field a clean accessible NAME and, where present, a separate DESCRIPTION. In this UI the visible
// label, the control, and any explanatory hint all live inside one <label class="field">, so by default a control's
// accessible name becomes the label's ENTIRE text (label plus the whole hint sentence). Point each control's name at
// just its label <span> (aria-labelledby) and its hint at aria-describedby, so the name stays the short label and the
// hint is announced as a description instead of being read as part of the name. One helper covers every field, like
// nameDialogs above, and it respects a name already set in the markup (the password fields set their own).
function describeFieldHints() {
	let n = 0;
	document.querySelectorAll('label.field').forEach((lab) => {
		const ctrl = lab.querySelector('input:not([type=checkbox]):not([type=radio]), select, textarea');
		if (!ctrl) return;
		const span = lab.querySelector(':scope > span');
		if (span && !ctrl.getAttribute('aria-label') && !ctrl.getAttribute('aria-labelledby')) {
			if (!span.id) span.id = 'fldLbl' + (n++);
			ctrl.setAttribute('aria-labelledby', span.id);
		}
		const hint = lab.querySelector(':scope > .hint, :scope > .checkhint');
		if (hint && !ctrl.getAttribute('aria-describedby')) {
			if (!hint.id) hint.id = 'fldHint' + (n++);
			ctrl.setAttribute('aria-describedby', hint.id);
		}
	});
}
describeFieldHints();
// Hide purely-decorative inline SVG icons from assistive tech. Every SVG in this UI sits inside a control or element
// that already carries its own text or aria-label, so the icon is decoration; marking any SVG not explicitly given a
// role/label as aria-hidden means a screen reader announces the control's name once, not an unnamed graphic beside it.
try { document.querySelectorAll('svg:not([aria-hidden]):not([aria-label]):not([role])').forEach((s) => s.setAttribute('aria-hidden', 'true')); } catch (_) {}
secKeyOK = webauthnSupported(); // WebAuthn on a localhost origin — enough for a roaming security key, no platform authenticator required
bioSupported().then(v => { bioOK = v; if (v) { try { refresh(); } catch (_) {} } }); // detect a platform authenticator (Touch ID / Hello) on a localhost origin, then re-render so a favorite's one-tap unlock button reads "Touch ID" rather than the generic label it briefly showed while this resolved
// If opened on 127.0.0.1 with a platform authenticator present, hint that localhost enables Touch ID.
(async () => {
	try {
		if (location.hostname !== BIO_RP_ID && window.PublicKeyCredential && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
			const url = 'http://localhost' + (location.port ? ':' + location.port : '');
			const h = $('#bioHint');
			h.textContent = '';
			h.append('Tip: open this app at ');
			const a = document.createElement('a'); a.href = url; a.textContent = url; h.append(a);
			h.append(' to unlock with Touch ID / Windows Hello.');
			h.hidden = false;
		}
	} catch (_) {}
})();
refresh();
// Poll only while the tab is actually visible — a backgrounded or minimized window does no server work for nobody,
// and every extra open tab would otherwise multiply the load. Refresh once immediately when the tab is shown again
// so it never displays stale state on return.
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

// ---- Tier 3: split across places, rebuild from shards, threshold key ----
// A reusable editable list of folder paths, rendered into a container with a Remove on each row.
function renderPathList(container, paths, onChange) {
	if (!paths.length) { container.innerHTML = '<p class="empty-note">No folders chosen yet.</p>'; return; }
	container.innerHTML = paths.map((p, i) => `<div class="dest-row"><code class="conn-val">${esc(p)}</code><button type="button" class="link-btn danger" data-rm="${i}">Remove</button></div>`).join('');
	container.querySelectorAll('[data-rm]').forEach(b => b.addEventListener('click', () => { paths.splice(Number(b.dataset.rm), 1); onChange(); }));
}
function stepProgress(barSel, fillSel, textSel) {
	return (p) => {
		const bar = $(barSel); if (!bar) return;
		// One seam for every progress bar, so ARIA is applied everywhere at once: mark it a live progressbar the first
		// time it is used, so a screen-reader user gets spoken feedback during long operations instead of silence.
		if (!bar.getAttribute('role')) { bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-live', 'polite'); bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', '100'); }
		if (!p) { bar.hidden = true; bar.classList.remove('indeterminate'); bar.removeAttribute('aria-busy'); bar.removeAttribute('aria-valuenow'); bar.removeAttribute('aria-valuetext'); return; }
		bar.hidden = false;
		if (p.indeterminate) { // a phase with no measurable percent (pack/unpack) — animate instead of showing a stuck number
			bar.classList.add('indeterminate'); bar.setAttribute('aria-busy', 'true'); bar.removeAttribute('aria-valuenow'); bar.setAttribute('aria-valuetext', (p.label || 'Working') + '…'); $(fillSel).style.width = ''; $(textSel).textContent = (p.label || 'Working') + '…';
		} else {
			const pct = p.percent || 0;
			bar.classList.remove('indeterminate'); bar.removeAttribute('aria-busy'); bar.setAttribute('aria-valuenow', String(pct)); bar.setAttribute('aria-valuetext', (p.label ? p.label + ' — ' : '') + pct + '%'); $(fillSel).style.width = pct + '%'; $(textSel).textContent = (p.label ? p.label + ' — ' : '') + pct + '%';
		}
	};
}

// -- Split (disperse) --
let disperseTarget = null, disperseDests = [];
const disperseProgress = stepProgress('#disperseProgress', '#disperseBarFill', '#disperseBarText');
function disperseGuidance() {
	const n = disperseDests.length, k = parseInt($('#disperseK').value, 10) || 0, g = $('#disperseGuidance');
	if (n < 2) { g.textContent = 'Add at least two folders (one shard goes in each).'; return; }
	if (!(k >= 1 && k <= n)) { g.textContent = 'The threshold must be between 1 and ' + n + '.'; return; }
	g.textContent = 'Any ' + k + ' of ' + n + ' rebuild the vault. Survives losing ' + (n - k) + ' folder' + ((n - k) === 1 ? '' : 's') + '. About ' + (Math.round(n / k * 100) / 100) + '× total storage.';
}
function renderDisperseDests() { renderPathList($('#disperseDests'), disperseDests, () => { renderDisperseDests(); disperseGuidance(); }); disperseGuidance(); }
function openDisperse(path, name) {
	disperseTarget = path; disperseDests = [];
	$('#disperseName').textContent = name; $('#disperseK').value = '2';
	renderDisperseDests();
	const r = $('#disperseResult'); r.hidden = true; r.innerHTML = ''; disperseProgress(null);
	$('#disperseDialog').showModal();
}
$('#disperseK').addEventListener('input', disperseGuidance);
$('#disperseAddDest').addEventListener('click', () => openBrowse({ title: 'Choose a destination folder', useLabel: 'Use this folder', onChoose: (p) => { if (!disperseDests.includes(p)) disperseDests.push(p); renderDisperseDests(); reopen('#disperseDialog'); } }));
async function runDisperse(force) {
	const n = disperseDests.length, k = parseInt($('#disperseK').value, 10);
	disperseProgress({ percent: 0, label: 'Starting' });
	showResult($('#disperseResult'), '', 'Splitting the vault. Keep ' + APP_NAME + ' running until this finishes.');
	const r = await withBusy(() => apiStream('/api/disperse', { path: disperseTarget, k, dests: disperseDests, force }, disperseProgress));
	disperseProgress(null);
	showResult($('#disperseResult'), 'ok', 'Split into ' + n + ' shards across your folders. Any ' + k + ' rebuild the vault — keep them in separate places. This is not a backup; keep one of those too.');
	return r;
}
$('#disperseGo').addEventListener('click', guarded(async (ev) => {
	const n = disperseDests.length, k = parseInt($('#disperseK').value, 10);
	if (n < 2) return showResult($('#disperseResult'), 'bad', 'Add at least two destination folders.');
	if (!(k >= 1 && k <= n)) return showResult($('#disperseResult'), 'bad', 'The threshold must be between 1 and ' + n + '.');
	try { await runDisperse(false); }
	catch (e) {
		disperseProgress(null);
		if (/already exists/i.test(e.message)) {
			const ok = await uiConfirm({ title: 'Overwrite shards?', message: 'Some destination folders already hold a shard for this vault. Overwrite them?', confirmLabel: 'Overwrite', danger: true });
			if (ok) { try { await runDisperse(true); } catch (e2) { disperseProgress(null); showResult($('#disperseResult'), 'bad', esc(e2.message)); } }
			return;
		}
		showResult($('#disperseResult'), 'bad', esc(e.message));
	}
}));

// -- Rebuild from shards --
let rebuildFolders = [];
const rebuildProgress = stepProgress('#rebuildProgress', '#rebuildBarFill', '#rebuildBarText');
function renderRebuildFolders() { renderPathList($('#rebuildFolders'), rebuildFolders, () => { renderRebuildFolders(); syncRebuildSchedule(); }); }
const sameFolders = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
// Reflect any existing repair schedule for the current folder set in the dropdown.
async function syncRebuildSchedule() {
	const sel = $('#rebuildSchedule'); if (!sel) return;
	sel.value = 'off';
	if (!rebuildFolders.length) return;
	try {
		const { schedules } = await api('/api/repair-schedules', {});
		const m = (schedules || []).find(s => sameFolders(s.folders || [], rebuildFolders));
		if (m && m.mode === 'interval') sel.value = 'interval:' + m.intervalHours;
	} catch (_) {}
}
function openRebuild() {
	rebuildFolders = []; $('#rebuildDest').value = '';
	renderRebuildFolders();
	['#rebuildStatus', '#rebuildResult'].forEach(s => { const el = $(s); el.hidden = true; el.innerHTML = ''; });
	$('#rebuildRepair').hidden = true; rebuildProgress(null); $('#rebuildSchedule').value = 'off';
	$('#rebuildDialog').showModal();
}
$('#rebuildOpen').addEventListener('click', openRebuild);
$('#rebuildAddFolder').addEventListener('click', () => openBrowse({ title: 'Choose a folder holding shards', useLabel: 'Use this folder', onChoose: (p) => { if (!rebuildFolders.includes(p)) rebuildFolders.push(p); renderRebuildFolders(); syncRebuildSchedule(); reopen('#rebuildDialog'); } }));
$('#rebuildSchedule').addEventListener('change', async () => {
	if (!rebuildFolders.length) { $('#rebuildSchedule').value = 'off'; return showResult($('#rebuildStatus'), 'bad', 'Add the shard folders first, then set a schedule.'); }
	const val = $('#rebuildSchedule').value;
	const body = val === 'off' ? { folders: rebuildFolders, mode: 'off' } : { folders: rebuildFolders, mode: 'interval', intervalHours: parseInt(val.split(':')[1], 10) };
	try { await withBusy(() => api('/api/repair-schedule', body)); showResult($('#rebuildStatus'), 'ok', val === 'off' ? 'Automatic checking turned off for these folders.' : 'These folders will be checked and repaired ' + $('#rebuildSchedule').selectedOptions[0].textContent.toLowerCase() + ', while the web interface is running.'); }
	catch (e) { showResult($('#rebuildStatus'), 'bad', esc(e.message)); }
});
$('#rebuildDestBrowse').addEventListener('click', () => openBrowse({ title: 'Choose where to rebuild', useLabel: 'Rebuild here', onChoose: (p) => { $('#rebuildDest').value = p; reopen('#rebuildDialog'); } }));
$('#rebuildCheck').addEventListener('click', async () => {
	if (!rebuildFolders.length) return showResult($('#rebuildStatus'), 'bad', 'Add at least one folder holding shards.');
	try {
		const s = await withBusy(() => api('/api/shards-inspect', { folders: rebuildFolders }));
		const msg = s.good + ' shard' + (s.good === 1 ? '' : 's') + ' found' + (s.k != null ? ' (need any ' + s.k + ' of ' + s.n + ')' : '') + '. ' + (s.recoverable ? 'Enough to rebuild.' : 'NOT enough — add more folders.');
		showResult($('#rebuildStatus'), s.recoverable ? 'ok' : 'bad', esc(msg));
		$('#rebuildRepair').hidden = !(s.recoverable && s.good < s.n);
	} catch (e) { showResult($('#rebuildStatus'), 'bad', esc(e.message)); }
});
$('#rebuildRepair').addEventListener('click', guarded(async () => {
	try {
		rebuildProgress({ percent: 0, label: 'Repairing' });
		const r = await withBusy(() => apiStream('/api/shards-repair', { folders: rebuildFolders }, rebuildProgress));
		rebuildProgress(null);
		showResult($('#rebuildStatus'), 'ok', 'Re-created ' + r.repaired + ' shard' + (r.repaired === 1 ? '' : 's') + '; the full set of ' + r.n + ' is restored.');
		$('#rebuildRepair').hidden = true;
	} catch (e) { rebuildProgress(null); showResult($('#rebuildStatus'), 'bad', esc(e.message)); }
})); // guarded: a shard repair rewrites files across the destination folders — never run two at once against the same set
$('#rebuildGo').addEventListener('click', guarded(async () => {
	if (!rebuildFolders.length) return showResult($('#rebuildResult'), 'bad', 'Add the folders holding the shards.');
	const dest = $('#rebuildDest').value.trim();
	try {
		rebuildProgress({ percent: 0, label: 'Starting' });
		showResult($('#rebuildResult'), '', 'Rebuilding the vault. Keep ' + APP_NAME + ' running until this finishes.');
		const r = await withBusy(() => apiStream('/api/reconstruct', { folders: rebuildFolders, destDir: dest || undefined }, rebuildProgress));
		rebuildProgress(null);
		showResult($('#rebuildResult'), 'ok', 'Rebuilt the vault at ' + esc(r.vault) + '. It has been added to your list — open it with your password.');
		refresh();
	} catch (e) { rebuildProgress(null); showResult($('#rebuildResult'), 'bad', esc(e.message)); }
})); // guarded: a reconstruction writes a whole rebuilt vault — never run two at once into the same destination

// -- Threshold key --
let thresholdTarget = null;
function openThreshold(path, name) {
	thresholdTarget = path;
	$('#thresholdName').textContent = name;
	$('#thresholdN').value = '3'; $('#thresholdK').value = '2'; $('#thresholdPass').value = '';
	$('#thresholdReadOnly').checked = false;
	const sh = $('#thresholdShares'); sh.hidden = true; sh.innerHTML = '';
	const r = $('#thresholdResult'); r.hidden = true; r.innerHTML = '';
	$('#thresholdDialog').showModal();
}
$('#keysAddThreshold').addEventListener('click', () => { const name = $('#keysName').textContent || 'Vault'; $('#keysDialog').close(); openThreshold(keysTarget, name); });
$('#thresholdGo').addEventListener('click', guarded(async () => {
	const n = parseInt($('#thresholdN').value, 10), k = parseInt($('#thresholdK').value, 10), password = $('#thresholdPass').value;
		const readOnly = !!$('#thresholdReadOnly').checked;
	if (!(k >= 2 && n >= k)) return showResult($('#thresholdResult'), 'bad', 'Choose 2 ≤ needed ≤ total shares.');
	if (!password) return showResult($('#thresholdResult'), 'bad', 'Enter the current password.');
	try {
		const r = await withBusy(() => api('/api/threshold-key', { path: thresholdTarget, password, n, k, readOnly }));
		const sh = $('#thresholdShares'); sh.hidden = false;
		sh.innerHTML = '<p class="hint">Save these now — they are shown once. Give one to each ' + (readOnly ? 'trusted contact' : 'holder') + '; any ' + k + ' together open the vault' + (readOnly ? ' to READ it (they can never change it or lock you out).' : '.') + '</p>' +
			r.shares.map((s, i) => `<div class="conn-row"><span class="conn-label">Share ${i + 1}</span><code class="conn-val" id="thrShare${i}">${esc(s)}</code><button type="button" class="copy-btn" data-copy="#thrShare${i}">Copy</button></div>`).join('');
		showResult($('#thresholdResult'), 'ok', (readOnly ? 'Emergency (read-only) access added.' : 'Threshold key added.') + ' To unlock, choose Mount and paste any ' + k + ' shares under “Unlock with threshold-key shares”.');
	} catch (e) { showResult($('#thresholdResult'), 'bad', esc(e.message)); }
})); // guarded: adding a threshold key rewrites the vault's key material — never run two at once
