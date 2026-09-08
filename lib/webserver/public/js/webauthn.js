'use strict';
// webauthn.js — shared WebAuthn PRF helpers used by BOTH the login page (login.js) and the app (app.js), so the
// base64url codec and the assertion-and-extract ceremony live in ONE place. Credential-handling code must not
// drift between two copies. Loaded as a classic script (the pages' Content-Security-Policy forbids inline code and
// bare modules), before the page script that uses it, and exposed on window.WebAuthnUtil.
(function (global) {
	// URL-safe base64 without padding — the wire form for credential ids, PRF salts, and derived secrets.
	function b64uEncode(buf) {
		var s = '', b = new Uint8Array(buf);
		for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
		return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}
	function b64uDecode(str) {
		str = String(str).replace(/-/g, '+').replace(/_/g, '/');
		while (str.length % 4) str += '=';
		var a = atob(str), b = new Uint8Array(a.length);
		for (var i = 0; i < a.length; i++) b[i] = a.charCodeAt(i);
		return b;
	}
	// Run a WebAuthn PRF assertion and return the derived secret (base64url), or throw. `rpId` is the relying-party
	// id (the page's hostname). `credentials` is [{ id, prfSalt }] with base64url values. The authenticator releases
	// the secret only after its own user check (fingerprint, face, PIN, or a key tap), so the secret never leaves it
	// unprompted; it becomes a vault key slot on the app side and a sign-in proof on the login side.
	async function derivePrfSecret(rpId, credentials) {
		var evalByCredential = {};
		credentials.forEach(function (c) { evalByCredential[c.id] = { first: b64uDecode(c.prfSalt) }; });
		var assertion = await navigator.credentials.get({ publicKey: {
			rpId: rpId,
			challenge: crypto.getRandomValues(new Uint8Array(32)),
			timeout: 60000,
			userVerification: 'required',
			allowCredentials: credentials.map(function (c) { return { type: 'public-key', id: b64uDecode(c.id) }; }),
			extensions: { prf: { evalByCredential: evalByCredential } }
		} });
		var prf = assertion.getClientExtensionResults().prf;
		var first = prf && prf.results && prf.results.first;
		if (!first) throw new Error('This device did not return a biometric key — its authenticator does not support the required extension.');
		return b64uEncode(first);
	}
	global.WebAuthnUtil = { b64uEncode: b64uEncode, b64uDecode: b64uDecode, derivePrfSecret: derivePrfSecret };
})(window);
