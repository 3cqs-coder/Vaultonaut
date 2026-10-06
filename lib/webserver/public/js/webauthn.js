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
	// Run a WebAuthn PRF assertion and return { secret, id } (both base64url), or throw. `rpId` is the relying-party
	// id (the page's hostname). `credentials` is [{ id, prfSalt }] with base64url values. The authenticator releases
	// the secret only after its own user check (fingerprint, face, PIN, or a key tap), so the secret never leaves it
	// unprompted; it becomes a vault key slot on the app side and a sign-in proof on the login side. `id` is the
	// credential the authenticator actually used — not a secret (the login page already lists the enrolled ids) — so
	// the server can verify the one matching credential instead of trying every enrolled hash.
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
		return { secret: b64uEncode(first), id: b64uEncode(assertion.rawId) };
	}
	// Run a WebAuthn sign-in assertion over a SERVER-ISSUED challenge and return what the server needs to verify it:
	// the credential id, the raw authenticatorData, clientDataJSON, and signature (all base64url), plus — only when a
	// legacy PRF credential was used — the derived PRF secret, so a key enrolled before the assertion format still
	// works through the same single ceremony. `credentials` is [{ id, prfSalt? }]; a prfSalt marks a legacy credential
	// and asks the authenticator to also release its PRF value. `challenge` is the server's base64url challenge.
	async function getLoginAssertion(rpId, credentials, challenge) {
		var evalByCredential = {};
		credentials.forEach(function (c) { if (c.prfSalt) evalByCredential[c.id] = { first: b64uDecode(c.prfSalt) }; });
		var pub = {
			rpId: rpId,
			challenge: b64uDecode(challenge),
			timeout: 60000,
			userVerification: 'required',
			allowCredentials: credentials.map(function (c) { return { type: 'public-key', id: b64uDecode(c.id) }; })
		};
		if (Object.keys(evalByCredential).length) pub.extensions = { prf: { evalByCredential: evalByCredential } };
		var assertion = await navigator.credentials.get({ publicKey: pub });
		var r = assertion.response;
		var prf = assertion.getClientExtensionResults().prf;
		var first = prf && prf.results && prf.results.first;
		return {
			id: b64uEncode(assertion.rawId),
			authenticatorData: b64uEncode(r.authenticatorData),
			clientDataJSON: b64uEncode(r.clientDataJSON),
			signature: b64uEncode(r.signature),
			prfSecret: first ? b64uEncode(first) : null
		};
	}
	global.WebAuthnUtil = { b64uEncode: b64uEncode, b64uDecode: b64uDecode, derivePrfSecret: derivePrfSecret, getLoginAssertion: getLoginAssertion };
})(window);
