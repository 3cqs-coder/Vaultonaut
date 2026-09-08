'use strict';
// login.js — the passwordless sign-in on the login page (Touch ID / Windows Hello / a security key). It reuses
// the same WebAuthn PRF the vault unlock uses: the authenticator releases a stable secret after its user check,
// and that secret is posted to /login where the server verifies it against the enrolled credentials' hashes.
// Loaded as an external file because the page's Content-Security-Policy forbids inline scripts. The relying-party
// id is the current hostname, so it works both on localhost and on a network-exposed HTTPS origin.
(function () {
	var el = document.getElementById('wa-descriptors');
	var btn = document.getElementById('waBtn');
	if (!btn || !el) return;
	var descriptors = [];
	try { descriptors = JSON.parse(el.textContent || '[]'); } catch (_) {}
	if (!window.PublicKeyCredential || !window.WebAuthnUtil || !descriptors.length) { btn.hidden = true; return; }
	btn.addEventListener('click', function () {
		btn.disabled = true; btn.textContent = 'Waiting for your device…';
		// The descriptors here carry the credential id in `id`; the shared helper expects { id, prfSalt }, so they
		// pass straight through. The relying-party id is the current hostname (works on localhost and HTTPS alike).
		WebAuthnUtil.derivePrfSecret(location.hostname, descriptors).then(function (secret) {
			document.getElementById('waSecret').value = secret;
			document.getElementById('waForm').submit();
		}).catch(function () { btn.disabled = false; btn.textContent = 'Try your device again'; });
	});
})();
