'use strict';
// login.js — the passwordless sign-in on the login page (Touch ID / Windows Hello / a security key). It reuses
// the same WebAuthn PRF the vault unlock uses: the authenticator releases a stable secret after its user check,
// and that secret is posted to /login where the server verifies it against the enrolled credentials' hashes.
// Loaded as an external file because the page's Content-Security-Policy forbids inline scripts. The relying-party
// id is the current hostname, so it works both on localhost and on a network-exposed HTTPS origin.
(function () {
	var el = document.getElementById('wa-descriptors');
	var chalEl = document.getElementById('wa-challenge');
	var btn = document.getElementById('waBtn');
	if (!btn || !el) return;
	var descriptors = [];
	try { descriptors = JSON.parse(el.textContent || '[]'); } catch (_) {}
	var challenge = chalEl ? (chalEl.textContent || '').trim() : '';
	if (!window.PublicKeyCredential || !window.WebAuthnUtil || !descriptors.length || !challenge) { btn.hidden = true; return; }
	btn.addEventListener('click', function () {
		btn.disabled = true; btn.textContent = 'Waiting for your device…';
		// One ceremony signs the server's single-use challenge. For a modern credential the signature IS the proof; for
		// a legacy credential the authenticator also releases its PRF secret, carried along so it still works. The
		// relying-party id is the current hostname (works on localhost and over HTTPS alike).
		WebAuthnUtil.getLoginAssertion(location.hostname, descriptors, challenge).then(function (r) {
			var set = function (id, v) { var e = document.getElementById(id); if (e) e.value = v || ''; };
			set('waId', r.id);
			set('waAuthData', r.authenticatorData);
			set('waClientData', r.clientDataJSON);
			set('waSignature', r.signature);
			set('waSecret', r.prfSecret); // present only for a legacy (PRF) credential
			document.getElementById('waForm').submit();
		}).catch(function () { btn.disabled = false; btn.textContent = 'Try your device again'; });
	});
})();
