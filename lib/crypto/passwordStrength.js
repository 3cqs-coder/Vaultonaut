// lib/passwordStrength.js — a small, dependency-free password-strength estimator, shared by the
// command line (required as a CommonJS module) and the browser UI (served verbatim as /js/strength.js
// and used as a global), so both surfaces score a password identically with ONE implementation.
//
// This is a guidance heuristic, not a security boundary: it nudges the user toward a stronger
// passphrase at the moment they choose one. The real protection is Argon2id key-wrapping; a weak
// password is unrecoverable by design, which is exactly why the meter exists.
//
// estimate(password) -> { score: 0..4, label, hint } where label is
//   'very weak' | 'weak' | 'fair' | 'good' | 'strong'. `hint` is a short, actionable suggestion, or
//   '' when the password is already strong.
(function (root, factory) {
	const api = factory();
	if (typeof module !== 'undefined' && module.exports) module.exports = api; // Node / CommonJS
	else root.VdiskStrength = api;                                             // browser global
})(typeof self !== 'undefined' ? self : this, function () {
	// A tiny set of the most-abused passwords/patterns. Kept intentionally small (this is a nudge,
	// not a cracking dictionary); the length + variety scoring does the heavy lifting.
	const COMMON = new Set([
		'password', 'passw0rd', 'letmein', 'welcome', 'admin', 'iloveyou', 'qwerty', 'qwertyuiop',
		'123456', '12345678', '123456789', '1234567890', '111111', '000000', 'abc123', 'monkey',
		'dragon', 'football', 'baseball', 'sunshine', 'princess', 'superman', 'trustno1', 'master',
		'hello', 'freedom', 'whatever', 'ninja', 'changeme', 'secret', 'root', 'toor'
	]);

	// Does the string run through a keyboard/alphabet/number sequence of length >= 4 (either way)?
	function hasRun(s) {
		const t = s.toLowerCase();
		let up = 1, down = 1;
		for (let i = 1; i < t.length; i++) {
			const d = t.charCodeAt(i) - t.charCodeAt(i - 1);
			up = d === 1 ? up + 1 : 1;
			down = d === -1 ? down + 1 : 1;
			if (up >= 4 || down >= 4) return true;
		}
		return false;
	}

	function estimate(password) {
		const pw = String(password == null ? '' : password);
		if (!pw) return { score: 0, label: 'very weak', hint: 'Enter a password.' };

		const lower = /[a-z]/.test(pw), upper = /[A-Z]/.test(pw), digit = /[0-9]/.test(pw);
		const symbol = /[^A-Za-z0-9]/.test(pw);
		const classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
		const unique = new Set(pw).size;

		// Base points from length — length dominates real-world strength.
		let score = 0;
		if (pw.length >= 8) score += 1;
		if (pw.length >= 12) score += 1;
		if (pw.length >= 16) score += 1;
		if (pw.length >= 20) score += 1;
		if (classes >= 3) score += 1;      // good character variety
		if (classes >= 2 && pw.length >= 10) score += 1;

		// Penalties for the patterns that make a long password weak anyway.
		const looksCommon = COMMON.has(pw.toLowerCase());
		if (looksCommon) score = 0;
		if (unique <= 2) score = Math.min(score, 1);           // "aaaaaaaa", "ababab"
		if (hasRun(pw)) score -= 1;                            // "abcdef", "123456", "qwerty"
		if (pw.length < 8) score = Math.min(score, 1);         // short is always weak

		score = Math.max(0, Math.min(4, score));

		const labels = ['very weak', 'weak', 'fair', 'good', 'strong'];
		let hint = '';
		if (score >= 4) hint = '';
		else if (looksCommon) hint = 'This is a commonly used password — choose something unique.';
		else if (pw.length < 12) hint = 'Use a longer password — several unrelated words are strong and easy to remember.';
		else if (classes < 3) hint = 'Mix in upper and lower case, a number, or a symbol.';
		else hint = 'A bit longer would be stronger.';

		return { score, label: labels[score], hint };
	}

	return { estimate };
});
