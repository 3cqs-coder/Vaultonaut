'use strict';
// lib/test/passwordstrength.js — the shared password-strength estimator (lib/passwordStrength.js) is a guidance
// heuristic used by the CLI, the prompt, and the web UI to nudge a user toward a stronger passphrase. It is the one
// scorer both surfaces run, so a regression that let a weak password read as strong (or rejected everything) would
// mislead the user at the exact moment they choose the password that protects the vault. It had no direct test; this
// pins the security-relevant bands. Pure and offline.
//
// Run:  node lib/test/passwordstrength.js

const S = require('../passwordStrength');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const LABELS = ['very weak', 'weak', 'fair', 'good', 'strong'];

// Shape: score is always an integer 0..4 and label is the matching band, for a spread of inputs.
for (const pw of ['', 'a', 'password', 'abcdefgh', 'Tr0ub4dour', 'correct-Horse-Battery-Staple-9!']) {
	const r = S.estimate(pw);
	const shaped = Number.isInteger(r.score) && r.score >= 0 && r.score <= 4 && r.label === LABELS[r.score] && typeof r.hint === 'string';
	ok('estimate(' + JSON.stringify(pw) + ') has a valid shape (score 0..4 + matching label)', shaped);
}

// Empty → the weakest band with a prompt to enter one.
{ const r = S.estimate(''); ok('an empty password is very weak', r.score === 0 && r.label === 'very weak'); }

// A commonly abused password scores 0 no matter its length/variety, and is flagged as common.
for (const pw of ['password', 'qwerty', 'iloveyou', 'trustno1']) {
	const r = S.estimate(pw);
	ok('the common password ' + JSON.stringify(pw) + ' scores 0', r.score === 0);
}
ok('a common password gets the "commonly used" hint', /commonly used/i.test(S.estimate('password').hint));

// Low-entropy repeats clamp to at most "weak", even when long enough to earn length points.
ok('a single repeated character clamps to <= 1 ("aaaaaaaa")', S.estimate('aaaaaaaa').score <= 1);
ok('a two-character repeat clamps to <= 1 ("abababab")', S.estimate('abababab').score <= 1);

// Anything shorter than 8 characters is always weak, whatever its variety.
ok('a short mixed password is still weak ("Aa1$")', S.estimate('Aa1$').score <= 1);

// A long, varied passphrase with no straight run reaches the top band and offers no nag.
{
	const r = S.estimate('correct-Horse-Battery-Staple-9!');
	ok('a long varied passphrase is strong with no hint', r.score === 4 && r.label === 'strong' && r.hint === '');
}

// A straight keyboard/alphabet run is penalized rather than rewarded for its length.
ok('a straight alphabet run is not strong ("abcdefghijklmnop")', S.estimate('abcdefghijklmnop').score < 4);

// Non-string input never throws and is treated as empty.
ok('a null/undefined password does not throw and reads very weak', S.estimate(null).score === 0 && S.estimate(undefined).score === 0);

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PASSWORD-STRENGTH CHECKS PASSED'));
process.exit(failures ? 1 : 0);
