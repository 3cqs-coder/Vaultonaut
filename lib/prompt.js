'use strict';
// lib/prompt.js — read a password from the terminal without echoing it. The
// password is never taken from a command-line argument or an environment variable
// (both are visible to other processes and leak into logs and shell history); it
// is typed at an interactive prompt and returned as a string held only in memory.

const readline = require('readline');
const Strength = require('./passwordStrength');

// Prompt without echo. Returns the entered string (without the trailing newline).
function hidden(question) {
	return new Promise((resolve) => {
		const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
		let captured = '';
		// Mute the output stream so keystrokes are not shown while typing.
		const origWrite = rl.output.write.bind(rl.output);
		rl._writeToOutput = (str) => {
			// Show the question text once, then suppress everything else.
			if (str && str.includes(question)) origWrite(str);
			else if (str === '\n' || str === '\r\n') origWrite(str);
		};
		rl.question(question, (answer) => {
			captured = answer;
			rl.close();
			process.stdout.write('\n');
			resolve(captured);
		});
	});
}

// Prompt for a new password twice and require the two entries to match.
async function newPassword(label = 'Password') {
	const a = await hidden(label + ': ');
	if (!a) throw new Error('Password cannot be empty.');
	// Guidance only (never blocks): a weak password is unrecoverable by design, so nudge the user
	// toward a stronger one before they confirm it.
	const s = Strength.estimate(a);
	process.stdout.write('Strength: ' + s.label + (s.hint ? ' — ' + s.hint : '') + '\n');
	const b = await hidden('Confirm ' + label.toLowerCase() + ': ');
	if (a !== b) throw new Error('Passwords did not match.');
	return a;
}

// A plain, echoing line prompt — for confirmations (never for secrets; use hidden() for those).
function line(question) {
	return new Promise((resolve) => {
		const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
		rl.question(question, (answer) => { rl.close(); resolve((answer || '').trim()); });
	});
}

module.exports = { hidden, newPassword, line };
