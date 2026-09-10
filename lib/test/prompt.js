'use strict';
// lib/test/prompt.js — the interactive password/confirmation prompts (lib/prompt.js) must FAIL FAST when standard
// input is closed (piped from an empty source, redirected from /dev/null, or otherwise not a terminal) instead of
// hanging forever waiting for input that can never arrive. A hang would wedge any scripted, cron, CI, or
// backgrounded run. Each case runs in a child process whose stdin is an empty, immediately-ended pipe; a timeout
// guards the "must not hang" property — if the child is still alive when the timeout fires, the test fails.
//
// Run:  node lib/test/prompt.js

const path = require('path');
const { spawnSync } = require('child_process');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const promptPath = path.resolve(__dirname, '..', 'prompt.js');

// Run one prompt function against a CLOSED stdin (input: '') in a child, with a hard timeout. The child exits 0
// only if the call REJECTED with the NO_INPUT error; 2 if it wrongly resolved; 3 if it rejected with a different
// error. A timeout leaves signal set (SIGTERM), which is the "it hung" failure we are guarding against.
function runClosedStdin(call) {
	const code = 'const p=require(' + JSON.stringify(promptPath) + ');'
		+ 'p.' + call + '.then(()=>process.exit(2),(e)=>process.exit(e&&e.message===p.NO_INPUT?0:3));';
	return spawnSync(process.execPath, ['-e', code], { input: '', timeout: 8000, encoding: 'utf8' });
}

function main() {
	console.log('[hidden() on closed stdin]');
	const h = runClosedStdin("hidden('Password: ')");
	ok('hidden() does not hang on EOF (the child exited, was not timed out)', h.signal == null);
	ok('hidden() rejects with the clear no-input error, not a wrong resolve or a different error', h.status === 0);

	console.log('[line() on closed stdin]');
	const l = runClosedStdin("line('Continue? ')");
	ok('line() does not hang on EOF (the child exited, was not timed out)', l.signal == null);
	ok('line() rejects with the clear no-input error', l.status === 0);

	console.log('[newPassword() on closed stdin]');
	// newPassword() calls hidden() twice; the FIRST read hits EOF, so it must reject fast, never hang.
	const n = runClosedStdin("newPassword('Password')");
	ok('newPassword() does not hang on EOF', n.signal == null);
	ok('newPassword() rejects (propagates the no-input error from its first hidden() read)', n.status === 0);

	console.log('[the error message is present and exported]');
	const prompt = require('../prompt');
	ok('NO_INPUT is exported and mentions standard input', typeof prompt.NO_INPUT === 'string' && /standard input/i.test(prompt.NO_INPUT));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL PROMPT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
