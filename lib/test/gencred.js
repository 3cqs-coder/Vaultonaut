'use strict';
// lib/test/gencred.js — the served node's endpoint credential (Serve.genCred) must always return EXACTLY the
// requested number of alphanumeric characters. An earlier strip-after-slice form could occasionally return a
// short 22-23 character credential, a silent entropy reduction on the network endpoint's password. This pins the
// length and charset so that cannot regress. Pure — no engine, no network.
//
// Run:  node lib/test/gencred.js

const Serve = require('../Serve');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const alnum = /^[A-Za-z0-9]+$/;
	let allDefaultLen = true, allAlnum = true, allCustomLen = true;
	for (let i = 0; i < 2000; i++) {
		const d = Serve.genCred();
		if (d.length !== 24) allDefaultLen = false;
		if (!alnum.test(d)) allAlnum = false;
		const c = Serve.genCred(40);
		if (c.length !== 40) allCustomLen = false;
	}
	ok('genCred() is always exactly 24 characters', allDefaultLen);
	ok('genCred() is always alphanumeric (no URL-safe punctuation slipped in)', allAlnum);
	ok('genCred(40) is always exactly 40 characters', allCustomLen);
	ok('two credentials are distinct (random, not constant)', Serve.genCred() !== Serve.genCred());

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL GENCRED CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
