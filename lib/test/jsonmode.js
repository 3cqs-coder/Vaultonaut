'use strict';
// lib/test/jsonmode.js — the global --json flag makes the CLI print exactly ONE JSON object on stdout: a { ok, data }
// envelope on success or { ok:false, error:{code,message} } on failure, with the exit code preserved and human text
// kept off stdout. Verified by running the real CLI in a subprocess (so the whole vaultonaut.js -> Commands path is
// exercised) plus a unit check of the stable error-code mapping. No engine, mount driver, or network needed.
//
// Run:  node lib/test/jsonmode.js

const { execFileSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const Commands = require('../Commands');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Run the real CLI with --json against an isolated data dir; return the parsed stdout JSON and the exit code. stderr
// (the human lines) is ignored — stdout must be JSON alone.
const CLI = path.join(__dirname, '..', '..', 'vaultonaut.js');
function runJson(args) {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vd-json-'));
	let stdout = '', code = 0;
	try { stdout = execFileSync(process.execPath, [CLI, '--data-dir', tmp, '--json', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); }
	catch (e) { stdout = String(e.stdout || ''); code = e.status == null ? 1 : e.status; }
	finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} }
	let json = null; try { json = JSON.parse(stdout.trim()); } catch (_) {}
	return { json, code, stdout };
}

function main() {
	// --- stable error-code mapping (unit) ---
	ok('an explicit e.code is preserved', Commands.jsonErrorCode({ code: 'MIRROR_IN_USE' }) === 'MIRROR_IN_USE');
	ok('a missing-vault message maps to NOT_A_VAULT', Commands.jsonErrorCode(new Error('No vault found at /x')) === 'NOT_A_VAULT');
	ok('a wrong-password message maps to WRONG_PASSWORD', Commands.jsonErrorCode(new Error('The password is incorrect.')) === 'WRONG_PASSWORD');
	ok('an unclassified error maps to ERROR', Commands.jsonErrorCode(new Error('something odd happened')) === 'ERROR');

	// --- failure envelope: exactly one JSON object, ok:false with a code, non-zero exit ---
	const err = runJson(['keys', '/no/such/vault-xyz']);
	ok('a failing command prints valid JSON on stdout', err.json !== null);
	ok('the failure envelope is ok:false with an error code', err.json && err.json.ok === false && err.json.error && err.json.error.code === 'NOT_A_VAULT');
	ok('a failing command exits non-zero', err.code !== 0);

	// --- success envelope: ok:true with structured data, zero exit ---
	const st = runJson(['status']);
	ok('a read command prints a valid JSON envelope', st.json !== null && st.json.ok === true);
	ok('status attaches structured data (a mounts array)', st.json && st.json.data && Array.isArray(st.json.data.mounts));
	ok('a successful command exits zero', st.code === 0);

	// --- doctor fills in platform data (engine/driver may be absent in CI; the envelope is still ok:true) ---
	const dr = runJson(['doctor']);
	ok('doctor returns ok:true with a platform field', dr.json && dr.json.ok === true && dr.json.data && typeof dr.json.data.platform === 'string');

	if (failures) { console.log('\n' + failures + ' CHECK(S) FAILED'); process.exit(1); }
	console.log('\nALL JSON-MODE CHECKS PASSED');
}
main();
