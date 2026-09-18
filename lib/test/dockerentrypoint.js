'use strict';
// lib/test/dockerentrypoint.js — BEHAVIORAL tests for the Docker container's process-1 entrypoint and its health
// probe (docker/entrypoint.js, docker/healthcheck.js). dockerdrift.js pins these statically (verify-self present,
// hardening present); this file actually RUNS them: the health probe reports healthy only when the port accepts
// connections; the entrypoint refuses to start when the self-check fails, propagates the child's exit code, and
// forwards a stop signal so the backend can drain. Skips gracefully when docker/ is absent.
//
// Run:  node -r ./lib/test/_setup.js lib/test/dockerentrypoint.js

const path = require('path');
const net = require('net');
const os = require('os');
const fs = require('fs');
const { spawn } = require('child_process');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const DOCKER = path.join(__dirname, '..', '..', 'docker');
const ENTRY = path.join(DOCKER, 'entrypoint.js');
const HEALTH = path.join(DOCKER, 'healthcheck.js');
const FIXTURE = path.join(__dirname, '_dockercli_fixture.js');
const NODE = process.execPath;

function runHealth(env) {
	return new Promise((res) => {
		const c = spawn(NODE, [HEALTH], { env: { ...process.env, ...env }, stdio: 'ignore' });
		c.on('exit', (code) => res(code));
		c.on('error', () => res(-1));
	});
}
// Spawn the entrypoint; resolve { code, signal } on exit. onReady(child) fires once the stand-in child prints READY.
function runEntry(args, env, onReady) {
	return new Promise((res) => {
		const c = spawn(NODE, [ENTRY, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'ignore'] });
		let buf = '';
		c.stdout.on('data', (d) => { buf += d; if (buf.includes('READY') && onReady) { const f = onReady; onReady = null; f(c); } });
		c.on('exit', (code, signal) => res({ code, signal }));
		c.on('error', () => res({ code: -1, signal: null }));
	});
}

async function main() {
	if (!fs.existsSync(ENTRY)) { console.log('  skip  (no docker/ deployment in this checkout)'); console.log('\nALL DOCKER-ENTRYPOINT CHECKS PASSED'); return process.exit(0); }

	// ── Health probe ──
	ok('healthcheck exits non-zero when HEALTHCHECK_PORT is unset', (await runHealth({ HEALTHCHECK_PORT: '' })) === 1);
	ok('healthcheck exits non-zero on an out-of-range port', (await runHealth({ HEALTHCHECK_PORT: '999999' })) === 1);
	const srv = net.createServer();
	await new Promise((r) => srv.listen(0, '127.0.0.1', r));
	const livePort = srv.address().port;
	ok('healthcheck exits 0 against a listening port', (await runHealth({ HEALTHCHECK_PORT: String(livePort) })) === 0);
	await new Promise((r) => srv.close(r));
	const freedPort = await new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
	ok('healthcheck exits non-zero against a closed port', (await runHealth({ HEALTHCHECK_PORT: String(freedPort) })) === 1);

	// ── Entrypoint self-attest gate: a failed verify-self must refuse to start ──
	{
		const r = await runEntry(['serve'], { VAULTONAUT_CLI: FIXTURE, VERIFY_EXIT: '1' });
		ok('entrypoint refuses to start when verify-self fails (self-attest gate)', r.code !== 0);
	}
	// ── Entrypoint exit-code propagation: the child's code becomes the entrypoint's code ──
	{
		const r = await runEntry(['serve'], { VAULTONAUT_SKIP_VERIFY: '1', VAULTONAUT_CLI: FIXTURE, EXIT_CODE: '7' });
		ok('entrypoint propagates the child exit code', r.code === 7);
	}
	// ── Entrypoint signal forwarding: SIGTERM must reach the child so the backend can drain. POSIX only — Windows has
	//    no real SIGTERM-to-child semantics, and the container runs on Linux regardless. ──
	if (process.platform !== 'win32') {
		const marker = path.join(os.tmpdir(), 'vn-entry-sig-' + process.pid + '-' + Date.now());
		try { fs.unlinkSync(marker); } catch (_) {}
		const r = await runEntry(['serve'], { VAULTONAUT_SKIP_VERIFY: '1', VAULTONAUT_CLI: FIXTURE, SIGNAL_MARKER: marker }, (child) => {
			setTimeout(() => { try { child.kill('SIGTERM'); } catch (_) {} }, 60);
		});
		let got = ''; try { got = fs.readFileSync(marker, 'utf8'); } catch (_) {}
		try { fs.unlinkSync(marker); } catch (_) {}
		ok('entrypoint forwards SIGTERM to the child (so the backend can drain)', got === 'SIGTERM' && (r.code === 0 || r.signal === 'SIGTERM'));
	} else {
		ok('entrypoint signal-forwarding test skipped on Windows (POSIX signal semantics)', true);
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DOCKER-ENTRYPOINT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}
main();
