'use strict';
// docker/entrypoint.js — the container's process 1. It does two things before handing control to the requested
// Vaultonaut command:
//
//   1. Self-attest. It runs `vaultonaut verify-self`, which checks the running code against the committed,
//      maintainer-signed release manifest (a classical Ed25519 signature and a post-quantum ML-DSA signature). If the
//      code has been altered, verification fails and the container REFUSES TO START. A running node therefore proves
//      its own integrity on every boot, on top of whatever signature the image itself carries.
//   2. Exec the command. It starts `vaultonaut <args>` (for example `relay ...` or `serve ...`) as a child, forwards
//      stop signals to it, and exits with the child's exit code — so the container stops cleanly and the backend gets
//      its normal drain-and-lock on shutdown.
//
// It is written in plain Node, with no shell and no third-party module, so it works on a minimal, shell-less base
// image as well as a full one. Set VAULTONAUT_SKIP_VERIFY=1 only for a throwaway admin one-off where self-attestation
// is not wanted; a serving or relay node should always leave it on.

const { spawnSync, spawn } = require('child_process');
const path = require('path');

// The real CLI by default; VAULTONAUT_CLI overrides it only so a test can point the entrypoint at a controllable
// stand-in child (to exercise signal forwarding and exit-code propagation). Production never sets it.
const CLI = process.env.VAULTONAUT_CLI || path.join(__dirname, '..', 'vaultonaut.js');
const args = process.argv.slice(2);

if (process.env.VAULTONAUT_SKIP_VERIFY !== '1') {
	const v = spawnSync(process.execPath, [CLI, 'verify-self'], { stdio: 'inherit' });
	if (v.status !== 0) {
		console.error('[entrypoint] Refusing to start: the signed bundle did not verify (status ' + (v.status == null ? 'unknown' : v.status) + ').');
		process.exit(v.status || 1);
	}
}

// Hand off to the real CLI. inherit stdio so logs stream straight to `docker logs`, and pipe our own stdin through so
// the backend still sees the parent-death / "quit" channel it uses to drain and lock on shutdown.
const child = spawn(process.execPath, [CLI, ...args], { stdio: 'inherit' });
for (const sig of ['SIGTERM', 'SIGINT']) {
	process.on(sig, () => { try { child.kill(sig); } catch (_) {} });
}
child.on('exit', (code, signal) => {
	if (signal) { try { process.kill(process.pid, signal); } catch (_) { process.exit(1); } }
	else process.exit(code == null ? 1 : code);
});
child.on('error', (err) => { console.error('[entrypoint] Could not start Vaultonaut: ' + (err && err.message)); process.exit(1); });
