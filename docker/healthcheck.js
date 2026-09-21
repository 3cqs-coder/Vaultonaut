'use strict';
// docker/healthcheck.js — a tiny, dependency-free liveness probe for the container HEALTHCHECK. It opens a TCP
// connection to the port the node listens on and reports healthy only if the connection succeeds, so an orchestrator
// (Compose, Kubernetes, a restart policy) restarts a node whose listener has died. Written in plain Node so it needs
// no `curl`/`nc` and works on a shell-less base image.
//
// The port comes from HEALTHCHECK_PORT (set per role in the compose file — a relay's control port, or a serving
// node's serve port). It never sends the vault password or any secret; it only checks that something is accepting
// connections.

const net = require('net');

const raw = process.env.HEALTHCHECK_PORT;
// No port configured means this container role has nothing to probe — for example a relay-joined node that only makes
// outbound connections, or a direct `docker run` of an image where the operator did not set HEALTHCHECK_PORT. Report
// HEALTHY rather than failing, so such a container is not marked unhealthy and restart-looped by a health-aware
// orchestrator. A port that IS set but invalid is a real misconfiguration and stays a failure.
if (raw == null || String(raw).trim() === '') {
	console.log('[healthcheck] no HEALTHCHECK_PORT set — nothing to probe for this role; reporting healthy.');
	process.exit(0);
}
const port = parseInt(raw, 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
	console.error('[healthcheck] HEALTHCHECK_PORT="' + raw + '" is not a valid port; cannot probe.');
	process.exit(1);
}
const host = process.env.HEALTHCHECK_HOST || '127.0.0.1';

const sock = net.connect({ host, port });
const timer = setTimeout(() => { sock.destroy(); process.exit(1); }, 3000);
if (timer.unref) timer.unref();
sock.on('connect', () => { clearTimeout(timer); sock.end(); process.exit(0); });
sock.on('error', () => { clearTimeout(timer); process.exit(1); });
