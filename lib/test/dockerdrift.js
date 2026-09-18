'use strict';
// lib/test/dockerdrift.js — a DRIFT GUARD over the Docker headless deployment under docker/. Like desktoplayout.js
// for the desktop shell, it pins the cross-file contracts that would otherwise only break at `docker build` / run
// time — a class of failure the rest of the unit suite never reaches. It asserts:
//   1. the runtime pins the same Node the project ships and the self-check needs;
//   2. the Dockerfile copies the COMPLETE signed set (a missing signed file makes the container refuse to start);
//   3. the compose relay ports match the app's own defaults;
//   4. the entrypoint self-attests (runs verify-self) before handing off;
//   5. every compose service keeps its hardening.
// Skips gracefully when docker/ is absent.
//
// Run:  node -r ./lib/test/_setup.js lib/test/dockerdrift.js

const fs = require('fs');
const path = require('path');
const Common = require('../Common');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
function done() { console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DOCKER-DRIFT CHECKS PASSED')); process.exit(failures ? 1 : 0); }
const REPO = path.join(__dirname, '..', '..');
const D = path.join(REPO, 'docker');
function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return ''; } }

function main() {
	if (!fs.existsSync(path.join(D, 'Dockerfile'))) { console.log('  skip  (no docker/ deployment in this checkout)'); return done(); }
	const dockerfile = read(path.join(D, 'Dockerfile'));
	const compose = read(path.join(D, 'docker-compose.yml'));
	const entry = read(path.join(D, 'entrypoint.js'));

	// 1. The image must pin the SAME Node the desktop bundle and CI pin (PINNED_NODE, which is >= 24.7 — the floor the
	//    post-quantum self-check needs). Pull that version from the packaging script and assert every `FROM node:<ver>`
	//    stage uses exactly it, so the container can never drift onto a Node that cannot verify the signed bundle.
	const pinned = (read(path.join(REPO, 'src-tauri', 'prepare-sidecar.js')).match(/PINNED_NODE\s*=\s*'([\d.]+)'/) || [])[1];
	const fromVers = [...dockerfile.matchAll(/FROM\s+node:([\d.]+)/g)].map((m) => m[1]);
	ok('the Docker image pins Node to PINNED_NODE on every stage (matches the desktop bundle and the self-check floor)', !!pinned && fromVers.length >= 1 && fromVers.every((v) => v === pinned));

	// 2. The Dockerfile must copy the COMPLETE signed set. A signed file that is not copied is MISSING inside the
	//    container, so the boot-time self-check reports it altered and REFUSES TO START — a break that only shows at
	//    run time. Derive the non-lib signed files from the manifest and assert each is named in a COPY line; the many
	//    lib/** files are covered by the single `COPY lib`. This is the guard that would have caught the two files
	//    (CONTRIBUTING.md, LICENSE) missed on the first build.
	let signed = [];
	try { const m = JSON.parse(read(path.join(REPO, 'release-manifest.json'))); signed = (m.files || []).map((f) => (typeof f === 'string' ? f : (f.path || f.name))).filter(Boolean); } catch (_) {}
	const nonLibSigned = signed.filter((f) => !f.startsWith('lib/'));
	const copiesLib = /COPY\s+lib\s+\.\/lib/.test(dockerfile);
	const missing = nonLibSigned.filter((f) => !dockerfile.includes(f) && !dockerfile.includes(path.basename(f)));
	ok('the Dockerfile copies every signed file so the in-container self-check verifies (no missing signed file)', signed.length > 0 && copiesLib && missing.length === 0);

	// 3. The compose relay ports must match the app's own defaults, so a node joining the hub agrees on the control
	//    port and the hub publishes the data-port range the app actually uses — no hand-editing to keep them in sync.
	const port = Common.DEFAULT_RELAY_PORT;
	const range = Common.DEFAULT_RELAY_DATA_PORT_RANGE;
	ok('the compose relay control port matches the app default (' + port + ')', new RegExp('--port[\\s\\S]{0,40}"?' + port + '"?').test(compose) && compose.includes(port + ':' + port));
	ok('the compose relay data-port range matches the app default (' + range[0] + '-' + range[1] + ')', compose.includes(range[0] + '-' + range[1]));

	// 4. The entrypoint must self-attest — run verify-self before starting the requested command — so a tampered
	//    bundle refuses to start. This is the property proven at build time; pin it so a refactor cannot drop it.
	ok('the container entrypoint self-attests (runs verify-self) before starting the requested command', /verify-self/.test(entry));

	// 5. Every service in the compose file must stay hardened. Pin that the read-only root filesystem, the dropped
	//    capabilities, and the no-privilege-escalation flag are all present for both active services, so a future edit
	//    cannot silently weaken the fleet.
	ok('every compose service is hardened (read-only rootfs, all capabilities dropped, no privilege escalation)',
		(compose.match(/read_only:\s*true/g) || []).length >= 2 && (compose.match(/cap_drop:/g) || []).length >= 2 && (compose.match(/no-new-privileges:true/g) || []).length >= 2);

	done();
}
main();
