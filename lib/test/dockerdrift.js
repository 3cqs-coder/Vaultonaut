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
	const copiesLib = /COPY\s+(?:--chown=\S+\s+)?lib\s+\.\/lib/.test(dockerfile);
	const missing = nonLibSigned.filter((f) => !dockerfile.includes(f) && !dockerfile.includes(path.basename(f)));
	ok('the Dockerfile copies every signed file so the in-container self-check verifies (no missing signed file)', signed.length > 0 && copiesLib && missing.length === 0);

	// 2b. The three release-integrity CONTROL files — the manifest and BOTH signatures — are NOT in the manifest's own
	//     files[] list, so the check above cannot cover them, yet the in-container self-check needs all three and the
	//     post-quantum signature is now REQUIRED (a pinned PQ public key). If the COPY ever dropped one (as .sig.pq was
	//     once missing from the npm package), the image would build and only fail at the operator's boot. Pin all three.
	for (const ctl of ['release-manifest.json', 'release-manifest.sig', 'release-manifest.sig.pq']) {
		ok('the Dockerfile copies the release control file ' + ctl, new RegExp('COPY[^\\n]*\\b' + ctl.replace(/\./g, '\\.') + '\\b').test(dockerfile));
	}

	// 3. The compose relay ports must match the app's own defaults, so a node joining the hub agrees on the control
	//    port and the hub publishes the data-port range the app actually uses — no hand-editing to keep them in sync.
	const port = Common.DEFAULT_RELAY_PORT;
	const range = Common.DEFAULT_RELAY_DATA_PORT_RANGE;
	ok('the compose relay control port matches the app default (' + port + ')', new RegExp('--port[\\s\\S]{0,40}"?' + port + '"?').test(compose) && compose.includes(port + ':' + port));
	ok('the compose relay data-port range matches the app default (' + range[0] + '-' + range[1] + ')', compose.includes(range[0] + '-' + range[1]));
	// The relay's HEALTHCHECK_PORT literal must be the SAME control port, or the health probe would test the wrong port
	// and mark a healthy hub unhealthy. Tie it to the app default too, so a port change cannot leave the probe behind.
	ok('the compose relay HEALTHCHECK_PORT matches the control port (' + port + ')', new RegExp('HEALTHCHECK_PORT:\\s*"?' + port + '"?').test(compose));

	// 3b. Both fleet services must run the SAME image, or an upgrade could split the fleet onto two versions. Pin that
	//     the relay and node image lines are identical (the shared `${VAULTONAUT_IMAGE}:${VAULTONAUT_VERSION}` default).
	const imageLines = (compose.match(/^\s*image:\s*\S+/gm) || []).map((l) => l.trim());
	ok('every fleet service uses the same image reference (one pull upgrades the whole fleet)', imageLines.length >= 2 && imageLines.every((l) => l === imageLines[0]));

	// 4. The entrypoint must self-attest — run verify-self before starting the requested command — so a tampered
	//    bundle refuses to start. This is the property proven at build time; pin it so a refactor cannot drop it. It
	//    must also forward BOTH stop signals to the child so the backend drains cleanly, and the health probe must
	//    validate its port (behaviorally covered by dockerentrypoint.js; pinned statically here too).
	ok('the container entrypoint self-attests (runs verify-self) before starting the requested command', /verify-self/.test(entry));
	ok('the entrypoint forwards both SIGTERM and SIGINT to the child (clean drain on stop)', /SIGTERM/.test(entry) && /SIGINT/.test(entry) && /child\.kill\(/.test(entry));
	const health = read(path.join(D, 'healthcheck.js'));
	ok('the health probe validates its port is in range before probing (no misfire on a bad port)', /HEALTHCHECK_PORT/.test(health) && /(< 1 \|\| .* > 65535|1, 65535|65535)/.test(health));

	// 5. Every service in the compose file must stay hardened. Pin that the read-only root filesystem, the dropped
	//    capabilities, and the no-privilege-escalation flag are all present for both active services, so a future edit
	//    cannot silently weaken the fleet.
	ok('every compose service is hardened (read-only rootfs, all capabilities dropped, no privilege escalation)',
		(compose.match(/read_only:\s*true/g) || []).length >= 2 && (compose.match(/cap_drop:/g) || []).length >= 2 && (compose.match(/no-new-privileges:true/g) || []).length >= 2);

	// 6. The engine is BAKED into the image so a serving node needs no first-serve download (it works air-gapped). To
	//    stay DRIFT-FREE the bake must reuse the app's own RcloneSetup — the single source of the pinned engine version
	//    and its committed checksums — and the Dockerfile must name no engine version or URL of its own. Pin all of it:
	//    the Dockerfile runs the bake and copies /engine and points the app there; the Dockerfile carries no hardcoded
	//    engine reference that could drift from the pin; and the bake script derives the engine and its license from
	//    RcloneSetup and ships the license (the engine is redistributed, so its notice must travel with it).
	const bake = read(path.join(D, 'bake-engine.js'));
	ok('the image bakes the engine (via the bake script) and copies it to /engine', /VAULTONAUT_ENGINE_DIR=\/engine node docker\/bake-engine\.js/.test(dockerfile) && /--from=builder \/engine \/engine/.test(dockerfile));
	ok('the runtime points the app at the baked engine (VAULTONAUT_ENGINE_DIR=/engine)', /VAULTONAUT_ENGINE_DIR=\/engine/.test(dockerfile) && /VAULTONAUT_ENGINE_DIR/.test(read(path.join(REPO, 'lib', 'Common.js'))));
	ok('the Dockerfile names no hardcoded engine version or URL (the pin stays single-sourced in RcloneSetup)', !/rclone-v|downloads\.rclone\.org|github\.com\/rclone/.test(dockerfile));
	ok('the bake script derives the engine and its license from RcloneSetup (single source, no drift)', /require\('\.\.\/lib\/RcloneSetup'\)/.test(bake) && /RcloneSetup\.ensure\(\)/.test(bake) && /RcloneSetup\.PINNED_TAG/.test(bake));
	ok('the bake ships the engine license alongside the binary (MIT redistribution notice)', /rclone-LICENSE\.txt/.test(bake));

	// 7. The read-only root filesystem needs every runtime write to land on the writable /data volume, so both the
	//    persistent data dir (XDG_DATA_HOME) AND the home directory (HOME — where a stray write by Node or the engine
	//    would otherwise go) must point at /data. If either drifted off /data, a serving node would fail the moment
	//    anything wrote outside the volume against the read-only root. Pin both to /data.
	ok('the runtime confines writes to the /data volume (HOME=/data and XDG_DATA_HOME=/data for the read-only rootfs)',
		/XDG_DATA_HOME=\/data/.test(dockerfile) && /HOME=\/data/.test(dockerfile));

	// 8. lib/test and lib/scripts are NOT part of the signed set, so if either reaches the image the boot-time
	//    self-check counts it as an extra file and refuses to start (TAMPERED). Two independent guarantees keep them
	//    out: the repo-root .dockerignore (honored by every builder, not only BuildKit) excludes them from the build
	//    context, AND the Dockerfile prunes them after copying lib (a backstop that holds even if the ignore file is
	//    bypassed). Pin both, so neither can be dropped and silently reintroduce the runtime-refusal risk.
	const dockerignore = read(path.join(REPO, '.dockerignore'));
	ok('the repo-root .dockerignore excludes lib/test and lib/scripts from the build context',
		/^lib\/test\s*$/m.test(dockerignore) && /^lib\/scripts\s*$/m.test(dockerignore));
	ok('the Dockerfile prunes lib/test and lib/scripts after copying lib (builder-agnostic backstop)',
		/rm -rf[^\n]*lib\/test[^\n]*lib\/scripts|rm -rf[^\n]*lib\/scripts[^\n]*lib\/test/.test(dockerfile));

	done();
}
main();
