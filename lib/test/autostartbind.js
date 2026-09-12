'use strict';
// lib/test/autostartbind.js — locks the network-bind support in autostart-on-boot, the piece that lets a user set
// the interface to start reachable from a phone or another device (a `--bind <ip>` argument in the login service).
// It is a pure unit test that NEVER calls install() (which would write to the user's real LaunchAgents / systemd /
// Run key); it exercises the three side-effect-free pieces install() is built from:
//   1. buildServiceText — the per-platform service-command generator. A real generate → parse round-trip proves a
//      network bind writes `--bind` and that bindFromServiceText reads it back, so the parser and the generator can
//      never drift apart (unlike frozen hand-written samples). It also proves no bind writes no `--bind`.
//   2. bindFromServiceText — the reverse parser status() uses to report this-computer-only vs network-reachable.
//   3. resolveBindArg — the single loopback-vs-network rule: loopback/empty becomes null (so an interface is never
//      silently exposed), a real IP is kept, and an invalid non-loopback address throws before anything installs.
//
// Run:  node lib/test/autostartbind.js   (no engine, no network, no side effects)

const Autostart = require('../Autostart');
const { bindFromServiceText, scriptFromServiceText, nodeFromServiceText, buildServiceText, resolveBindArg } = Autostart;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const PLATFORMS = ['macos', 'linux', 'windows'];
const parts = (bindArg) => ({ node: '/opt/node', script: '/app/vaultonaut.js', port: 7420, bindArg, ddOverride: null, root: '/app' });

function main() {
	// --- generate → parse round-trip on the REAL generator, so the parser and the generator are verified against
	// each other (not against frozen hand-written samples that could drift from the actual output). ---
	for (const p of PLATFORMS) {
		const withBind = buildServiceText(p, parts('192.168.1.54'));
		ok('[' + p + '] a network bind writes --bind into the service command', /--bind/.test(withBind) && bindFromServiceText(withBind) === '192.168.1.54');
		// The wildcard address the UI uses must round-trip too.
		ok('[' + p + '] the 0.0.0.0 wildcard bind round-trips', bindFromServiceText(buildServiceText(p, parts('0.0.0.0'))) === '0.0.0.0');
		// No bind => no --bind anywhere in the command, and the parser agrees it is this-computer-only.
		const noBind = buildServiceText(p, parts(null));
		ok('[' + p + '] no bind writes no --bind (stays this-computer-only)', !/--bind/.test(noBind) && bindFromServiceText(noBind) === null);
		// The SCRIPT path must round-trip too: the stale-command boot check reads it back to detect a moved/deleted
		// install, so a parser/generator drift would false-fire (or miss) that warning. Prove they stay in step.
		ok('[' + p + '] the launcher script path round-trips through scriptFromServiceText', scriptFromServiceText(withBind) === '/app/vaultonaut.js' && scriptFromServiceText(noBind) === '/app/vaultonaut.js');
		// The NODE path must round-trip too: the stale-command boot check reads it back to warn when the runtime a
		// headless service was installed with is gone (moved/upgraded), so the node parser must stay in step with the
		// generator exactly as the script parser does.
		ok('[' + p + '] the node binary path round-trips through nodeFromServiceText', nodeFromServiceText(withBind) === '/opt/node' && nodeFromServiceText(noBind) === '/opt/node');
	}

	// A systemd WorkingDirectory must be escaped like the ExecStart node/script paths. systemd treats `%` as a
	// specifier (for example %h for the home directory), so an install directory containing a literal `%` would be
	// mis-expanded and the service would run against the wrong directory. The value is quoted and each `%` doubled to
	// a literal `%%`, matching how the node and script paths on the ExecStart line are escaped.
	{
		const linux = buildServiceText('linux', { node: '/opt/node', script: '/app/vaultonaut.js', port: 7420, bindArg: null, ddOverride: null, root: '/srv/app %20 dir' });
		ok('[linux] WorkingDirectory is quoted and escapes a literal % (a systemd specifier)', linux.includes('WorkingDirectory="/srv/app %%20 dir"'));
	}

	// --- resolveBindArg is the single rule install() uses to decide loopback-vs-network, tested here with no side
	// effects (never calls install(), which would write a real login entry to the host). A loopback or empty value
	// must resolve to null so it can never silently expose an interface the user meant to keep local. ---
	for (const b of ['127.0.0.1', '127.0.0.2', 'localhost', '::1', '', '  ', null, undefined]) {
		ok('resolveBindArg treats ' + JSON.stringify(b) + ' as this-computer-only (null)', resolveBindArg(b) === null);
	}
	ok('resolveBindArg keeps a real network IP', resolveBindArg('192.168.1.54') === '192.168.1.54' && resolveBindArg('0.0.0.0') === '0.0.0.0');
	ok('resolveBindArg trims surrounding whitespace on a network IP', resolveBindArg('  10.0.0.5  ') === '10.0.0.5');

	// --- an invalid non-loopback bind fails fast (before install writes or loads anything) ---
	let threw = false;
	try { resolveBindArg('not-an-ip'); } catch (e) { threw = /valid IP address/.test(e.message); }
	ok('resolveBindArg rejects an invalid bind address', threw);

	return done();
}

function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL AUTOSTART-BIND CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
