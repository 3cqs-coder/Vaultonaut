'use strict';
// lib/test/p2ptimers.js — a cross-module WATCHDOG for the peer-to-peer transport stack. The standing engineering
// principle is that nothing on the shared web/background service may block the event loop or hold it open: every timer
// must be unref'd, no *Sync I/O on a hot path, and no non-portable socket options. These modules (HolePunch, Tunnel,
// Relay, PortMap, LanDiscovery) all run on that shared service, so this pins the invariant at the source level and
// catches a future regression — a ref'd timer, a stray *Sync, a reusePort — before it ships. It is deliberately a
// simple source scan (no runtime), so it can never itself hang or flake.
//
// Run:  node lib/test/p2ptimers.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const MODULES = ['HolePunch', 'Tunnel', 'Relay', 'PortMap', 'LanDiscovery'];

for (const name of MODULES) {
	const src = fs.readFileSync(path.join(__dirname, '..', name + '.js'), 'utf8');
	const timers = (src.match(/set(Timeout|Interval)\(/g) || []).length;
	const unrefs = (src.match(/\.unref\(\)/g) || []).length;
	// Every timer must be paired with an unref so a standalone process still exits and the shared service is never held
	// open by a background timer. (These modules have no timer that intentionally holds the loop, so equality is exact.)
	ok(name + ': every setTimeout/setInterval is unref\'d (' + timers + ' timers, ' + unrefs + ' unrefs)', timers === unrefs);
	// No blocking *Sync file/exec I/O on these shared-service paths.
	ok(name + ': no blocking *Sync I/O', !/readFileSync|writeFileSync|execSync|execFileSync|existsSync|mkdirSync|readdirSync/.test(src));
	// No non-portable socket options: reusePort/SO_REUSEPORT throw on Windows/macOS in Node; a comment may name them
	// (to explain the avoidance), so only an actual option usage (`reusePort:`) is a failure.
	ok(name + ': never sets the non-portable reusePort option', !/reusePort\s*:/.test(src));
	// Never a SHELL: any process a module does start (PortMap runs the gateway command) must go through execFile with an
	// argument array, never exec()/spawn(shell:true), so an OS value can never be interpreted as a shell command.
	ok(name + ': runs no shell', !/[^a-zA-Z.]exec\(|shell:\s*true|spawn\([^)]*shell/.test(src));
}

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL P2P-TIMER WATCHDOG CHECKS PASSED'));
process.exit(failures ? 1 : 0);
