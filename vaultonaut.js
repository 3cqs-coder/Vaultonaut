#!/usr/bin/env node
'use strict';

/*

	Vaultonaut — cross-platform, real-time encrypted virtual disks.
	Copyright (C) 2026 3CQS

	This program is free software: you can redistribute it and/or modify it under the terms of the
	GNU Affero General Public License as published by the Free Software Foundation, either version 3
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
	even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
	Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License along with this program.
	If not, see <https://www.gnu.org/licenses/>. The full text is in the LICENSE file.

*/

// vaultonaut.js — the command-line entry point. Deliberately slim: it installs the shutdown
// handlers, names the process, parses arguments, and hands off to lib/Commands. Every command's
// logic lives in that module, not here. Options come from arguments only, never environment
// variables; passwords are prompted without echo; the mount runs as a background process.

// Enforce the minimum Node.js version FIRST, before anything modern is required, so an unsupported runtime gets
// a clear "requires Node.js >= X" message instead of a cryptic crash deep inside a dependency. Bootstrap and
// Brand are tiny, dependency-free, parse-safe modules, so requiring them this early is safe on an old runtime.
require('./lib/Bootstrap').enforceNodeVersion(__dirname, require('./lib/Brand').name);

// Give libuv's filesystem thread pool headroom before any async I/O starts (it reads this only at first use). The
// service runs a lot of concurrent, sometimes slow, disk work — per-vault status polls across possibly removable or
// network drives, mounts, backups — and the default pool of four is easily saturated, which would let a few slow
// drives starve every other file operation. A larger fixed pool prevents that. Set in code (not asked of the user);
// an existing value is left untouched.
if (!process.env.UV_THREADPOOL_SIZE) process.env.UV_THREADPOOL_SIZE = '16';

// Prefer IPv4 for outbound DNS FIRST, before any network-using module is required, so downloads, cloud vaults,
// timestamp requests, and relay hops all inherit it and stay resilient on hosts with flaky IPv6 (see lib/DnsOrder).
require('./lib/DnsOrder').prefer(process.argv);

const ProcRegistry = require('./lib/ProcRegistry');
const Brand = require('./lib/Brand');
const Commands = require('./lib/Commands');

ProcRegistry.installShutdownHandlers(); // clean up in-flight engine calls if interrupted

(async () => {
	const { positionals, flags } = Commands.parse(process.argv.slice(2));
	// Point the data directory at a custom path if asked (before anything reads a data path). The per-OS default
	// is used otherwise. The guardian subprocess is launched with the resolved path, so it always matches.
	const Common = require('./lib/Common');
	// The packaged desktop shell launches the service with --desktop so the backend knows it is the native app
	// (not a headless/CLI install). Recorded once here; autostart reads it to skip the browser-launcher shortcut.
	if (flags.desktop) Common.setDesktopApp(true);
	if (flags['data-dir'] !== undefined) {
		const dd = flags['data-dir'];
		// A bare "--data-dir" with no path parses as `true`; refuse it clearly rather than silently using "<cwd>/true".
		if (typeof dd === 'string' && dd.trim()) Common.setDataDir(dd);
		else { console.error('Error: --data-dir needs a folder path, for example:  ' + Brand.cli + ' --data-dir /path/to/data <command>'); process.exit(1); }
	}
	Common.ensureDataDir(); // create the per-user data directory (owner-only) on a fresh machine, before anything reads it
	const cmd = positionals.shift();
	// Show a meaningful name in the OS process list instead of "node" (macOS/Linux; console title on Windows).
	try { process.title = cmd === '_guard' ? Brand.slug + '-guardian' : Brand.slug; } catch (_) {}
	try {
		const { keepAlive } = await Commands.dispatch(cmd, positionals, flags);
		// Exit one-shot commands explicitly so a stat pending on a wedged mount cannot keep the process
		// alive after the work is done. Long-running commands set keepAlive and run until interrupted.
		if (!keepAlive) process.exit(process.exitCode || 0);
	} catch (e) {
		console.error('\nError: ' + e.message);
		if (e.install) console.error('\n' + e.install);
		process.exit(1);
	}
})();
