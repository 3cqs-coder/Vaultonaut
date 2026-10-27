'use strict';
// tauri-build.js — run the Tauri build, targeting a specific Rust triple when asked. An npm script cannot portably
// read an environment variable into a command argument (POSIX parameter expansion is not understood by the Windows
// shell npm uses), so this tiny Node wrapper selects the target the same way on every OS. When
// VAULTONAUT_TAURI_TARGET is set — the macOS release sets it to "universal-apple-darwin" — the build passes
// `--target <triple>` so one .app/.dmg runs natively on both Intel and Apple Silicon; otherwise it builds normally
// for the host. Uses only Node built-ins so it behaves identically on macOS, Windows, and Linux.

const { spawnSync } = require('child_process');

const target = String(process.env.VAULTONAUT_TAURI_TARGET || '').trim();
const args = ['build'];
if (target) args.push('--target', target);

const isWin = process.platform === 'win32';
// `npm run` puts node_modules/.bin on PATH, so the local `tauri` CLI resolves. On Windows it is a .cmd shim, which
// cannot be spawned directly without a shell. Invoke cmd.exe explicitly instead of passing shell:true with an args
// array (deprecated in Node 24, and it concatenates rather than escapes those arguments). The arguments here are
// static, but the explicit form is both warning-free and safe if this wrapper ever gains a user-provided target.
const r = isWin
	? spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'tauri', ...args], { stdio: 'inherit', windowsHide: true })
	: spawnSync('tauri', args, { stdio: 'inherit' });
if (r.error) { console.error('Failed to run the Tauri build: ' + r.error.message); process.exit(1); }
process.exit(r.status == null ? 1 : r.status);
