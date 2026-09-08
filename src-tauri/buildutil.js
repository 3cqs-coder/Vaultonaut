'use strict';
// buildutil.js — small shared helpers for the desktop-packaging scripts, so the cross-platform npm invocation
// lives in one place instead of being retyped in each. (The packaging watchdog under lib/test keeps its own copy
// on purpose — a watchdog should not depend on the tooling it exists to check.)

const { spawnSync } = require('child_process');

// Run npm cross-platform. On Windows npm is a .cmd shim, and current Node refuses to spawn a .cmd without a
// shell (it throws EINVAL), so the shell is enabled there; the arguments are always static, so this adds no
// injection surface. Pass capture:true to collect stdout (returns the spawnSync result); otherwise output is
// inherited. Returns the spawnSync result object (check .status).
function runNpm(args, { cwd, capture = false, env } = {}) {
	const isWin = process.platform === 'win32';
	return spawnSync(isWin ? 'npm.cmd' : 'npm', args, {
		cwd,
		shell: isWin,
		encoding: 'utf8',
		stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
		env: env ? { ...process.env, ...env } : process.env,
		maxBuffer: 64 * 1024 * 1024,
	});
}

module.exports = { runNpm };
