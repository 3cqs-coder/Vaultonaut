'use strict';
// Root-level entry point for the desktop version mirror.
//
// Tauri runs beforeDevCommand/beforeBuildCommand through a platform shell. An inline `node -e "..."` command is
// fragile there: Windows cmd.exe does not preserve the inner quotes the way POSIX shells do, and it broke the
// 1.3.2 Windows build. A plain script name has no quoting to mis-parse.
//
// This wrapper makes `node sync-version.js` work from either plausible Tauri working directory:
//   - from the repository root, this file delegates to src-tauri/sync-version.js;
//   - from src-tauri, Node resolves the real script directly from the current directory.
// The real implementation stays single-sourced in src-tauri/sync-version.js.
require('./src-tauri/sync-version.js');
