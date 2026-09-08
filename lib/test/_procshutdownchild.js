'use strict';
// Fixture for procregistry.js (underscore-prefixed, so the test runner skips it). It registers a shutdown task
// that writes a marker file, installs the shutdown handlers (twice, to prove idempotence), signals readiness, and
// stays alive until it receives a stop signal — at which point the graceful-exit path must run the task and exit 0.
const fs = require('fs');
const marker = process.argv[2];
const P = require('../ProcRegistry');
P.onShutdown(async () => { try { fs.writeFileSync(marker, 'shutdown-ran'); } catch (_) {} });
P.installShutdownHandlers();
P.installShutdownHandlers(); // second call must be a no-op (handlers installed once)
process.stdout.write('ready\n');
setInterval(() => {}, 1000);
