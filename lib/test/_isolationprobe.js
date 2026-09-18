'use strict';
// Test helper (the leading underscore keeps the runner from executing it as a test). It prints the data directory
// Common resolves to, so testisolation.js can spawn it WITHOUT the _setup preload and prove the test-entry fail-safe
// in Common.dataDir isolates a direct `node lib/test/...` run to .test-data rather than the user's real data dir.
process.stdout.write(require('../Common').dataDir());
