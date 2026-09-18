'use strict';
// Test helper (the leading underscore keeps the runner from executing it as a test). It prints, as JSON, the data
// directory AND the engine (bin) directory Common resolves to, so testisolation.js can spawn it WITHOUT the _setup
// preload and prove two fail-safes in Common: (1) a direct `node lib/test/...` run isolates dataDir() to .test-data
// rather than the user's real data dir; (2) binDir() ignores any stray VAULTONAUT_ENGINE_DIR in the environment for a
// test-launched process, so a dev/CI shell variable can never steer a test at some other engine directory.
const Common = require('../Common');
process.stdout.write(JSON.stringify({ dataDir: Common.dataDir(), binDir: Common.binDir() }));
