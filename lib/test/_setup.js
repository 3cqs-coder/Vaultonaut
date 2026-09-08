'use strict';
// Test isolation preload. The real data directory is now the per-user OS location (see Common.defaultDataDir),
// but the test suite must NEVER read or write there — it would scatter locks, state, ledgers, and a test
// credential key across the user's real data. It also must not use the shipped program folder's own `data/`
// (that folder is not used by the app at all any more). So point BOTH the data directory and the engine at a
// dedicated, git-ignored `.test-data/` under the project — self-contained, obviously a test area, and safe to
// delete. Individual tests that need their own throwaway data dir still override Common.dataDir after this runs;
// their override wins, and the engine stays pinned here so they never re-download or need a system rclone.
//
// Preloaded via `node -r ./lib/test/_setup.js <test>` (see the "test" / "test:all" package scripts). The leading
// underscore keeps the battery runner from executing it as a test.
const path = require('path');
const Common = require('../Common');
const testData = path.join(__dirname, '..', '..', '.test-data');
Common.setDataDir(testData);
Common.setBinDir(path.join(testData, 'bin')); // the bundled engine is fetched here once and reused across tests
