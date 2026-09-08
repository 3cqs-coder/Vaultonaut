'use strict';
// lib/test/_runchildfixture.js — a worker built on WorkerRun.runChild, used by workerrun.js to verify the
// child-side lifecycle (dispatch → progress → done/error). Not a test itself; runChild is a no-op outside
// a worker, so launching this standalone does nothing.
require('../WorkerRun').runChild({
	echo: async (args, progress) => { progress({ percent: 50, label: 'working' }); return { got: args }; },
	boom: async () => { throw new Error('handler failed'); },
}, { label: 'test' });
