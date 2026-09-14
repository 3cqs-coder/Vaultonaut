'use strict';
// lib/test/_runprocessfixture.js — a child built on WorkerRun.runProcessChild, used by workerrun.js to verify the
// child-PROCESS lifecycle (job in → single result out → exit) and its self-imposed memory/time bounds. Not a test
// itself; runProcessChild is a no-op outside a forked child (no process.send), so launching this standalone does
// nothing. `hog` grows off-heap memory to trip the child's own RSS budget; `spin` burns CPU to trip the parent maxMs.
require('../WorkerRun').runProcessChild({
	echo: async (args) => ({ got: args }),
	boom: async () => { throw new Error('handler failed'); },
	hog: async () => { const keep = []; for (;;) { const b = Buffer.alloc(16 * 1024 * 1024); b.fill(1); keep.push(b); if (keep.length % 4 === 0) await new Promise((r) => setImmediate(r)); } },
	spin: async () => { for (;;) { /* busy-wait to exceed the parent's time budget */ } },
	sleep: async () => { await new Promise(() => {}); }, // yields forever: the event loop stays free, so the child's own self-timeout can fire
	env: async () => ({ keys: Object.keys(process.env), path: !!process.env.PATH, secret: process.env.VDISK_TEST_SECRET || null }), // report what the child inherited, for the env-scrub check
}, { label: 'test' });
