'use strict';
// lib/test/_runprocessfixture.js — a child built on WorkerRun.runProcessChild, used by workerrun.js to verify the
// child-PROCESS lifecycle (job in → single result out → exit) and its self-imposed memory/time bounds. Not a test
// itself; runProcessChild is a no-op outside a forked child (no process.send), so launching this standalone does
// nothing. `hog` grows off-heap memory to trip the child's own RSS budget; `spin` burns CPU to trip the parent maxMs.
// `count` streams progress (2nd handler arg) then finishes; `stall` streams a few then goes silent forever (to prove
// progress re-arms the parent idle watchdog and later silence trips it).
require('../WorkerRun').runProcessChild({
	echo: async (args) => ({ got: args }),
	boom: async () => { throw new Error('handler failed'); },
	hog: async () => { const keep = []; for (;;) { const b = Buffer.alloc(16 * 1024 * 1024); b.fill(1); keep.push(b); if (keep.length % 4 === 0) await new Promise((r) => setImmediate(r)); } },
	spin: async () => { for (;;) { /* busy-wait to exceed the parent's time budget */ } },
	sleep: async () => { await new Promise(() => {}); }, // yields forever: the event loop stays free, so the child's own self-timeout can fire
	count: async (args, progress) => { const n = (args && args.n) || 4; for (let i = 0; i < n; i++) { progress({ percent: Math.floor((i + 1) / n * 100), label: 'step ' + (i + 1) }); await new Promise((r) => setTimeout(r, 40)); } return { counted: n }; },
	stall: async (args, progress) => { for (let i = 0; i < 3; i++) { progress({ percent: (i + 1) * 10 }); await new Promise((r) => setTimeout(r, 60)); } await new Promise(() => {}); }, // stream, then hang: idle watchdog should fire only after the progress stops
	env: async () => ({ keys: Object.keys(process.env), path: !!process.env.PATH, secret: process.env.VDISK_TEST_SECRET || null }), // report what the child inherited, for the env-scrub check
}, { label: 'test' });
