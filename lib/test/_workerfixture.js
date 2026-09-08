'use strict';
// lib/test/_workerfixture.js — a controllable worker used only by workerrun.js to exercise WorkerRun's
// lifecycle and its progress-idle watchdog. Not a test itself (the leading underscore keeps it out of any
// glob run, and it no-ops if launched outside a worker). workerData.mode selects the behavior.
const { parentPort, workerData } = require('worker_threads');
if (!parentPort) { process.exit(0); return; } // run standalone: do nothing

const mode = (workerData && workerData.mode) || 'done';
if (mode === 'done') {
	parentPort.postMessage({ type: 'progress', payload: { percent: 50 } });
	parentPort.postMessage({ type: 'done', result: { ok: true } });
} else if (mode === 'hang') {
	// Alive but silent — posts nothing, so only the idle watchdog can end it (not the exit path).
	setInterval(() => {}, 1000);
} else if (mode === 'progress-then-hang') {
	// Emit progress for a while, then go silent — the watchdog should fire only after the silence.
	let n = 0;
	const t = setInterval(() => { if (n++ < 4) parentPort.postMessage({ type: 'progress', payload: { percent: n * 10 } }); else clearInterval(t); }, 40);
	setInterval(() => {}, 1000); // stay alive after going silent
}
