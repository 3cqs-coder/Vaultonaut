'use strict';
// lib/WorkerRun.js — one small, shared helper for running a CPU-heavy job in a worker thread so the
// calling process's event loop (and any mounted-drive health checks) stay responsive. The worker
// streams { type: 'progress', payload } messages that are forwarded to onProgress, and ends with a
// single { type: 'done', result } or { type: 'error', message }. Used by both the self-healing worker
// and the dispersal worker — the same lifecycle, in one place. Cross-platform (worker_threads works on
// macOS, Linux, and Windows).
//
//   runWorker(workerFile, workerData, onProgress, opts) -> Promise<result>
// opts.idleMs (optional): a progress-idle watchdog. A healthy job streams progress steadily, so going
// silent for idleMs means a read has wedged (e.g. an unresponsive network-backed vault) — the worker is
// then terminated and the promise rejected so the caller (and any in-flight guard it holds) is freed,
// rather than hanging forever. It resets on every message, so a job that keeps making progress is never
// interrupted; it is NOT a wall-clock cap. Off by default (0), so callers that don't stream progress
// regularly are unaffected. opts.idleMessage names the operation in the timeout error.

const { Worker } = require('worker_threads');

function runWorker(workerFile, workerData, onProgress, opts = {}) {
	const idleMs = opts.idleMs || 0;
	return new Promise((resolve, reject) => {
		let worker;
		try { worker = new Worker(workerFile, { workerData, ...(opts.resourceLimits ? { resourceLimits: opts.resourceLimits } : {}) }); }
		catch (e) { reject(e); return; }
		let settled = false;
		let timer = null;
		const clearTimer = () => { if (timer) { clearTimeout(timer); timer = null; } };
		const finish = (fn, val) => { if (settled) return; settled = true; clearTimer(); fn(val); worker.terminate().catch(() => {}); };
		const arm = idleMs
			? () => { clearTimer(); timer = setTimeout(() => finish(reject, new Error((opts.idleMessage || 'A background operation') + ' stopped responding (no progress for ' + Math.round(idleMs / 1000) + 's) and was stopped; the storage may be unresponsive. Try again.')), idleMs); if (timer.unref) timer.unref(); }
			: () => {};
		arm(); // cover worker startup and the wait for its first message
		worker.on('message', (msg) => {
			arm(); // any message (progress, done, error) means the worker is alive — reset the idle timer
			if (!msg) return;
			if (msg.type === 'progress') { if (onProgress) { try { onProgress(msg.payload); } catch (_) {} } }
			else if (msg.type === 'done') finish(resolve, msg.result);
			else if (msg.type === 'error') finish(reject, new Error(msg.message));
		});
		worker.on('error', (e) => finish(reject, e));
		// A message the parent cannot deserialize would otherwise leave the promise pending forever (a hang, not a
		// crash). Reject cleanly instead, so the caller's own fallback/error path runs rather than stalling.
		worker.on('messageerror', (e) => finish(reject, e instanceof Error ? e : new Error('A worker sent an unreadable message.')));
		worker.on('exit', (code) => { if (!settled) { settled = true; clearTimer(); reject(new Error('A worker stopped unexpectedly (exit ' + code + ').')); } });
	});
}

// The CHILD side, symmetric with runWorker: parse workerData ({op, args}), dispatch to a handler map,
// and post the single { done } or { error } that the parent lifecycle above expects — plus a progress()
// poster passed to each handler. Handlers share one contract: handler(args, progress) -> result. Owning
// both sides here keeps the message protocol (progress/done/error) in one place. A no-op when loaded
// outside a worker (no parentPort), so the file is import-safe.
function runChild(handlers, { label = 'background' } = {}) {
	const { parentPort, workerData } = require('worker_threads');
	if (!parentPort) return;
	const progress = (payload) => { try { parentPort.postMessage({ type: 'progress', payload }); } catch (_) {} };
	(async () => {
		try {
			const { op, args } = workerData || {};
			const fn = handlers && handlers[op];
			if (typeof fn !== 'function') throw new Error('Unknown ' + label + ' operation: ' + op);
			const result = await fn(args, progress);
			parentPort.postMessage({ type: 'done', result });
		} catch (e) {
			parentPort.postMessage({ type: 'error', message: (e && e.message) || String(e) });
		}
	})();
}

module.exports = { runWorker, runChild };
