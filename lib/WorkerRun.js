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
// opts.maxMs (optional): an ABSOLUTE wall-clock cap, armed once and never reset. Use it for a job that does
// NOT stream progress (so idleMs cannot protect it) but must still be bounded — a worker that starts and then
// never posts done/error is stopped after maxMs and the promise rejects, so the caller's fallback runs instead
// of hanging forever. Set it well above any legitimate run time so it only ever catches a genuinely stuck worker.
// opts.resourceLimits (optional): forwarded to the Worker so a job can be run with a hard JS-heap cap (a reaching of
// which terminates the worker as a catchable error). opts.execArgv (optional): forwarded to the Worker; pass [] to
// stop an inherited --max-old-space-size from overriding a resourceLimits heap cap.
//
//   runProcess(childFile, job, opts) -> Promise<result>
// The same idea for a job that must be isolated in MEMORY, not just off the event loop. A worker THREAD shares this
// process's address space, so a job that grows large OFF-HEAP/native memory (a document reader decoding a crafted
// file) could drive the whole app to an out-of-memory kill, and on some platforms a terminated thread's memory is
// not even returned to the OS — sequential such jobs ratchet the process's memory upward. runProcess forks a
// separate child PROCESS (ChildRun.runChild on the far side): its memory is its own, never counts against the app,
// and is fully reclaimed by the OS when it exits, so no single job and no sequence of jobs can exhaust the parent.
// The child is given a hard JS-heap cap via opts.execArgv (e.g. ['--max-old-space-size=768']) and bounds its own
// off-heap growth; opts.maxMs stops a stuck child. Cross-platform (child_process.fork works on macOS/Linux/Windows).

const { Worker } = require('worker_threads');

function runWorker(workerFile, workerData, onProgress, opts = {}) {
	const idleMs = opts.idleMs || 0;
	const maxMs = opts.maxMs || 0;
	return new Promise((resolve, reject) => {
		let worker;
		try { worker = new Worker(workerFile, { workerData, ...(opts.resourceLimits ? { resourceLimits: opts.resourceLimits } : {}), ...(opts.execArgv ? { execArgv: opts.execArgv } : {}) }); }
		catch (e) { reject(e); return; }
		let settled = false;
		let timer = null, hardTimer = null;
		const clearTimer = () => { if (timer) { clearTimeout(timer); timer = null; } if (hardTimer) { clearTimeout(hardTimer); hardTimer = null; } };
		const finish = (fn, val) => { if (settled) return; settled = true; clearTimer(); fn(val); worker.terminate().catch(() => {}); };
		const arm = idleMs
			? () => { if (timer) clearTimeout(timer); timer = setTimeout(() => finish(reject, new Error((opts.idleMessage || 'A background operation') + ' stopped responding (no progress for ' + Math.round(idleMs / 1000) + 's) and was stopped; the storage may be unresponsive. Try again.')), idleMs); if (timer.unref) timer.unref(); }
			: () => {};
		arm(); // cover worker startup and the wait for its first message
		if (maxMs) { hardTimer = setTimeout(() => finish(reject, new Error((opts.idleMessage || 'A background operation') + ' did not finish within ' + Math.round(maxMs / 1000) + 's and was stopped.')), maxMs); if (hardTimer.unref) hardTimer.unref(); } // absolute cap, never reset by messages
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

// Run one job in an isolated child PROCESS (see the header). Forks `childFile` (which uses runProcessChild on the far
// side), sends it `job` over the IPC channel, and resolves the child's single result — or rejects on a child error,
// an early exit (e.g. the OS or its own heap cap killed it), or the opts.maxMs deadline. The child is always killed
// on settle, so a stuck or memory-hungry child is torn down and its memory returned to the OS. Never leaves the
// promise pending. `serialization: 'advanced'` so a Buffer in the job/result survives the IPC round-trip intact.
function runProcess(childFile, job, opts = {}) {
	const maxMs = opts.maxMs || 0;
	return new Promise((resolve, reject) => {
		let child;
		// fork runs `process.execPath <childFile>`, which requires execPath to be a real Node binary. That holds for a
		// normal install and for the branded-launcher desktop build (a renamed copy of the node binary is still Node).
		// If the app is ever repackaged as a single self-contained executable (execPath = the app, not Node), this must
		// pass the app entry plus a mode flag instead of a bare script path.
		// windowsHide so a forked child never flashes a console window: when the packaged desktop app runs the Node
		// service with no console of its own, a console-subsystem child would otherwise get a brand-new visible window
		// (one per document during indexing). stdio:'ignore' does NOT suppress that window; windowsHide does.
		try { child = require('child_process').fork(childFile, [], { execArgv: opts.execArgv || [], serialization: 'advanced', stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true }); }
		catch (e) { reject(e); return; }
		let settled = false, hardTimer = null;
		const clearTimer = () => { if (hardTimer) { clearTimeout(hardTimer); hardTimer = null; } };
		const finish = (fn, val) => { if (settled) return; settled = true; clearTimer(); fn(val); try { child.kill(); } catch (_) {} };
		if (maxMs) { hardTimer = setTimeout(() => finish(reject, new Error((opts.label || 'A background operation') + ' did not finish within ' + Math.round(maxMs / 1000) + 's and was stopped.')), maxMs); if (hardTimer.unref) hardTimer.unref(); }
		child.on('message', (msg) => { if (!msg) return; if (msg.ok) finish(resolve, msg.result); else finish(reject, new Error((msg && msg.error) || 'The helper process reported an error.')); });
		child.on('error', (e) => finish(reject, e));
		child.on('exit', (code, signal) => { if (!settled) { settled = true; clearTimer(); reject(new Error('A helper process stopped unexpectedly (exit ' + code + (signal ? ', ' + signal : '') + ').')); } });
		try { child.send(job); } catch (e) { finish(reject, e); } // a send failure (channel already gone) rejects rather than hanging
	});
}

// The CHILD-PROCESS side, symmetric with runProcess: wait for the single job message, run the handler for its op, and
// send back exactly one { ok, result } or { ok:false, error }, then exit so the OS reclaims all of the child's memory
// (the point of process isolation). It also enforces its OWN limits so it can never become a runaway even if the
// parent goes away (a reindex cancel, or the app exiting, would otherwise orphan it):
//   • an off-heap RSS budget (job.rssLimitMb) — samples its RSS and exits if it climbs past the budget, ending a
//     native/decode-buffer bomb cleanly rather than waiting for an OS out-of-memory kill;
//   • a self wall-clock deadline (job.selfTimeoutMs) — a backstop that exits an orphaned child whose (async) work
//     never returns, so it can't linger after the parent that would have killed it is gone;
//   • parent disconnect — if the IPC channel closes (the parent thread/process vanished), exit promptly.
// (A pure non-yielding synchronous loop blocks these JS-timer/event backstops; the parent's maxMs → kill is what
// bounds that while the parent is alive, and the process heap cap bounds an allocation-heavy synchronous loop.)
// A no-op outside a forked child (no process.send).
function runProcessChild(handlers, { label = 'background' } = {}) {
	if (typeof process.send !== 'function') return;
	try { process.once('disconnect', () => { try { process.exit(0); } catch (_) {} }); } catch (_) {} // parent gone -> don't linger
	process.once('message', async (job) => {
		const rssLimitMb = (job && job.rssLimitMb) || 0;
		const selfTimeoutMs = (job && job.selfTimeoutMs) || 0;
		let mon = null, deadline = null;
		if (rssLimitMb) { let base = 0; try { base = process.memoryUsage().rss; } catch (_) {} const limit = base + rssLimitMb * 1024 * 1024; mon = setInterval(() => { let rss = 0; try { rss = process.memoryUsage().rss; } catch (_) { return; } if (rss > limit) { try { process.exit(2); } catch (_) {} } }, 200); if (mon.unref) mon.unref(); }
		if (selfTimeoutMs) { deadline = setTimeout(() => { try { process.exit(4); } catch (_) {} }, selfTimeoutMs); if (deadline.unref) deadline.unref(); }
		let out;
		try {
			const fn = handlers && handlers[job && job.op];
			if (typeof fn !== 'function') throw new Error('Unknown ' + label + ' operation: ' + (job && job.op));
			out = { ok: true, result: await fn(job.args) };
		} catch (e) { out = { ok: false, error: (e && e.message) || String(e) }; }
		if (mon) { try { clearInterval(mon); } catch (_) {} }
		if (deadline) { try { clearTimeout(deadline); } catch (_) {} }
		try { process.send(out, () => process.exit(0)); } catch (_) { try { process.exit(0); } catch (__) {} } // exit AFTER the message is flushed
	});
}

module.exports = { runWorker, runChild, runProcess, runProcessChild };
