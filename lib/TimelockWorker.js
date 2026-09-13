'use strict';
// lib/TimelockWorker.js — runs the pairing-heavy time-lock encrypt/decrypt off the main thread, so sealing or
// opening a beneficiary grant never blocks the service event loop or a mounted drive's health checks. The crypto
// lives in Timelock.js; this only marshals a small job across the thread boundary (bytes in, bytes out, no files).
// A no-op when loaded outside a worker (runChild returns immediately), so requiring the file is import-safe.
//
// Ops (workerData.op / .args):
//   seal { round, payloadB64, publicKey? } -> { blob }
//   open { blob, sigHex }                  -> { payloadB64 }

const Timelock = require('./Timelock');
const WorkerRun = require('./WorkerRun');

// A genuine crypto failure (wrong signature, altered data) is returned as { ok:false, error } — NOT thrown — so the
// caller can tell it apart from a worker that never started (which rejects the run). That lets the caller re-run
// inline only for a real worker-startup failure, never repeating the pairing math on an authentic crypto failure.
WorkerRun.runChild({
	seal: async ({ round, payloadB64, publicKey }) => { try { return { ok: true, blob: Timelock.sealToRound(round, Buffer.from(payloadB64, 'base64'), { publicKey }) }; } catch (e) { return { ok: false, error: (e && e.message) || String(e) }; } },
	open: async ({ blob, sigHex }) => { try { return { ok: true, payloadB64: Timelock.openWithSignature(blob, Buffer.from(sigHex, 'hex')).toString('base64') }; } catch (e) { return { ok: false, error: (e && e.message) || String(e) }; } },
}, { label: 'time-lock' });
