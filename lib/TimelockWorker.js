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

WorkerRun.runChild({
	seal: async ({ round, payloadB64, publicKey }) => ({ blob: Timelock.sealToRound(round, Buffer.from(payloadB64, 'base64'), { publicKey }) }),
	open: async ({ blob, sigHex }) => ({ payloadB64: Timelock.openWithSignature(blob, Buffer.from(sigHex, 'hex')).toString('base64') }),
}, { label: 'time-lock' });
