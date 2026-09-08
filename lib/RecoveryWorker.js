'use strict';
// lib/RecoveryWorker.js — runs a single self-healing operation (protect / verify / heal) off the
// main thread. The heavy Reed–Solomon math would otherwise block the event loop; here it cannot
// stall the local web server or its mount health checks. Progress is streamed back as { percent,
// label } messages, and the final result (or error) ends the worker. The actual work lives in the
// shared cores in Recovery.js, so there is no duplicated logic.

// The cores already share the handler(args, progress) contract, so the child lifecycle (parse → dispatch
// → done/error, with a progress poster) lives once in WorkerRun.runChild.
require('./WorkerRun').runChild(require('./Recovery').CORES, { label: 'recovery' });
