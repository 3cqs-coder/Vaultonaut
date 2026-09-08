'use strict';
// lib/KdfWorker.js — runs the memory-hard Argon2id key derivation off the main thread, so unlocking a
// vault or checking a web-login password never blocks the event loop (and the mounted-drive health checks
// that run on it). The derivation itself lives in Kdf.deriveSecretRaw, so there is no duplicated logic; the
// child lifecycle (parse -> dispatch -> done/error) lives once in WorkerRun.runChild. Import-safe outside a
// worker (runChild is a no-op with no parentPort).
require('./WorkerRun').runChild({ derive: (args) => require('./Kdf').deriveSecretRaw(args.passphrase, args.params) }, { label: 'key-derivation' });
