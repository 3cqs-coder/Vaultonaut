'use strict';
// lib/PackWorker.js — builds a vault's portable container (the .vdisk zip) off the main thread. Packing streams
// the tree entry-by-entry (constant memory, one open file at a time), so doing it here keeps the long-running
// service's event loop clear during the CPU-bound compression (matching the self-healing and dispersal workers).
// The zip logic itself lives in Net.zipDir — this only wires it to the shared worker lifecycle. Progress ({ indeterminate | percent,
// label }) is streamed back to the caller, and the container marker is rebuilt here from Brand so nothing
// brand-specific is hardcoded.
const path = require('path');
const Net = require('./Net');
const Brand = require('./Brand');

require('./WorkerRun').runChild({
	pack: async ({ vaultDir, out, override }, progress) => {
		const marker = Buffer.from(JSON.stringify({ container: 1, tool: Brand.slug }));
		await Net.zipDir(vaultDir, out, { prefix: path.basename(vaultDir), extra: { [Net.CONTAINER_MARKER]: marker }, override: override || {}, onProgress: progress });
		return { file: out };
	}
}, { label: 'pack' });
