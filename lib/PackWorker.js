'use strict';
// lib/PackWorker.js — packs and UNPACKS a vault's portable container (the .vdisk zip) off the main thread. Both
// stream entry-by-entry (constant memory, one open file at a time), so doing this here keeps the long-running
// service's event loop clear during the CPU-bound work (matching the self-healing and dispersal workers). UNPACK
// also matters for isolation: it parses an archive that arrives from OUTSIDE (an imported/unpacked container is
// untrusted input), so running it in a worker contains a parser fault — a crash becomes a worker exit the shared
// lifecycle turns into a clean rejection, and a hang is bounded by the worker's idle/absolute watchdog — instead of
// reaching the main process. The zip logic itself lives in Net.zipDir / Net.unzip (with its entry-count, zip-slip,
// and inflation-bomb guards); this only wires it to the shared worker lifecycle. Progress ({ indeterminate |
// percent, label }) is streamed back to the caller, and the container marker is rebuilt here from Brand so nothing
// brand-specific is hardcoded.
const path = require('path');
const Net = require('./Net');
const Brand = require('./Brand');

require('./WorkerRun').runChild({
	pack: async ({ vaultDir, out, override }, progress) => {
		const marker = Buffer.from(JSON.stringify({ container: 1, tool: Brand.slug }));
		await Net.zipDir(vaultDir, out, { prefix: path.basename(vaultDir), extra: { [Net.CONTAINER_MARKER]: marker }, override: override || {}, onProgress: progress });
		return { file: out };
	},
	unpack: async ({ src, staging }, progress) => {
		const tops = await Net.unzip(src, staging, { onProgress: progress }); // Net.unzip keeps its own untrusted-input guards; the worker adds fault isolation
		return { tops };
	}
}, { label: 'pack' });
