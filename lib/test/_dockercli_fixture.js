'use strict';
// Test stand-in for vaultonaut.js, driven by docker/entrypoint.js via the VAULTONAUT_CLI override. It is a helper (the
// leading underscore keeps the runner from executing it as a test). Its behavior keys off argv and env:
//   - argv[2] === 'verify-self'  -> exit with VERIFY_EXIT (default 0), so a test can simulate a tampered bundle.
//   - else, if EXIT_CODE is set  -> exit with it at once, so a test can check exit-code propagation.
//   - else                       -> print READY, stay alive, and on SIGTERM/SIGINT write the signal name to the file
//                                    named by SIGNAL_MARKER and exit 0, so a test can check signal forwarding.
const fs = require('fs');

if (process.argv[2] === 'verify-self') { process.exit(parseInt(process.env.VERIFY_EXIT || '0', 10)); }
if (process.env.EXIT_CODE) { process.exit(parseInt(process.env.EXIT_CODE, 10)); }

const marker = process.env.SIGNAL_MARKER;
for (const sig of ['SIGTERM', 'SIGINT']) {
	process.on(sig, () => { try { if (marker) fs.writeFileSync(marker, sig); } catch (_) {} process.exit(0); });
}
const keep = setInterval(() => {}, 1000); // stay alive until signaled
if (keep.unref) { /* keep it referenced so the process lives */ }
process.stdout.write('READY\n');
