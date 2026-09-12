'use strict';
// lib/test/tamperunknown.js — a baseline record this build cannot interpret (a bumped version or an unknown
// integrity scheme) must FAIL CLOSED on mount: it is surfaced as a tamper warning and the session is left
// untrusted, never silently accepted. A holder of a read/data credential can write such a record, so silently
// trusting it would suppress detection and quietly void a seal. Guards against that regression.
//
// Run:  node lib/test/tamperunknown.js   (needs the bundled engine)

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const vdisk = require('../index');
const { serializeBaselineAsync, parseBaselineAsync } = require('../Vault')._baselineFormat; // read/write the baseline in its real on-disk format (a header line + newline-delimited files), not a hand-rolled JSON.parse

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function bumpBaselineVersion(vaultDir, to) {
	const m = await vdisk.mount(vaultDir, { password: 'pw' });
	try {
		const snap = path.join(m.mountpoint, '.vaultsnapshot'); // the signed baseline record lives in the store
		const rec = await parseBaselineAsync(await fsp.readFile(snap, 'utf8'));
		rec.version = to;
		await fsp.writeFile(snap, await serializeBaselineAsync(rec), { mode: 0o600 });
	} finally { await vdisk.unmount(vaultDir); }
}

(async () => {
	const base = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-unk-'));
	const v = path.join(base, 'K.vault');
	try {
		await vdisk.create(v, { password: 'pw' });
		let m = await vdisk.mount(v, { password: 'pw' });
		await fsp.writeFile(path.join(m.mountpoint, 'doc.txt'), 'hello', { mode: 0o600 });
		await vdisk.unmount(v);
		await vdisk.seal(v, { password: 'pw' }); // strict, signed, deep baseline (the tripwire)

		m = await vdisk.mount(v, { password: 'pw' });
		ok('a clean sealed vault mounts with no false tamper warning', m.tamper == null);
		await vdisk.unmount(v);

		// ATTACK: bump the in-vault baseline record to a version this build cannot interpret.
		await bumpBaselineVersion(v, 9999);

		m = await vdisk.mount(v, { password: 'pw' });
		const t = m.tamper;
		ok('an unrecognized baseline version is SURFACED on mount, not silently trusted', !!t && t.kind === 'tamper');
		ok('the seal state is carried through, so the seal is never silently voided', !!t && t.sealed === true);
		await vdisk.unmount(v);
	} finally {
		for (const kv of await vdisk.listKnownVaults().catch(() => [])) { const p = kv.path || kv; if (typeof p === 'string' && p.includes(path.basename(base))) await vdisk.removeKnownVault(p).catch(() => {}); }
		await fsp.rm(base, { recursive: true, force: true }).catch(() => {});
	}

	console.log(failures ? ('\n' + failures + ' CHECK(S) FAILED') : '\nALL UNKNOWN-BASELINE CHECKS PASSED');
	process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
