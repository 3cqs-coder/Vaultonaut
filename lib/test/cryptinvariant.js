'use strict';
// lib/test/cryptinvariant.js — locks the two invariants that keep vault confidentiality from ever silently
// weakening:
//   1) The engine crypt section ALWAYS encrypts file and directory names, and its builder rejects config-line
//      injection (a newline in any interpolated field could append arbitrary rclone directives). Pure string
//      building — no engine needed, so these checks always run.
//   2) A vault manifest whose name-encryption fields have been altered to a weaker mode is REFUSED on read, so a
//      corrupted or hand-tampered manifest fails with a clear message instead of building a config that no longer
//      matches the on-disk ciphertext. Needs the engine to create a real vault; skipped when it is unavailable.
//
// Run:  node lib/test/cryptinvariant.js

const os = require('os');
const path = require('path');
const fsp = require('fs').promises;
const crypto = require('crypto');
const Rclone = require('../Rclone');
const vdisk = require('../index');
const Vault = require('../Vault');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const threw = async (fn) => { try { await fn(); return false; } catch (_) { return true; } };
let workspace = null;

function testCryptSection() {
	// Fail-safe defaults: even with the name-encryption fields absent, the section still encrypts names.
	const def = Rclone.buildConfig({ cipherDir: '/data', passwordObscured: 'p', saltObscured: 's' });
	ok('crypt section defaults filename_encryption to standard', /\nfilename_encryption = standard\n/.test(def));
	ok('crypt section defaults directory_name_encryption to true', /\ndirectory_name_encryption = true\n/.test(def));

	// An explicit strong config renders as-is; a directory_name_encryption of false is the only value that turns it
	// off (matching the builder), and nothing a manifest could carry weakens filename encryption below "standard".
	const strong = Rclone.buildConfig({ cipherDir: '/d', passwordObscured: 'p', filenameEnc: 'standard', dirNameEnc: true });
	ok('crypt section keeps standard name encryption', /filename_encryption = standard/.test(strong) && /directory_name_encryption = true/.test(strong));

	// Config-line injection: a newline in ANY interpolated field must be rejected, not silently folded into the
	// remote definition (where it could add arbitrary engine directives).
	for (const field of ['cipherDir', 'passwordObscured', 'saltObscured', 'filenameEnc', 'filenameEncoding']) {
		const base = { cipherDir: '/d', passwordObscured: 'p', saltObscured: 's' };
		base[field] = 'x\ntype = local'; // a crafted second directive
		let rejected = false;
		try { Rclone.buildConfig(base); } catch (_) { rejected = true; }
		ok('crypt section rejects a newline injected into "' + field + '"', rejected);
	}
	// A carriage return is caught too (not only \n).
	ok('crypt section rejects a carriage return in the remote name', (() => { try { Rclone.cryptRemoteSection('a\rb', { cipherDir: '/d', passwordObscured: 'p' }); return false; } catch (_) { return true; } })());
}

async function testManifestInvariant() {
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('  (engine missing — skipping the manifest-tamper checks)'); return; }
	const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'vdisk-cryptinv-')); workspace = tmp;
	const src = path.join(tmp, 'src'); await fsp.mkdir(src);
	await fsp.writeFile(path.join(src, 'a.txt'), crypto.randomBytes(256));
	const v = path.join(tmp, 'Inv.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// A freshly created vault always satisfies the invariant.
	const m0 = await Vault.readManifest(v);
	ok('a new vault encrypts names by default', m0.crypt.filename_encryption === 'standard' && m0.crypt.directory_name_encryption === true);

	const mf = path.join(v, 'vault.json'), bak = path.join(v, '.vault.bak');
	const readRaw = async () => JSON.parse(await fsp.readFile(mf, 'utf8'));
	// Overwrite BOTH the manifest and its self-heal backup, so the read cannot silently recover the good copy and
	// mask the tamper — the invariant assertion itself must be what refuses it.
	const writeBoth = async (obj) => { const s = JSON.stringify(obj, null, 2); await fsp.writeFile(mf, s); try { await fsp.writeFile(bak, s); } catch (_) {} };

	// Weaken filename encryption -> refused on read.
	let raw = await readRaw(); raw.crypt.filename_encryption = 'off';
	await writeBoth(raw);
	ok('a manifest with weakened filename encryption is refused', await threw(() => Vault.readManifest(v)));

	// Disable directory-name encryption -> refused on read.
	raw = await readRaw(); raw.crypt.filename_encryption = 'standard'; raw.crypt.directory_name_encryption = false;
	await writeBoth(raw);
	ok('a manifest with directory-name encryption disabled is refused', await threw(() => Vault.readManifest(v)));
}

async function main() {
	testCryptSection();
	try { await testManifestInvariant(); }
	finally { if (workspace) await fsp.rm(workspace, { recursive: true, force: true }).catch(() => {}); }
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL CRYPT-INVARIANT CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
