'use strict';
// lib/test/mobile-reader.js — proves the portable, browser-ready decryptor (public/mobile/crypt-reader.js)
// opens a real vault BYTE-FOR-BYTE. It creates a vault with the actual engine, mints a WEB read capability
// (revealed salt + read key), then — using ONLY the portable reader and its vendored primitives, no engine —
// decrypts every encrypted file's NAME and CONTENT straight off the ciphertext on disk and checks each one
// against the original. This is the strongest possible check: the exact code a phone runs is validated
// against ciphertext the real engine produced. It also confirms the de-obscure (reveal) matches the engine.
//
// Run:  node lib/test/mobile-reader.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

// Walk a directory, returning every file path relative to root (POSIX separators).
async function walk(root, rel = '') {
	const out = [];
	for (const ent of await fsp.readdir(path.join(root, rel), { withFileTypes: true })) {
		const r = rel ? rel + '/' + ent.name : ent.name;
		if (ent.isDirectory()) out.push(...await walk(root, r));
		else out.push(r);
	}
	return out;
}

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-mobile-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Rclone = require('../Rclone');
	const reader = require('../webserver/public/mobile/crypt-reader.js');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }
	const bin = d.engine.rclone;

	// The de-obscure helper must reverse the engine's own obscure exactly.
	const secret = 'a salt / password with spaces and symbols !@#$%^&*()';
	const obscured = await Rclone.obscure(bin, secret);
	ok('reveal() reverses the engine obscure exactly', Rclone.reveal(obscured) === secret);

	// A vault with deliberately awkward files: empty, tiny, exactly one block, just over one block, a name
	// whose length is a multiple of the cipher block (forces a full extra pad block), and a nested path.
	const src = path.join(tmp, 'src');
	const files = {
		'empty.bin': Buffer.alloc(0),
		'small.txt': Buffer.from('hello world — a small file', 'utf8'),
		'exactly64k.bin': Buffer.alloc(65536, 7),
		'justover.bin': Buffer.concat([Buffer.alloc(65536, 3), Buffer.from('tail bytes past one block')]),
		'sixteen_chars.md': Buffer.from('name length is a multiple of sixteen', 'utf8'), // 16-char name
		'folder/nested/deep data.txt': Buffer.from('deep in a couple of encrypted folders', 'utf8'),
	};
	for (const [rel, buf] of Object.entries(files)) {
		const p = path.join(src, rel); await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.writeFile(p, buf);
	}
	const v = path.join(tmp, 'Phone.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// Mint a WEB read capability and parse it exactly as a browser would.
	const web = await vdisk.makeWebReadCap(v, { password: 'pw1' });
	ok('a web read capability is minted', /^vdwrc1\./.test(web.token));
	const cap = JSON.parse(Buffer.from(web.token.split('.')[1], 'base64url').toString('utf8'));
	ok('the capability carries a read key, a revealed salt, and the standard filename mode', !!cap.key && !!cap.salt && cap.fn === 'standard');

	// From here on: NO engine. Derive keys and decrypt straight off the ciphertext on disk.
	const keys = reader.deriveKeys(cap.key, cap.salt);
	const cipherRoot = path.join(v, 'data');
	const encPaths = await walk(cipherRoot);

	// Build a map of decrypted-relative-path -> decrypted content for every encrypted file present.
	const got = {};
	for (const encRel of encPaths) {
		let name;
		try { name = reader.decryptPath(keys.nameKey, keys.nameTweak, encRel, cap.dn); }
		catch (e) { continue; } // engine-internal sidecars (e.g. a self-test canary) are not our concern
		const cipher = await fsp.readFile(path.join(cipherRoot, encRel));
		got[name] = reader.decryptContent(keys.dataKey, cipher);
	}

	let allNames = true, allContent = true, allSizes = true;
	for (const [rel, buf] of Object.entries(files)) {
		const g = got[rel];
		if (!g) { allNames = false; console.log('     (missing after decrypt: ' + rel + ')'); continue; }
		if (reader.decryptedSize((await fsp.readFile(path.join(cipherRoot, encPathFor(encPaths, keys, rel, cap.dn)))).length) !== buf.length) allSizes = false;
		if (Buffer.from(g).length !== buf.length || !Buffer.from(g).equals(buf)) allContent = false;
	}
	ok('every file name decrypts to the original (including a nested path and a block-aligned name)', allNames);
	ok('every file content decrypts byte-for-byte (empty, tiny, one block, over one block)', allContent);
	ok('decryptedSize() predicts the plaintext length from the ciphertext length', allSizes);

	// A tampered ciphertext byte must fail the authentication, never return wrong plaintext.
	const target = encPaths.find(p => { try { return reader.decryptPath(keys.nameKey, keys.nameTweak, p, cap.dn) === 'small.txt'; } catch (_) { return false; } });
	const cbytes = new Uint8Array(await fsp.readFile(path.join(cipherRoot, target)));
	cbytes[cbytes.length - 1] ^= 0xff;
	let rejected = false; try { reader.decryptContent(keys.dataKey, cbytes); } catch (_) { rejected = true; }
	ok('a single flipped ciphertext byte is rejected, not silently mis-decrypted', rejected);

	return done();
}

// Find the encrypted path on disk whose decrypted name equals rel (small helper for the size check).
function encPathFor(encPaths, keys, rel, dn) {
	const reader = require('../webserver/public/mobile/crypt-reader.js');
	return encPaths.find(p => { try { return reader.decryptPath(keys.nameKey, keys.nameTweak, p, dn) === rel; } catch (_) { return false; } });
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-READER CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
