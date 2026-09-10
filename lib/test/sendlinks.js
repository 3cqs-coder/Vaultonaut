'use strict';
// lib/test/sendlinks.js — "Send" links. Two layers:
//   1) the in-memory store (lib/webserver/sendLinks.js): expiry, a view limit that really limits, optional link
//      password (constant-time), fail-closed redemption, size + entry caps — all without a vault.
//   2) end to end with a real vault: Vault.sealItemForSend seals ONE item under a fresh key; the store keeps only
//      the ciphertext; redeeming returns it; decrypting with the returned key (Node's AES-GCM, the exact layout the
//      recipient's Web Crypto uses) reproduces the original item; and the key never appears in what the store holds.
// Needs the engine + a mount driver for layer 2 (secure notes live in the mount); layer 1 is pure and always runs.
//
// Run:  node lib/test/sendlinks.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const crypto = require('crypto');
const { createSendStore } = require('../webserver/sendLinks');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function storeTests() {
	let t = 1000;
	const store = createSendStore({ now: () => t });
	// View-once: one redemption works, the second is gone.
	const a = store.create({ ciphertext: 'CT-A', meta: { kind: 'item' }, ttlMs: 60000, maxViews: 1 });
	ok('create returns an id, expiry, and the view limit', !!a.id && a.maxViews === 1 && a.expiresAt === t + 60000);
	const r1 = store.redeem(a.id);
	ok('a view-once link redeems once, returning the ciphertext', r1.ciphertext === 'CT-A' && r1.remaining === 0);
	ok('a view-once link cannot be redeemed again (gone)', store.redeem(a.id).gone === true);

	// View limit of 3 really limits to 3.
	const b = store.create({ ciphertext: 'CT-B', ttlMs: 60000, maxViews: 3 });
	let served = 0; for (let i = 0; i < 5; i++) { if (store.redeem(b.id).ciphertext) served++; }
	ok('a 3-view link serves exactly three times, then is gone', served === 3);

	// Expiry (the store floors a TTL at 1 minute, so use that and step past it).
	const c = store.create({ ciphertext: 'CT-C', ttlMs: 60000, maxViews: 10 });
	t += 61000;
	ok('an expired link is gone even with views remaining', store.redeem(c.id).gone === true);

	// Link password (constant-time compare): wrong password is refused, right one works, and info reveals only that
	// a password is needed (never the ciphertext).
	const pwHash = crypto.createHash('sha256').update('open-sesame', 'utf8').digest('hex');
	const d = store.create({ ciphertext: 'CT-D', ttlMs: 60000, maxViews: 5, pwHash });
	ok('info says a password is needed and never leaks the ciphertext', store.info(d.id).needsPassword === true && !JSON.stringify(store.info(d.id)).includes('CT-D'));
	ok('a wrong link password is refused without spending a view', store.redeem(d.id, 'nope').badPassword === true && store.info(d.id).remaining === 5);
	ok('the correct link password releases the ciphertext', store.redeem(d.id, 'open-sesame').ciphertext === 'CT-D');

	// Caps: oversize ciphertext and too many entries are refused.
	let tooBig = false; try { store.create({ ciphertext: 'x'.repeat(store.MAX_CIPHERTEXT_BYTES + 1), ttlMs: 1000, maxViews: 1 }); } catch (_) { tooBig = true; }
	ok('an oversize item is refused (no memory blowup)', tooBig);
	ok('an unknown id is gone', store.redeem('nope').gone === true);
	ok('revoke removes a link', (() => { const e = store.create({ ciphertext: 'CT-E', ttlMs: 60000, maxViews: 1 }); store.revoke(e.id); return store.redeem(e.id).gone === true; })());
}

let tmp = null;
async function endToEnd() {
	const vdisk = require('../index');
	const Kdf = require('../Kdf');
	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping the end-to-end send checks.'); return; }
	if (!d.driver.ok) { console.log('No mount driver — skipping the end-to-end send checks.'); return; }
	const src = path.join(tmp, 'src'); await fsp.mkdir(src, { recursive: true });
	await fsp.writeFile(path.join(src, 'a.txt'), 'x');
	const v = path.join(tmp, 'Send.vault'); await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });
	const cacheDir = path.join(tmp, 'cache');
	await vdisk.mount(v, { password: 'pw1', cacheDir });
	try {
		const saved = await vdisk.noteSave(v, { title: 'Shared login', type: 'login', note: 'for the contractor', fields: [
			{ id: 'u', kind: 'text', label: 'Username', value: 'guest' },
			{ id: 'p', kind: 'password', label: 'Password', value: 'send-me-safely-42' } ] });
		const sealed = await vdisk.sealItemForSend(v, { id: saved.id });
		ok('sealItemForSend returns ciphertext, a fresh key, and minimal meta (no title)', !!sealed.ciphertext && !!sealed.key && sealed.meta.kind === 'item' && sealed.meta.title === undefined);
		ok('the sealed ciphertext contains no plaintext of the item', !Buffer.from(sealed.ciphertext, 'base64').toString('latin1').includes('send-me-safely-42') && !sealed.ciphertext.includes('Shared login'));

		// The store keeps ONLY the ciphertext — never the key.
		const store = createSendStore();
		const rec = store.create({ ciphertext: sealed.ciphertext, meta: sealed.meta, ttlMs: 60000, maxViews: 1 });
		ok('what the store holds does not contain the key', !JSON.stringify([...Object.values(store)]).includes(sealed.key) && store.info(rec.id).remaining === 1);

		// The recipient decrypts with the key from the link fragment. Node's AES-GCM here mirrors the browser's Web
		// Crypto: iv is the first 12 bytes, then ciphertext+tag — the exact layout Kdf.wrapSecret wrote.
		const got = store.redeem(rec.id);
		const gcmOpen = (b64, keyB64url) => { const buf = Buffer.from(b64, 'base64'); const kb = Buffer.from(keyB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); const iv = buf.subarray(0, 12), tag = buf.subarray(buf.length - 16), ct = buf.subarray(12, buf.length - 16); const dc = crypto.createDecipheriv('aes-256-gcm', kb, iv); dc.setAuthTag(tag); return Buffer.concat([dc.update(ct), dc.final()]).toString('utf8'); };
		const item = JSON.parse(gcmOpen(got.ciphertext, sealed.key));
		ok('the recipient key decrypts the ciphertext to the original item', item.title === 'Shared login' && item.type === 'login' && item.note === 'for the contractor' && item.fields[1].value === 'send-me-safely-42');
		ok('Kdf.unwrapSecret opens the same ciphertext with the raw key (round-trip parity)', JSON.parse(Kdf.unwrapSecret(sealed.ciphertext, Buffer.from(sealed.key.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))).title === 'Shared login');
	} finally { await vdisk.unmount(v, {}).catch(() => {}); }
	await vdisk.removeKnownVault(v).catch(() => {});
}

async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-sendlinks-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	storeTests();
	await endToEnd();
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL SEND-LINK CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}
main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
