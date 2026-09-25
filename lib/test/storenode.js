'use strict';
// lib/test/storenode.js — the untrusted storage-node role: this machine offers space for OTHER people's vaults, holding
// only opaque ciphertext in per-client slots. It verifies the invariants that make it zero-knowledge and safe:
//   1. an invite creates its OWN random slot subfolder, and the connect code points at THAT slot's subpath (so clients
//      are isolated and can never read one another's data or the store root);
//   2. the node NEVER adopts the blobs — nothing is added to its vault list — so it never tries to open/mount them;
//   3. slots are listable, their usage measurable (for the advisory quota), and removable (with a path-separator guard
//      so a slot id can never escape the store root);
//   4. the serve reuses the SHARED transport (serveDirTransport) rather than a second copy, and serves the store root.
// Pure/deterministic (no engine, no network): storeInvite is fed a mock live-serve handle. Cross-platform.
//
// Run:  node lib/test/storenode.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-store-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.setDataDir(dataDir); // the supported override: internal dataDir()/storeDir()/vaultsDir() read this
	const Vault = require('../Vault');

	ok('the store root lives under the data dir, separate from owned vaults', Common.storeDir() === path.join(dataDir, 'store') && Common.storeDir() !== Common.vaultsDir());

	// A mock live-serve handle (as serveStore would return); storeInvite must not need a real network serve.
	const served = { url: 'https://host.example:7443/', user: 'u', pass: 'p', ca: '-----CERT-----' };
	const inv = await Vault.storeInvite(served, 'Friend’s laptop');
	ok('an invite returns a random slot and a connect code', !!inv.slot && inv.slot.length >= 12 && typeof inv.code === 'string' && inv.code.length > 0);
	ok('the invite creates the slot subfolder under the store root', fs.existsSync(path.join(Common.storeDir(), inv.slot)));
	// The code must point at the slot's SUBPATH, so the client is confined to its own subfolder.
	const parsed = Vault.parsePeerCode(inv.code);
	ok('the connect code carries the slot subpath (client is confined to its slot)', !!parsed && parsed.url === served.url + inv.slot + '/');
	ok('the connect code carries the pinned certificate and login', parsed.ca === served.ca && parsed.user === 'u' && parsed.password === 'p');

	// A second invite gets a DIFFERENT slot — clients never collide.
	const inv2 = await Vault.storeInvite(served, 'Phone');
	ok('a second invite gets a different, isolated slot', inv2.slot !== inv.slot && fs.existsSync(path.join(Common.storeDir(), inv2.slot)));

	// The node NEVER adopts the held blobs: no vault is ever registered by offering storage.
	const state = fs.existsSync(Common.statePath()) ? JSON.parse(await fsp.readFile(Common.statePath(), 'utf8')) : { vaults: [] };
	ok('offering storage never adds a vault to this node\'s list (never adopts the blobs)', !(state.vaults && state.vaults.length));

	// Slots are listable with their labels and usage.
	await fsp.writeFile(path.join(Common.storeDir(), inv.slot, 'blob.bin'), Buffer.alloc(2048));
	const slots = await Vault.listStoreSlots();
	ok('both slots are listed with their labels', slots.length === 2 && slots.some((s) => s.label === 'Friend’s laptop') && slots.some((s) => s.label === 'Phone'));
	const usage = await Vault.storeUsage();
	ok('store usage reports the slot count and total bytes held', usage.slots === 2 && usage.bytes >= 2048);

	// A slot id can never contain a path separator (no escaping the store root).
	let escaped = false; try { await Vault.removeStoreSlot('../evil'); } catch (_) { escaped = true; }
	ok('a slot id with a path separator is refused (no store-root escape)', escaped);

	// Removing a slot deletes its data and forgets it.
	await Vault.removeStoreSlot(inv.slot);
	ok('removing a slot deletes its subfolder and drops it from the list', !fs.existsSync(path.join(Common.storeDir(), inv.slot)) && (await Vault.listStoreSlots()).length === 1);

	// Source guards: serveStore reuses the shared transport and never adopts blobs.
	const src = fs.readFileSync(path.join(__dirname, '..', 'Vault.js'), 'utf8');
	ok('serveStore reuses the shared serveDirTransport (no duplicated serve transport)', /async function serveStore\([\s\S]{0,400}serveDirTransport\(dir,/.test(src));
	ok('serveStore never registers the store as a vault (no State.addVault in the storage-node role)', !/async function serveStore\([\s\S]{0,400}State\.addVault/.test(src) && !/async function storeInvite\([\s\S]{0,600}State\.addVault/.test(src));
	ok('serveVault and serveStore share one transport (serveVault delegates to serveDirTransport)', /async function serveVault\([\s\S]{0,1000}serveDirTransport\(abs,/.test(src));

	// Wiring: the role is enabled/managed by loopback-only setup routes, torn down on shutdown/lock/travel, and a
	// self-check advisory quota watches how full it gets.
	const idx = fs.readFileSync(path.join(__dirname, '..', 'webserver', 'index.js'), 'utf8');
	ok('starting the storage node is loopback-gated (refused over a network-exposed connection)', /app\.post\('\/api\/store-serve-start'[\s\S]{0,160}refuseOutboundIfExposed[\s\S]{0,120}startStoreServing/.test(idx));
	ok('minting an invite is loopback-gated and calls Vault.storeInvite', /app\.post\('\/api\/store-invite'[\s\S]{0,200}refuseOutboundIfExposed[\s\S]{0,200}Vault\.storeInvite/.test(idx));
	ok('slot listing and removal routes are registered', /app\.post\('\/api\/store-slots'[\s\S]{0,120}listStoreSlots/.test(idx) && /app\.post\('\/api\/store-slot-remove'[\s\S]{0,120}removeStoreSlot/.test(idx));
	ok('the storage serve is torn down on lock-all and travel and on shutdown', (idx.match(/stopStoreServing\(\)/g) || []).length >= 3);
	const sc = fs.readFileSync(path.join(__dirname, '..', 'SelfCheck.js'), 'utf8');
	ok('an advisory storage-node quota self-check is registered and only walks when a cap is set', /register\('storage_node_quota'[\s\S]{0,300}storeQuotaMB[\s\S]{0,200}if \(quotaMb <= 0\) return null/.test(sc));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL STORE-NODE CHECKS PASSED'));
	Common.setDataDir(null);
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
