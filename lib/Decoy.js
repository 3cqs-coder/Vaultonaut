'use strict';
// lib/Decoy.js — OPTIONAL, per-vault duress/decoy protection. A protected vault is paired with a separate
// DECOY vault; opening the protected vault with the decoy vault's password transparently opens the decoy
// instead of the real one. So a user compelled to unlock a vault can hand over the decoy password and reveal
// only harmless decoy contents. This is the honest analogue of a hidden-volume scheme for a folder-of-files
// vault: we cannot hide a second volume inside one vault's random-looking free space (there is none), so the
// decoy is a real, separate vault, and the pairing — not the vault — is what stays hidden.
//
// The deniable storage itself — one file of a fixed number of fixed-size, random-looking slots — is the shared
// SlotRegistry primitive. Here we give those slots MEANING:
//   • A MANAGER slot (opened by a manager password) holds the authoritative list of mappings, so the whole
//     registry can be rebuilt safely on every change — no slot is ever clobbered blind. For each mapping it
//     stores the real and decoy vault paths plus the decoy password's DERIVED key (never the password), so a
//     rebuild can recreate that mapping's duress slot without the password.
//   • A per-mapping DURESS slot (opened by the decoy vault's own password) lets the MOUNT path resolve a
//     decoy with only that password — no manager password needed. Resolution derives ONE Argon2id and trial-
//     decrypts EVERY slot with no short-circuit, so a wrong password and a decoy password do identical work.
//   • The remaining slots are random filler, indistinguishable from a real slot.
//
// Honest limits (surfaced in the disclosures): this hides a vault's CONTENTS under a one-time compelled
// unlock, NOT the existence of the vault (its name is still in your list), nor that encrypted data exists,
// nor filesystem metadata, backups, or OS indexes. A multi-snapshot adversary who sees your disk over time
// can still infer a hidden pairing from changing bytes. It is session-level deniability, and in key-
// disclosure jurisdictions revealing a decoy while a real vault provably exists may itself carry legal risk.

const path = require('path');
const Common = require('./Common');
const SR = require('./SlotRegistry');

const SLOT_COUNT = 16;                 // fixed for every registry — the number of decoys is invisible (up to this)
const MANAGER_PW_WRONG = 'The manager password is incorrect.'; // one wording for every manager-unlock failure
const reg = SR.store('registry.json');
// Serialize the whole read-modify-write of the registry WITHIN this process. setDecoy/removeDecoy read the
// authoritative mapping list, derive an Argon2id key (a wide await window), then rewrite the whole file — so
// without this, two concurrent changes in one process (a double-submit, or two tabs) could both read the old list
// and the later write would silently drop the other's mapping, leaving a vault the user believes is duress-
// protected unprotected. ACROSS processes (a CLI change while the service runs one, or two CLI invocations) the
// queue does not apply, so a monotonic `epoch` in the record guards that case: each write records epoch+1, and both
// mutators re-check the on-disk epoch right before writing and refuse if it moved — the fail-safe analogue of the
// cross-process lock the settings store uses, without a lock's deadlock risk. Reads (resolveDecoy/listMappings)
// need neither: the underlying write is atomic, so a concurrent reader sees the old or new file, never a torn one.
const regQueue = Common.serialQueue();

function registryPath() { return reg.path(); }
function hasRegistry() { return reg.has(); }
async function removeRegistry() { await reg.remove(); }

// Open the manager slot with the manager password. Runs ONE Argon2id and trial-decrypts EVERY slot with no
// short-circuit, then returns the manager payload (with its mappings) or null for a wrong password. The KDF
// params come from the registry so decoy passwords stay consistent across rebuilds.
async function loadManager(managerPassword) {
	const r = await reg.read();
	const Km = await SR.deriveK(managerPassword, r.kdf);
	const slots = reg.slotBuffers(r);
	let manager = null;
	// A record written by a NEWER format (o.v > 1) deliberately gets NO visible "update the app" refuse-forward here,
	// unlike every other on-disk format in the project. This feature is DENIABLE by design: surfacing a newer-version
	// notice would reveal that a decoy/duress registry exists, defeating its whole purpose. A future format simply
	// fails the kind/mapping match below and reads as "no decoy" — the correct, silent, fail-safe outcome.
	manager = SR.findSlot(Km, slots, (o) => o.kind === 'manager' && Number(o.v) === 1); // constant-work scan (no early break), so the registry stays deniable
	if (!manager) return null;
	return { mappings: Array.isArray(manager.mappings) ? manager.mappings : [], kdf: r.kdf, Km, epoch: Number(r.epoch) || 0 };
}
// The registry's write counter, or 0 when there is no registry. Used for the optimistic conflict check below.
async function currentEpoch() { try { const r = await reg.read(); return Number(r.epoch) || 0; } catch (_) { return 0; } }

// Rebuild the whole registry from the authoritative mapping list: the manager slot, one duress slot per
// mapping (recreated from the mapping's stored derived key — no password needed), and random filler to the
// fixed count, all shuffled. A full rebuild means a change can never clobber another mapping's slot.
async function rebuild(Km, mappings, kdf, epoch) {
	const manager = { v: 1, kind: 'manager', createdAt: new Date().toISOString(), mappings };
	const slots = [SR.encryptSlot(Km, manager)];
	for (const m of mappings) slots.push(SR.encryptSlot(Buffer.from(m.duressK, 'base64'), { v: 1, kind: 'duress', realVault: m.realVault, decoyVault: m.decoyVault }));
	if (slots.length > SLOT_COUNT) throw new Error('Too many decoy pairings for the registry (max ' + (SLOT_COUNT - 1) + ').');
	// `epoch` is a monotonic write counter carried in the record (outside any slot, so it reveals nothing about the
	// mappings). setDecoy/removeDecoy read it before deriving and re-check it right before this write, so a change
	// made by ANOTHER PROCESS during the (slow) key derivation is caught and refused rather than silently clobbered.
	await reg.write(reg.record(slots, SLOT_COUNT, { kdf, epoch: Number(epoch) || 0 }));
}
// Fail-safe conflict check: refuse to overwrite the registry if its write counter changed since we read it (another
// process paired/removed a decoy while we were deriving). The residual window between this check and the atomic
// rename is sub-millisecond, versus the seconds-long Argon2id derivation this protects. The caller retries.
async function assertUnchanged(baseEpoch) {
	if ((await currentEpoch()) !== baseEpoch) throw new Error('The decoy configuration was changed elsewhere a moment ago. Nothing was overwritten — try again.');
}

// Pair a real vault with a decoy vault, triggered by the decoy vault's own password. Creates the registry on
// first use (the manager password is set then). Requires the correct manager password thereafter. Replaces any
// existing pairing for the same real vault. The real and decoy vault MUST differ, and the decoy password (which
// is the decoy vault's password) MUST differ from the manager password.
async function setDecoy({ realVault, decoyVault, decoyPassword, managerPassword, fingerprints } = {}) {
	if (!realVault || !decoyVault) throw new Error('A real vault and a decoy vault are both required.');
	if (Common.samePath(realVault, decoyVault)) throw new Error('The decoy vault must be different from the real vault.');
	if (!decoyPassword) throw new Error('The decoy vault\'s password is required (it is the duress trigger).');
	if (!managerPassword) throw new Error('A manager password is required to manage decoys.');
	if (String(decoyPassword) === String(managerPassword)) throw new Error('The manager password must differ from the decoy vault\'s password.');
	return regQueue(async () => {
		let mappings, kdf, Km, baseEpoch;
		if (hasRegistry()) {
			const m = await loadManager(managerPassword);
			if (!m) throw new Error(MANAGER_PW_WRONG);
			mappings = m.mappings; kdf = m.kdf; Km = m.Km; baseEpoch = m.epoch;
		} else {
			kdf = SR.newKdfParams(); Km = await SR.deriveK(managerPassword, kdf); mappings = []; baseEpoch = 0;
		}
		const duressK = (await SR.deriveK(decoyPassword, kdf)).toString('base64');
		mappings = mappings.filter(x => !Common.samePath(x.realVault, realVault));
		// `fingerprints` is an OPAQUE record the caller (the vault layer) computes from the paired vaults' public
		// manifests, so the manager-authenticated list can later detect a pairing that has silently gone stale (a
		// vault moved/replaced, or the decoy's keys changed). Decoy neither reads nor interprets it — it just
		// travels in the manager slot's mapping list and is handed back by listMappings.
		mappings.push({ realVault: path.resolve(realVault), decoyVault: path.resolve(decoyVault), duressK, fingerprints: fingerprints || null });
		await assertUnchanged(baseEpoch);
		await rebuild(Km, mappings, kdf, baseEpoch + 1);
		return { paired: true };
	});
}

// Remove the decoy pairing for a real vault. Requires the manager password. Removes the whole registry when
// the last pairing is gone.
async function removeDecoy({ realVault, managerPassword } = {}) {
	if (!hasRegistry()) return { removed: false };
	return regQueue(async () => {
		if (!hasRegistry()) return { removed: false };
		const m = await loadManager(managerPassword);
		if (!m) throw new Error(MANAGER_PW_WRONG);
		const mappings = m.mappings.filter(x => !Common.samePath(x.realVault, realVault));
		if (mappings.length === m.mappings.length) return { removed: false };
		if (mappings.length === 0) { await assertUnchanged(m.epoch); await removeRegistry(); return { removed: true, empty: true }; }
		await assertUnchanged(m.epoch);
		await rebuild(m.Km, mappings, m.kdf, m.epoch + 1);
		return { removed: true };
	});
}

// List the decoy pairings (real → decoy vault paths). Requires the manager password — this is the hidden
// management view. Returns null for a wrong password.
async function listMappings(managerPassword) {
	// Deniability: "no registry" must be indistinguishable from "wrong password" — the same result AND the same
	// timing — or this endpoint becomes an oracle for whether any decoy is configured. With no registry, still
	// burn an equivalent Argon2id derivation (default params, a fresh salt) and return the same failure as a wrong
	// password, rather than returning [] instantly and revealing that nothing is set up.
	if (!hasRegistry()) { try { await SR.deriveK(String(managerPassword || ''), SR.newKdfParams()); } catch (_) {} return null; }
	const m = await loadManager(managerPassword);
	if (!m) return null;
	return m.mappings.map(x => ({ realVault: x.realVault, decoyVault: x.decoyVault, fingerprints: x.fingerprints || null }));
}

// MOUNT-PATH resolution: given a real vault and an entered password, return the decoy vault to open instead,
// or null. Runs ONE Argon2id and trial-decrypts EVERY slot with no short-circuit (a wrong password and a
// decoy password do identical work). Only a duress slot whose realVault matches redirects — so a decoy
// password only ever redirects the vault it was paired with.
async function resolveDecoy(realVault, password) {
	if (!hasRegistry()) return null;
	let r; try { r = await reg.read(); } catch (_) { return null; }
	const K = await SR.deriveK(password, r.kdf);
	const slots = reg.slotBuffers(r);
	const want = path.resolve(realVault);
	// As in loadManager: a newer-format record (o.v > 1) is silently skipped, never surfaced — deniability forbids a
	// visible refuse-forward here. Matching v===1 explicitly also stops a future v2 payload's fields being misread.
	// The constant-work scan (no early break) keeps the lookup timing independent of whether a mapping matches.
	const found = SR.findSlot(K, slots, (o) => o.kind === 'duress' && Number(o.v) === 1 && Common.samePath(o.realVault, want));
	return found ? found.decoyVault : null;
}

module.exports = {
	hasRegistry, setDecoy, removeDecoy, listMappings, resolveDecoy, removeRegistry, registryPath, SLOT_COUNT,
};
