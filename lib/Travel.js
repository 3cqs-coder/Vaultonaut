'use strict';
// lib/Travel.js — OPTIONAL travel mode. Before you travel, hide your vaults from this app and lock everything,
// so a MANUAL inspection of the running app reveals nothing. A separate TRAVEL PASSWORD restores them later.
//
// What it stores: one encrypted slot (in a uniform SlotRegistry file, so the file does not reveal how much is
// hidden) holding the known-vault list and the per-vault settings that name vault paths — everything that would
// otherwise sit in plaintext in this app's own state. Enabling removes all of that from the live state and locks
// every vault; restoring puts it back. The vault folders on disk are never touched, so nothing can be lost: even
// if this registry were deleted, the vaults are still on disk and can be re-added by their folder.
//
// HONEST LIMITS (the UI must surface these plainly — this is not anti-forensics):
//   • It hides the POINTER in this app. It does NOT remove the encrypted data from your disk. The vault folders
//     are still there for anyone who lists the disk.
//   • It cannot defeat a forensic disk image, a snapshot/diff of your disk over time, a backup (Time Machine /
//     File History / cloud — which also keep the pre-travel state), or OS traces (recent files, thumbnails,
//     mount history, search indexes) written by the system outside this app.
//   • It is a control against INSPECTION of this app, not against forensics or the law. In many places you can
//     be compelled to disclose passwords, and concealing or wiping data during an inspection can itself be an
//     offense. The only robust protection at a border is to NOT CARRY the data — leave it at home and fetch it
//     over the network afterward (this tool can back up, mirror, or serve a vault to do exactly that).
//   • Do this calmly BEFORE you travel, never as a panic action in front of an inspector.

const SR = require('./SlotRegistry');

const SLOT_COUNT = 8;                 // a handful of fixed slots; the real one is indistinguishable among filler
const reg = SR.store('travel.json');

function hasHidden() { return reg.has(); }
function registryPath() { return reg.path(); }

// Stash a blob under the travel password. One real slot plus random filler.
async function enable(travelPassword, blob) {
	if (!travelPassword) throw new Error('A travel password is required.');
	const kdf = SR.newKdfParams();
	const K = await SR.deriveK(travelPassword, kdf);
	const slot = SR.encryptSlot(K, { v: 1, kind: 'travel', createdAt: new Date().toISOString(), blob });
	await reg.write(reg.record([slot], SLOT_COUNT, { kdf }));
}

// Read and decrypt the stashed blob with the travel password, WITHOUT deleting it — so a caller re-applies the
// blob to the live state first and only then calls clear(), and nothing is lost if it is interrupted. Returns
// null for a wrong password or no active travel mode.
async function restore(travelPassword) {
	if (!reg.has()) return null;
	let r; try { r = await reg.read(); } catch (_) { return null; }
	const K = await SR.deriveK(travelPassword, r.kdf);
	const slots = reg.slotBuffers(r);
	let found = null;
	for (let i = 0; i < slots.length; i++) { const o = SR.tryDecryptSlot(K, slots[i]); if (o && o.kind === 'travel' && found === null) found = o; } // no break: constant work
	return found ? (found.blob || {}) : null;
}

async function clear() { await reg.remove(); }

module.exports = { hasHidden, enable, restore, clear, registryPath };
