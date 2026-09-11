'use strict';
// lib/SlotRegistry.js — a small, shared, uniform "slot registry": ONE file of a FIXED number of fixed-SIZE
// slots, each indistinguishable from random without its key (a padded, AEAD-encrypted blob). Which slots are
// real, and how many, is invisible from the file. It is the deniable-storage primitive behind two features —
// the per-vault decoy pairings and travel mode — kept in one place so the crypto is written and reviewed once.
//
// A slot is: hkdfSalt(32) || iv(12) || AES-256-GCM(padded-plaintext) || tag(16). Each write draws a fresh HKDF
// salt (so a per-write subkey) and a fresh IV. Reading trial-decrypts every slot with a candidate key and no
// short-circuit, so a wrong key and a real key do identical work. The plaintext is padded to a fixed size, so
// every slot is byte-identical in length whatever it holds.
//
// This is deliberately format-STABLE: the sizes, the AEAD, and the HKDF info string below must not change, or
// registries written by earlier versions would stop opening. New callers reuse these exact parameters.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const Common = require('./Common');
const Kdf = require('./Kdf');

const PLAINTEXT_SIZE = 16384;                 // uniform per-slot payload size (headroom for long path lists)
const HKDF_SALT_LEN = 32, IV_LEN = 12, TAG_LEN = 16;
const SLOT_LEN = HKDF_SALT_LEN + IV_LEN + PLAINTEXT_SIZE + TAG_LEN;
const AEAD = 'aes-256-gcm';
const HKDF_INFO = Buffer.from('registry-slot-v1');   // STABLE — do not change (would break existing registries)
const SUPPORTED_V = 1; // the on-disk registry format this build reads and writes (see record())

// Is a parsed registry record a format this build actually understands? A future version may bump `v`, change the
// AEAD, or resize the slots. This build must NEVER trial-decrypt such a file with its OWN cipher and slot size —
// that would be a silent misread. Refusing forward keeps that fail-closed. Older files predate the `v`/`aead`/
// `slotSize` fields, so a MISSING field is accepted (treated as the current format); only a PRESENT field that
// disagrees is refused. The refusal is deliberately silent (an unreadable file, indistinguishable from a wrong key
// or corruption) so it never reveals to a coercer that a newer-format deniable registry exists — the callers already
// treat an unreadable registry as "nothing here".
function isSupportedRecord(reg) {
	if (!reg || typeof reg !== 'object') return false;
	if (reg.v != null && !(Number(reg.v) <= SUPPORTED_V)) return false; // a newer (or non-numeric) version → refuse forward
	if (reg.aead != null && reg.aead !== AEAD) return false;            // a cipher this build does not implement
	if (reg.slotSize != null && Number(reg.slotSize) !== SLOT_LEN) return false; // slots of a different size
	return true;
}

// KDF parameters (the vault KDF's Argon2id, low-memory profile) with a fresh per-registry salt.
function newKdfParams() { return Kdf.defaultParams('standard'); }
async function deriveK(credential, params) { return Kdf.deriveKey(String(credential || ''), params); }

// Pad a payload's JSON to the fixed plaintext size (4-byte big-endian length prefix + bytes + zero fill).
function pad(str) {
	const b = Buffer.from(String(str), 'utf8');
	if (b.length + 4 > PLAINTEXT_SIZE) throw new Error('Registry payload too large to fit one slot.');
	const out = Buffer.alloc(PLAINTEXT_SIZE); out.writeUInt32BE(b.length, 0); b.copy(out, 4); return out;
}
function unpad(buf) { const n = buf.readUInt32BE(0); if (n < 0 || n + 4 > buf.length) return null; return buf.subarray(4, 4 + n).toString('utf8'); }

// Encrypt one JS object into a fixed-size slot buffer.
function encryptSlot(K, obj) {
	const hkdfSalt = crypto.randomBytes(HKDF_SALT_LEN);
	const slotKey = Buffer.from(crypto.hkdfSync('sha256', K, hkdfSalt, HKDF_INFO, 32));
	const iv = crypto.randomBytes(IV_LEN);
	const c = crypto.createCipheriv(AEAD, slotKey, iv, { authTagLength: TAG_LEN });
	const ct = Buffer.concat([c.update(pad(JSON.stringify(obj))), c.final()]);
	return Buffer.concat([hkdfSalt, iv, ct, c.getAuthTag()]);
}
// Try to decrypt a slot with K. Returns the payload object, or null. Never throws.
function tryDecryptSlot(K, slot) {
	try {
		if (!Buffer.isBuffer(slot) || slot.length !== SLOT_LEN) return null;
		const hkdfSalt = slot.subarray(0, HKDF_SALT_LEN);
		const iv = slot.subarray(HKDF_SALT_LEN, HKDF_SALT_LEN + IV_LEN);
		const ct = slot.subarray(HKDF_SALT_LEN + IV_LEN, HKDF_SALT_LEN + IV_LEN + PLAINTEXT_SIZE);
		const tag = slot.subarray(SLOT_LEN - TAG_LEN);
		const slotKey = Buffer.from(crypto.hkdfSync('sha256', K, hkdfSalt, HKDF_INFO, 32));
		const d = crypto.createDecipheriv(AEAD, slotKey, iv, { authTagLength: TAG_LEN });
		d.setAuthTag(tag);
		const pt = Buffer.concat([d.update(ct), d.final()]);
		const json = unpad(pt); if (json == null) return null;
		return JSON.parse(json);
	} catch (_) { return null; }
}
// Try to decrypt EVERY slot with K and return the first decrypted payload that satisfies `match`, scanning ALL
// slots with NO early break — so the work (and thus the timing) is identical whether a match is absent, is the
// first slot, or is the last. That constant-work discipline is what keeps the decoy, duress, and travel registries
// DENIABLE: an early break would leak, through timing, whether a matching secret exists and roughly where. The
// three registries share this one helper so a future edit cannot add a `break` to just one copy and silently
// reintroduce the oracle. `match` is a cheap predicate over the decrypted object; the expensive per-slot decrypt
// runs unconditionally for every slot regardless of the outcome.
function findSlot(K, slots, match) {
	let found = null;
	for (let i = 0; i < slots.length; i++) { const o = tryDecryptSlot(K, slots[i]); if (o && found === null && match(o)) found = o; }
	return found;
}
function randomSlot() { return crypto.randomBytes(SLOT_LEN); } // indistinguishable filler
function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }

// A file-backed store of slots. `fileName` lives under the data directory; a one-generation `.bak` guards a
// torn write. Callers own the slot semantics (which keys open which slots); this handles bytes and files.
function store(fileName) {
	const filePath = () => path.join(Common.dataDir(), fileName);
	const bakPath = () => filePath() + '.bak';
	return {
		path: filePath,
		has() { try { return fs.existsSync(filePath()); } catch (_) { return false; } },
		// A corrupt/truncated primary falls back to the backup; a genuinely missing file (ENOENT) is rethrown. A
		// record whose declared format this build does not understand (a newer `v`/`aead`/`slotSize`) is refused
		// forward — treated exactly like a corrupt file — so a newer registry is never trial-decrypted with this
		// build's cipher and slot size. If only the primary is newer (mid-upgrade), a still-supported backup wins.
		async read() {
			const parse = (buf) => { const reg = JSON.parse(buf); if (!isSupportedRecord(reg)) throw new Error('unsupported-registry-format'); return reg; };
			try { return parse(await fsp.readFile(filePath(), 'utf8')); }
			catch (e) { if (e.code === 'ENOENT') throw e; try { return parse(await fsp.readFile(bakPath(), 'utf8')); } catch (_) { throw e; } }
		},
		slotBuffers(reg) { return ((reg && reg.slots) || []).map(s => { try { return Buffer.from(s, 'base64'); } catch (_) { return Buffer.alloc(0); } }); },
		async write(reg) {
			await fsp.mkdir(Common.dataDir(), { recursive: true });
			try { if (fs.existsSync(filePath())) await fsp.copyFile(filePath(), bakPath()); } catch (_) {}
			await Common.writeJsonAtomic(filePath(), reg, { fsync: true, mode: 0o600 });
		},
		async remove() { await fsp.rm(filePath(), { force: true }); await fsp.rm(bakPath(), { force: true }); },
		// Serialize a set of slot buffers into the on-disk record, padded with random filler to `count` and shuffled.
		record(slots, count, extra) {
			const out = slots.slice();
			if (out.length > count) throw new Error('Too many slots for this registry.');
			while (out.length < count) out.push(randomSlot());
			shuffle(out);
			return Object.assign({ v: SUPPORTED_V, aead: AEAD, slotCount: count, slotSize: SLOT_LEN, slots: out.map(b => b.toString('base64')) }, extra || {});
		},
	};
}

module.exports = { newKdfParams, deriveK, encryptSlot, tryDecryptSlot, findSlot, randomSlot, store, isSupportedRecord, PLAINTEXT_SIZE, SLOT_LEN, SUPPORTED_V }; // shuffle is internal-only (used by store); not exported
