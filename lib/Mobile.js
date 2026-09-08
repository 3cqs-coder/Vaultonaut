'use strict';
// lib/Mobile.js — in-process sessions for mobile access. A mobile session lets a phone pull ONE vault's
// CIPHERTEXT (never plaintext — the server does not decrypt) and decrypt it locally in the browser with the
// portable reader. Everything here is deliberately EPHEMERAL and in-memory: a session holds a short-lived
// bearer token (kept only as a hash), the vault's ciphertext root, and the web read capability the phone
// redeems once. Nothing is written to disk, so a bearer secret never lands at rest and a restart simply ends
// every session (the user re-pairs). The web read capability itself IS recorded in the vault's signed share
// roster (by makeWebReadCap), so an owner can still see and revoke the decryption grant.
//
// Security model (fail-closed throughout):
//   - The session, not any request field, binds the one vault. A caller cannot pivot vaults.
//   - The bearer token is 256-bit, compared in constant time against a stored hash.
//   - Pairing uses a SHORT one-time code (small enough to QR reliably) exchanged ONCE for the heavy material.
//   - Every file read is contained to the vault's ciphertext root (lexical + realpath + symlink rejection).
//   - Sessions and pairing codes expire; expired entries are swept lazily on every access.

const crypto = require('crypto');
const path = require('path');
const fsp = require('fs').promises;
const Vault = require('./Vault');
const Common = require('./Common');

// Bound every filesystem probe on a mobile request: the ciphertext store can sit on a removable or network drive
// that wedges, where a plain readdir/lstat/realpath would block the request and pin a libuv threadpool slot. A
// timeout fails the single probe fast (skipped in the listing, a clean error in resolveFile) instead of hanging.
const FS_PROBE_MS = 4000;
const bounded = (p) => Common.withTimeout(p, FS_PROBE_MS);

const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;   // a phone session lasts 12h by default, then the phone re-pairs
const LOCAL_TTL_MS = 2 * 60 * 60 * 1000;      // a LOCAL in-app viewer session is short-lived: it holds the decryption
                                              // key in memory only while you are viewing, and the viewer also ends it
                                              // when its tab closes (see /m/stop), so it should not linger for long
const PAIR_TTL_MS = 10 * 60 * 1000;           // the one-time pairing code is good for 10 minutes

const sessions = new Map();   // sessionId -> { vaultId, cipherRoot, cipherRootReal, bearerHash, webCap, name, createdAt, expiresAt }
const pairings = new Map();   // code -> { sessionId, expiresAt } (single use)

// A short, human-and-QR-friendly one-time code: ~50 bits of entropy in Crockford-ish base32, grouped. Each of
// the 10 characters draws 5 bits from its OWN random byte, so all 50 bits are independent (a single shared
// buffer indexed by i % length would repeat, correlating characters and cutting the real entropy).
function shortCode() {
	const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
	const b = crypto.randomBytes(10); let out = '';
	for (let i = 0; i < 10; i++) out += A[b[i] & 31]; // 10 chars x 5 bits = ~50 bits
	return out.slice(0, 5) + '-' + out.slice(5);
}

function sweep() {
	const now = Date.now();
	for (const [k, v] of pairings) if (v.expiresAt <= now) pairings.delete(k);
	for (const [k, v] of sessions) if (v.expiresAt <= now) sessions.delete(k);
}

// Start a mobile-access session for a vault. Returns the one-time pairing code and the session id (for the
// desktop UI); the heavy material (read cap + bearer) is handed out only when the phone redeems the code.
async function start(vaultDir, { password, ttlMs, local } = {}) {
	sweep();
	// `local` is the in-app viewer opened in this machine's own browser: an ephemeral session whose grant is NOT
	// recorded in the vault's access roster (record:false), so viewing files never accumulates entries there.
	const prep = await Vault.mobilePrepare(vaultDir, { password, record: !local });
	const cipherRootReal = await bounded(fsp.realpath(prep.cipherRoot)).catch(() => prep.cipherRoot); // bounded: the store may sit on a wedgeable drive, like the per-request probes below
	const sessionId = crypto.randomBytes(16).toString('hex');
	const bearer = crypto.randomBytes(32).toString('base64url'); // 256-bit
	const now = Date.now();
	const expiresAt = now + (Number(ttlMs) > 0 ? Number(ttlMs) : (local ? LOCAL_TTL_MS : DEFAULT_TTL_MS));
	sessions.set(sessionId, { vaultId: prep.vaultId, sid: prep.sid, cipherRoot: prep.cipherRoot, cipherRootReal, bearerHash: Common.sha256(String(bearer)), webCap: prep.webCap, name: prep.name, local: !!local, createdAt: now, expiresAt, _bearer: bearer });
	const code = shortCode();
	pairings.set(code, { sessionId, expiresAt: now + PAIR_TTL_MS });
	return { sessionId, code, name: prep.name, sid: prep.sid, expiresAt };
}

// Redeem a one-time pairing code (single use) for the material the phone needs. Fail-closed: an unknown,
// expired, or already-used code yields nothing, and the code is consumed on the first valid lookup.
function redeem(code) {
	sweep();
	const c = String(code || '').trim().toUpperCase();
	let hit = null;
	for (const [k, v] of pairings) { if (Common.timingSafeEqualHashed(k, c)) { hit = v; pairings.delete(k); break; } }
	if (!hit) return null;
	const s = sessions.get(hit.sessionId);
	if (!s || s.expiresAt <= Date.now()) return null;
	const bearer = s._bearer;
	delete s._bearer; // the plaintext bearer is needed exactly once, here; drop it so only its hash remains in memory
	return { sessionId: hit.sessionId, bearer, cap: s.webCap, name: s.name, local: !!s.local, base: '/m/files/' + hit.sessionId + '/', list: '/m/list/' + hit.sessionId };
}

// Authorize a bearer against a session. Returns the session on success, null otherwise (fail-closed).
function authorize(sessionId, bearer) {
	sweep();
	const s = sessions.get(String(sessionId || ''));
	if (!s || s.expiresAt <= Date.now()) return null;
	if (!bearer || !Common.timingSafeEqual(s.bearerHash, Common.sha256(String(bearer)))) return null;
	return s;
}

// List the ciphertext files in a session's vault as encrypted relative paths + sizes. The names stay
// encrypted here — the phone decrypts them locally with the reader. Bounded walk, contained to the root.
async function list(session, { cap = 50000, budgetMs = 10000 } = {}) {
	const root = session.cipherRoot;
	const out = [];
	const start = Date.now();
	const spent = () => out.length >= cap || Date.now() - start > budgetMs; // bound count AND time so a huge vault can never grow the response without limit or stall the request
	async function walk(rel) {
		if (spent()) return;
		let ents;
		try { ents = await bounded(fsp.readdir(path.join(root, rel), { withFileTypes: true })); } catch (_) { return; }
		for (const e of ents) {
			if (spent()) return;
			const r = rel ? rel + '/' + e.name : e.name;
			if (e.isDirectory()) { await walk(r); }
			else if (e.isFile()) { let size = 0; try { size = (await bounded(fsp.stat(path.join(root, r)))).size; } catch (_) {} out.push({ path: r, size }); }
			// symlinks and other special files are skipped — only regular files are ever offered
		}
	}
	await walk('');
	return out;
}

// Resolve a client-supplied encrypted relative path to a safe, contained absolute file path, or throw.
// Layered, fail-closed: reject NUL/backslash/absolute/traversal lexically, then confirm the real path is
// inside the vault's real ciphertext root (defeats a symlink that escapes), and require a regular file.
async function resolveFile(session, relPath) {
	const raw = String(relPath || '');
	if (raw.indexOf('\0') >= 0 || raw.indexOf('\\') >= 0) throw new Error('bad path');
	if (path.isAbsolute(raw)) throw new Error('bad path');
	const target = path.resolve(session.cipherRoot, raw);
	const relBack = path.relative(session.cipherRoot, target);
	if (relBack === '' || relBack.startsWith('..') || path.isAbsolute(relBack)) throw new Error('bad path');
	const st = await bounded(fsp.lstat(target)); // lstat: a symlinked final component is rejected outright
	if (st.isSymbolicLink() || !st.isFile()) throw new Error('not a file');
	const real = await bounded(fsp.realpath(target));
	const rootReal = session.cipherRootReal || await bounded(fsp.realpath(session.cipherRoot));
	const relReal = path.relative(rootReal, real);
	if (relReal.startsWith('..') || path.isAbsolute(relReal)) throw new Error('escapes root');
	return { abs: real, rel: relReal, size: st.size };
}

function stop(sessionId) { const had = sessions.delete(String(sessionId || '')); for (const [k, v] of pairings) if (v.sessionId === sessionId) pairings.delete(k); return had; }
// Stop every live session created from a given roster share id — used so revoking a share also cuts off its running
// mobile session IN THIS PROCESS (a cross-process revoke still relies on rotate for a hard cut-off, as documented).
function stopBySid(sid) { let n = 0; for (const [id, s] of sessions) if (s.sid === sid) { if (stop(id)) n++; } return n; }
// Stop every session serving a given vault (its cipherRoot lives inside the vault folder). Called when a vault is
// unmounted/locked, so a phone or in-app viewer cannot keep serving that vault's ciphertext — and holding its
// in-memory read key — after the user has locked it. Path-based so it needs no manifest read.
function stopByVaultPath(vaultDir) {
	let n = 0;
	try {
		const target = path.resolve(String(vaultDir || ''));
		if (!target) return 0;
		for (const [id, s] of sessions) {
			const root = path.resolve(s.cipherRoot || '');
			if (root === target || root.startsWith(target + path.sep)) { if (stop(id)) n++; }
		}
	} catch (_) {}
	return n;
}
function stopAll() { sessions.clear(); pairings.clear(); }
function listSessions() { sweep(); return [...sessions.entries()].map(([id, s]) => ({ sessionId: id, name: s.name, createdAt: s.createdAt, expiresAt: s.expiresAt })); }

module.exports = { start, redeem, authorize, list, resolveFile, stop, stopBySid, stopByVaultPath, stopAll, listSessions, sweep, DEFAULT_TTL_MS, PAIR_TTL_MS };
