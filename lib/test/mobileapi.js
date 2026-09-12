'use strict';
// lib/test/mobileapi.js — the mobile-access SESSION layer (lib/Mobile.js): one-time pairing, constant-time
// bearer auth, single-vault binding, a ciphertext listing, and fail-closed path containment. It also ties
// the layer to the portable reader end to end: pair -> list -> fetch one ciphertext file by its contained
// path -> decrypt it locally -> confirm it matches the original. No HTTP here (that is exercised separately);
// this proves the logic that the routes lean on.
//
// Run:  node lib/test/mobileapi.js

const os = require('os');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

let tmp = null;
async function main() {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-mobileapi-'));
	const Common = require('../Common');
	const dataDir = path.join(tmp, 'data'); await fsp.mkdir(dataDir, { recursive: true });
	Common.dataDir = () => dataDir;
	Common.statePath = () => path.join(dataDir, 'state.json');
	const vdisk = require('../index');
	const Mobile = require('../Mobile');
	const reader = require('../webserver/public/mobile/crypt-reader.js');

	const d = await vdisk.doctor();
	if (!d.engine.ok) { console.log('Engine missing — skipping.'); return done(); }

	const src = path.join(tmp, 'src');
	const files = { 'notes.txt': Buffer.from('mobile session notes', 'utf8'), 'pics/logo.bin': Buffer.alloc(1000, 9) };
	for (const [rel, buf] of Object.entries(files)) { const p = path.join(src, rel); await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.writeFile(p, buf); }
	const v = path.join(tmp, 'Session.vault');
	await vdisk.importFolder(v, { password: 'pw1', sourceDir: src });

	// Start a session; the desktop gets a short code + a session id, not the heavy material.
	const s = await Mobile.start(v, { password: 'pw1' });
	ok('start() returns a short one-time pairing code and a session id', /^[0-9A-Z]{5}-[0-9A-Z]{5}$/.test(s.code) && !!s.sessionId);

	// A wrong password must fail closed (no session leaked).
	let badPw = false; try { await Mobile.start(v, { password: 'nope' }); } catch (_) { badPw = true; }
	ok('start() with the wrong password is refused', badPw);

	// A LOCAL (in-app viewer) session is ephemeral: it must NOT add an entry to the vault's access roster, so
	// viewing files in this browser never litters "who has access". A phone session (default) DOES record a
	// revocable grant, exactly as a device handed the vault should.
	const beforeShares = (await vdisk.listShares(v)).shares.length;
	const sLocal = await Mobile.start(v, { password: 'pw1', local: true });
	ok('a local in-app viewer session records NO access-roster entry', (await vdisk.listShares(v)).shares.length === beforeShares);
	const sPhone = await Mobile.start(v, { password: 'pw1' });
	ok('a phone session DOES record one revocable access-roster entry', (await vdisk.listShares(v)).shares.length === beforeShares + 1);
	ok('a local session expires sooner than a phone session (shorter TTL)', (sLocal.expiresAt - Date.now()) < (sPhone.expiresAt - Date.now()));
		// The recorded phone grant must carry an EXPIRY matching the session TTL, so it self-clears from the access
		// roster when the 12h session ends, rather than lingering as a never-expiring 'Mobile access' row that overstated
		// who had live access long after the session (and any process restart) was gone.
		const phoneShare = (await vdisk.listShares(v)).shares.find(sh => /Mobile access/i.test(sh.label || ''));
		ok('the recorded phone grant carries an expiry (self-clears, not never-expires)', !!phoneShare && Number.isFinite(Number(phoneShare.exp)) && Math.abs(Number(phoneShare.exp) - sPhone.expiresAt) < 60 * 1000);

	// Redeem the code once: get the read cap + bearer. Redeeming again must fail (single use).
	const red = Mobile.redeem(s.code);
	ok('redeem() hands out the web read cap and a bearer', !!red && /^vdwrc1\./.test(red.cap) && !!red.bearer);
	ok('the pairing code is single-use', Mobile.redeem(s.code) === null);
	ok('an unknown pairing code yields nothing', Mobile.redeem('ZZZZZ-ZZZZZ') === null);

	// Bearer auth: correct bearer authorizes; wrong bearer is refused.
	ok('the correct bearer authorizes the session', !!Mobile.authorize(s.sessionId, red.bearer));
	ok('a wrong bearer is refused', Mobile.authorize(s.sessionId, 'not-the-token') === null);
	ok('a wrong session id is refused', Mobile.authorize('deadbeef', red.bearer) === null);
	const session = Mobile.authorize(s.sessionId, red.bearer);

	// Listing returns encrypted paths + sizes for the real files (engine sidecars may add a couple more).
	const listing = await Mobile.list(session);
	ok('list() returns at least the imported files', listing.length >= 2 && listing.every(e => typeof e.path === 'string' && typeof e.size === 'number'));

	// Path containment: traversal, absolute, and backslash paths are all refused.
	let t1 = false, t2 = false, t3 = false;
	try { await Mobile.resolveFile(session, '../../../etc/passwd'); } catch (_) { t1 = true; }
	try { await Mobile.resolveFile(session, '/etc/passwd'); } catch (_) { t2 = true; }
	try { await Mobile.resolveFile(session, '..\\..\\secret'); } catch (_) { t3 = true; }
	ok('path traversal, absolute, and backslash paths are all refused', t1 && t2 && t3);

	// End to end: parse the cap as the phone would, then pull each ciphertext file by its CONTAINED path and
	// decrypt it locally — the names and bytes must match the originals.
	const cap = JSON.parse(Buffer.from(red.cap.split('.')[1], 'base64url').toString('utf8'));
	const keys = reader.deriveKeys(cap.key, cap.salt);
	const got = {};
	for (const entry of listing) {
		let name; try { name = reader.decryptPath(keys.nameKey, keys.nameTweak, entry.path, cap.dn); } catch (_) { continue; }
		const r = await Mobile.resolveFile(session, entry.path);
		got[name] = reader.decryptContent(keys.dataKey, await fsp.readFile(r.abs));
	}
	let match = true;
	for (const [rel, buf] of Object.entries(files)) { const g = got[rel]; if (!g || !Buffer.from(g).equals(buf)) { match = false; console.log('     (mismatch: ' + rel + ')'); } }
	ok('every file pulled through the session decrypts to the original', match);

	// A web/mobile capability must be minted with the READ-WRITE password only (so it lands in the signed roster and
	// stays revocable) and must be recorded fail-closed — a read-only holder cannot create one.
	await vdisk.addReadOnlyKey(v, { password: 'pw1', readOnlyPassword: 'ro1' });
	let roRefused = false;
	try { await vdisk.makeWebReadCap(v, { password: 'ro1' }); } catch (_) { roRefused = true; }
	ok('a read-only password cannot mint a web/mobile capability', roRefused);
	const wc = await vdisk.makeWebReadCap(v, { password: 'pw1', label: 'Test mobile' });
	const roster = await vdisk.listShares(v);
	ok('a web/mobile capability is recorded in the signed roster', (roster.shares || []).some(x => x.sid === wc.sid));

	// Revoking a share also stops its LIVE mobile session in this process (in addition to marking it revoked).
	const s2 = await Mobile.start(v, { password: 'pw1' });
	ok('a fresh session is live before revocation', Mobile.listSessions().some(x => x.sessionId === s2.sessionId));
	await vdisk.revokeShare(v, { password: 'pw1', sid: s2.sid });
	ok('revoking a share stops its live mobile session', Mobile.listSessions().every(x => x.sessionId !== s2.sessionId));

	// Stopping the session revokes access immediately.
	Mobile.stop(s.sessionId);
	ok('stop() revokes the session (bearer no longer authorizes)', Mobile.authorize(s.sessionId, red.bearer) === null);

	return done();
}

async function done() {
	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL MOBILE-API CHECKS PASSED'));
	if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
	process.exit(failures ? 1 : 0);
}

main().catch(async (e) => { console.error(e); if (tmp) await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {}); process.exit(1); });
