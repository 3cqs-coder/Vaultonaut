'use strict';
// lib/test/emergencyseal.js — the emergency/inheritance sealed box (lib/Emergency.js). Covers the post-quantum
// hybrid seal (X25519 + ML-KEM-768, X-Wing) when the runtime has built-in ML-KEM, the classical fallback, that
// both formats round-trip and fail closed, and that a classical (v1) blob still opens after the hybrid upgrade
// (an already-armed seal must never stop opening). No engine or mount driver needed.
//
// Run:  node lib/test/emergencyseal.js

const crypto = require('crypto');
const E = require('../Emergency');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

function main() {
	const pq = E.isPostQuantum();
	console.log('  post-quantum hybrid available on this runtime: ' + pq);

	const message = 'vdrc1.' + crypto.randomBytes(96).toString('base64url'); // a stand-in read capability
	const kp = E.generateContactKeypair();
	const sealed = E.seal(kp.publicKey, message);

	ok('a contact keypair and a sealed blob are produced', !!kp.publicKey && !!kp.privateKey && !!sealed);
	ok('the seal round-trips to the exact message', E.open(kp.privateKey, sealed) === message);

	// When ML-KEM is available, the seal must actually be the hybrid (v2) format, not silently classical.
	const pubTag = Buffer.from(kp.publicKey, 'base64')[0];
	const blobTag = Buffer.from(sealed, 'base64')[0];
	if (pq) {
		ok('the contact key is the hybrid (v2) format', pubTag === 0x02);
		ok('the sealed blob is the hybrid (v2) format', blobTag === 0x02);
		ok('the hybrid public key carries both an X25519 and an ML-KEM-768 key (~1.2 KB)', Buffer.from(kp.publicKey, 'base64').length > 1180);
	}

	// A wrong contact key can never open it.
	const other = E.generateContactKeypair();
	let wrongThrew = false; try { E.open(other.privateKey, sealed); } catch (_) { wrongThrew = true; }
	ok('a different private key fails closed', wrongThrew);

	// A TRUNCATED sealed blob must fail with a clean domain error, never a raw RangeError from reading a length
	// prefix past the end of the buffer — the length-prefixed container validates its bounds.
	const truncated = Buffer.from(sealed, 'base64').subarray(0, 3).toString('base64'); // keep only the version byte + a partial length
	let truncErr = null; try { E.open(kp.privateKey, truncated); } catch (e) { truncErr = e; }
	ok('a truncated sealed blob fails closed with a clear error (not a raw RangeError)', !!truncErr && truncErr.name !== 'RangeError');

	// Any alteration fails the AEAD tag.
	const tampered = Buffer.from(sealed, 'base64'); tampered[tampered.length - 1] ^= 0xff;
	let tamperThrew = false; try { E.open(kp.privateKey, tampered.toString('base64')); } catch (_) { tamperThrew = true; }
	ok('a tampered blob fails closed', tamperThrew);

	// Backward compatibility: a classical (v1) contact key + blob — as an install on an older runtime, or a seal
	// armed before this upgrade — must still open. Build one directly with bare X25519 DER (the v1 format).
	const x = crypto.generateKeyPairSync('x25519');
	const v1Pub = x.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
	const v1Priv = x.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
	const v1Sealed = E.seal(v1Pub, message); // a v1 key routes to the classical seal
	ok('a classical (v1) contact key seals in the classical format', Buffer.from(v1Sealed, 'base64')[0] === 44);
	ok('a classical (v1) sealed blob still round-trips', E.open(v1Priv, v1Sealed) === message);

	// Domain separation: a blob sealed for one PURPOSE must not open under another, even to the right key. The same
	// seal is reused for a member capability, an owner-recovery share, and a share bundle; each binds its own label.
	const ctxSealed = E.seal(kp.publicKey, message, 'member-cap');
	ok('a context-bound blob opens with the SAME context', E.open(kp.privateKey, ctxSealed, 'member-cap') === message);
	let wrongCtxThrew = false; try { E.open(kp.privateKey, ctxSealed, 'owner-recovery'); } catch (_) { wrongCtxThrew = true; }
	ok('the same blob fails closed under a DIFFERENT context (no cross-purpose reuse)', wrongCtxThrew);
	let noCtxThrew = false; try { E.open(kp.privateKey, ctxSealed); } catch (_) { noCtxThrew = true; }
	ok('a context-bound blob does not open with the default (empty) context', noCtxThrew);
	ok('an empty context reproduces the original bytes (an armed emergency seal still opens)', E.open(kp.privateKey, E.seal(kp.publicKey, message, '')) === message);

	// REFUSE FORWARD: a packed key/blob tagged with a version NEWER than this build (a leading byte in 0x03..0x0f,
	// above the v2 tag but below any v1 structural marker) must fail with a clear "update" error, not be misrouted
	// into the v1 path where it dies with a confusing low-level crypto error.
	const newerBlob = Buffer.concat([Buffer.from([0x03]), Buffer.from(sealed, 'base64').subarray(1)]).toString('base64');
	let newerErr = null; try { E.open(kp.privateKey, newerBlob); } catch (e) { newerErr = e; }
	ok('a newer-version sealed blob is refused with a clear message', !!newerErr && /newer version/i.test(newerErr.message));
	let newerKeyErr = null; try { E.seal(Buffer.from([0x03, 0x00, 0x01, 0x00]).toString('base64'), message); } catch (e) { newerKeyErr = e; }
	ok('sealing to a newer-version contact key is refused', !!newerKeyErr && /newer version/i.test(newerKeyErr.message));

	// A packed KEY must consume its whole buffer: trailing bytes appended to a hybrid key are rejected, so a key has
	// exactly one encoding (no silent acceptance of a padded variant). Only meaningful when the hybrid format is used.
	if (pq) {
		const padded = Buffer.concat([Buffer.from(kp.publicKey, 'base64'), Buffer.from([0, 0, 0])]).toString('base64');
		let padErr = null; try { E.seal(padded, message); } catch (e) { padErr = e; }
		ok('a hybrid key with trailing bytes is refused (exact-consumption)', !!padErr && /trailing data/i.test(padErr.message));
	}

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-SEAL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
