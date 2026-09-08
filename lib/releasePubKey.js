'use strict';
// lib/releasePubKey.js — the maintainer's RELEASE-SIGNING public key (hex-encoded Ed25519), the trust root for
// verifying that this copy of the application is the authentic, unmodified release.
//
// This is EMPTY until the maintainer sets up release signing with `node lib/scripts/sign-release.js --init`, which
// generates the keypair, writes the public key here, and saves the PRIVATE key to a location outside the repo.
// While it is empty the self-integrity check is inert (a source checkout is treated as unsigned), so the app
// behaves exactly as before signing is adopted.
//
// The public key is safe to publish and to embed — it can only VERIFY, never sign. Publish the same value in the
// README and on the official site so users can anchor their verification to a key they obtained independently, not
// only to the copy embedded in a download they have not yet trusted.
module.exports = { pubkey: '5b548433373774a18a00c2c82c896c42a1cf68df63358c5e9136ac68bc03f137' };
