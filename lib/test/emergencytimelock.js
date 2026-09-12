'use strict';
// lib/test/emergencytimelock.js — the two-gate emergency seal (Emergency.timelockSeal / timelockOpen): a message is
// sealed to a beneficiary's key (the identity gate, post-quantum hybrid) AND time-locked to a drand round (the delay
// gate). Opening needs BOTH the round's beacon signature and the beneficiary's private key, so a grant grabbed early
// is inert and, even after the round matures, is useless to anyone but the beneficiary. Offline: a stand-in beacon
// key stands in for drand, so the suite never touches the network.
//
// Run:  node lib/test/emergencytimelock.js

const Emergency = require('../Emergency');
const Timelock = require('../Timelock');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const contact = Emergency.generateContactKeypair();      // the beneficiary keeps the private half
	const other = Emergency.generateContactKeypair();        // a different person
	const beacon = Timelock._test.genKey();                  // stands in for the drand chain
	const round = 40000000;
	const token = 'read-cap:emergency-inheritance-token-☃-café';

	const blob = await Emergency.timelockSeal(contact.publicKey, token, round, { publicKey: beacon.publicKey });
	ok('the two-gate blob records its time-lock round', Timelock.blobRound(blob) === round);

	const sig = Timelock._test.signRound(beacon.sk, round); // the signature the beacon publishes when the round matures
	const opened = await Emergency.timelockOpen(contact.privateKey, blob, sig);
	ok('opening with the round signature AND the beneficiary key recovers the token', opened === token);

	// fail-closed: the beneficiary key alone is not enough without a valid round signature
	const tornSig = Buffer.from(sig); tornSig[5] ^= 0xff;
	let noSig = false; try { await Emergency.timelockOpen(contact.privateKey, blob, tornSig); } catch (_) { noSig = true; }
	ok('a wrong/immature beacon signature cannot open it (delay gate holds)', noSig);

	// fail-closed: the round signature alone is not enough without the beneficiary key
	let noKey = false; try { await Emergency.timelockOpen(other.privateKey, blob, sig); } catch (_) { noKey = true; }
	ok('a different beneficiary key cannot open it even with the right signature (identity gate holds)', noKey);

	// fail-closed: altering the blob body breaks it
	const torn = JSON.parse(blob); const ct = Buffer.from(torn.ct, 'base64'); ct[0] ^= 0xff; torn.ct = ct.toString('base64');
	let tornFail = false; try { await Emergency.timelockOpen(contact.privateKey, JSON.stringify(torn), sig); } catch (_) { tornFail = true; }
	ok('an altered blob fails to open', tornFail);

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL EMERGENCY-TIMELOCK CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
