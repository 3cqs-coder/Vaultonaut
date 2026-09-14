'use strict';
// lib/test/driverinstall.js — the mount-driver installer fetch guards. Downloading and launching a native, privileged
// installer is one of the few outward, high-trust actions the app takes, so its safety rails must not silently erode:
//   1. It must REFUSE to launch an installer with no published checksum (nothing to verify the download against).
//   2. It must FORWARD that checksum to the downloader as expectedSha256 (so the download is actually verified, not
//      merely fetched).
//   3. The launch path must use the OS front doors (open / msiexec) and NEVER a flag that suppresses the OS code-
//      signature check — that signature is the authenticity anchor (see the trust model in DriverInstall.js).
// These are guarded here with stubbed network calls (no real download) plus a static scan of the launch commands.
//
// Run:  node lib/test/driverinstall.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

async function main() {
	const Net = require('../Net');
	const DriverInstall = require('../DriverInstall');
	const { fetchAndVerify } = DriverInstall._test;

	// --- 1. Refuse an installer with no published checksum ---
	const realLatest = Net.githubLatestAsset, realDownload = Net.download;
	let downloadCalls = [];
	Net.download = async (url, dest, opts) => { downloadCalls.push({ url, dest, opts }); }; // never touch the network
	try {
		Net.githubLatestAsset = async () => ({ name: 'winfsp-2.0.msi', url: 'https://example/winfsp-2.0.msi', tag: 'v2.0', sha256: '' });
		let threw = '';
		try { await fetchAndVerify('winfsp/winfsp', () => true, 'WinFsp'); } catch (e) { threw = e.message; }
		ok('an installer with NO published checksum is refused', /refusing to launch an unverified/i.test(threw));
		ok('nothing is downloaded when the checksum is missing', downloadCalls.length === 0);

		// --- 2. Forward the published checksum to the downloader as expectedSha256 ---
		downloadCalls = [];
		const sha = 'a'.repeat(64);
		Net.githubLatestAsset = async () => ({ name: 'winfsp-2.0.msi', url: 'https://example/winfsp-2.0.msi', tag: 'v2.0', sha256: sha });
		await fetchAndVerify('winfsp/winfsp', () => true, 'WinFsp');
		ok('the download is invoked once when a checksum is present', downloadCalls.length === 1);
		ok('the published checksum is forwarded to the downloader as expectedSha256', downloadCalls[0] && downloadCalls[0].opts && downloadCalls[0].opts.expectedSha256 === sha);
	} finally { Net.githubLatestAsset = realLatest; Net.download = realDownload; }

	// --- 3. The launch commands never suppress the OS signature check (static scan) ---
	const src = fs.readFileSync(path.join(__dirname, '..', 'DriverInstall.js'), 'utf8');
	ok('macOS opens the .pkg through the OS installer front door (open)', /launch\('open', \[pkg\]\)/.test(src));
	ok('Windows launches the .msi through msiexec with just /i (interactive, signature-checked)', /launch\('msiexec', \['\/i', msi\]\)/.test(src));
	// A silent/quiet MSI (/qn or /quiet) would install without the user seeing the publisher, and no flag may disable
	// the signature/UAC prompt. None of these must appear in the launch args.
	ok('no silent/quiet MSI flag is used (the user must see the signed installer)', !/\/qn\b/i.test(src) && !/\/quiet\b/i.test(src));
	ok('no NOGATEKEEPER / signature-suppressing flag is present', !/nogatekeeper/i.test(src) && !/allow-untrusted/i.test(src));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DRIVER-INSTALL CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
