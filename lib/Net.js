'use strict';
// lib/Net.js — one small, shared networking helper used by both the engine
// downloader and the driver installer, so the download / verify / unzip logic
// lives in exactly one place. It follows redirects, streams to disk with a
// progress line, verifies SHA-256 (deleting the file on mismatch), reads small
// JSON/text bodies, and resolves the latest release asset (with its published
// SHA-256 digest) from a GitHub repository.

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
// archiver (zip WRITER) and unzipper (zip READER) are required LAZILY inside zipDir()/unzip() — the only functions
// that use them — because they are heavy to load (~80 ms combined) yet touched only by the rare pack/import/engine
// -extract paths, while this module's common network helpers use just http/https/crypto/fs. Deferring them keeps
// service startup and every CLI command roughly twice as fast, at the cost of loading them once on first archive use.
// Both stream (constant memory, one entry at a time), so the any-size invariant is unchanged.
const Common = require('./Common');
const Brand = require('./Brand');
const Zip = require('./Zip'); // the app-wide zip/unzip module; re-exported below so existing Net.unzip / Net.zipDir callers are unchanged

const UA = Brand.slug + '-setup';
const IDLE_TIMEOUT_MS = 30000; // abort a connection that opens then stalls with no data
const MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024;   // 1 GiB — the engine/installer downloads are tens of MB; this stops a runaway or hostile server filling the disk BEFORE the checksum can reject it

const MAX_BODY_BYTES = 16 * 1024 * 1024;         // 16 MiB — in-memory JSON/checksum bodies are tiny (KB); this bounds a hostile/MITM'd endpoint or redirect target streaming unbounded data into memory
const BODY_DEADLINE_MS = 60 * 1000;              // absolute cap for a small in-memory fetch — a drip server that trickles bytes just under the idle window can't hold the connection open forever
const DOWNLOAD_DEADLINE_MS = 20 * 60 * 1000;     // absolute cap for a streamed download (the real ones are tens of MB; this only trips a deliberately-slow/drip source)


// Resolve one redirect hop's Location against the current URL.
function resolveRedirect(current, location) {
	if (location.startsWith('http')) return location;
	if (location.startsWith('/')) { const u = new URL(current); return u.protocol + '//' + u.host + location; }
	return current.replace(/[^/]+$/, '') + location;
}

// Refuse a redirect that downgrades HTTPS to plain HTTP. Following one would let a network attacker (or a
// hostile endpoint) strip transport security mid-fetch — dangerous for the release-metadata/checksum fetches,
// whose integrity would otherwise be trusted. An http→http or https→https(→http is blocked) redirect is fine.
function assertNoDowngrade(from, to) {
	if (from.startsWith('https:') && to.startsWith('http://')) throw new Error('refusing to follow a redirect that downgrades HTTPS to plain HTTP: ' + to);
}

// Attach timeouts to a request. The IDLE timeout aborts a connection that opens then stalls with no data
// (resets on activity, so a slow-but-progressing transfer is not cut off). The ABSOLUTE deadline (when > 0)
// bounds the TOTAL time, so a drip source that trickles a byte just inside every idle window can't hold the
// connection open indefinitely. Both destroy the request, which rejects the promise.
function armTimeout(req, reject, deadlineMs = 0) {
	req.setTimeout(IDLE_TIMEOUT_MS, () => req.destroy(new Error('network idle timeout')));
	if (deadlineMs > 0) {
		const t = setTimeout(() => req.destroy(new Error('network deadline exceeded (' + Math.round(deadlineMs / 1000) + 's)')), deadlineMs);
		if (t.unref) t.unref();
		req.on('close', () => clearTimeout(t));
	}
	req.on('error', reject);
}

// GET a small body into memory (follows redirects). For JSON/checksum files only.
function getBuffer(url, redirectsLeft = 6, endBy = Date.now() + BODY_DEADLINE_MS) {
	return new Promise((resolve, reject) => {
		const mod = url.startsWith('https') ? https : http;
		const req = mod.get(url, { headers: { 'User-Agent': UA, 'Accept': 'application/vnd.github+json, text/plain, */*' } }, (res) => {
			if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
				if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
				let next; try { next = resolveRedirect(url, res.headers.location); assertNoDowngrade(url, next); } catch (e) { res.resume(); return reject(e); }
				res.resume();
				return getBuffer(next, redirectsLeft - 1, endBy).then(resolve).catch(reject); // share the absolute deadline across hops
			}
			if (res.statusCode !== 200) { res.resume(); return reject(new Error('The download server returned HTTP ' + res.statusCode + ' for ' + url + '. Check your internet connection and try again; if it persists, the source may be temporarily unavailable.')); }
			const chunks = [];
			let got = 0;
			res.on('data', c => { got += c.length; if (got > MAX_BODY_BYTES) { try { req.destroy(); } catch (_) {} return reject(new Error('response body exceeded the size limit for ' + url)); } chunks.push(c); });
			res.on('end', () => resolve(Buffer.concat(chunks)));
			res.on('error', reject);
		});
		armTimeout(req, reject, Math.max(1, endBy - Date.now())); // absolute deadline: the REMAINING budget on this hop, so redirects don't reset it
	});
}

async function getText(url) { return (await getBuffer(url)).toString('utf8'); }
async function getJson(url) { return JSON.parse(await getText(url)); }

// POST a small JSON body to a fixed URL — for the user-configured notification webhook. Best-effort and bounded: it
// does NOT follow redirects (a webhook is a fixed endpoint the caller controls) and reads no response body; it resolves
// with the status code, or rejects on a transport or timeout error. The idle+deadline timeouts from armTimeout bound a
// hung endpoint so a notification can never stall its caller. http and https are both allowed (a webhook may be a
// loopback push helper); anything else is refused.
function postJson(url, obj, { timeoutMs = 10000 } = {}) {
	return new Promise((resolve, reject) => {
		let mod;
		try { const u = new URL(url); mod = u.protocol === 'https:' ? https : (u.protocol === 'http:' ? http : null); } catch (_) { return reject(new Error('The webhook URL is not a valid URL.')); }
		if (!mod) return reject(new Error('A webhook URL must start with http:// or https://.'));
		const body = Buffer.from(JSON.stringify(obj == null ? {} : obj), 'utf8');
		const req = mod.request(url, { method: 'POST', headers: { 'User-Agent': UA, 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => {
			res.on('data', () => {}); // drain and discard — only the status matters
			res.on('end', () => resolve({ status: res.statusCode || 0 }));
			res.on('error', reject);
		});
		armTimeout(req, reject, Math.max(1, timeoutMs)); // arms idle + absolute deadline and attaches req 'error' -> reject
		req.end(body);
	});
}

function sha256File(p) { return Common.hashFileStream(p); } // streamed hex SHA-256 (shared seam — see Common.hashFileStream)

// Download `url` to `dest`, verifying expectedSha256 if given. Writes to a TEMP sibling and moves it into place
// only on full success, so a failed, rejected, or checksum-mismatched download NEVER truncates or removes an
// existing file at `dest`. This makes the helper safe for ANY caller, not only ones that already pass a throwaway
// temp path — a future caller can point `dest` at a live "last good" file without risking it.
async function download(url, dest, opts = {}) {
	const tmp = dest + '.part-' + process.pid + '-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex'); // random suffix so two concurrent downloads to the same dest never share a temp
	try { await downloadTo(url, tmp, opts); await Common.renameWithRetry(tmp, dest); return dest; } // renameWithRetry rides out a transient Windows lock on an existing dest, so this is genuinely safe for any caller's dest
	catch (e) { try { await fsp.unlink(tmp); } catch (_) {} throw e; }
}

// Stream a download to dest (follows redirects), printing a progress line. If
// expectedSha256 is given, verify after download and DELETE the file on mismatch —
// so a tampered or corrupted binary is never used. `label` names the file in the
// progress line. Internal: callers use download() above, which routes through a temp.
function downloadTo(url, dest, opts = {}, redirectsLeft = 6, endBy = Date.now() + DOWNLOAD_DEADLINE_MS) {
	const { label = 'file' } = opts;
	return new Promise((resolve, reject) => {
		const file = fs.createWriteStream(dest);
		const mod = url.startsWith('https') ? https : http;
		const req = mod.get(url, { headers: { 'User-Agent': UA } }, (res) => {
			if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
				file.close(); fsp.unlink(dest).catch(() => {}); // async, non-blocking cleanup of the partial file
				if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
				let next; try { next = resolveRedirect(url, res.headers.location); assertNoDowngrade(url, next); } catch (e) { res.resume(); return reject(e); }
				res.resume();
				return downloadTo(next, dest, opts, redirectsLeft - 1, endBy).then(resolve).catch(reject); // share the absolute deadline across hops
			}
			if (res.statusCode !== 200) { file.close(); fsp.unlink(dest).catch(() => {}); res.resume(); return reject(new Error('The download server returned HTTP ' + res.statusCode + ' while downloading ' + label + '. Check your internet connection and try again; if it persists, the source may be temporarily unavailable.')); }
			const total = parseInt(res.headers['content-length'] || '0', 10);
			if (total > MAX_DOWNLOAD_BYTES) { file.close(); fsp.unlink(dest).catch(() => {}); res.resume(); return reject(new Error('refusing to download ' + label + ': it declares ' + Math.round(total / 1e6) + ' MB, over the ' + Math.round(MAX_DOWNLOAD_BYTES / 1e6) + ' MB limit.')); }
			let got = 0, lastPct = -1;
			res.on('data', (c) => {
				got += c.length;
				if (got > MAX_DOWNLOAD_BYTES) { try { req.destroy(); } catch (_) {} try { file.close(); } catch (_) {} fsp.unlink(dest).catch(() => {}); return reject(new Error('download of ' + label + ' exceeded the ' + Math.round(MAX_DOWNLOAD_BYTES / 1e6) + ' MB size limit and was stopped.')); }
				if (total > 0) {
					const pct = Math.floor(got / total * 100);
					if (pct !== lastPct && pct % 10 === 0) { lastPct = pct; try { process.stdout.write('\r  Downloading ' + label + '… ' + pct + '%'); } catch (_) {} }
				}
			});
			// A mid-body response-stream error (network drop, reset) isn't always mirrored onto `req`, so
			// handle it here too: drop the partial file and reject rather than leave the promise hanging.
			res.on('error', (e) => { try { file.close(); } catch (_) {} fsp.unlink(dest).catch(() => {}); reject(e); });
			res.pipe(file);
			file.on('finish', async () => {
				file.close();
				try { process.stdout.write('\n'); } catch (_) {}
				if (opts.expectedSha256) {
					try {
						const actual = await sha256File(dest);
						if (actual.toLowerCase() !== opts.expectedSha256.toLowerCase()) {
							fsp.unlink(dest).catch(() => {});
							return reject(new Error('checksum mismatch for ' + label + ' (expected ' + opts.expectedSha256.slice(0, 12) + '…, got ' + actual.slice(0, 12) + '…)'));
						}
					} catch (e) { return reject(e); }
				}
				resolve(dest);
			});
			// A write-stream error (a full or failing disk) must tear down the transfer like the other error paths —
			// otherwise res keeps draining into a dead file until a size/deadline limit trips, wasting bandwidth.
			file.on('error', (e) => { try { req.destroy(); } catch (_) {} try { file.close(); } catch (_) {} fsp.unlink(dest).catch(() => {}); reject(e); });
		});
		armTimeout(req, reject, Math.max(1, endBy - Date.now())); // absolute deadline: remaining budget on this hop, so redirects don't reset it
	});
}

// Pick a matching asset from a GitHub release object → { name, url, sha256, tag }.
// GitHub publishes each asset's SHA-256 in the `digest` field, which we use to
// verify the download without a separate checksum file. sha256 is null if the
// field is absent (callers decide whether that is acceptable).
function pickAsset(rel, matchFn, where) {
	const asset = (rel.assets || []).find(matchFn);
	if (!asset) { const e = new Error('No matching download was found for this system in ' + where + '. This operating system or processor architecture may not have a prebuilt engine available; see the README for how to install one manually.'); e.code = 'NO_ASSET'; throw e; }
	return { name: asset.name, url: asset.browser_download_url, sha256: (asset.digest || '').replace(/^sha256:/, '') || null, tag: rel.tag_name };
}

// Resolve an asset from a repo's LATEST release.
async function githubLatestAsset(repo, matchFn) {
	return pickAsset(await getJson('https://api.github.com/repos/' + repo + '/releases/latest'), matchFn, repo + '@latest');
}

// Resolve an asset from a repo's SPECIFIC tagged release (used to pin a known-good
// version instead of blindly tracking latest).
async function githubAssetForTag(repo, tag, matchFn) {
	return pickAsset(await getJson('https://api.github.com/repos/' + repo + '/releases/tags/' + tag), matchFn, repo + '@' + tag);
}



// Measure a directory tree's total file size (bytes). Used by dispersal to reserve staging space up front. ASYNC
// (fsp, not sync fs) so it never blocks the event loop — it can be driven from the long-running web server, where a
// blocked loop would stall the mounted-drive health checks.
async function treeSize(dir) {
	let total = 0;
	for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
		const abs = path.join(dir, e.name);
		if (e.isSymbolicLink()) continue;
		if (e.isDirectory()) total += await treeSize(abs);
		else if (e.isFile()) total += (await fsp.stat(abs)).size;
	}
	return total;
}





module.exports = { getText, download, postJson, sha256File, treeSize, githubLatestAsset, githubAssetForTag, unzip: Zip.unzip, zipDir: Zip.zipDir, CONTAINER_MARKER: Zip.CONTAINER_MARKER };
// Exposed ONLY so the network-guard test can exercise the HTTPS->HTTP downgrade refusal and the redirect resolver
// directly (a trusted-HTTPS loopback server is not feasible in the suite, since the client correctly validates certs).
module.exports._test = { assertNoDowngrade, resolveRedirect };
