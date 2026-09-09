'use strict';
// lib/UpdateCheck.js — an OPTIONAL, best-effort check for a newer published release.
//
// It only READS a version number from the release host and compares it to this build. It never downloads or installs
// anything: getting the update stays a deliberate user action, and a downloaded release is still verified by the
// signed, dependency-free verifier (its authenticity does not depend on this check being honest). Because the check
// makes an OUTBOUND network request, it is OFF by default and runs only when the user asks for it (a manual check) or
// explicitly turns on automatic checks — a privacy- and security-conscious default.
//
// Cross-platform: it uses the runtime's built-in fetch, and every call is bounded by a timeout so a slow or
// unreachable host can never hang a command, a request, or a background tick. It NEVER throws — every failure
// resolves to { ok:false, error } so no caller is ever broken by a failed check.

const Brand = require('./Brand');
const Common = require('./Common');
const ReleaseIntegrity = require('./ReleaseIntegrity');

// The default source is the tags list of the project's public repository. It is overridable (a CLI argument, or a
// stored setting) so the release home is not permanently locked to one host — the authenticity of an actual download
// is guaranteed by the signed release manifest, so the check source only has to report a version number.
const DEFAULT_OWNER = '3cqs-coder';
const DEFAULT_REPO = 'Vaultonaut';
const DEFAULT_TAGS_URL = 'https://api.github.com/repos/' + DEFAULT_OWNER + '/' + DEFAULT_REPO + '/tags';
const RELEASES_URL = 'https://github.com/' + DEFAULT_OWNER + '/' + DEFAULT_REPO + '/releases';
const FETCH_TIMEOUT_MS = 6000;
// The response is untrusted (any host can be pointed at via the override), so cap how much of it we read into memory:
// a tags list is a few kilobytes, and this ceiling is generous while making a hostile or misconfigured endpoint unable
// to exhaust the heap. Over the cap is treated as an unreadable response (a failed check), never an unbounded read.
const MAX_RESPONSE_BYTES = 1024 * 1024;

// Read a fetch Response body as text with a hard byte cap, aborting the moment the cap is passed. Uses the body's
// async iterator (Node's fetch exposes a web ReadableStream), with a text() fallback bounded by Content-Length for any
// runtime whose body is not iterable. Returns null when the body is missing or exceeds the cap.
async function readCappedText(res, cap) {
	try {
		const len = Number(res.headers && res.headers.get && res.headers.get('content-length'));
		if (Number.isFinite(len) && len > cap) return null; // declared oversize — reject before reading a byte
		if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
			const chunks = []; let total = 0;
			for await (const chunk of res.body) {
				total += chunk.length;
				if (total > cap) return null; // stop as soon as it grows past the ceiling
				chunks.push(Buffer.from(chunk));
			}
			return Buffer.concat(chunks).toString('utf8');
		}
		const text = await res.text();
		return Buffer.byteLength(text, 'utf8') > cap ? null : text;
	} catch (_) { return null; }
}

// Parse a version into numeric segments so 1.9 sorts BEFORE 1.10 — a string compare would order '9' after '1' and
// miss that update. Any non-numeric decoration (a leading 'v', a '-rc1' suffix) is dropped; a missing segment is 0.
function parseVersion(v) {
	return String(v == null ? '' : v).replace(/^[^0-9]*/, '').split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
}
// -1 if a < b, 0 if equal, 1 if a > b — segment by segment, missing segments counting as 0.
function compareVersions(a, b) {
	const pa = parseVersion(a), pb = parseVersion(b);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y ? -1 : 1; }
	return 0;
}
// The highest-versioned tag name in a tags list. The host's own ordering is not relied upon, and a non-version tag
// (e.g. "nightly") parses to 0.0.0 and is ignored in favor of any real version — so the newest RELEASE is chosen.
function latestTag(tags) {
	let best = null;
	for (const t of (Array.isArray(tags) ? tags : [])) { const name = t && t.name; if (!name) continue; if (best == null || compareVersions(name, best) > 0) best = String(name); }
	return best;
}

// Whether a build version is NEWER than the latest published release — a locally built or pre-release copy that is
// ahead of the public release. Surfaced so the UI can say "you are ahead" rather than "up to date" or "update".
function isAhead(current, latest) { return latest != null && compareVersions(current, latest) > 0; }

// Fetch the latest published version and compare it to this build. Returns a plain result and NEVER throws.
async function checkForUpdate({ url, timeoutMs = FETCH_TIMEOUT_MS } = {}) {
	const current = ReleaseIntegrity.appVersion() || '0.0.0';
	const out = { ok: false, updateAvailable: false, ahead: false, current, latest: null, releasesUrl: RELEASES_URL, checkedAt: new Date().toISOString(), error: null };
	try {
		// Bounded via the shared Common.fetchWithTimeout (one abort + timer-unref discipline for every outbound request).
		const res = await Common.fetchWithTimeout(url || DEFAULT_TAGS_URL, { headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': Brand.slug + '-update-check' } }, Math.max(1000, timeoutMs));
		if (!res || !res.ok) { out.error = 'The update source could not be reached (HTTP ' + (res ? res.status : '—') + ').'; return out; }
		const text = await readCappedText(res, MAX_RESPONSE_BYTES);
		if (text == null) { out.error = 'The update source returned an unreadable or oversized response.'; return out; }
		let body; try { body = JSON.parse(text); } catch (_) { out.error = 'The update source returned an unreadable response.'; return out; }
		const latest = latestTag(body);
		if (!latest) { out.error = 'No published release was found to compare against.'; return out; }
		out.latest = latest;
		out.updateAvailable = compareVersions(latest, current) > 0;
		out.ahead = isAhead(current, latest);
		out.ok = true;
		return out;
	} catch (e) {
		out.error = (e && e.name === 'AbortError') ? 'The update check timed out.' : 'Could not reach the update source.';
		return out;
	}
}

module.exports = { checkForUpdate, parseVersion, compareVersions, latestTag, isAhead, DEFAULT_TAGS_URL, RELEASES_URL };
