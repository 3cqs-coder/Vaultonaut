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
const ReleaseIntegrity = require('./ReleaseIntegrity');

// The default source is the tags list of the project's public repository. It is overridable (a CLI argument, or a
// stored setting) so the release home is not permanently locked to one host — the authenticity of an actual download
// is guaranteed by the signed release manifest, so the check source only has to report a version number.
const DEFAULT_OWNER = '3cqs-coder';
const DEFAULT_REPO = 'Vaultonaut';
const DEFAULT_TAGS_URL = 'https://api.github.com/repos/' + DEFAULT_OWNER + '/' + DEFAULT_REPO + '/tags';
const RELEASES_URL = 'https://github.com/' + DEFAULT_OWNER + '/' + DEFAULT_REPO + '/releases';
const FETCH_TIMEOUT_MS = 6000;

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
	const controller = new AbortController();
	const timer = setTimeout(() => { try { controller.abort(); } catch (_) {} }, Math.max(1000, timeoutMs));
	if (timer.unref) timer.unref();
	try {
		const res = await fetch(url || DEFAULT_TAGS_URL, { signal: controller.signal, headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': Brand.slug + '-update-check' } });
		if (!res || !res.ok) { out.error = 'The update source could not be reached (HTTP ' + (res ? res.status : '—') + ').'; return out; }
		let body; try { body = await res.json(); } catch (_) { out.error = 'The update source returned an unreadable response.'; return out; }
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
	} finally { clearTimeout(timer); }
}

module.exports = { checkForUpdate, parseVersion, compareVersions, latestTag, isAhead, DEFAULT_TAGS_URL, RELEASES_URL };
