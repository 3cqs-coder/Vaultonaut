'use strict';
// lib/Notify.js — best-effort, opt-in delivery of a small set of CRITICAL Vaultonaut events to the owner through a
// user-configured channel, so a high-stakes event reaches them even when the app is not open. The motivating case is
// the dead-man's-switch check-in reminder: a heads-up that emergency access is about to release prevents an accidental,
// irreversible release.
//
// Privacy-first: a notification lands in a third-party inbox or endpoint, so it carries only an event TYPE, an optional
// OPAQUE vault LABEL, and a short message — never file names, counts, sizes, or contents. In "generic" mode even the
// specifics are dropped, leaving only a generic "an event needs your attention". Off by default: nothing is ever sent
// unless the owner turns notifications on and configures a channel.
//
// Fail-safe and non-blocking: a delivery failure is caught and logged, never thrown into the caller (a scheduler tick),
// and the HTTP send is time-bounded (see Net.postJson) so a hung endpoint cannot stall anything. The only channel today
// is a webhook (one JSON POST to a URL the user controls — e.g. their own push service); the module is shaped so email
// or other channels can be added without touching callers.
const Net = require('./Net');
const Common = require('./Common');
const Brand = require('./Brand'); // the display name is single-sourced here, never hardcoded (see the brand-drift guard)

// The events this module knows about, each with a default enabled state and a human title. Adding an event here is all
// a new caller needs; the settings UI reads this list so a new event appears automatically.
// Only events that are ACTUALLY wired to a real trigger appear here — a toggle for an event that never fires is a
// misleading dead control (a pitfall seen in similar tools). New events are added here as their trigger is wired.
const EVENTS = {
	'checkin-reminder':   { title: 'Check-in reminder',            defaultOn: true },
	'emergency-released': { title: 'Emergency access released',    defaultOn: true },
	'backup-failed':      { title: 'Scheduled backup failed',      defaultOn: true },
	'system-check':       { title: 'System check needs attention', defaultOn: true },
	'test':               { title: 'Test notification',            defaultOn: true },
};

// A short bounded retry with backoff, so a critical alert (the check-in reminder above all) survives a transient blip
// rather than being lost on a single failed POST. Kept small: three attempts over ~2.5s total, non-blocking, and the
// whole thing is still best-effort — a persistently unreachable endpoint is logged and given up on, never retried in a
// tight loop. (Delivery history and additional channels are tracked in the backlog.)
const RETRY_BACKOFFS_MS = [0, 500, 2000];

// Extract the notification config from a settings object. All fields are optional and default to off/empty, so an
// absent `notify` section (an older client, or a fresh install) simply means no notifications.
function configFrom(settings) {
	const n = (settings && settings.notify) || {};
	return {
		enabled: !!n.enabled,
		webhookUrl: typeof n.webhookUrl === 'string' ? n.webhookUrl.trim() : '',
		generic: !!n.generic,
		events: (n.events && typeof n.events === 'object') ? n.events : {},
	};
}

// Is a given event type enabled? Requires notifications on overall, then the per-event toggle (defaulting to the
// event's built-in default when the user has not set it explicitly).
function eventEnabled(cfg, type) {
	if (!cfg || !cfg.enabled) return false;
	const v = cfg.events[type];
	return v === undefined ? !!(EVENTS[type] && EVENTS[type].defaultOn) : !!v;
}

// Build the privacy-safe payload for a webhook POST. In generic mode, the label and specific message are dropped.
function payloadFor(cfg, ev) {
	const title = (EVENTS[ev.type] && EVENTS[ev.type].title) || Brand.name;
	if (cfg.generic) {
		return { app: Brand.name, type: ev.type, title: Brand.name, message: 'A ' + Brand.name + ' event needs your attention. Open the app to see it.', ts: new Date().toISOString() };
	}
	const out = { app: Brand.name, type: ev.type, title, message: ev.message || title, ts: new Date().toISOString() };
	if (ev.label) out.vault = String(ev.label); // an opaque vault label only — never contents
	return out;
}

// Deliver one event. The caller passes the settings it already has (avoiding a re-read on a hot tick). Returns a small
// result object and NEVER throws — a scheduler tick can call this without a try/catch of its own.
//   ev = { type, message?, label? }
async function emit(ev, settings) {
	try {
		if (!ev || !ev.type) return { delivered: false, skipped: 'no-type' };
		const cfg = configFrom(settings);
		if (!eventEnabled(cfg, ev.type)) return { delivered: false, skipped: 'disabled' };
		if (!cfg.webhookUrl) return { delivered: false, skipped: 'no-channel' };
		const payload = payloadFor(cfg, ev);
		let lastStatus = 0, lastErr = null;
		for (let i = 0; i < RETRY_BACKOFFS_MS.length; i++) {
			if (RETRY_BACKOFFS_MS[i]) await new Promise((r) => setTimeout(r, RETRY_BACKOFFS_MS[i]));
			try {
				const r = await Net.postJson(cfg.webhookUrl, payload, { timeoutMs: 10000 });
				lastStatus = r && r.status;
				if (lastStatus >= 200 && lastStatus < 300) return { delivered: true, status: lastStatus, attempts: i + 1 };
			} catch (e) { lastErr = e; }
		}
		// Describe the failure WITHOUT echoing the raw error message: a Node transport error text embeds the host/IP/port
		// (and a URL/query token can ride along), so report only the HTTP status or the error CLASS (its code) — enough to
		// diagnose, nothing that leaks where the webhook points. This is logged locally and returned to the local test.
		const reason = lastStatus ? ('the endpoint returned HTTP ' + lastStatus) : ('the endpoint could not be reached' + (lastErr && lastErr.code ? ' (' + lastErr.code + ')' : ''));
		try { Common.warn('A notification for "' + ev.type + '" could not be delivered after ' + RETRY_BACKOFFS_MS.length + ' attempts: ' + reason + '.'); } catch (_) {}
		return { delivered: false, status: lastStatus || undefined, error: reason, attempts: RETRY_BACKOFFS_MS.length };
	} catch (e) {
		try { Common.warn('A notification could not be sent (' + (e && e.code ? e.code : 'error') + ').'); } catch (_) {}
		return { delivered: false, error: 'the notification could not be sent' };
	}
}

module.exports = { emit, configFrom, eventEnabled, payloadFor, EVENTS };
