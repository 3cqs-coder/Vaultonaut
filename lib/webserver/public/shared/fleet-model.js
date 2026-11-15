'use strict';
// Shared fleet model — pure logic for the multi-node fleet view: the Overview "Fleet" tile summary and the node list
// the Fleet dialog renders, computed from the cached fleet snapshot the server already put in the state. Lives here so
// the exact rollup logic is unit-tested in Node with no browser. ES5 (var, function expressions), loaded with a
// <script> tag before app.js and exported for require() in tests. Reads only status/counts — never a vault identity.
(function (root) {
	function arr(v) { return Array.isArray(v) ? v : []; }
	function hostOf(url) { try { var m = String(url || '').match(/^[a-z]+:\/\/([^/]+)/i); return m ? m[1] : String(url || ''); } catch (e) { return String(url || ''); } }

	// All user-facing text comes from this catalog through the shared i18n helper (one {var} template per string,
	// plural forms chosen by the locale) — never built with "+" or a hardcoded English plural. A version marker like
	// "· v1.1.0" is appended as a literal because a version number is not translatable.
	var I18n = (typeof require === 'function') ? require('./i18n') : (root.VaultI18n || null);
	var STRINGS = {
		en: {
			t_fleet: 'Fleet',
			fleetValue_one: '{online} online · {n} node', fleetValue_other: '{online} online · {n} nodes',
			needAttention_one: '{n} node needs attention', needAttention_other: '{n} nodes need attention',
			allHealthy: 'All nodes healthy',
			unreachableReason: 'Unreachable · {reason}', unreachable: 'Unreachable', notChecked: 'Not checked yet',
			errors_one: '{n} error', errors_other: '{n} errors',
			warnings_one: '{n} warning', warnings_other: '{n} warnings',
			healthy: 'Healthy', nodeFallback: 'Node'
		}
	};
	function T(lang, key, vars) { return I18n ? I18n.t(STRINGS, lang, key, vars) : key; }

	// A node's status maps to a severity: a reachable-but-erroring node is the worst (something is actually wrong on it),
	// an unreachable node is a warning (it may simply be off), online is good, and never-polled is neutral.
	function levelOf(status) {
		if (status === 'degraded') return 'error';
		if (status === 'unreachable') return 'warn';
		if (status === 'online') return 'good';
		return 'neutral';
	}
	var RANK = { good: 0, neutral: 0, warn: 1, error: 2 };

	function fleetVerdict(nodes) {
		var worst = 'good';
		for (var i = 0; i < nodes.length; i++) { var l = levelOf(nodes[i] && nodes[i].status); if (RANK[l] > RANK[worst]) worst = l; }
		return worst;
	}

	function fleetTile(state, lang) {
		lang = lang || 'en';
		var nodes = arr(state.fleet);
		if (!nodes.length) return null; // no nodes enrolled — omit the tile entirely
		var online = 0, attention = 0;
		for (var i = 0; i < nodes.length; i++) {
			var s = nodes[i] && nodes[i].status;
			if (s === 'online') online++;
			if (s === 'degraded' || s === 'unreachable') attention++;
		}
		return {
			id: 'fleet', title: T(lang, 't_fleet'), level: fleetVerdict(nodes),
			value: T(lang, 'fleetValue', { online: online, n: nodes.length }),
			detail: attention ? T(lang, 'needAttention', { n: attention }) : T(lang, 'allHealthy'),
			action: 'fleet'
		};
	}

	// The list the Fleet dialog renders — one row per node with a status and a short health summary. No token is present
	// in the state, so none can leak here.
	function nodeList(state, lang) {
		lang = lang || 'en';
		return arr(state.fleet).map(function (n) {
			n = n || {};
			var h = n.health || {};
			var detail;
			if (n.status === 'unreachable') detail = n.error ? T(lang, 'unreachableReason', { reason: n.error }) : T(lang, 'unreachable');
			else if (n.status === 'unknown') detail = T(lang, 'notChecked');
			else detail = (h.status === 'error' ? T(lang, 'errors', { n: h.errors }) : (h.warnings ? T(lang, 'warnings', { n: h.warnings }) : T(lang, 'healthy'))) + (h.version ? ' · v' + h.version : '');
			return { id: n.id, label: n.label || hostOf(n.url) || T(lang, 'nodeFallback'), sub: hostOf(n.url), status: n.status || 'unknown', level: levelOf(n.status), detail: detail };
		});
	}

	root.VaultFleet = { fleetTile: fleetTile, nodeList: nodeList, fleetVerdict: fleetVerdict, levelOf: levelOf, STRINGS: STRINGS };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultFleet;
