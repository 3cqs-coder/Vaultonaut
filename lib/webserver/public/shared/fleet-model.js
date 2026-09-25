'use strict';
// Shared fleet model — pure logic for the multi-node fleet view: the Overview "Fleet" tile summary and the node list
// the Fleet dialog renders, computed from the cached fleet snapshot the server already put in the state. Lives here so
// the exact rollup logic is unit-tested in Node with no browser. ES5 (var, function expressions), loaded with a
// <script> tag before app.js and exported for require() in tests. Reads only status/counts — never a vault identity.
(function (root) {
	function arr(v) { return Array.isArray(v) ? v : []; }
	function hostOf(url) { try { var m = String(url || '').match(/^[a-z]+:\/\/([^/]+)/i); return m ? m[1] : String(url || ''); } catch (e) { return String(url || ''); } }

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

	function fleetTile(state) {
		var nodes = arr(state.fleet);
		if (!nodes.length) return null; // no nodes enrolled — omit the tile entirely
		var online = 0, attention = 0;
		for (var i = 0; i < nodes.length; i++) {
			var s = nodes[i] && nodes[i].status;
			if (s === 'online') online++;
			if (s === 'degraded' || s === 'unreachable') attention++;
		}
		return {
			id: 'fleet', title: 'Fleet', level: fleetVerdict(nodes),
			value: online + ' online · ' + nodes.length + (nodes.length === 1 ? ' node' : ' nodes'),
			detail: attention ? (attention + (attention === 1 ? ' node needs attention' : ' nodes need attention')) : 'All nodes healthy',
			action: 'fleet'
		};
	}

	// The list the Fleet dialog renders — one row per node with a status and a short health summary. No token is present
	// in the state, so none can leak here.
	function nodeList(state) {
		return arr(state.fleet).map(function (n) {
			n = n || {};
			var h = n.health || {};
			var detail;
			if (n.status === 'unreachable') detail = n.error ? ('Unreachable · ' + n.error) : 'Unreachable';
			else if (n.status === 'unknown') detail = 'Not checked yet';
			else detail = (h.status === 'error' ? (h.errors + ' error(s)') : (h.warnings ? (h.warnings + ' warning(s)') : 'Healthy')) + (h.version ? ' · v' + h.version : '');
			return { id: n.id, label: n.label || hostOf(n.url) || 'Node', sub: hostOf(n.url), status: n.status || 'unknown', level: levelOf(n.status), detail: detail };
		});
	}

	root.VaultFleet = { fleetTile: fleetTile, nodeList: nodeList, fleetVerdict: fleetVerdict, levelOf: levelOf };
})(typeof window !== 'undefined' ? window : this);

if (typeof module !== 'undefined' && module.exports) module.exports = (typeof window !== 'undefined' ? window : this).VaultFleet;
