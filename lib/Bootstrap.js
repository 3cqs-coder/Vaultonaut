'use strict';

// lib/Bootstrap.js — the earliest startup guard, kept separate and written in plain ES5 (var / function, no
// template literals, no optional chaining) with NO require of any feature module, so it can load and run on a
// very old or minimal runtime BEFORE the entry point pulls in anything modern. Its one job is to fail early and
// clearly when the runtime is older than package.json's engines.node, instead of letting an unsupported Node
// crash later with a cryptic error deep inside a dependency (or a syntax error from newer JS).

// Pure: is `current` older than `required` (both dotted "x.y.z" strings)? Compares component-wise and
// NUMERICALLY (so 24.9 < 24.15, not the reverse a string compare would give), tolerant of differing lengths and
// of non-numeric noise (a "-nightly" suffix, etc.). Exposed for tests.
function isNodeOlder(required, current) {
	var toNums = function (v) { return String(v).split('.').map(function (n) { return parseInt(n, 10) || 0; }); };
	var r = toNums(required), c = toNums(current);
	for (var i = 0; i < r.length; i++) {
		if ((c[i] || 0) < r[i]) { return true; }
		if ((c[i] || 0) > r[i]) { return false; }
	}
	return false;
}

// Exit early with a clear message if the runtime is older than package.json's engines.node. `rootDir` is the
// entry point's __dirname (where package.json lives); `appLabel` names the product in the message. A failure in
// the check ITSELF never blocks startup — a missing or oddly-shaped engines field must not stop a valid runtime.
function enforceNodeVersion(rootDir, appLabel) {
	var label = appLabel || 'This program';
	try {
		var required = require(rootDir + '/package.json').engines.node.replace(/[^0-9.]/g, '');
		if (required && isNodeOlder(required, process.versions.node)) {
			console.error('\n' + label + ' requires Node.js >= ' + required + ', but this is Node ' + process.versions.node + '.\nPlease install a newer Node.js and start it again.\n');
			process.exit(1);
		}
	} catch (e) { /* if the version check itself fails, never block a valid runtime from starting */ }
}

module.exports = {
	enforceNodeVersion: enforceNodeVersion,
	isNodeOlder: isNodeOlder // exposed for tests
};
