'use strict';
// lib/test/dialogactions.js — guards a layout invariant that has regressed more than once: a ".dialog-actions" row
// is styled as a STICKY dialog FOOTER (it pins to the bottom with a top divider and negative side margins that let it
// span the dialog's full width). That styling is correct only for the footer that ENDS a view. When the same class is
// reused for an actions row in the MIDDLE of a view (for example an "Add beneficiary" button with more fields below
// it), it must also carry the ".dialog-actions-inline" reset — otherwise the negative margins break it out full-bleed
// and draw a stray full-width divider, and on a scrolling dialog "position: sticky" floats it over the fields below.
//
// A dialog often holds several swapped PANELS (a "create" view and a "done" view, say), each shown one at a time and
// each ending in its own legitimate footer — so "the last .dialog-actions in the dialog is the only footer" is wrong.
// The real rule is per-panel: within the panel that contains it, an actions row is a footer only when NO field content
// follows it. This test builds a small container tree (div/form/details/fieldset) from index.ejs so it can find each
// actions row's panel and check what really follows it, rather than guessing from raw position.
//
// Static only (no browser, no engine — fast and cross-platform, like the other UI-drift tests). It also pins that the
// CSS reset is the COMPOUND selector ".dialog-actions.dialog-actions-inline": a single-class reset would tie the base
// rule on specificity and, because the base rule comes later in the file, silently LOSE the cascade and do nothing.
//
// Run:  node lib/test/dialogactions.js

const fs = require('fs');
const path = require('path');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }

const web = path.join(__dirname, '..', 'webserver', 'public');
const read = (p) => fs.readFileSync(p, 'utf8');

const hasClass = (openTag, cls) => new Set((/class="([^"]*)"/.exec(openTag)?.[1] || '').split(/\s+/).filter(Boolean)).has(cls);

// Build a tree of the container elements (div/form/details/fieldset) inside one dialog block, each with its source
// range and parent. Content elements (label/input/select…) are NOT nodes — they are found later by scanning raw text
// within a panel's range, which is all the "does field content follow?" test needs.
function containerTree(html) {
	const re = /<(div|form|details|fieldset)\b[^>]*>|<\/(div|form|details|fieldset)>/g;
	const nodes = [];
	const stack = [];
	let m;
	while ((m = re.exec(html))) {
		if (m[1]) { // opening tag
			const node = { tag: m[1], open: m[0], start: m.index, openEnd: re.lastIndex, end: -1, parent: stack.length ? stack[stack.length - 1] : null };
			nodes.push(node);
			stack.push(node);
		} else if (stack.length) { // closing tag — pair with the nearest open of the same tag
			for (let i = stack.length - 1; i >= 0; i--) { if (stack[i].tag === m[2]) { stack[i].end = re.lastIndex; stack.length = i; break; } }
		}
	}
	return nodes;
}

// The panel a row belongs to — the range we scan for "what follows this row". When the row is wrapped in a panel
// <div> (a child of the <form>), that wrapper is the view. When the row is a DIRECT child of the form (a plain
// single-view dialog with its fields and one footer straight under the form), the whole form is the view — returning
// the row itself would make the "does field content follow?" slice empty and misread every such footer/mid row.
function panelOf(node, form, rootEnd) {
	if (node.parent === form) return form || { end: rootEnd }; // direct child of the form (or top-level when there is no form)
	let cur = node;
	while (cur.parent && cur.parent !== form) cur = cur.parent;
	return cur; // the panel wrapper that is a direct child of the form
}

// Does real field content appear in `slice`? These are the markers that mean "more of the view follows this row".
const FIELD_MARKERS = [/class="field"/, /<input\b/, /<select\b/, /<textarea\b/, /<fieldset\b/, /class="[^"]*\bdialog-actions\b/];
const hasFieldContent = (slice) => FIELD_MARKERS.some((re) => re.test(slice));

function main() {
	const ejs = read(path.join(web, 'views', 'index.ejs'));
	const css = read(path.join(web, 'css', 'app.css'));

	const dialogs = [...ejs.matchAll(/<dialog\b[\s\S]*?<\/dialog>/g)].map((x) => x[0]);
	ok('index.ejs has <dialog> blocks to inspect', dialogs.length > 0);

	let midCount = 0, footerCount = 0;
	for (const block of dialogs) {
		const id = /<dialog[^>]*id="([^"]*)"/.exec(block)?.[1] || '(unnamed)';
		const nodes = containerTree(block);
		const form = nodes.find((n) => n.tag === 'form') || null;
		const rows = nodes.filter((n) => n.tag === 'div' && hasClass(n.open, 'dialog-actions') && n.end > 0);
		// A footer that is a DIRECT child of the form is the view's ONE main footer. Its presence tells the two dialog
		// shapes apart: dialogs whose only actions rows sit inside swapped, mutually-exclusive panels (each its own
		// footer) have NO form-level footer, whereas a dialog with a main footer may also show additive sub-sections
		// ABOVE it (like the "deliver keys" block) whose own actions row therefore sits mid-view and needs the reset.
		const hasFormLevelFooter = rows.some((r) => r.parent === form);
		for (const row of rows) {
			const panel = panelOf(row, form, block.length);
			// The row needs the reset when it is NOT the bottom-most actions row of the visible view. That is true when
			// (1) field content follows it within its own panel, OR (2) it sits inside a sub-section (not a direct child
			// of the form) while the form has its own main footer that will render below it.
			const after = block.slice(row.end, panel.end);
			const midView = hasFieldContent(after) || (row.parent !== form && hasFormLevelFooter);
			if (midView) {
				midCount++;
				ok('dialog #' + id + ' mid-view .dialog-actions row (more of the view follows it) carries .dialog-actions-inline', hasClass(row.open, 'dialog-actions-inline'));
			} else {
				footerCount++;
				// A true footer must NOT carry the reset (that would drop the intended sticky footer) — keeps the two roles honest.
				ok('dialog #' + id + ' footer .dialog-actions row does NOT carry the mid-view reset', !hasClass(row.open, 'dialog-actions-inline'));
			}
		}
	}
	ok('found mid-view actions rows to guard (the pattern is in use)', midCount > 0);
	ok('found footer actions rows (classifier distinguishes the two roles)', footerCount > 0);

	// The reset must be the COMPOUND selector so it outranks the base .dialog-actions rule regardless of source order.
	ok('app.css defines the reset as the COMPOUND selector .dialog-actions.dialog-actions-inline', /\.dialog-actions\.dialog-actions-inline\s*\{/.test(css));
	ok('app.css does NOT rely on a bare single-class .dialog-actions-inline reset (it would lose the cascade)', !/(^|[^.\w-])\.dialog-actions-inline\s*\{/m.test(css));
	ok('app.css .dialog-actions base rule is still the sticky footer the reset guards against', /\.dialog-actions\s*\{[^}]*position:\s*sticky/.test(css));

	console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL DIALOG-ACTIONS CHECKS PASSED'));
	process.exit(failures ? 1 : 0);
}

main();
