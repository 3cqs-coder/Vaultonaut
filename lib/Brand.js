'use strict';
// lib/Brand.js — the product's identity, in ONE place.
//
// To rename the product, edit the values below; nothing else in the codebase hardcodes the name.
// Each field is a distinct KIND of identity, so they can be changed independently:
//
//   • name         display name — the UI, banners, messages, the OS process title
//   • cli          the command users type (help text is generated from this)
//   • slug         lowercase id — the on-disk format marker, the branded process/executable name
//   • vaultExt     the vault folder suffix (kept separate from the name on purpose — a rename need
//                  not change the on-disk extension unless you want it to)
//   • mountDirName the default mount-root folder created under the user's home directory
//   • serviceId    the OS scheduled-task / service identifier (no spaces)
//
// (The npm package name in package.json and the prose in docs/README.md are edited by hand on a rename.
// Two spots also carry the name/cli/ext for fallback or substitution, NOT as an independent source of truth:
// the web client's data-* fallbacks in public/js/app.js, and the CLI help placeholders in lib/Commands.js
// that are substituted with these Brand values at print time. Update those alongside a rename if they drift.)
const vaultExt = '.vault';
module.exports = {
	name: 'Vaultonaut',
	cli: 'vdisk',
	slug: 'vaultonaut',
	vaultExt,
	packExt: '.vdisk',
	mountDirName: 'Vaultonaut',
	serviceId: 'VaultonautUI',
	// A case-insensitive regex matching the vault-extension suffix, single-sourced here so the several
	// places that strip it (mount lookup, display name) don't each rebuild the escaped pattern.
	vaultExtRe: new RegExp(vaultExt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i'),
};
