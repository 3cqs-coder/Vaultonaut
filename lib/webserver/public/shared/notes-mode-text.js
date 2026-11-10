/* shared/notes-mode-text.js — the user-facing strings for the focused password-manager mode, in ONE place.
   The module is a tiny UMD file: the server requires it to render the initial page, and the browser reads it for
   dynamic messages. A future locale can replace the map without touching the note logic. Template ids, field kinds,
   and item types remain stable language-neutral slugs; only human-readable labels live here. */
(function (root, factory) {
	var text = factory();
	if (typeof module === 'object' && module.exports) module.exports = text;
	else root.VaultNotesText = text;
})(typeof self !== 'undefined' ? self : this, function () {
	return {
		title: 'Password manager',
		backToVaults: '← Vaults',
		vaults: 'Vaults',
		readOnlyNotice: 'This vault is open read-only, so items can be viewed but not changed. Reopen it with a read-write password to edit.',
		backToVaultsLabel: 'Back to the vault list',
		lead: 'Open a vault with its password. No drive is mounted, and decrypted items stay in this browser tab.',
		vault: 'Vault',
		vaultPassword: 'Vault password',
		open: 'Open',
		opening: 'Opening…',
		loadingVaults: 'Loading vaults…',
		noVaults: 'No vaults found — open the full interface to create one',
		chooseVault: 'Choose a vault to open.',
		enterPassword: 'Enter the vault password.',
		couldNotOpen: 'Could not open the vault.',
		dialogTitle: 'Password manager',
		lock: 'Lock',
		changeTheme: 'Change theme',
		hintBefore: 'This is the same encrypted vault as the drive, using the same secure-note format. ',
		fullInterface: 'Open the full vault interface',
		hintAfter: ' to create a vault or manage files.'
	};
});
