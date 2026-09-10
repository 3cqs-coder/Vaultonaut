'use strict';
// lib/index.js — the programmatic API. Everything the command-line tool does is
// available here as plain async functions, so the encrypted virtual disk can be
// embedded in another Node application without shelling out. Nothing here blocks
// the event loop.
//
//   const vdisk = require('vaultonaut');
//   await vdisk.create('/path/Personal.vault', { password });
//   const { mountpoint } = await vdisk.mount('/path/Personal.vault', { password });
//   await vdisk.unmount(mountpoint);

const Vault = require('./Vault');
const Watchdog = require('./Watchdog');
const SelfCheck = require('./SelfCheck');
const RcloneSetup = require('./RcloneSetup');
const Driver = require('./Driver');
const DriverInstall = require('./DriverInstall');
const Autostart = require('./Autostart');

module.exports = {
	kdfLevels: Object.keys(require('./Kdf').LEVELS), // the valid security-level names, for CLI/UI validation
	create: Vault.create,
	importFolder: Vault.importFolder,
	changePassword: Vault.changePassword,
	addKey: Vault.addKey,
	removeKey: Vault.removeKey,
	addRecoveryKey: Vault.addRecoveryKey,
	addDeviceKey: Vault.addDeviceKey,
	addKeyfile: Vault.addKeyfile,
	keyfileDigestFromFile: Vault.keyfileDigestFromFile,
	addReadOnlyKey: Vault.addReadOnlyKey,   // dual-key: a password that opens the vault read-only
	makeReadCap: Vault.makeReadCap,         // a shareable read-only capability token (with optional expiry)
	makeWebReadCap: Vault.makeWebReadCap,   // a read-only capability shaped for the browser decryptor (revealed salt)
	shareSeal: Vault.shareSeal,             // seal a read cap to a recipient's public key (portable offline share)
	shareOpen: Vault.shareOpen,             // recipient opens a sealed share bundle with their private key
	enableTeam: Vault.enableTeam,           // turn a solo vault into a team vault (mint the owner key)
	addMember: Vault.addMember,             // add a member by their public key (read or read-write)
	listMembers: Vault.listMembers,         // list a team vault's members + roster state
	removeMember: Vault.removeMember,       // remove a member (soft; rotate separately for true revocation)
	setMemberOwner: Vault.setMemberOwner,   // promote a member to owner, or demote an owner to a plain member
	addDevice: Vault.addDevice,             // enroll another device key for an existing member
	removeDevice: Vault.removeDevice,       // revoke one device, keeping the member's other devices
	setupOwnerRecovery: Vault.setupOwnerRecovery, // split owner access across n trustees, any k restore it
	getRecoveryShare: Vault.getRecoveryShare,     // a trustee opens their sealed recovery share
	recoverOwner: Vault.recoverOwner,             // reconstruct owner access from k trustee shares (self-verified)
	unlockByMemberKey: Vault.unlockByMemberKey, // recover the capability from a member's private key
	parseReadCap: Vault.parseReadCap,
	listShares: Vault.listShares,           // the signed roster of who has access
	revokeShare: Vault.revokeShare,         // mark a share revoked
	pruneShares: Vault.pruneShares,         // remove revoked/expired entries from the access list
	decoyProtected: Vault.decoyProtected,   // does any per-vault decoy pairing exist?
	decoySet: Vault.decoySet,               // pair a real vault with a decoy vault (opened by the decoy's password)
	decoyRemove: Vault.decoyRemove,         // remove a vault's decoy pairing (manager password)
	decoyList: Vault.decoyList,             // list decoy pairings (manager password) — the hidden management view
	travelEnable: Vault.travelEnable,       // hide all vaults + lock, stashed under a travel password
	travelRestore: Vault.travelRestore,     // restore what travel mode hid (travel password)
	travelStatus: Vault.travelStatus,       // is travel mode currently active?
	emergencyKeypair: Vault.emergencyKeypair,   // a contact generates this; shares only the public half
	emergencyEnroll: Vault.emergencyEnroll,     // set up the dead-man's switch (contact pubkey + windows)
	emergencyArm: Vault.emergencyArm,           // seal a vault's read cap to the contact
	emergencyCheckIn: Vault.emergencyCheckIn,   // "I'm still here" — resets the timer, vetoes a release
	emergencyStatus: Vault.emergencyStatus,     // is it set up, and how long until release
	emergencyTick: Vault.emergencyTick,         // periodic check (releases when overdue) — wired into the service
	emergencyNoteClockDrift: Vault.emergencyNoteClockDrift, // record a detected forward clock jump so the timer discounts it
	emergencyOpen: Vault.emergencyOpen,         // contact side: open a sealed blob with their private key
	emergencyDisarm: Vault.emergencyDisarm,     // cancel the arrangement (remember: true revocation is rotating keys)
	rotate: Vault.rotate,                   // rotate keys + re-encrypt the whole store (true revocation)
	verifySuccession: Vault.verifySuccession, // verify the signed identity-succession chain
	resumeRekey: Vault.resumeRekey,         // finish or roll back an interrupted rotation
	listKeys: Vault.listKeys,
	deviceDescriptors: Vault.deviceDescriptors,
	mount: Vault.mount,
	recordMountPrefs: Vault.recordMountPrefs, // remember a vault's chosen mount mode
	setFavorite: Vault.setFavorite,           // mark a vault as a favorite (surfaced first, one-tap unlock)
	listVersions: Vault.listVersions,         // browse prior file versions kept by a backup or a mirror (both sides)
	restoreVersion: Vault.restoreVersion,     // restore a file from a version snapshot (as a non-clobbering copy)
	importFiles: Vault.importFiles,           // stream files into a mounted vault (bypasses OS copy)
	unmount: Vault.unmount,
	lockAll: Vault.lockAll,
	getSettings: Vault.getSettings,
	setSettings: Vault.setSettings,
	status: Vault.status,
	listMounts: Vault.listMounts,   // plain, non-blocking read of the mount state (no per-mount stat) — used by `stop`
	list: Vault.list,
	searchNames: Vault.searchNames,   // filename search (mounted = no password; unmounted = password)
	contentReindex: Vault.contentReindex,       // build/refresh the in-vault full-text index (mounted; incremental; worker)
	contentSearch: Vault.contentSearch,         // search inside files via the in-vault index (mounted)
	contentIndexStatus: Vault.contentIndexStatus, // is there an index, and how many files it covers
	verify: Vault.verify,
	scanSyncArtifacts: Vault.scanSyncArtifacts,
	protect: Vault.protect,
	recoveryStatus: Vault.recoveryStatus,
	verifyRecovery: Vault.verifyRecovery,
	heal: Vault.heal,
	unprotect: Vault.unprotect,
	secureRemove: Vault.secureRemove,
	refreshRecoveryIfStale: Vault.refreshRecoveryIfStale,
	mirrorDestFor: Vault.mirrorDestFor,
	mirrorStatus: Vault.mirrorStatus,
	setMirrorDest: Vault.setMirrorDest,
	removeMirror: Vault.removeMirror,
	syncMirror: Vault.syncMirror,
	syncMirrorIfConfigured: Vault.syncMirrorIfConfigured,
	listPeers: Vault.listPeers,
	savePeer: Vault.savePeer,
	removePeer: Vault.removePeer,
	testPeer: Vault.testPeer,
	serveVault: Vault.serveVault,
	setRelay: Vault.setRelay,
	getRelay: Vault.getRelay,
	makePeerCode: Vault.makePeerCode,
	parsePeerCode: Vault.parsePeerCode,
	getUiAuth: Vault.getUiAuth,
	setUiPassword: Vault.setUiPassword,
	addUiWebauthn: Vault.addUiWebauthn,
	removeUiWebauthn: Vault.removeUiWebauthn,
	verifyUiWebauthn: Vault.verifyUiWebauthn,
	clearUiPassword: Vault.clearUiPassword,
	disperse: Vault.disperse,                       // Tier 3: split a vault into n shards, any k rebuild it
	reconstructFromShards: Vault.reconstructFromShards,
	inspectShards: Vault.inspectShards,
	repairDispersal: Vault.repairDispersal,
	dispersalGuidance: Vault.dispersalGuidance,
	addThresholdKey: Vault.addThresholdKey,         // Tier 3: split the unlock key k-of-n across holders
	unlockSecretFromShares: Vault.unlockSecretFromShares,
	listRepairSchedules: Vault.listRepairSchedules, // Tier 3: scheduled cross-node shard repair
	saveRepairSchedule: Vault.saveRepairSchedule,
	removeRepairSchedule: Vault.removeRepairSchedule,
	dispersalRepairTick: Vault.dispersalRepairTick,
	mirrorLeaseStatus: Vault.mirrorLeaseStatus,
	claimLeaseForMount: Vault.claimLeaseForMount,
	releaseLease: Vault.releaseLease,
	refreshLease: Vault.refreshLease,
	LEASE_HEARTBEAT_INTERVAL_MS: Vault.LEASE_HEARTBEAT_INTERVAL_MS,
	snapshot: Vault.snapshot,
	seal: Vault.seal,
	unseal: Vault.unseal,
	audit: Vault.audit,
	checkOnMount: Vault.checkOnMount, // run the on-mount crash-vs-tamper check without mounting (diagnostics/tests)
	fingerprint: Vault.fingerprint,
	recoveryKit: Vault.recoveryKit,         // a printable one-page Recovery Kit (identity, fingerprint, spare key)
	attest: Vault.attest,                   // create a trusted timestamp proving the vault's exact state at a time
	attestations: Vault.attestations,       // list and verify a vault's timestamped proofs
	makeBundle: Vault.makeBundle,           // package a portable, third-party-verifiable proof bundle
	verifyBundle: Vault.verifyBundle,       // verify a proof bundle offline -> GENUINE / TAMPERED / ROLLED-BACK
	fileProof: Vault.fileProof,             // a small, shareable proof that ONE file is in the vault's signed state
	verifyFileProof: Vault.verifyFileProof, // verify a single-file proof offline -> GENUINE / TAMPERED / UNVERIFIED
	notesList: Vault.notesList,             // secure notes kept as encrypted files inside a mounted vault
	noteGet: Vault.noteGet,
	noteSave: Vault.noteSave,
	noteDelete: Vault.noteDelete,
	notesHealth: Vault.notesHealth,         // on-device password-health report (reused / weak / opt-in breach)
	sealItemForSend: Vault.sealItemForSend,  // seal one item for an expiring, view-limited Send link
	tamperLog: Vault.tamperLog,
	pack: Vault.pack,
	unpack: Vault.unpack,
	backup: Vault.backup,
	restore: Vault.restore,
	backupDestFor: Vault.backupDestFor,
	verifyBackup: Vault.verifyBackup,
	getBackupSchedule: Vault.getBackupSchedule,
	setBackupSchedule: Vault.setBackupSchedule,
	isBackupDue: Vault.isBackupDue,
	getScrubSchedule: Vault.getScrubSchedule,
	setScrubSchedule: Vault.setScrubSchedule,
	runScrub: Vault.runScrub,
	scrubScheduleTick: Vault.scrubScheduleTick,
	listSftpDests: Vault.listSftpDests,
	saveSftpDest: Vault.saveSftpDest,
	removeSftpDest: Vault.removeSftpDest,
	testSftpDest: Vault.testSftpDest,
	listCloudRemotes: Vault.listCloudRemotes,   // cloud storage backends for cloud-backed vaults
	saveCloudRemote: Vault.saveCloudRemote,
	removeCloudRemote: Vault.removeCloudRemote,
	testCloudRemote: Vault.testCloudRemote,
	cloudAuthorize: Vault.cloudAuthorize,       // browser OAuth sign-in for a cloud backend -> { token }
	saveCloudOAuth: Vault.saveCloudOAuth,       // store an OAuth cloud remote (token encrypted at rest)
	isOAuthBackend: Vault.isOAuthBackend,       // does a storage type sign in with a browser account?
	cloudFilenameEncoding: Vault.cloudFilenameEncoding, // the fixed name encoding a backend needs (base32768 for UTF-16)
	doctor: Vault.doctor,
	selfCheck: SelfCheck.run,          // run the boot-time integrity self-check -> findings[]
	registerCheck: SelfCheck.register, // add a custom self-check: registerCheck(name, fn)
	sweep: Vault.sweep,
	// One-shot responsiveness probe of the given tracked mounts -> { <mountpoint>: health }.
	mountHealth: async (mounts) => (await Watchdog.refresh(mounts)).snapshot,
	reveal: Vault.reveal,
	readManifest: Vault.readManifest,
	defaultMountRoot: Vault.defaultMountRoot,
	resolveVaultDir: Vault.resolveVaultDir,
	displayName: Vault.displayName,   // vault path -> friendly name; used by the CLI's confirm prompts and decoy/rotate/remove

	addKnownVault: Vault.addKnownVault,
	removeKnownVault: Vault.removeKnownVault,
	listKnownVaults: Vault.listKnownVaults,
	setup: RcloneSetup.ensure,
	detectDriver: Driver.detect,
	installDriver: DriverInstall.install,
	autostart: Autostart
};
