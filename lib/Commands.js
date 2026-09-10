'use strict';
// lib/Commands.js — every command-line command lives here. The entry point (vaultonaut.js) is a
// slim launcher that parses arguments and hands off to dispatch(); all command logic, prompts, and
// help text are in this module. Options come from arguments only — never environment variables.

const vdisk = require('./index');
const prompt = require('./prompt');
const OwnerClient = require('./OwnerClient');
const State = require('./State');
const Brand = require('./Brand');
const ProcRegistry = require('./ProcRegistry');
const Common = require('./Common');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process'); // core module; used by the Windows supervisor, the browser opener, and the detached-service launcher

// Format a timestamp for display. An expiry epoch can arrive as a number OR as a numeric string; coerce an
// all-digits value to a number first so it never renders as "Invalid Date", while leaving ISO date strings
// untouched. One helper so every displayed time is coerced the same way and cannot drift between call sites.
function fmtTime(x) {
	if (x == null || x === '') return '';
	const n = (typeof x === 'string' && /^\d+$/.test(x)) ? Number(x) : x;
	const d = new Date(n);
	return isNaN(d.getTime()) ? String(x) : d.toLocaleString();
}

// A compact one-line preview of a change list (added/removed/modified), capped so a huge set stays
// readable. Shared by the mount tamper warning and the seal preview; the audit report prints the
// full list instead (one per line) since the user asked to see everything there.
function changePreview(label, arr, max = 20) {
	if (!arr || !arr.length) return;
	console.log('  ' + label + ' (' + arr.length + '): ' + arr.slice(0, max).join(', ') + (arr.length > max ? ', …' : ''));
}

// A consequential-action gate for expert-only, hard-to-reverse changes (decoy, travel, emergency): require the
// user to type "I understand" before proceeding. Returns true to go ahead, false (after saying so) to cancel.
// Single-sourced so every such gate reads and behaves identically.
async function confirmUnderstand() {
	const ack = await prompt.line('Type "I understand" to continue: ');
	if (ack.toLowerCase() === 'i understand') return true;
	console.log('Canceled — nothing was changed.');
	return false;
}

// A typed-name gate for hard-to-reverse actions on a specific vault (rotate, remove a member or device with
// re-encryption, secure-remove): the user must type the vault's exact display name to proceed. Single-sourced so the
// compare behaves identically everywhere — trimmed, so stray trailing whitespace never silently defeats the gate.
// `buildPrompt(name)` returns the question to ask; on a mismatch this prints `cancelMsg` and returns false.
async function confirmVaultName(target, buildPrompt, cancelMsg) {
	const name = vdisk.displayName(target);
	const ans = (await prompt.line(buildPrompt(name))).trim();
	if (ans === name) return true;
	console.log(cancelMsg);
	return false;
}

// A single-line progress meter for long self-heal operations, so the terminal always shows work is
// happening (a TTY updates one line in place; a redirected stdout stays quiet to avoid log spam).
// Returns an onProgress callback with a .done() to finish the line.
function cliProgress(opts = {}) {
	const stream = opts.stream || process.stdout; // rotate reports on stderr so its result lines stay clean on stdout
	const tty = stream.isTTY;
	let active = false;
	const onProgress = (p) => {
		if (!p || !tty) return;
		active = true;
		// Redraw one line with \r; pad to a fixed width so a shorter label fully overwrites a longer
		// previous one (no ANSI codes, so it stays correct on every terminal).
		const line = (p.label ? p.label + ' ' : '') + (p.percent == null ? '' : p.percent + '%');
		stream.write('\r' + line.padEnd(42));
	};
	onProgress.done = () => { if (active && tty) stream.write('\n'); active = false; }; // keep the final line, move on
	return onProgress;
}

function parse(argv) {
	const positionals = [];
	const flags = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a.startsWith('--')) {
			const body = a.slice(2);
			// Support BOTH "--flag value" and "--flag=value". Without the "=" form a value joined with "="
			// silently misfired: "--flag=value" set the bogus key "flag=value" to true and left the real flag
			// undefined, so a handler used its default — a silent, sometimes security-relevant wrong result
			// (e.g. "--kdf=high" quietly created a standard-strength vault; "--expires=7" minted a share with no
			// expiry). Splitting on the first "=" binds the value to the flag as the user intended.
			const eq = body.indexOf('=');
			if (eq >= 0) { flags[body.slice(0, eq)] = body.slice(eq + 1); continue; }
			const key = body;
			const next = argv[i + 1];
			if (next === undefined || next.startsWith('--')) { flags[key] = true; }
			else { flags[key] = next; i++; }
		} else positionals.push(a);
	}
	return { positionals, flags };
}

// Validate a --port value to a whole number in 1..65535, or return `dflt` when the flag is absent. Throws a
// clear usage line on a present-but-invalid value, so a typo (or a bare "--port" that parses as `true`, or a
// non-numeric value) is rejected up front instead of silently falling back to the default or handing NaN to the
// listener to fail later with an opaque bind error. One helper so every port flag is checked the same way.
function parsePort(flag, dflt) {
	if (flag === undefined) return dflt;
	const n = parseInt(flag, 10);
	if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error('--port must be a whole number from 1 to 65535 (for example, --port ' + (dflt || Common.DEFAULT_UI_PORT) + ').');
	return n;
}

// Resolve a relay token from --token or --token-file, keeping the secret OFF the command line where argv is
// world-readable (via ps / /proc/<pid>/cmdline on a shared or public host). Returns { token, provided }; both the
// serve node and the relay hub use this so the two agree. A bare --token (no value) parses to boolean true and is
// rejected rather than used as the literal token.
async function resolveToken(flags, { required = false, what = 'the relay token' } = {}) {
	let token = (typeof flags.token === 'string' && flags.token) ? flags.token : null;
	let provided = !!token;
	if (!token && flags['token-file']) {
		try { token = (await fs.promises.readFile(flags['token-file'], 'utf8')).trim(); }
		catch (_) { throw new Error('Could not read the token file: ' + flags['token-file']); }
		if (!token) throw new Error('The token file is empty: ' + flags['token-file']);
		provided = true;
	}
	if (required && !token) throw new Error('A token is required — pass --token <value> or, to keep it off the command line, --token-file <path> (for ' + what + ').');
	return { token, provided };
}

let HELP_CACHE = null;
// The help copy lives in lib/templates/help.txt, written with the default names; the product identity is
// substituted in from Brand at print time, so a rename needs no edits to the copy. Command invocations, the
// pack extension, the mount-dir folder, and the banner name all follow Brand. Read once and cached (a one-shot
// CLI path over a local file, so a synchronous read is fine here).
function help() {
	if (HELP_CACHE === null) {
		try { HELP_CACHE = fs.readFileSync(path.join(__dirname, 'templates', 'help.txt'), 'utf8').replace(/\n$/, ''); }
		catch (_) { HELP_CACHE = 'Virtual Disk — help is unavailable (lib/templates/help.txt is missing from this install).'; }
	}
	console.log(HELP_CACHE
		.replace(/^Virtual Disk —/, Brand.name + ' —')                 // banner
		.replace(/\bnode vaultonaut\.js\b/g, 'node ' + Brand.slug + '.js') // the "run from the folder" form (rename-safe)
		.replace(/^(\s*)vdisk /gm, `$1${Brand.cli} `)                  // command invocations
		.replace(/~\/Virtual Disks\//g, '~/' + Brand.mountDirName + '/') // default mount root
		.replace(/\.vdisk\b/g, Brand.packExt));                        // portable-container extension
}

let NOTICES_CACHE = null;
// Advisory blocks for expert / hard-to-reverse actions (decoy, travel, emergency, rotate) live in
// lib/templates/notices.txt, one [section] per block, so the copy is edited as text rather than as sequences of
// console.log calls — the same reason the help text is externalized. Product names are substituted at print time
// (rename-safe), like help(). Read once and parsed into sections; a one-shot CLI path over a local file.
function notice(key) {
	if (NOTICES_CACHE === null) {
		NOTICES_CACHE = {};
		try {
			const raw = fs.readFileSync(path.join(__dirname, 'templates', 'notices.txt'), 'utf8');
			let cur = null, buf = [];
			for (const line of raw.split('\n')) {
				const m = /^\[(.+)\]\s*$/.exec(line);
				if (m) { if (cur) NOTICES_CACHE[cur] = buf.join('\n').replace(/^\n+|\n+$/g, ''); cur = m[1]; buf = []; }
				else if (cur !== null) buf.push(line);
			}
			if (cur) NOTICES_CACHE[cur] = buf.join('\n').replace(/^\n+|\n+$/g, '');
		} catch (_) { /* a missing notices file just yields empty blocks; the action still proceeds */ }
	}
	return (NOTICES_CACHE[key] || '')
		.replace(/^(\s*)vdisk /gm, `$1${Brand.cli} `)   // any command reference stays rename-safe
		.replace(/\.vdisk\b/g, Brand.packExt);
}

// Validate an optional --kdf security level against the single source of truth (Kdf.LEVELS). Higher
// levels are costlier to brute-force, slightly slower to unlock, and need more RAM to open.
function requireKdfLevel(flags) {
	const level = flags.kdf;
	if (level && !vdisk.kdfLevels.includes(level)) throw new Error('Unknown --kdf level "' + level + '". Choose ' + vdisk.kdfLevels.join(', ') + '.');
	return level;
}

// Validate the optional --expires flag shared by read-cap and share-seal: absent means "never expires", otherwise it
// must be a positive number of days. One helper so both share-minting commands check and word it identically.
function requireExpiresDays(flags) {
	// A BARE `--expires` (no value) parses as the boolean true, and Number(true) === 1 would sneak past a plain
	// `> 0` check and silently mint a 1-day share. Reject the bare flag explicitly, alongside a non-positive value.
	if (flags.expires !== undefined && (flags.expires === true || !(Number(flags.expires) > 0))) {
		throw new Error('--expires needs a positive number of days, for example --expires 7. Omit it for a share that never expires.');
	}
}

async function cmdCreate(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' create <path> [--cloud <remote-id> --remote-path <folder>]');
	const level = requireKdfLevel(flags);
	// A cloud vault keeps its keys local but stores the encrypted data on a saved cloud remote (see `cloud add`).
	const cloud = flags.cloud ? { remoteId: flags.cloud, remotePath: flags['remote-path'] || '' } : undefined;
	// Tamper-proof (WORM) mode locks each uploaded version for a retention window (S3 / S3-compatible only).
	let worm;
	if (flags.worm || flags['retain-days']) {
		if (!cloud) throw new Error('--worm needs a cloud vault on S3 or S3-compatible storage (add --cloud <id> --remote-path <bucket/...>).');
		if (flags['retain-days'] === true) throw new Error('--retain-days needs a number of days, for example --retain-days 30 (a bare --retain-days is not a value).'); // a bare flag parses to true → Number(true) is 1, which would silently mean a 1-day lock
		const retainDays = Number(flags['retain-days']);
		if (!(retainDays > 0)) throw new Error('--worm needs --retain-days <N> (how many days each version stays locked, at least 1).');
		const mode = String(flags['worm-mode'] || 'governance').toLowerCase();
		if (mode === 'compliance') console.log('WARNING: compliance mode is irreversible — until each version\'s retention expires, NOBODY (not even you, not even the account owner) can delete or overwrite it. Storage keeps growing with every edit, and the only early-out is closing the cloud account. Use governance mode unless you specifically need this.');
		worm = { mode: mode === 'compliance' ? 'compliance' : 'governance', retainDays };
	}
	const password = await prompt.newPassword('Password');
	const res = await vdisk.create(target, { password, level, cloud, worm });
	console.log('Created ' + (worm ? 'tamper-proof ' : '') + (cloud ? 'cloud ' : '') + 'vault at ' + res.vault + (level && level !== 'standard' ? ' (security level: ' + level + ')' : ''));
	if (res.identity) console.log('Vault identity: ' + res.identity + '\n  Record this somewhere safe and separate (it never changes). It is how you — or anyone you give a proof to — later confirm a copy is genuinely this vault. A Recovery Kit ("' + Brand.cli + ' recovery-kit") saves it for you.');
	if (worm) console.log('Tamper-proof (' + worm.mode + ', ' + worm.retainDays + '-day lock): edits and deletes become new, locked versions — storage grows with churn, and locked versions cannot be reclaimed until they age out. Add a lifecycle rule at your provider to expire old versions after the lock window if you want that space back.');
	console.log('Mount it with:  ' + Brand.cli + ' mount "' + res.vault + '"');
}

// Cloud storage backends: saved, reusable references to a remote (s3, b2, webdav, …) a cloud vault stores on.
async function cmdCloud(pos, flags) {
	const sub = (pos[0] || 'list').toLowerCase();
	if (sub === 'list') {
		const remotes = await vdisk.listCloudRemotes();
		if (!remotes.length) { console.log('No cloud storage configured. Add one with:\n  ' + Brand.cli + ' cloud add --type <s3|b2|webdav|…> [--label <name>] key=value …'); return; }
		remotes.forEach(r => console.log('  ' + r.id + '   ' + r.type + '   ' + (r.label || '')));
		return;
	}
	if (sub === 'remove') { const id = pos[1]; if (!id) throw new Error('Usage: ' + Brand.cli + ' cloud remove <id>'); await vdisk.removeCloudRemote(id); console.log('Removed cloud storage ' + id + '.'); return; }
	if (sub === 'test') { const id = pos[1]; if (!id) throw new Error('Usage: ' + Brand.cli + ' cloud test <id> [remote-path]'); const r = await vdisk.testCloudRemote(id, pos[2] || ''); console.log(r.ok ? 'Reachable — ' + r.detail : 'Not reachable — ' + r.detail); if (!r.ok) process.exitCode = 1; return; } // non-zero on failure so a script can gate on reachability, matching peer-test
	if (sub === 'connect') {
		const type = (pos[1] || flags.type || '').toLowerCase();
		if (!type || !vdisk.isOAuthBackend(type)) throw new Error('Usage: ' + Brand.cli + ' cloud connect <drive|dropbox|onedrive> [--label <name>] [--client-id <id> --client-secret <secret>]');
		console.log('Signing in to ' + type + ' in your browser. If it does not open automatically, open the link below.');
		const res = await vdisk.cloudAuthorize(type, { clientId: flags['client-id'], clientSecret: flags['client-secret'], onUrl: (url) => { console.log('\n  ' + url + '\n'); openUrl(url); } });
		const r = await vdisk.saveCloudOAuth({ label: flags.label, type, token: res.token, clientId: flags['client-id'], clientSecret: flags['client-secret'] });
		console.log('Connected ' + type + ' (id ' + r.id + ').');
		console.log('Create a vault on it with:\n  ' + Brand.cli + ' create <path> --cloud ' + r.id + ' --remote-path <folder>');
		return;
	}
	if (sub === 'add') {
		const type = flags.type;
		if (!type) throw new Error('Usage: ' + Brand.cli + ' cloud add --type <type> [--label <name>] [--secrets-file <path>] key=value …');
		// Auto-classify each key=value: password-type fields are engine-obscured, other known-secret fields are
		// stored encrypted and written verbatim, everything else is a plain option. Covers s3/b2/webdav directly.
		const OBSCURE = new Set(['pass', 'password', 'key_file_pass']);
		const PLAINSEC = new Set(['secret_access_key', 'key', 'token', 'sas_url', 'client_secret', 'account']);
		const opts = {}, secretsPlain = {}, secretsObscure = {};
		// Pairs may be given on the command line OR, to keep long-lived cloud secrets OFF argv (world-readable via
		// ps / /proc/<pid>/cmdline on a shared machine), in a --secrets-file: one key=value per line, with blank
		// lines and #-comments ignored. Both sources are classified identically.
		const pairs = pos.slice(1);
		if (flags['secrets-file']) {
			let text; try { text = fs.readFileSync(String(flags['secrets-file']), 'utf8'); } catch (_) { throw new Error('Could not read the secrets file "' + flags['secrets-file'] + '". Check the path and that the file exists.'); }
			for (const line of text.split(/\r?\n/)) { const t = line.trim(); if (t && !t.startsWith('#')) pairs.push(t); }
		}
		for (const kv of pairs) { const i = kv.indexOf('='); if (i < 0) continue; const k = kv.slice(0, i).trim(), v = kv.slice(i + 1); if (OBSCURE.has(k)) secretsObscure[k] = v; else if (PLAINSEC.has(k)) secretsPlain[k] = v; else opts[k] = v; }
		const r = await vdisk.saveCloudRemote({ type, label: flags.label, opts, secretsPlain, secretsObscure });
		console.log('Added cloud storage "' + (flags.label || type) + '" (id ' + r.id + ').');
		console.log('Create a vault on it with:\n  ' + Brand.cli + ' create <path> --cloud ' + r.id + ' --remote-path <folder>');
		return;
	}
	throw new Error('Usage: ' + Brand.cli + ' cloud <list|connect|add|remove|test>');
}
// Best-effort open a URL in the user's browser (for the OAuth consent page). Never throws — the URL is also
// printed, so a headless machine can still copy it. Delegates to the one shared opener so Windows uses the
// reliable `cmd /c start` form rather than `explorer`, which can open a file window instead of the browser.
function openUrl(url) { openInBrowser(url); }

async function cmdImport(pos, flags) {
	const [source, target] = pos;
	if (!source) throw new Error('Usage: ' + Brand.cli + ' import <folder> [vault-path]   (creates a new vault from an existing folder)');
	const level = requireKdfLevel(flags);
	// Default the vault path to "<folder><vaultExt>" next to the source when not given.
	const dest = target || (path.resolve(source).replace(/[\\/]+$/, '') + Brand.vaultExt);
	const password = await prompt.newPassword('Password');
	const r = await vdisk.importFolder(dest, { password, sourceDir: source, level });
	console.log('Imported ' + r.count + ' file' + (r.count === 1 ? '' : 's') + ' into a new vault at ' + r.vault + '.');
	console.log('Your original files at ' + r.source + ' are unchanged. Once you have confirmed the vault opens and');
	console.log('holds everything, delete the originals yourself (and keep your system disk encrypted so no plaintext');
	console.log('remnants remain). Mount it with:  ' + Brand.cli + ' mount "' + r.vault + '"');
}

async function cmdPasswd(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' passwd <path>');
	const oldPassword = await prompt.hidden('Current password: ');
	const newPassword = await prompt.newPassword('New password');
	await vdisk.changePassword(target, { oldPassword, newPassword });
	console.log('Password changed. Use the new password from now on — the old one no longer opens this vault.');
}

async function cmdKeys(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' keys <path>');
	const { slots, level } = await vdisk.listKeys(target);
	if (!slots.length) { console.log('This vault has no key slots (it predates them).'); return; }
	console.log('Keys for this vault (' + slots.length + ', security level: ' + level + '):');
	for (const s of slots) console.log('  ' + s.id + '  [' + (s.kind || 'password') + ']  ' + (s.keyfileName || s.label || '') + (s.createdAt ? '  — added ' + s.createdAt : ''));
	console.log('\nAdd one with "' + Brand.cli + ' addkey", a recovery key with "' + Brand.cli + ' recovery", remove one with "' + Brand.cli + ' rmkey <path> <id>".');
}

async function cmdAddKey(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' addkey <path>');
	const password = await prompt.hidden('Current password: ');
	const newPassword = await prompt.newPassword('New password to add');
	const r = await vdisk.addKey(target, { password, newPassword, label: flags.label });
	console.log('Added. This vault now opens with ' + r.count + ' keys. Any of them unlocks it; none re-encrypts your files.');
}

async function cmdAddKeyfile(pos, flags) {
	const [target, keyfile] = pos;
	if (!target || !keyfile) throw new Error('Usage: ' + Brand.cli + ' addkeyfile <path> <keyfile>');
	const password = await prompt.hidden('Current password: ');
	const keyfileDigest = await vdisk.keyfileDigestFromFile(keyfile);
	const r = await vdisk.addKeyfile(target, { password, keyfileDigest, keyfileName: path.basename(keyfile), label: flags.label });
	console.log('Added a keyfile. This vault now opens with ' + r.count + ' keys — the keyfile unlocks it on its own:');
	console.log('    ' + Brand.cli + ' mount "' + target + '" --keyfile "' + keyfile + '"');
	console.log('Keep the keyfile safe and separate (e.g. on a USB stick). Anyone with the file can unlock the vault,');
	console.log('and losing it removes that way in — your password still works unless you remove its key.');
}

async function cmdRecovery(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' recovery <path>');
	const password = await prompt.hidden('Current password: ');
	const r = await vdisk.addRecoveryKey(target, { password });
	console.log('\nRecovery key (store it safely — it is shown ONCE and opens this vault):\n');
	console.log('    ' + r.recoveryKey + '\n');
	console.log('Keep it somewhere separate from the vault. Enter it like a password to recover access.');
}

// Add a read-only password: opens the vault for reading but can never change it. Authorizing it needs
// a read-write password (only an owner can hand out read access).
async function cmdReadOnly(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' read-only <path>');
	const password = await prompt.hidden('Current read-write password: ');
	const readOnlyPassword = await prompt.newPassword('New read-only password');
	await vdisk.addReadOnlyKey(target, { password, readOnlyPassword });
	console.log('Read-only password added. Someone who unlocks with it can read the vault but cannot change it — it mounts read-only, and cannot add keys or take snapshots.');
}

// Mint a shareable read capability: a token that opens a COPY of the vault read-only, with no password.
// Optional --expires <days> sets a client-enforced expiry; --label names it in the "who has access" list.
async function cmdReadCap(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' read-cap <path> [--expires <days>] [--label <name>]');
	requireExpiresDays(flags);
	const password = await prompt.hidden('Password: ');
	const { token, sid, exp } = await vdisk.makeReadCap(target, { password, label: flags.label, expiryDays: flags.expires });
	console.log('\nRead capability (grants READ-ONLY access to a copy of this vault):\n');
	console.log('    ' + token + '\n');
	console.log('Share id: ' + sid + (exp ? '   expires ' + fmtTime(exp) : '   no expiry'));
	console.log('\nShare it together with a copy of the ' + Brand.vaultExt + ' folder. The recipient opens it with:');
	console.log('    ' + Brand.cli + ' mount <copy> --read-cap <token>');
	console.log('It carries the read key, so treat it like a password — anyone with it can read the contents.');
	console.log('See who has access with "' + Brand.cli + ' shares ' + target + '"; revoke with "' + Brand.cli + ' revoke-share ' + target + ' ' + sid + '".');
	console.log('Note: expiry and revocation apply going forward and to a served node; they cannot recall a');
	console.log('copy someone already downloaded. To cut off a leaked read key for good, re-encrypt the vault.');
}

// Portable, offline sharing to a recipient's public key. Three steps: the recipient makes a keypair and sends
// their public key; the sender seals a read cap to it; the recipient opens the bundle with their private key.
// Reuses the same contact keypair and post-quantum seal as emergency access — here the payload is a read cap.
async function cmdShareKeypair() {
	const kp = vdisk.emergencyKeypair(); // the very keypair the seal/open below use
	console.log('The RECIPIENT runs this and keeps it safe. Send the sender ONLY the public key; never share the private key.\n');
	console.log('PUBLIC key (give this to whoever is sharing the vault with you):\n  ' + kp.publicKey + '\n');
	console.log('PRIVATE key (keep this secret — it is how you open a sealed share):\n  ' + kp.privateKey);
}

async function cmdShareSeal(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' share-seal <path> --to <public-key|file> [--expires <days>] [--label <name>] [--out <file>]');
	const recipientPub = readKeyArg(flags.to);
	if (!recipientPub) throw new Error('Provide the recipient\'s public key with --to <public-key|file> (they make one with "' + Brand.cli + ' share-keypair").');
	requireExpiresDays(flags);
	const password = await prompt.hidden('Password: ');
	const { bundle, exp, pq } = await vdisk.shareSeal(target, { password, recipientPub, label: flags.label, expiryDays: flags.expires });
	const json = JSON.stringify(bundle, null, 2);
	if (flags.out) {
		try { fs.writeFileSync(String(flags.out), json, { mode: 0o600 }); } catch (_) { throw new Error('Could not write the sealed share to "' + flags.out + '". Check the folder exists and is writable.'); }
		console.log('Sealed share written to ' + String(flags.out) + (pq ? '  (post-quantum)' : '  (classical)') + '.');
	} else {
		console.log(json);
	}
	console.log('\nGive the recipient this bundle AND a copy of the ' + Brand.vaultExt + ' folder (or the cloud location).');
	console.log('Only their private key can open it. They read it with:');
	console.log('    ' + Brand.cli + ' share-open <bundle> --key <their-private-key>');
	if (exp) console.log('The read access inside expires ' + fmtTime(exp) + '.');
	console.log('Honest limit: once opened, a recipient who keeps the copy and the read key can ignore an expiry — to cut off a leaked key for good, re-encrypt the vault.');
}

async function cmdShareOpen(pos, flags) {
	const bundleFile = pos[0];
	if (!bundleFile) throw new Error('Usage: ' + Brand.cli + ' share-open <bundle-file> --key <private-key|file>');
	const priv = readKeyArg(flags.key);
	if (!priv) throw new Error('Provide your private key with --key <private-key|file> (the one from "' + Brand.cli + ' share-keypair").');
	let raw; try { raw = fs.readFileSync(String(bundleFile), 'utf8'); } catch (_) { throw new Error('Could not read the shared file "' + bundleFile + '". Check the path and that the file exists.'); }
	const { token, vault, exp } = vdisk.shareOpen(raw, priv);
	console.log('Opened a sealed share' + (vault ? ' for "' + vault + '"' : '') + '. Read capability:\n');
	console.log('    ' + token + '\n');
	if (exp) console.log('Expires ' + fmtTime(exp) + '.');
	console.log('Mount your copy of the vault read-only with:');
	console.log('    ' + Brand.cli + ' mount <copy> --read-cap <the token above>');
}

// --- Team / multi-user vaults ---------------------------------------------------------------------
async function cmdTeamEnable(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' team-enable <path>');
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.enableTeam(target, { password });
	console.log('Team access enabled. You are the owner (owner fingerprint ' + r.ownerFingerprint + ').');
	console.log('Add members with "' + Brand.cli + ' member-add ' + target + ' --to <their public key>". Each member makes a keypair with "' + Brand.cli + ' share-keypair" and sends you the PUBLIC key; verify its fingerprint over a channel you trust before adding.');
}
async function cmdMemberAdd(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' member-add <path> --to <public-key|file> [--write] [--label <name>]');
	const memberPub = readKeyArg(flags.to);
	if (!memberPub) throw new Error('Provide the member\'s public key with --to <public-key|file> (they make one with "' + Brand.cli + ' share-keypair").');
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.addMember(target, { password, memberPub, role: flags.write ? 'write' : 'read', label: flags.label });
	console.log('Added a ' + (r.role === 'write' ? 'read-write' : 'read-only') + ' member (id ' + r.memberId + ', fingerprint ' + r.fingerprint + ').');
	console.log('Give them a copy of the ' + Brand.vaultExt + ' folder (or the shared location). They open it with their private key: "' + Brand.cli + ' mount <copy> --member-key <their private key>".');
}
async function cmdMembers(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' members <path>');
	const r = await vdisk.listMembers(target);
	if (!r.team) { console.log('This vault is not a team vault. Enable it with "' + Brand.cli + ' team-enable ' + target + '".'); return; }
	console.log('Team vault (epoch ' + r.epoch + ', key generation ' + r.keyGeneration + ', owner ' + r.ownerFingerprint + ').');
	console.log('Roster signature: ' + (r.rosterValid ? 'valid' : 'INVALID — the membership list has been altered'));
	if (!r.members.length) { console.log('No members yet.'); return; }
	console.log('Members (' + r.members.length + '):');
	for (const m of r.members) {
		console.log('  ' + (m.owner ? 'owner' : (m.role === 'write' ? 'rw' : 'ro')) + '  ' + (m.label || 'Member') + '   id ' + m.memberId + (m.deviceCount > 1 ? '   (' + m.deviceCount + ' devices)' : '   fp ' + m.fingerprint));
		if (m.deviceCount > 1) for (const d of m.devices) console.log('        device ' + d.slotId + '   fp ' + d.fingerprint + (d.label && d.label !== m.label ? '   ' + d.label : ''));
	}
	if (r.recovery) console.log('Owner recovery: any ' + r.recovery.k + ' of ' + r.recovery.n + ' trustees can restore owner access.' + (r.recovery.stale ? ' WARNING: it was set up before the last key rotation and no longer works — re-run "' + Brand.cli + ' owner-recovery".' : ''));
}
async function cmdMemberAddDevice(pos, flags) {
	const [target, memberId] = pos;
	if (!target || !memberId) throw new Error('Usage: ' + Brand.cli + ' member-add-device <path> <member-id> --to <device-public-key|file>');
	const devicePub = readKeyArg(flags.to);
	if (!devicePub) throw new Error('Provide the new device\'s public key with --to <public-key|file>.');
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.addDevice(target, { password, memberId, devicePub, label: flags.label });
	console.log('Enrolled a device (id ' + r.slotId + ', fingerprint ' + r.fingerprint + ') for member ' + memberId + '. They open the vault with that device\'s private key.');
}
async function cmdMemberRemoveDevice(pos, flags) {
	const [target, slotId] = pos;
	if (!target || !slotId) throw new Error('Usage: ' + Brand.cli + ' member-remove-device <path> <device-id> [--soft] [--yes]');
	const soft = !!flags.soft;
	if (!soft) {
		console.log('Removing this device re-encrypts the vault under a fresh key so the device can never open future content; the member\'s other devices keep working. It also invalidates every OTHER password, read link, recovery key, keyfile, and security-key/Touch ID sign-in on the vault — re-add the ones you still need afterward (especially a recovery key). Use --soft to only drop it from the roster.');
		// A full re-encryption is consequential, so confirm first — the same gate as rotate and as the web UI's
		// "Revoke and re-encrypt". --yes skips it for scripts; --soft avoids the re-encryption entirely.
		if (!flags.yes && !(await confirmVaultName(target, n => 'Type the vault name ("' + n + '") to confirm re-encrypting it: ', 'Canceled — nothing was changed.'))) return;
	}
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.removeDevice(target, { password, slotId, rotate: !soft });
	console.log(r.revoked ? 'Device removed and revoked (vault re-encrypted).' : 'Device dropped from the roster (not yet revoked — rotate to fully cut it off).');
}
async function cmdMemberRemove(pos, flags) {
	const [target, memberId] = pos;
	if (!target || !memberId) throw new Error('Usage: ' + Brand.cli + ' member-remove <path> <member-id> [--soft] [--yes]');
	const soft = !!flags.soft;
	if (!soft) {
		console.log('Removing this member re-encrypts the whole vault under a fresh key (needs ~2x free space) so the member can never open future content. It also invalidates every OTHER password, read link, recovery key, keyfile, and security-key/Touch ID sign-in — re-add the ones you still need afterward (especially a recovery key). Use --soft to only drop them from the roster now and rotate later.');
		// A full re-encryption is consequential, so confirm first — the same gate as rotate and as the web UI's
		// "Remove and re-encrypt". --yes skips it for scripts; --soft avoids the re-encryption entirely.
		if (!flags.yes && !(await confirmVaultName(target, n => 'Type the vault name ("' + n + '") to confirm re-encrypting it: ', 'Canceled — nothing was changed.'))) return;
	}
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.removeMember(target, { password, memberId, rotate: !soft });
	if (r.revoked) console.log('Removed and revoked member ' + r.removed + ' — the vault was re-encrypted; their key can no longer open new content.');
	else console.log('Dropped member ' + r.removed + ' from the roster. NOT yet revoked: the vault key is unchanged, so a copy they already kept still opens this data. Run "' + Brand.cli + ' member-remove ' + target + ' ' + memberId + '" without --soft (or "' + Brand.cli + ' rotate ' + target + '") to fully revoke.');
}

async function cmdMemberPromote(pos, flags, demote) {
	const [target, memberId] = pos;
	if (!target || !memberId) throw new Error('Usage: ' + Brand.cli + ' member-' + (demote ? 'demote' : 'promote') + ' <path> <member-id>');
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.setMemberOwner(target, { password, memberId, owner: !demote });
	if (demote) console.log('Demoted member ' + r.memberId + ' to a plain member. Note: they held the owner key, so to be certain they can no longer manage membership, rotate owner access (remove and re-add owners).');
	else console.log('Promoted member ' + r.memberId + ' to owner — they can now manage membership.');
}
function readKeyList(v) { return splitList(v).map(readKeyArg).filter(Boolean); }
async function cmdOwnerRecovery(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' owner-recovery <path> --trustees <pub1,pub2,…> --threshold <k>');
	const pubs = readKeyList(flags.trustees);
	if (pubs.length < 2) throw new Error('Provide at least two trustee public keys with --trustees <pub1,pub2,…> (each a key or a file).');
	const k = parseInt(flags.threshold || flags.k, 10);
	if (!Number.isInteger(k)) throw new Error('Set the threshold with --threshold <k> — how many trustees are needed to recover.');
	const password = await prompt.hidden('Owner password: ');
	const r = await vdisk.setupOwnerRecovery(target, { password, k, trustees: pubs.map((pub, i) => ({ pub, label: 'Trustee ' + (i + 1) })) });
	console.log('Owner recovery set up: any ' + r.k + ' of ' + r.n + ' trustees can restore owner access.');
	console.log('Each trustee later runs "' + Brand.cli + ' recovery-share ' + target + ' --key <their private key>" to get their share, and any ' + r.k + ' shares recover with "' + Brand.cli + ' owner-recover ' + target + ' --shares <share1,share2,…>".');
}
async function cmdRecoveryShare(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' recovery-share <path> --key <private-key|file>');
	const priv = readKeyArg(flags.key);
	if (!priv) throw new Error('Provide your trustee private key with --key <private-key|file>.');
	const r = await vdisk.getRecoveryShare(target, priv);
	if (!r) { console.log('This key holds no recovery share for that vault.'); return; }
	console.log('Your recovery share (give it to whoever is recovering owner access; ' + r.k + ' of ' + r.n + ' are needed):\n');
	console.log('    ' + r.share);
}
async function cmdOwnerRecover(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' owner-recover <path> --shares <share1,share2,…>');
	const shares = splitList(flags.shares);
	if (shares.length < 2) throw new Error('Provide the trustee shares with --shares <share1,share2,…>.');
	const newPassword = await prompt.hidden('Choose a new owner password: ');
	await vdisk.recoverOwner(target, { shares, newPassword, label: 'Recovered owner' });
	console.log('Owner access recovered. Open the vault with your new password — you are an owner and can manage membership again.');
}

// Show the roster of who has access (read links / read-only keys handed out), with expiry and revoke state.
async function cmdShares(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' shares <path>');
	const rep = await vdisk.listShares(target);
	if (!rep.shares.length) { console.log('No shares have been handed out for this vault.'); return; }
	const rosterWarn = rep.rolledBack ? '   ⚠ this access list is an OLDER version than this computer last saw — it may have been rolled back to undo a revocation'
		: (rep.sigOk ? '' : '   ⚠ the roster signature did NOT verify — it may have been altered');
	console.log('Who has access (' + rep.shares.length + '):' + rosterWarn);
	for (const s of rep.shares) {
		const state = s.revoked ? 'REVOKED' : s.expired ? 'expired' : 'active';
		console.log('  [' + state + '] ' + s.sid + '  ' + (s.label || '') + (s.exp ? '  (expires ' + fmtTime(s.exp) + ')' : '') + '  ' + (s.perm || 'read'));
	}
	console.log('\nRevoke one with "' + Brand.cli + ' revoke-share ' + target + ' <share-id>".');
}

// Per-vault decoy (duress) protection (advanced). A protected vault is paired with a separate DECOY vault;
// opening the protected vault with the decoy vault's password opens the decoy instead. Pairings live in a
// uniform encrypted registry (their existence is invisible) and are managed with a MANAGER password.
async function cmdDecoy(pos) {
	const sub = (pos[0] || 'status').toLowerCase();
	if (sub === 'status') { console.log('Per-vault decoy protection is ' + (vdisk.decoyProtected() ? 'configured' : 'not configured') + '.'); return; }
	if (sub === 'set' || sub === 'add') {
		const realVault = pos[1], decoyVault = pos[2];
		if (!realVault || !decoyVault) throw new Error('Usage: ' + Brand.cli + ' decoy set <real-vault> <decoy-vault>');
		console.log('Pairing "' + vdisk.displayName(realVault) + '" with the decoy "' + vdisk.displayName(decoyVault) + '".');
		console.log('Afterward, opening the real vault with the DECOY vault\'s password opens the decoy instead.');
		console.log(notice('decoy-limits'));
		if (!(await confirmUnderstand())) return;
		const decoyPassword = await prompt.hidden('The DECOY vault\'s password (this becomes the duress trigger): ');
		const managerPassword = await prompt.hidden('A manager password (used only to manage decoys): ');
		await vdisk.decoySet({ realVault, decoyVault, decoyPassword, managerPassword });
		console.log('Paired. Opening "' + vdisk.displayName(realVault) + '" with the decoy password now opens the decoy.');
		return;
	}
	if (sub === 'list') {
		if (!vdisk.decoyProtected()) { console.log('No decoy pairings are configured.'); return; }
		const managerPassword = await prompt.hidden('Manager password: ');
		const mappings = await vdisk.decoyList(managerPassword);
		if (mappings == null) { console.log('The manager password is incorrect.'); process.exitCode = 1; return; } // nonzero so a script can tell the wrong-password case from an empty list
		if (!mappings.length) { console.log('No decoy pairings.'); return; }
		for (const m of mappings) console.log('  ' + vdisk.displayName(m.realVault) + '  →  decoy: ' + vdisk.displayName(m.decoyVault));
		return;
	}
	if (sub === 'remove' || sub === 'off') {
		const realVault = pos[1];
		if (!realVault) throw new Error('Usage: ' + Brand.cli + ' decoy remove <real-vault>');
		const managerPassword = await prompt.hidden('Manager password: ');
		const r = await vdisk.decoyRemove({ realVault, managerPassword });
		console.log(r.removed ? ('Removed the decoy pairing for "' + vdisk.displayName(realVault) + '".' + (r.empty ? ' No pairings remain.' : '')) : 'No decoy pairing was set for that vault.');
		return;
	}
	throw new Error('Usage: ' + Brand.cli + ' decoy <status|set|list|remove>');
}

// Travel mode: hide every vault from this app and lock them, restorable with a travel password.
async function cmdTravel(pos) {
	const sub = (pos[0] || 'status').toLowerCase();
	if (sub === 'status') { console.log('Travel mode is ' + (vdisk.travelStatus().active ? 'ON — your vaults are hidden. Restore with "' + Brand.cli + ' travel off".' : 'off.')); return; }
	if (sub === 'on' || sub === 'enable') {
		console.log(notice('travel-limits'));
		if (!(await confirmUnderstand())) return;
		const password = await prompt.newPassword('Travel password (you will need it to restore)');
		const r = await vdisk.travelEnable({ travelPassword: password });
		console.log('Travel mode on — ' + r.hidden + ' vault' + (r.hidden === 1 ? '' : 's') + ' hidden and locked. Restore with "' + Brand.cli + ' travel off".');
		return;
	}
	if (sub === 'off' || sub === 'restore') {
		const password = await prompt.hidden('Travel password: ');
		const r = await vdisk.travelRestore({ travelPassword: password });
		console.log('Restored ' + r.restored + ' vault' + (r.restored === 1 ? '' : 's') + '.');
		return;
	}
	throw new Error('Usage: ' + Brand.cli + ' travel <on|off|status>');
}

// Health-based restart: let the guardian kill a WEDGED (hung) service so the system relaunches it. Off by
// default; the drain-progress interlock guarantees it never kills a service that is cleanly shutting down.
async function cmdWedgeRestart(pos) {
	const sub = (pos[0] || 'status').toLowerCase();
	if (sub === 'status') { const on = (await vdisk.getSettings()).wedgeRestart === true; console.log('Health-based restart (kill + relaunch a WEDGED service) is ' + (on ? 'ON.' : 'off.')); return; }
	if (sub === 'on' || sub === 'enable') {
		console.log('This lets the background guardian kill a WEDGED (hung, not merely crashed) service so the');
		console.log('system relaunches it — health-based restart, not just crash restart. It never kills a service');
		console.log('that is cleanly shutting down or still flushing data to disk; only a genuinely hung one, whose');
		console.log('un-flushed data is already unrecoverable. It works with the login/boot service you installed.');
		await vdisk.setSettings({ wedgeRestart: true });
		console.log('Health-based restart is ON.');
		return;
	}
	if (sub === 'off' || sub === 'disable') { await vdisk.setSettings({ wedgeRestart: false }); console.log('Health-based restart is off — a wedged service is locked (vaults secured) but not restarted.'); return; }
	throw new Error('Usage: ' + Brand.cli + ' wedge-restart <on|off|status>');
}

// Emergency / inheritance access — a dead-man's switch. Seals a vault's READ access to a trusted contact; if
// you stop checking in, it is released to them. Read-only; the vault itself is never at risk.
function readKeyArg(v) { // a base64 key, or a path to a file containing it
	if (!v) return '';
	try { if (fs.existsSync(v)) return fs.readFileSync(v, 'utf8').trim(); } catch (_) {}
	return String(v).trim();
}
async function cmdEmergency(pos, flags) {
	const sub = (pos[0] || 'status').toLowerCase();
	if (sub === 'keypair') {
		const kp = vdisk.emergencyKeypair();
		console.log('A trusted contact runs this and keeps it safe. Give the OWNER only the public key; never share the private key.\n');
		console.log('PUBLIC key (give this to the vault owner):\n  ' + kp.publicKey + '\n');
		console.log('PRIVATE key (keep this secret — it is how you will open access later):\n  ' + kp.privateKey);
		return;
	}
	if (sub === 'enroll') {
		const contactPubKey = readKeyArg(flags['contact-key']);
		if (!contactPubKey) throw new Error('Usage: ' + Brand.cli + ' emergency enroll --contact-key <public-key|file> [--label <name>] [--inactive-days 30] [--grace-days 14]');
		// Validate the timer inputs up front — a non-numeric value would otherwise become NaN and poison the release
		// schedule of a data-access safety feature, and "0" inactivity must be refused rather than silently defaulted.
		// A bare --inactive-days / --grace-days (no value) parses to boolean true, and Number(true) is 1, which would
		// slip these >=1 / >=0 checks and be forwarded as a nonsense value — reject it explicitly, like --expires does.
		if (flags['inactive-days'] === true || (flags['inactive-days'] !== undefined && !(Number(flags['inactive-days']) >= 1))) throw new Error('--inactive-days needs a positive number of days (at least 1), for example --inactive-days 30.');
		if (flags['grace-days'] === true || (flags['grace-days'] !== undefined && !(Number(flags['grace-days']) >= 0))) throw new Error('--grace-days needs a number of days that is 0 or more, for example --grace-days 14.');
		console.log(notice('emergency-limits'));
		if (!(await confirmUnderstand())) return;
		const r = await vdisk.emergencyEnroll({ contactPubKey, contactLabel: flags.label, inactivityDays: flags['inactive-days'], graceDays: flags['grace-days'] });
		if (r.rearmNeeded) console.log('The trusted contact changed, so ' + r.rearmNeeded + ' previously armed vault' + (r.rearmNeeded === 1 ? ' was' : 's were') + ' unarmed (they were sealed to the old contact). Re-arm each one for the new contact.');
		console.log('Enrolled. Arm a vault with:  ' + Brand.cli + ' emergency arm <vault>');
		return;
	}
	if (sub === 'arm') {
		const target = pos[1]; if (!target) throw new Error('Usage: ' + Brand.cli + ' emergency arm <vault>');
		const password = await prompt.hidden('Vault password: ');
		await vdisk.emergencyArm(target, { password });
		console.log('Armed "' + vdisk.displayName(target) + '". Remember to check in with:  ' + Brand.cli + ' emergency check-in');
		return;
	}
	if (sub === 'check-in' || sub === 'checkin') { await vdisk.emergencyCheckIn(); console.log('Checked in — the timer is reset and any pending release is withdrawn.'); return; }
	if (sub === 'status') {
		const s = await vdisk.emergencyStatus();
		if (!s.enrolled) { console.log('Emergency access is not set up.'); return; }
		console.log('Emergency access: ' + s.phase.toUpperCase() + ' — contact "' + s.contactLabel + '", ' + s.inactivityDays + '-day inactivity + ' + s.graceDays + '-day grace.');
		console.log('  Last check-in: ' + s.lastCheckIn + (s.phase === 'released' ? '' : '  (about ' + s.daysUntilRelease + ' day(s) until release without a check-in)'));
		console.log('  Vaults armed: ' + (s.armed.length ? s.armed.map(a => a.name).join(', ') : 'none'));
		if (s.phase === 'released') console.log('  RELEASED on ' + s.releasedAt + ' — check in to withdraw it.');
		return;
	}
	if (sub === 'disarm') { await vdisk.emergencyDisarm(); console.log('Disarmed. Note: to be certain a released or copied blob can never open the vault, rotate its keys.'); return; }
	throw new Error('Usage: ' + Brand.cli + ' emergency <keypair|enroll|arm|check-in|status|disarm>');
}
// The CONTACT side: open a released sealed blob with their private key, recovering the read link.
async function cmdEmergencyOpen(pos, flags) {
	const file = pos[0]; const priv = readKeyArg(flags.key);
	if (!file || !priv) throw new Error('Usage: ' + Brand.cli + ' emergency-open <sealed-file> --key <your-private-key|file>');
	let sealed; try { sealed = fs.readFileSync(file, 'utf8').trim(); } catch (_) { throw new Error('Could not read the sealed inheritance file "' + file + '". Check the path and that the file exists.'); }
	const link = vdisk.emergencyOpen(priv, sealed);
	console.log('Read link recovered. Open a copy of the vault with it:\n');
	console.log('  ' + Brand.cli + ' mount <vault-folder> --read-cap ' + link);
	return;
}

// Rotate the vault's keys and re-encrypt the whole store — true, cryptographic revocation of a leaked key.
async function cmdRotate(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' rotate <path> [--reason <text>] [--yes]');
	console.log(notice('rotate-limits'));
	if (!flags.yes && !(await confirmVaultName(target, n => 'Type the vault name ("' + n + '") to confirm: ', 'Rotation canceled — nothing was changed.'))) return;
	const password = await prompt.hidden('Password: ');
	console.log('Re-encrypting… this can take a while for a large vault.');
	const prog = cliProgress({ stream: process.stderr }); // report on stderr so the result lines below stay clean on stdout
	const r = await vdisk.rotate(target, { password, reason: flags.reason || 'manual rotation', onProgress: prog });
	prog.done();
	console.log('Done. The vault was re-encrypted and its identity rotated.');
	console.log('  New identity:     ' + r.newIdentity);
	console.log('  New fingerprint:  ' + r.fingerprint);
	console.log('Record the new identity (or make a fresh Recovery Kit with "' + Brand.cli + ' recovery-kit ' + target + '"),');
	console.log('and re-add any keys or read links you want to keep.');
	if (r.recoveryDropped) console.log('\n⚠ This vault no longer has a recovery key. If you forget its password there is no way back in — add one now with "' + Brand.cli + ' recovery ' + target + '".');
}

async function cmdRevokeShare(pos) {
	const target = pos[0], sid = pos[1];
	if (!target || !sid) throw new Error('Usage: ' + Brand.cli + ' revoke-share <path> <share-id>');
	const password = await prompt.hidden('Password: ');
	await vdisk.revokeShare(target, { password, sid });
	console.log('Share ' + sid + ' marked revoked in the vault\'s access list, and any live in-app viewer session it');
	console.log('started on this machine was ended. This does not recall a copy someone already downloaded, nor stop a');
	console.log('read link they still hold — re-encrypt the vault ("' + Brand.cli + ' rotate ' + target + '") to truly cut off a leaked read key.');
}

async function cmdPruneShares(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' prune-shares <path>');
	const password = await prompt.hidden('Password: ');
	const r = await vdisk.pruneShares(target, { password });
	console.log(r.removed ? ('Removed ' + r.removed + ' revoked/expired entr' + (r.removed === 1 ? 'y' : 'ies') + '; ' + r.remaining + ' remain.') : 'Nothing to remove — no revoked or expired entries.');
}

async function cmdRmKey(pos) {
	const [target, slotId] = pos;
	if (!target || !slotId) throw new Error('Usage: ' + Brand.cli + ' rmkey <path> <key-id>   (see "' + Brand.cli + ' keys <path>")');
	const password = await prompt.hidden('Password (must be a DIFFERENT key than the one removed): ');
	const r = await vdisk.removeKey(target, { password, slotId });
	console.log('Removed. This vault now opens with ' + r.count + ' key' + (r.count === 1 ? '' : 's') + '.');
}

// Mount through a RUNNING local owner (the web / background service) when one is up, so the mount is owned by a
// long-lived process that holds the key in memory and finalizes cleanly on unmount — unifying the CLI with the
// web app. Falls back to a direct in-process mount on ANY problem (no owner, unreachable, login-gated), so the
// mount path never depends on the owner. Returns a result shaped like Vault.mount's so the caller prints it the
// same way either path.
async function mountVia(target, opts) {
	try {
		const own = await OwnerClient.find();
		if (own) {
			const resp = await OwnerClient.post(own.url, '/api/mount', {
				path: target, password: opts.password, readCap: opts.readCap, memberKey: opts.memberKey, readOnly: opts.readOnly, force: opts.force,
				streaming: opts.streaming, workingDisk: opts.workingDisk, fuseBackend: opts.fuseBackend,
				mountpoint: opts.mountpoint, volname: opts.volname, cacheSizeMB: opts.cacheSizeMB,
				vfsCacheMode: opts.vfsCacheMode, cacheDir: opts.cacheDir, allowOther: opts.allowOther,
				rememberPrefs: opts.rememberPrefs // record this vault's mode preference only if the user explicitly chose one (mirrors the standalone CLI)
			}, 5 * 60 * 1000); // a mount is quick; bound it so a wedged owner can't hang the CLI for the long default (that budget is for unmount's flush wait)
			if (OwnerClient.isUsable(resp)) {
				// The owner definitively handled it: use its answer (do NOT also mount locally). A reported failure
				// is the real reason, so surface it rather than silently retrying a direct mount.
				if (!resp.ok) throw Object.assign(new Error((resp.body && resp.body.error) || 'The vault could not be mounted.'), { viaOwnerFatal: true });
				const b = resp.body || {};
				return { mountpoint: b.mountpoint, cacheMode: b.mode, inRam: !!b.inRam, ramDowngraded: !!b.ramDowngraded, tamper: b.tamper || null, viaOwner: true };
			}
			// 401 / 403 / login-gated owner — cannot drive it; fall through to a direct mount.
		}
	} catch (e) {
		if (e && e.viaOwnerFatal) throw e; // a real owner-side mount failure — do not mask it with a local retry
	}
	return vdisk.mount(target, opts);
}

// A value-expecting flag given with NO value parses to boolean `true`. Reject that up front with a clear,
// example-bearing message, rather than letting it flow on as `true`/"true" and fail later as a raw type error
// (e.g. fsp.readFile(true) → ERR_INVALID_ARG_TYPE). The string-valued counterpart to the numeric-flag guards.
function requireStringFlag(flags, key, example) {
	if (flags[key] === true) throw new Error('--' + key + ' needs a value' + (example ? ', for example ' + example : '') + '.');
}
async function cmdMount(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' mount <path>');
	// Reject a bare (value-less) string flag before prompting for a password, so a typo fails clearly and instantly.
	for (const [k, ex] of [['keyfile', '--keyfile /path/to/keyfile'], ['read-cap', '--read-cap <token>'], ['member-key', '--member-key /path/to/key'], ['key-shares', '--key-shares "share1,share2"'], ['mountpoint', '--mountpoint /path'], ['volname', '--volname MyVault'], ['cache-dir', '--cache-dir /path']]) requireStringFlag(flags, k, ex);
	// Validate the mount flags up front — BEFORE prompting for a password — with the valid values, rather than
	// asking for a password only to fail on a typo, silently falling back to a default, or failing later as a raw
	// engine error (matching how --redundancy and --kdf are checked).
	if (flags['fuse-backend'] != null && String(flags['fuse-backend']).toLowerCase() !== 'smb') {
		throw new Error('Unknown --fuse-backend "' + flags['fuse-backend'] + '". Use "smb" for the SMB transport (macOS/FUSE-T), or omit it for the default.');
	}
	if (flags['vfs-cache-mode'] != null && !['off', 'minimal', 'writes', 'full'].includes(String(flags['vfs-cache-mode']))) {
		throw new Error('Unknown --vfs-cache-mode "' + flags['vfs-cache-mode'] + '". Use one of: off, minimal, writes, full (or omit it — most vaults want the default).');
	}
	if (flags['cache-size'] != null && !(parseInt(flags['cache-size'], 10) > 0)) {
		throw new Error('--cache-size must be a positive number of megabytes (for example, --cache-size 4096).');
	}
	// Ways to unlock: a read capability (read-only, no password), threshold-key shares, a keyfile, or a
	// typed password. A read capability always mounts read-only.
	const readCap = flags['read-cap'];
	const memberKey = readKeyArg(flags['member-key']); // a team member unlocks with their own private key
	let password;
	if (!readCap && !memberKey) {
		if (flags['key-shares']) {
			password = vdisk.unlockSecretFromShares(splitList(flags['key-shares'])); // throws if fewer than k shares
		} else if (flags.keyfile) { password = await vdisk.keyfileDigestFromFile(flags.keyfile); }
		else { password = await prompt.hidden('Password: '); }
	}
	const opts = {
		password, readCap, memberKey: memberKey || undefined,
		mountpoint: flags.mountpoint,
		volname: flags.volname,
		readOnly: !!flags['read-only'],
		force: !!flags.force, // override a cross-machine write lease (may create sync-conflict copies)
		// Pass a cache-mode flag only when actually given (undefined, not false), so that a plain
		// "vdisk mount" falls back to this vault's remembered preference instead of forcing the default.
		streaming: flags.streaming ? true : undefined,
		workingDisk: flags['working-disk'] ? true : undefined,
		fuseBackend: flags['fuse-backend'], // macOS/FUSE-T: 'smb' to use the SMB transport (large-write reliability)
		cacheSizeMB: flags['cache-size'] ? parseInt(flags['cache-size'], 10) : undefined,
		vfsCacheMode: flags['vfs-cache-mode'],
		cacheDir: flags['cache-dir'],
		allowOther: !!flags['allow-other'],
		// Remember this vault's mode ONLY when the user explicitly chose one — so a later plain "vdisk mount"
		// reuses it, but a plain mount never overwrites a remembered choice with the defaults. Carried to the
		// owner so a delegated mount records prefs on the same condition.
		rememberPrefs: !!(flags['working-disk'] || flags.streaming || flags['fuse-backend'])
	};
	const res = await mountVia(target, opts);
	// Record the chosen mode as this vault's preference. Skipped when the owner handled the mount — it recorded
	// them itself — and only when the user actually chose a mode (see rememberPrefs above).
	if (!res.viaOwner && opts.rememberPrefs) {
		try { await vdisk.recordMountPrefs(target, { readOnly: !!flags['read-only'], workingDisk: !!flags['working-disk'], streaming: !!flags.streaming, fuseBackend: flags['fuse-backend'] }); } catch (_) {}
	}
	// Report the mode and — the important part — that nothing decrypted touched the disk.
	if (res.cacheMode === 'off') {
		if (res.ramDowngraded) console.log('Note: you asked for a working disk, but no in-memory RAM disk could be set up on this machine, so it fell back to streaming. On Windows, install the ImDisk virtual-disk driver to enable in-place editing; macOS and Linux have it built in.');
		console.log('Mounted in streaming mode — nothing is cached. In-place writes (databases, and smooth media on macOS) are not available in this mode.');
	} else if (res.inRam) {
		console.log('Mounted' + (res.cacheMode === 'full' ? ' as a full working disk' : '') + ' — files play and edit normally. The write buffer is kept in RAM, so nothing decrypted is ever written to disk.');
	} else {
		console.log('Mounted' + (res.cacheMode === 'full' ? ' as a full working disk' : '') + ' — using the cache directory you specified (on disk).');
	}
	console.log('Mounted "' + path.basename(res.mountpoint) + '" at ' + res.mountpoint);
	// Automatic tamper detection. The "interrupted" kind is the owner's own edits from a session that was
	// not finalized in this process — the normal case when you mount and unmount with separate `vdisk`
	// commands (the unmount command holds no key, so the baseline is caught up here, at the next mount),
	// and also after a genuine crash / hard kill / power loss. Either way the changes are the owner's, so
	// report them plainly rather than as a tamper warning. (For strict at-rest verification between
	// sessions, seal the vault or run it through the always-on background service, which finalizes live.)
	if (res.tamper && res.tamper.kind === 'interrupted') {
		const t = res.tamper;
		console.log('\nℹ  Changes from your last session have been saved to this vault:');
		changePreview('modified', t.modified); changePreview('removed', t.removed); changePreview('added', t.added);
		console.log('  This is normal after editing the vault. If you did not make these changes, run "' + Brand.cli + ' audit ' + target + '".');
	} else if (res.tamper) {
		const t = res.tamper;
		console.log('\n⚠  This vault changed since it was last used:');
		if (t.tamper && t.tamper.length) console.log('  ' + t.tamper.join('\n  '));
		changePreview('modified', t.modified); changePreview('removed', t.removed); changePreview('added', t.added); changePreview('foreign', t.foreign);
		console.log('  Unmount, then "' + Brand.cli + ' audit ' + target + '" for the full list. If the change was');
		console.log('  intentional, "' + Brand.cli + ' snapshot ' + target + '" accepts it as the new baseline.');
	}
	console.log('\nUnmount with:  ' + Brand.cli + ' unmount "' + res.mountpoint + '"');
}

// Unmount through the owner when the mount is owned by a running service — only that long-lived process holds
// the key to finalize the session cleanly (re-sign the baseline, clear the marker). A mount this CLI made on its
// own, or any owner problem, tears down directly. Returns the unmount result shape either way.
async function unmountVia(target, uopts) {
	// The stuck-mount escape hatch must act promptly and never wait on a possibly-wedged owner, so --force always
	// tears down directly. A write-lease left behind by a service-owned mount is then self-corrected by the
	// service's own health tick, so nothing is leaked.
	if (uopts.force) return vdisk.unmount(target, uopts);
	try {
		const own = await OwnerClient.find();
		if (own) {
			// Decide ownership with the SAME resolver the unmount itself uses (State.find matches a mountpoint, a
			// full vault path, or a bare name, case-folded on Windows), so a service-owned mount is never missed and
			// torn down directly — which would skip the owner's finalization and leave its write-lease refreshing.
			const entry = await State.find(target).catch(() => null);
			if (entry && /^ui:/.test(String(entry.owner || ''))) {
				const resp = await OwnerClient.post(own.url, '/api/unmount', { target, wipeCache: uopts.wipeCache });
				// The owner already runs the post-unmount recovery refresh + mirror sync (schedulePostUnmount) and,
				// holding the key, it is the one that finalized the session — so mark the result to skip the CLI's
				// own post-unmount work below. Includes the {ok:false, flushing} deferral shape unchanged.
				if (OwnerClient.isUsable(resp) && resp.body) return { ...resp.body, viaOwner: true };
			}
		}
	} catch (_) { /* fall through to a direct unmount */ }
	return vdisk.unmount(target, uopts);
}

async function cmdUnmount(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' unmount <path|mountpoint>');
	// Clear the decrypted working cache by default for privacy; --keep-cache opts out.
	// --force overrides a stuck/stale mount (skips the flush; may discard unflushed writes). --recover is the
	// explicit last resort for a wedged drive that --force could not release (see the not-ok branch below).
	const res = await unmountVia(target, { wipeCache: !flags['keep-cache'], force: !!flags.force || !!flags.recover, recover: !!flags.recover });
	if (!res.ok) {
		// "flushing" is not a failure: the vault is still safely saving buffered changes and was left mounted so
		// nothing is lost. Tell the user to simply wait and retry — NOT to force, which would discard those writes.
		if (res.flushing) console.log('Still saving buffered changes to ' + res.mountpoint + ' — nothing is lost. Wait a moment, then run unmount again. (A large just-written file can take a while to finish saving.)');
		else if (res.stuck) console.log('The drive at ' + res.mountpoint + ' is wedged and could not be released even by recovery — its file server has stopped responding. Restarting the computer is the last option; nothing in the vault is lost.');
		else console.log('Could not fully unmount ' + res.mountpoint + ' (it may be busy). Try again with --force, or "' + Brand.cli + ' unmount ' + JSON.stringify(target) + ' --recover" as a last resort for a wedged drive.');
		process.exitCode = 1; return;
	}
	if (res.recovered) { console.log('Recovered the wedged drive at ' + res.mountpoint + ' without a restart.'); }
	console.log('Unmounted ' + res.mountpoint);
	// If the vault has self-healing recovery data and its contents changed, refresh it so it stays
	// current. Best-effort — a hiccup here never fails the unmount that already succeeded. The
	// preamble prints only once an actual rebuild starts (an unchanged vault does no work here).
	// Skipped when the owner handled the unmount — it already schedules this refresh (and the mirror sync).
	if (!res.forced && !res.viaOwner && res.vault) {
		try {
			const prog = cliProgress();
			let announced = false;
			const onProgress = (p) => { if (!announced) { announced = true; console.log('Refreshing self-healing recovery data for your changes…'); } prog(p); };
			const r = await vdisk.refreshRecoveryIfStale(res.vault, { onProgress }); prog.done();
			if (r.refreshed) console.log('Recovery data is up to date.');
		} catch (e) { console.log('Note: could not refresh recovery data (' + e.message + '). Run "' + Brand.cli + ' protect" when convenient.'); }
	}
}

async function cmdRepair() {
	console.log('Checking for stale mounts and leftovers…');
	await vdisk.sweep();
	console.log('Done. Released any stale (crashed) mounts and cleaned up leftover files.');
}

async function cmdLock() {
	const r = await vdisk.lockAll();
	if (r.total === 0) { console.log('No vaults are mounted.'); return; }
	console.log('Locked ' + r.locked + ' of ' + r.total + ' vault' + (r.total === 1 ? '' : 's') + '.');
	if (r.busy) console.log(r.busy + ' still in use (a file is open) — close it and run "' + Brand.cli + ' lock" again.');
}

async function cmdAutolock(pos) {
	const arg = pos[0];
	if (arg === undefined) { const s = await vdisk.getSettings(); console.log('Auto-lock: ' + (s.autoLockMinutes ? s.autoLockMinutes + ' minutes of inactivity' : 'off')); return; }
	const min = parseInt(arg, 10);
	if (!Number.isFinite(min) || min < 0) throw new Error('Usage: ' + Brand.cli + ' autolock <minutes>   (0 to turn off)');
	await vdisk.setSettings({ autoLockMinutes: min });
	console.log(min ? 'Auto-lock set: vaults lock after ' + min + ' minutes of inactivity (while the web app is running).' : 'Auto-lock turned off.');
}

async function cmdBandwidth(pos) {
	const arg = pos.join(' ').trim();
	if (arg === '') { const s = await vdisk.getSettings(); console.log('Sync bandwidth limit: ' + (s.bwlimit ? s.bwlimit : 'unlimited')); return; }
	if (/^(off|none|unlimited|0)$/i.test(arg)) { await vdisk.setSettings({ bwlimit: '' }); console.log('Sync bandwidth limit removed (unlimited).'); return; }
	const bw = Common.validateBwlimit(arg); // shared with the web interface, so both harden AND validate the engine input identically — a bad rate fails here with an example, not opaquely at sync time
	await vdisk.setSettings({ bwlimit: bw });
	console.log('Sync bandwidth limit set: ' + bw + ' (applies to off-site backups and mirrors). Use a timetable like "08:00,512k 23:00,off" for off-peak windows.');
}

// Show or set a boolean setting from an [on|off] argument. Shared by the simple on/off toggles so the CLI and
// the web interface stay at parity without each toggle re-implementing the same parse-and-report dance.
async function cmdBoolSetting(pos, { key, label, onText, offText }) {
	const arg = String(pos[0] || '').trim().toLowerCase();
	if (arg === '') { const s = await vdisk.getSettings(); console.log(label + ': ' + (s[key] ? 'on' : 'off')); return; }
	if (!/^(on|off|true|false|yes|no|1|0)$/.test(arg)) throw new Error('Usage: ' + label.toLowerCase().replace(/\s+/g, '-') + ' [on|off]');
	const on = /^(on|true|yes|1)$/.test(arg);
	await vdisk.setSettings({ [key]: on });
	console.log(on ? onText : offText);
}
const cmdLockOnSleep = (pos) => cmdBoolSetting(pos, { key: 'lockOnSleep', label: 'Lock on sleep',
	onText: 'Lock on sleep is on — mounted vaults lock when the computer sleeps (while the web app is running).',
	offText: 'Lock on sleep is off.' });
const cmdAutoTimestamp = (pos) => cmdBoolSetting(pos, { key: 'autoAttest', label: 'Auto-timestamp',
	onText: 'Auto-timestamp is on — a trusted timestamp is recorded automatically after changes.',
	offText: 'Auto-timestamp is off.' });

async function cmdStatus() {
	const rows = await vdisk.status();
	if (!rows.length) { console.log('No vaults are mounted.'); return; }
	const health = await vdisk.mountHealth(rows); // { <mountpoint>: 'healthy'|'unresponsive'|'dead' }
	let anyStuck = false, anyStale = false;
	for (const r of rows) {
		let state = r.mounted && r.alive ? 'mounted' : (r.alive ? 'starting' : 'stale');
		if (state === 'stale') anyStale = true;
		if (health[r.mountpoint] === 'unresponsive') { state = 'stuck'; anyStuck = true; } // wedged: engine alive, drive not answering
		console.log([state.padEnd(8), r.mountpoint, '←', r.vault, '(pid ' + r.pid + ')'].join(' '));
	}
	if (anyStuck) console.log('\nA "stuck" vault stopped responding. Recover it now (no reboot):  ' + Brand.cli + ' unmount <path> --force');
	if (anyStale) console.log('\nA "stale" vault was left by a crashed engine (the drive is already gone). Clear it with:  ' + Brand.cli + ' repair');
}

async function cmdList(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' list <path>');
	const password = await prompt.hidden('Password: ');
	const files = await vdisk.list(target, { password });
	if (!files.length) console.log('(vault is empty)');
	else files.forEach(f => console.log(f));
}

async function cmdSearch(pos, flags = {}) {
	const target = pos[0], query = pos.slice(1).join(' ');
	if (!target || !query) throw new Error('Usage: ' + Brand.cli + ' search <path> <query> [--in]');
	// --in searches INSIDE files via the encrypted in-vault index (the vault must be mounted).
	if (flags.in || flags.content) {
		const res = await vdisk.contentSearch(target, { query });
		if (res.noIndex) { console.log('No content index yet — build one with "' + Brand.cli + ' reindex ' + target + '".'); return; }
		if (res.stale) { console.log('The content index needs rebuilding — run "' + Brand.cli + ' reindex ' + target + '".'); return; }
		if (!res.results.length) { console.log('No files contain "' + query + '".'); return; }
		res.results.forEach(m => console.log('  ' + m.path));
		console.log('\n' + res.results.length + ' file' + (res.results.length === 1 ? '' : 's') + ' matched.');
		return;
	}
	// A mounted vault searches with no password; only prompt when it turns out to be unmounted.
	let res;
	try { res = await vdisk.searchNames(target, { query }); }
	catch (e) {
		if (/not mounted/i.test(e.message)) { const password = await prompt.hidden('Password: '); res = await vdisk.searchNames(target, { query, password }); }
		else throw e;
	}
	if (!res.matches.length) { console.log('No matches for "' + query + '".'); return; }
	res.matches.forEach(m => console.log('  ' + m));
	console.log('\n' + res.matches.length + ' match' + (res.matches.length === 1 ? '' : 'es') + (res.mounted ? '' : ' (searched unmounted)') + '.');
}

// Build or refresh the content-search index for a mounted vault (incremental; the index lives in the vault).
async function cmdReindex(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' reindex <path>');
	const prog = cliProgress();
	const r = await vdisk.contentReindex(target, { onProgress: prog });
	prog.done();
	console.log('Indexed ' + r.indexed + ' file' + (r.indexed === 1 ? '' : 's') + ' (' + r.added + ' added, ' + r.changed + ' changed, ' + r.removed + ' removed).');
	console.log('The index is stored inside the vault, so take a new tamper snapshot with "' + Brand.cli + ' snapshot ' + target + '".');
}

async function cmdVerify(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' verify <path>');
	requireStringFlag(flags, 'keyfile', '--keyfile /path/to/keyfile'); // a bare --keyfile must fail clearly, not as a raw fsp.readFile(true) error
	const password = flags['no-password'] ? undefined
		: flags.keyfile ? await vdisk.keyfileDigestFromFile(flags.keyfile)
		: await prompt.hidden('Password (blank to check the manifest only): ');
	const rep = await vdisk.verify(target, { password: password || undefined, deep: !flags.quick });
	console.log('Vault:      ' + rep.vault);
	console.log('Manifest:   ' + rep.manifest);
	if (rep.password) console.log('Password:   ' + rep.password);
	if (rep.integrity) console.log('Integrity:  ' + rep.integrity + ' (' + rep.files + ' files read)');
	if (rep.errors.length) console.log('\nIssues:\n  ' + rep.errors.join('\n  '));
	printSyncIssues(rep.syncIssues);
	const rs = await vdisk.recoveryStatus(target);
	console.log('Recovery:   ' + (rs.unreadable ? 'present, but ' + rs.message
		: rs.protected ? 'protected (' + rs.tier + ' level, ~' + rs.redundancyPercent + '%) — "' + Brand.cli + ' heal" repairs corruption'
		: 'not protected (run "' + Brand.cli + ' protect" to add self-healing)'));
	const ms = await vdisk.mirrorStatus(target);
	console.log('Mirror:     ' + (!ms.configured ? 'none (set one up with "' + Brand.cli + ' mirror")'
		: (ms.primed ? 'to ' + ms.dest + (ms.lastSyncAt ? ' (last synced ' + fmtTime(ms.lastSyncAt) + ')' : '') + (ms.lastConflicts ? ' — conflicts to resolve' : '') : 'to ' + ms.dest + ' (not primed yet — run "' + Brand.cli + ' sync")')));
	console.log('\n' + (rep.ok ? 'Vault is healthy.' : 'Problems were found — see above.'));
	if (!rep.ok) process.exitCode = 1;
}

async function cmdProtect(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' protect <path> [--redundancy low|medium|high] [--thorough]');
	const tier = flags.redundancy || 'medium';
	if (!['low', 'medium', 'high'].includes(tier)) throw new Error('Unknown --redundancy "' + tier + '". Choose low, medium, or high.');
	const thorough = !!flags.thorough;
	console.log('Building recovery data (no password needed — it works over the encrypted files)…');
	const prog = cliProgress();
	const r = await vdisk.protect(target, { tier, thorough, onProgress: prog }); prog.done();
	console.log('Protected ' + r.vault + ' at the ' + r.tier + ' level (about ' + r.redundancyPercent + '% recovery).');
	console.log(r.dataBlocks + ' data blocks, ' + r.parityBlocks + ' recovery blocks, ' + r.stripes + ' stripe(s).');
	if (thorough) console.log('Thorough change detection is on: the recovery data refreshes even after an in-place edit that keeps a file the same size (at the cost of re-reading the vault on each unmount).');
	console.log('\nRun "' + Brand.cli + ' heal ' + target + '" any time to detect and repair corruption. It refreshes on its own');
	console.log('after you change the vault\'s contents. Recovery is NOT a backup — keep an off-site copy too.');
}

// Print the cloud-sync leftovers (conflicted copies, half-finished uploads) a verify/audit found — one shared
// helper so both commands render them identically, always with a truncation tail rather than a silent cut-off.
function printSyncIssues(list) {
	if (!list || !list.length) return;
	console.log('\nSync leftovers (' + list.length + ') — these are from your cloud-sync tool, not tampering:');
	for (const s of list.slice(0, 20)) console.log('  [' + s.kind + '] ' + s.file + ' — ' + s.why);
	if (list.length > 20) console.log('  … and ' + (list.length - 20) + ' more');
}

// A short line about the recovery data's authenticity signature (present on a verify/heal result). The
// precedence lives once in Vault (res.authenticity.state); this only maps that state to plain-language text.
function recoveryAuthLine(res) {
	const a = res && res.authenticity;
	if (!a) return null;
	switch (a.state) {
		case 'tampered': return '⚠ Authenticity: the recovery data is signed but the signature did NOT verify — it may have been altered or forged.';
		case 'downgrade': return '⚠ Authenticity: this recovery data is not signed, though a signed version was seen before — if you did not just rebuild it without unlocking, treat it with suspicion.';
		case 'verified': return '✓ Authenticity: signed by the vault\'s write key and verified.';
		default: return 'Authenticity: not signed (weaker trust) — it will be signed after the next read-write unlock and unmount.';
	}
}

async function cmdHeal(pos, flags = {}) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' heal <path> [--force]');
	const prog = cliProgress();
	const rep = await vdisk.verifyRecovery(target, { onProgress: prog }); prog.done();
	if (!rep.protected) { console.log('This vault has no recovery data. Run "' + Brand.cli + ' protect ' + target + '" first.'); process.exitCode = 1; return; }
	const authLine = recoveryAuthLine(rep); if (authLine) console.log(authLine);
	// Refuse to repair from recovery data whose signature is present but invalid: reconstructing from a forged
	// index could corrupt files. --force is the explicit "repair anyway" override so a rare multi-fault (real
	// damage AND a bit-rotten signature) can never leave a vault permanently unrepairable.
	if (rep.authenticity && rep.authenticity.state === 'tampered' && !flags.force) { console.log('Repair was not attempted. Rebuild the recovery data from a trusted read-write session ("' + Brand.cli + ' protect ' + target + '" while unlocked), delete the .recovery folder and rebuild it, or repair anyway with --force if you trust this vault.'); process.exitCode = 1; return; }
	if (rep.clean) { console.log('No corruption found — the vault matches its recovery data.'); return; }
	console.log('Damage found: ' + rep.damagedData + ' data block(s) and ' + rep.damagedParity + ' recovery block(s)' + (rep.oversizeFiles ? ' and ' + rep.oversizeFiles + ' over-long file(s)' : '') + '.');
	if (!rep.fullyRecoverable) console.log('Warning: ' + rep.unrecoverableStripes + ' area(s) have more damage than the recovery data can repair — restore those from a backup.');
	const prog2 = cliProgress();
	const h = await vdisk.heal(target, { allowUnverified: !!flags.force, force: !!flags.force, onProgress: prog2 }); prog2.done();
	if (h.repairedUnverified) console.log('Note: repaired despite an unverified recovery signature (--force). Re-establish trust by rebuilding the recovery data from a read-write session.');
	const nFiles = (h.repairedFiles || []).length;
	console.log('Repaired ' + h.repairedData + ' data block(s) and ' + h.repairedParity + ' recovery block(s)' + (h.repairedSize ? ' and trimmed ' + h.repairedSize + ' over-long file(s)' : '') + (nFiles ? ', across ' + nFiles + ' encrypted file(s)' : '') + '.');
	if (h.changedSkipped) console.log(h.changedSkipped + ' file(s) changed since protection was last updated and were left exactly as they are — those changes are your data, not damage. Run "protect" again to update the recovery data to match the current contents. (If you are certain the change is corruption, not an edit, re-run with --force to repair it from the recovery data.)');
	if (h.writeErrors) { console.log(h.writeErrors + ' repair(s) could not be written — check that the disk has free space and the files are not read-only or locked, then run heal again.'); process.exitCode = 1; }
	if (h.unrecoverableStripes) { console.log(h.unrecoverableStripes + ' area(s) could not be repaired (beyond the recovery budget).'); process.exitCode = 1; }
	else if (!h.writeErrors) console.log('The vault is repaired — open it to confirm.');
}

// --- Tier 3: disperse across nodes + threshold key ---------------------------------------------
function splitList(v) { return String(v || '').split(',').map(s => s.trim()).filter(Boolean); }

async function cmdDisperse(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' disperse <path> --to <dir1,dir2,...> --threshold <k> [--force]');
	const dests = splitList(flags.to);
	if (dests.length < 2) throw new Error('Provide at least two destination folders with --to <dir1,dir2,...> (one per shard).');
	const n = dests.length;
	const k = parseInt(flags.threshold, 10);
	if (!(k >= 1 && k <= n)) throw new Error('--threshold must be between 1 and the number of destinations (' + n + ').');
	const g = vdisk.dispersalGuidance(n, k);
	console.log('Dispersing into ' + n + ' shards — any ' + k + ' rebuild the vault (survives losing ' + g.tolerate + ' node' + (g.tolerate === 1 ? '' : 's') + '; about ' + g.expansionFactor + '× total storage). Each node holds only opaque, incomplete ciphertext.');
	const prog = cliProgress();
	const r = await vdisk.disperse(target, { n, k, dests, force: !!flags.force, onProgress: prog }); prog.done();
	console.log('Done. Shards written:');
	r.shards.forEach(f => console.log('  ' + f));
	console.log('\nTo use the vault again, gather any ' + k + ' shards and run "' + Brand.cli + ' reconstruct --shards <s1,...> --to <folder>".');
	console.log('Dispersal is for durability, not a live drive — it is not a substitute for a backup of a vault you use day to day.');
}

async function cmdReconstruct(pos, flags) {
	if (flags.shards === true) throw new Error('--shards needs one or more folder paths, for example --shards "folderA,folderB".');
	const shards = splitList(flags.shards).concat(pos);
	if (!shards.length) throw new Error('Usage: ' + Brand.cli + ' reconstruct --shards <s1,s2,...> --to <folder>');
	if (flags.to === true) throw new Error('--to needs a folder path, for example --to ./RebuiltVault.');
	const dest = flags.to ? String(flags.to) : process.cwd();
	if (!flags.to) console.log('No --to folder given — rebuilding into the current folder: ' + dest);
	const prog = cliProgress();
	const r = await vdisk.reconstructFromShards(shards, dest, { onProgress: prog }); prog.done();
	console.log('Rebuilt the vault at ' + r.vault + '. Open it with your password (or its keyfile / threshold key) as usual.');
}

async function cmdShards(pos) {
	if (!pos.length) throw new Error('Usage: ' + Brand.cli + ' shards <shard-file> [more…]');
	const s = await vdisk.inspectShards(pos);
	console.log(s.good + ' of ' + s.total + ' shard(s) readable' + (s.k != null ? ' (need any ' + s.k + ' of ' + s.n + ')' : '') + '.');
	s.shards.forEach(i => console.log('  ' + (i.ok ? 'ok  ' : 'BAD ') + (i.idx != null ? '#' + i.idx + ' ' : '') + i.path));
	console.log(s.recoverable ? 'Recoverable: yes.' : 'Recoverable: NO — too many shards are missing or corrupt.');
	if (!s.recoverable) process.exitCode = 1;
}

async function cmdRepairShards(pos) {
	if (!pos.length) throw new Error('Usage: ' + Brand.cli + ' repair-shards <shard-file> [more…]');
	const prog = cliProgress();
	const r = await vdisk.repairDispersal(pos, { onProgress: prog }); prog.done();
	console.log('Repaired ' + r.repaired + ' shard(s); the full set of ' + r.n + ' is restored.');
}

async function cmdVerifyBackup(pos, flags) {
	const vault = pos[0];
	if (!vault) throw new Error('Usage: ' + Brand.cli + ' verify-backup <vault> [--dest <folder|sftp:id>]   (check a backup is complete and restorable)');
	requireStringFlag(flags, 'dest', '--dest <folder|sftp:id>');
	const r = await vdisk.verifyBackup(vault, { dest: flags.dest });
	const label = { RESTORABLE: 'RESTORABLE', INCOMPLETE: 'INCOMPLETE', DIFFERENT: 'DIFFERENT VAULT', UNREADABLE: 'UNREADABLE' }[r.verdict] || r.verdict;
	console.log('Backup check: ' + label);
	if (r.total != null) console.log('  ' + r.present + ' of ' + r.total + ' encrypted files present at ' + r.dest + '.');
	console.log('  ' + r.reason);
	if (r.verdict !== 'RESTORABLE') process.exitCode = 1;
}

async function cmdScrub(pos, flags) {
	const vault = pos[0];
	if (!vault) throw new Error('Usage: ' + Brand.cli + ' scrub <vault> [--heal]   (check the recovery data for bit-rot; --heal repairs any damage from it)');
	const prog = cliProgress();
	const r = await vdisk.runScrub(vault, { autoHeal: !!flags.heal, onProgress: prog }); prog.done();
	if (r.skipped) { console.log('Nothing to scrub: ' + r.skipped + '.'); return; }
	if (r.clean) console.log('Integrity scrub: clean — the recovery data verifies and no damage was found.');
	else if (r.healed) console.log('Integrity scrub: repaired ' + r.repaired + ' damaged area(s) from the recovery data.');
	else { console.log('Integrity scrub: DAMAGE FOUND. Run "' + Brand.cli + ' scrub ' + vault + ' --heal" to repair it from the recovery data.'); process.exitCode = 1; } // non-zero so a scheduled/scripted scrub can detect unrepaired corruption, matching heal/verify-backup/shards
}
// Parse the shared "--daily HH:MM | --every <hours>" scheduling flags into a timing object, so the backup,
// scrub, and repair schedule commands can never drift on how a time is read.
function scheduleTimingFromFlags(flags) {
	if (flags.daily) {
		// Validate up front rather than storing a NaN or out-of-range time that would later fire wrong or print "NaN".
		const m = /^(\d{1,2}):(\d{1,2})$/.exec(String(flags.daily).trim());
		const hour = m ? parseInt(m[1], 10) : NaN, minute = m ? parseInt(m[2], 10) : NaN;
		if (!m || hour > 23 || minute > 59) throw new Error('--daily takes a 24-hour time as HH:MM, from 00:00 to 23:59 (for example, --daily 03:00).');
		return { mode: 'daily', hour, minute };
	}
	const hours = parseInt(flags.every, 10);
	if (flags.every != null && (!Number.isFinite(hours) || hours < 1)) throw new Error('--every takes a whole number of hours, at least 1 (for example, --every 24).');
	return { mode: 'interval', intervalHours: Number.isFinite(hours) && hours >= 1 ? hours : 24 };
}
// A one-line human summary of a stored schedule's timing ("every 24h" / "daily at 03:00" / "off").
function describeScheduleWhen(s) {
	if (s.mode === 'interval') return 'every ' + s.intervalHours + 'h';
	if (s.mode === 'daily') return 'daily at ' + String(s.hour).padStart(2, '0') + ':' + String(s.minute).padStart(2, '0');
	return 'off';
}

// Both schedule commands clear the schedule when given "off"/"none" as the first positional or a bare --off flag; one
// helper so they read that request identically. (repair-schedule uses a "remove" subcommand shape instead, by design.)
function scheduleOffRequested(pos, flags) {
	return !!(flags.off || (pos[1] && /^(off|none)$/i.test(pos[1])));
}

async function cmdBackupSchedule(pos, flags) {
	const vault = pos[0];
	if (!vault) throw new Error('Usage: ' + Brand.cli + ' backup-schedule <vault> <off | --dest <folder|sftp:id> [--every <hours> | --daily HH:MM]>');
	if (scheduleOffRequested(pos, flags)) { await vdisk.setBackupSchedule(vault, { mode: 'off' }); console.log('Scheduled backup turned off.'); return; }
	requireStringFlag(flags, 'dest', '--dest <folder|sftp:id>'); // a bare --dest (no value) parses to true; reject it before the !flags.dest check, which true would slip past
	if (!flags.dest) throw new Error('A backup destination is required: --dest <folder|sftp:id>.');
	const s = (await vdisk.setBackupSchedule(vault, { dest: String(flags.dest), ...scheduleTimingFromFlags(flags) })).schedule;
	console.log('Scheduled backup set (' + describeScheduleWhen(s) + ') to ' + s.dest + '. It runs while the web interface is running.');
}

async function cmdScrubSchedule(pos, flags) {
	const vault = pos[0];
	if (!vault) throw new Error('Usage: ' + Brand.cli + ' scrub-schedule <vault> <off | --every <hours> | --daily HH:MM> [--heal]');
	if (scheduleOffRequested(pos, flags)) { await vdisk.setScrubSchedule(vault, { mode: 'off' }); console.log('Integrity scrub schedule turned off.'); return; }
	const s = (await vdisk.setScrubSchedule(vault, { autoHeal: !!flags.heal, ...scheduleTimingFromFlags(flags) })).schedule;
	console.log('Integrity scrub scheduled (' + describeScheduleWhen(s) + (s.autoHeal ? ', auto-repair on' : ', check only') + '). It runs while the web interface is running.');
}

async function cmdRepairSchedule(pos, flags) {
	const sub = (pos[0] || 'list').toLowerCase();
	if (sub === 'list') {
		const list = await vdisk.listRepairSchedules();
		if (!list.length) { console.log('No repair schedules. Add one with "' + Brand.cli + ' repair-schedule add --folders <f1,f2,...> --every <hours>" (or --daily HH:MM).'); return; }
		for (const s of list) {
			console.log(s.id + '  ' + describeScheduleWhen(s) + '  [' + s.folders.length + ' folder(s)]' + (s.lastResult ? '  last: ' + s.lastResult : ''));
			s.folders.forEach(f => console.log('     ' + f));
		}
		return;
	}
	if (sub === 'add' || sub === 'set') {
		const folders = splitList(flags.folders);
		if (!folders.length) throw new Error('Usage: ' + Brand.cli + ' repair-schedule add --folders <f1,f2,...> [--every <hours> | --daily HH:MM]');
		const r = await vdisk.saveRepairSchedule({ folders, ...scheduleTimingFromFlags(flags), label: flags.label });
		console.log('Repair schedule saved (' + r.id + '). It runs while the web interface is running.');
		return;
	}
	if (sub === 'remove' || sub === 'off') {
		const id = pos[1];
		if (!id) throw new Error('Usage: ' + Brand.cli + ' repair-schedule remove <id>');
		await vdisk.removeRepairSchedule(id);
		console.log('Repair schedule removed.');
		return;
	}
	throw new Error('Usage: ' + Brand.cli + ' repair-schedule <list | add --folders <…> [--every <h>|--daily HH:MM] | remove <id>>');
}

async function cmdThresholdKey(pos, flags, { emergency = false } = {}) {
	const target = pos[0];
	const cmd = emergency ? 'emergency-access' : 'threshold-key';
	if (!target) throw new Error('Usage: ' + Brand.cli + ' ' + cmd + ' <path> --shares <n> --threshold <k>' + (emergency ? '' : ' [--read-only]'));
	const n = parseInt(flags.shares, 10), k = parseInt(flags.threshold, 10);
	if (!(k >= 2 && n >= k)) throw new Error('Choose --shares <n> and --threshold <k> with 2 ≤ k ≤ n.');
	const readOnly = emergency || !!flags['read-only'];
	const password = await prompt.hidden('Current password: ');
	const r = await vdisk.addThresholdKey(target, { password, n, k, readOnly });
	if (readOnly) {
		console.log('Added ' + k + '-of-' + n + ' emergency access (READ-ONLY). Give ONE share to each trusted');
		console.log('contact — any ' + k + ' together can open the vault to READ it, but can never change it or lock');
		console.log('you out. They cannot act until ' + k + ' of them cooperate, so keep the shares apart. Shown once:');
	} else {
		console.log('Added a ' + k + '-of-' + n + ' threshold key. Give ONE share to each holder — any ' + k + ' together unlock the vault. Shown once:');
	}
	r.shares.forEach((s, i) => console.log('  share ' + (i + 1) + ': ' + s));
	console.log('\nUnlock with: ' + Brand.cli + ' mount <path> --key-shares <share,share,...>');
}

async function cmdUnprotect(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' unprotect <path> [--yes]');
	// Removing the recovery data is not catastrophic — the vault still opens — but it silently discards the vault's
	// self-heal protection, so confirm first (like the other data-affecting commands), with --yes to skip the prompt.
	if (!flags || !flags.yes) {
		console.log('This removes the recovery data from "' + vdisk.displayName(target) + '". The vault will still open, but it can no longer self-heal from corruption or bit-rot until you run "' + Brand.cli + ' protect" again.');
		const ans = await prompt.line('Remove it? (y/N): ');
		if (!/^y(es)?$/i.test(ans.trim())) { console.log('Canceled — the recovery data was left in place.'); return; }
	}
	// Require the vault's read-write password: removing self-heal protection is a standing-security change, so a path
	// alone is not enough (mirrors permanent delete).
	const password = await prompt.hidden('Vault password: ');
	await vdisk.unprotect(target, { password });
	console.log('Removed the recovery data for ' + target + '.');
}

// Crypto-erase a vault: destroy its keys so this copy can never be opened again. Irreversible, so the default
// path forces an explicit safety-copy choice and a typed confirmation; --panic erases immediately for a duress
// emergency. Only the keys are destroyed (fast and effective); the ciphertext, without them, is meaningless.
async function cmdSecureRemove(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' secure-remove <vault> [--keep <file' + Brand.packExt + '> | --no-keep] [--panic]');
	const manifest = await vdisk.readManifest(target).catch(() => null);
	if (!manifest) throw new Error('That is not a vault (no readable manifest at ' + target + ').');
	const name = vdisk.displayName(target); // brand-correct name derivation (strips the vault extension, follows a rename)
	const backend = (manifest.crypt && manifest.crypt.backend) || {};
	const cloud = !!backend.remoteId;   // a cloud vault keeps its ciphertext at a provider
	const worm = !!backend.worm;        // tamper-proof (WORM) locks each uploaded version for a retention window
	const panic = !!flags.panic;
	let keepPath;
	if (panic) {
		console.log('PANIC: erasing "' + name + '" immediately, with no safety copy.');
	} else {
		if (flags.keep === undefined && !flags['no-keep']) throw new Error('Choose a safety copy first: --keep <file> saves a portable, still-encrypted copy before erasing, or --no-keep erases without one. (For a real emergency, --panic erases immediately with no copy and no prompt.)');
		if (flags.keep === true) throw new Error('--keep needs a filename, for example --keep "' + name + Brand.packExt + '". Use --no-keep to erase without a safety copy. (Nothing was destroyed.)');
		keepPath = flags.keep ? String(flags.keep) : undefined;
		console.log('This PERMANENTLY destroys the keys for the vault "' + name + '". Afterward this copy can NEVER be opened again — not with your password, not with a recovery key.');
		console.log('Backups, mirrors, and other copies keep their own keys and are unaffected. If this is your ONLY copy, the data is gone forever.');
		console.log('Anything you exported that still carries a working key — a Recovery Kit, a recovery key, threshold (Shamir) shares, or an emergency-access seal — can bring this data back. Destroy those too if you want it truly gone.');
		if (cloud) console.log('The encrypted data already in the cloud stays there, and your provider may keep prior or soft-deleted versions of it. That is harmless once the keys are gone — the ciphertext can no longer be decrypted — but it lingers, and costs storage, until you delete those versions or they age out.');
		if (cloud && worm) console.log('This vault used tamper-proof (WORM) mode, so those uploaded versions are locked at the provider and cannot be deleted until their retention window expires — the encrypted data stays there, undecryptable but present, until then.');
		console.log('(On flash storage some encrypted remnants may linger physically, but without the keys they are meaningless.)');
		if (!(await confirmVaultName(target, n => 'Type the vault name (' + n + ') to confirm, or anything else to cancel: ', 'Did not match — nothing was destroyed.'))) return;
	}
	// Require the vault's own read-write password before erasing — even in a panic. The name alone is no secret, so
	// this proves the person destroying the vault can actually open it; secureRemove verifies it before touching anything.
	const password = await prompt.hidden('Vault password (required to erase): ');
	const res = await vdisk.secureRemove(target, { password, keepPath });
	if (res.kept) console.log('Saved a portable encrypted copy to: ' + res.kept + ' (open it later with the vault password).');
	console.log('Securely removed "' + name + '". Its keys are destroyed' + (res.cloud ? ', so the cloud store is left but can no longer be decrypted' : '') + '.');
}

async function cmdSnapshot(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' snapshot <path>');
	// Taking a snapshot writes an UNSEALED baseline, so on a sealed vault it removes the tripwire.
	// Never do that silently: refuse unless the user confirms with --force, and point at "unseal".
	const sealed = await vdisk.readManifest(target).then(m => m.snapshot && m.snapshot.sealed).catch(() => false);
	if (sealed && !flags.force) {
		console.log('This vault is sealed. Taking a snapshot would remove the seal (the tamper tripwire) and');
		console.log('return it to automatic tracking. If that is what you want, re-run with --force, or use');
		console.log('"' + Brand.cli + ' unseal ' + target + '" instead. To keep the seal and accept new contents, use "' + Brand.cli + ' seal".');
		process.exitCode = 1;
		return;
	}
	const password = await prompt.hidden('Password: ');
	const rep = await vdisk.snapshot(target, { password, force: !!flags.force }); // the gate above already confirmed a sealed removal
	console.log('Vault:        ' + rep.vault);
	console.log('Snapshot:     recorded ' + rep.count + ' file' + (rep.count === 1 ? '' : 's') + ' at ' + rep.createdAt);
	console.log('Version:      ' + rep.seq);
	console.log('Fingerprint:  ' + rep.fingerprint);
	if (sealed) console.log('The seal was removed — this vault is now on automatic tracking again.');
	console.log('\nRecord the fingerprint somewhere safe — later you can confirm the vault is this exact');
	console.log('version. Run "' + Brand.cli + ' audit ' + target + '" to detect anything added, removed, or modified.');
}

async function cmdFingerprint(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' fingerprint <path>');
	const rep = await vdisk.fingerprint(target); // no password needed — neither value is secret
	console.log('Vault:        ' + rep.vault);
	if (rep.identity) console.log('Identity:     ' + rep.identity + '   (stable — this is which vault it is)');
	if (!rep.fingerprint) { console.log('No snapshot has been taken yet — mount the vault once, or run "' + Brand.cli + ' snapshot".'); return; }
	console.log('Version:      ' + rep.seq);
	console.log('Fingerprint:  ' + rep.fingerprint + '   (changes as you edit — this is the exact state)');
	console.log('Recorded at:  ' + rep.at);
	console.log('\nRecord the IDENTITY once, out of band. Any vault whose identity matches — and whose baseline still');
	console.log('verifies (run "' + Brand.cli + ' audit") — is genuinely yours; a hacker\'s recreation has a different identity.');
}

// Package a portable, third-party-verifiable proof bundle from a vault.
async function cmdMakeBundle(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' make-bundle <path> [--out <folder>]');
	const password = await prompt.hidden('Password: ');
	const r = await vdisk.makeBundle(target, { password, outDir: flags.out });
	console.log('Proof bundle written to ' + r.bundle);
	console.log('Identity ' + r.identity + ', fingerprint ' + r.fingerprint + ', version ' + r.seq + '.');
	console.log('Anyone can verify it offline with:  ' + Brand.cli + ' verify-bundle "' + r.bundle + '"');
}
// Verify a proof bundle offline — no vault, no password needed.
async function cmdVerifyBundle(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' verify-bundle <bundle-folder> [--expect <recorded-origin-identity>]');
	const r = await vdisk.verifyBundle(target, { expectIdentity: flags.expect });
	console.log('Verdict:   ' + r.verdict);
	if (r.identity) console.log('Identity:  ' + r.identity + (r.seq != null ? '   (version ' + r.seq + ')' : ''));
	if (r.originIdentity) console.log('Origin:    ' + r.originIdentity + '   (the vault\'s ORIGINAL identity)');
	if (r.asOf) console.log('As of:     ' + r.asOf + (r.timestamped ? '   (trusted timestamp)' : ''));
	else if (r.verdict === 'GENUINE') console.log('As of:     (no timestamp proof in this bundle)');
	console.log('\nChecks:');
	for (const c of r.checks) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.name + (c.detail ? '  — ' + c.detail : ''));
	// Honest limits — a stateless offline check cannot answer these two on its own; the reader must.
	if (!flags.expect && r.originIdentity) console.log('\nConfirm the Origin identity above matches the value the vault owner gave you separately (their Recovery Kit, website, or a value they told you). The math proves the lineage is self-consistent, not that this origin is the right one — pass it with --expect to have this check it for you.');
	if (r.verdict === 'GENUINE' && !r.timestamped) console.log('Note: with no trusted-timestamp proof in this bundle, "GENUINE" cannot prove this is the LATEST version — only that it is internally authentic and untampered.');
	process.exitCode = r.verdict === 'GENUINE' ? 0 : 1;
}

async function cmdAttest(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' attest <path> [--tsa <url>]   |   ' + Brand.cli + ' attest <path> --list');
	if (flags.list) {
		const rep = await vdisk.attestations(target);
		console.log('Vault:     ' + rep.vault);
		console.log('Identity:  ' + rep.identity + (rep.currentSeq != null ? '   (current version ' + rep.currentSeq + ')' : ''));
		if (!rep.items.length) { console.log('\nNo timestamp proofs yet. Create one with "' + Brand.cli + ' attest ' + target + '".'); return; }
		console.log('\nTimestamp proofs (' + rep.items.length + '):');
		for (const it of rep.items) {
			const mark = it.verified ? (it.matchesCurrent ? '✓ current' : '✓') : '⚠ ' + (it.reason || 'unverified');
			const link = it.chained ? '' : '  ⚠ chain break';
			console.log('  [' + mark + '] version ' + it.seq + '  at ' + (it.genTime || it.at) + '  via ' + it.tsaUrl + link);
		}
		console.log(rep.chainOk ? '\n✓ Proof chain intact (tamper-evident as a whole).' : '\n⚠ The proof chain is BROKEN — a proof was reordered, inserted, or altered.');
		if (rep.rolledBack) console.log('⚠ ROLLBACK: this vault presents an OLDER version (' + rep.currentSeq + ') than its own attested history (up to ' + rep.maxAttestedSeq + ') — it may have been rolled back to an earlier state.');
		if (rep.head) console.log('\nChain head — record it out of band (or keep the Recovery Kit) to detect a rollback later:\n    version ' + rep.head.seq + '  ·  ' + (rep.head.genTime || '(time in token)') + '  ·  head ' + String(rep.head.chain).slice(0, 16) + '…');
		console.log('\nEach proof certifies the vault\'s exact state at the signed time, verifiable by anyone.');
		return;
	}
	console.log('Requesting a trusted timestamp…');
	const r = await vdisk.attest(target, { tsaUrl: flags.tsa });
	console.log('\nTimestamp proof created for version ' + r.seq + ':');
	console.log('  Certified time:  ' + (r.genTime || '(unknown)'));
	console.log('  Authority:       ' + r.tsaUrl);
	console.log('  Total proofs:    ' + r.count);
	console.log('\nThe proof is stored beside the vault (attestations.json) and travels with your backups.');
	// A default authority is fully verified before the proof is returned; a custom --tsa whose certificate does not
	// chain to a trusted root is recorded but NOT independently trusted, so say so plainly rather than presenting it
	// as proven time.
	if (r.verified === false) console.log('Note: this authority\'s certificate could not be verified to a trusted root' + (r.verifyReason ? ' (' + r.verifyReason + ')' : '') + ', so the recorded time is not independently trusted. Use a default authority for a trusted timestamp.');
	else console.log('It proves this exact state existed at the certified time, and anyone can verify it.');
}

async function cmdRecoveryKit(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' recovery-kit <path> [output.html]  [--no-key]');
	// By default the kit includes a freshly generated recovery key (needs the current password to add
	// the key slot). --no-key makes an identity-only kit that changes nothing and needs no password.
	const addKey = !flags['no-key'];
	const password = addKey ? await prompt.hidden('Current password: ') : undefined;
	const r = await vdisk.recoveryKit(target, { password, addKey });
	const outArg = pos[1] || flags.out;
	const outFile = path.resolve(outArg || (vdisk.displayName(r.vault) + '-recovery-kit.html'));
	try { fs.writeFileSync(outFile, r.html, { mode: 0o600 }); } catch (_) { throw new Error('Could not write the Recovery Kit to "' + outFile + '". Check the folder exists and is writable.'); } // owner-only: it can carry a recovery key
	console.log('Recovery Kit written to:\n    ' + outFile + '\n');
	console.log('Open it in a browser and print it or save the PDF, then store it somewhere safe and');
	console.log('separate from the vault.');
	if (r.recoveryKey) console.log('\nIt contains a recovery key, shown only in this file — keep the file private.');
}

async function cmdAudit(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' audit <path>');
	const password = await prompt.hidden('Password: ');
	const rep = await vdisk.audit(target, { password });
	console.log('Vault:        ' + rep.vault);
	if (rep.errors.length) { console.log('\n' + rep.errors.join('\n')); process.exitCode = 1; return; }
	if (rep.snapshotAt) console.log('Baseline:     ' + rep.snapshotAt + (rep.sealed ? '  (SEALED)' : ''));
	if (rep.seq != null) console.log('Version:      ' + rep.seq);
	if (rep.fingerprint) console.log('Fingerprint:  ' + rep.fingerprint);
	const list = (label, arr) => { if (arr.length) console.log('\n' + label + ' (' + arr.length + '):\n  ' + arr.join('\n  ')); };
	if (rep.tamper.length) console.log('\nTampering:\n  ' + rep.tamper.join('\n  '));
	list('Modified', rep.modified);
	list('Removed', rep.removed);
	list('Added', rep.added);
		list('Foreign (undecryptable, added from outside the vault or corrupted)', rep.foreign);
	printSyncIssues(rep.syncIssues);
	console.log('\n' + (rep.clean ? 'No changes — the vault matches its baseline.'
		: (rep.sealed ? 'Changes detected against the SEAL — see above. Re-seal to accept them.' : 'Changes were detected — see above.')));
	if (!rep.clean) process.exitCode = 1;
}

async function cmdSeal(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' seal <path>');
	const password = await prompt.hidden('Password: ');
	// Reviewed seal: if the vault already has outstanding changes against its baseline, show exactly
	// what sealing will accept before writing the new trusted state — a seal is a deliberate act.
	let accept = null;
	const chk = await vdisk.audit(target, { password });
	// A vault with no baseline yet is the normal first-seal case, not an error; any other error stops.
	if (chk.errors && chk.errors.length && !chk.noSnapshot) { console.log('\n' + chk.errors.join('\n')); process.exitCode = 1; return; }
	if (!chk.clean && !chk.noSnapshot) {
		accept = { modified: chk.modified || [], removed: chk.removed || [], added: chk.added || [] };
		const n = accept.modified.length + accept.removed.length + accept.added.length;
		console.log('\nSealing will accept these ' + n + ' change' + (n === 1 ? '' : 's') + ' as the new trusted baseline:');
		changePreview('Modified', accept.modified); changePreview('Removed', accept.removed); changePreview('Added', accept.added);
	}
	const rep = await vdisk.seal(target, { password, accept });
	console.log('\nSealed ' + rep.vault + ' at version ' + rep.seq + ' (fingerprint ' + rep.fingerprint + ').');
	console.log('Any added, removed, or changed file is now flagged until you accept it by sealing');
	console.log('again — on every mount, and (for a same-size content swap) on a deep audit.');
	console.log('Run "' + Brand.cli + ' unseal ' + target + '" to stop.');
}

async function cmdUnseal(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' unseal <path>');
	const password = await prompt.hidden('Password: ');
	await vdisk.unseal(target, { password });
	console.log('Unsealed. This vault is back to automatic tracking (changes made while it is in use are accepted).');
}

async function cmdTamperLog(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' tamper-log <path>');
	const { events, history } = await vdisk.tamperLog(target); // no password — the log holds no secrets
	if (!events.length) { console.log('No tampering has been recorded for this vault.'); return; }
	// The history is itself hash-chained and anchored; report whether that record is intact before listing it.
	// The verdict is decided once in Integrity.verifyTamperLog (history.verdict); this only maps it to text.
	if (history && history.verdict === 'altered') console.log('⚠ WARNING: this tamper history has itself been altered (' + (history.reason || 'inconsistent') + ') — the record below cannot be fully trusted.');
	else if (history && history.verdict === 'signed') console.log('✓ History verified (hash-chained and signed by the vault\'s write key).');
	else if (history && history.verdict === 'chained') console.log('History verified (hash-chained).');
	console.log('Tamper history (newest first):');
	for (const e of events) {
		const parts = [];
		if (e.notes && e.notes.length) parts.push(e.notes.join('; '));
		if (e.modified && e.modified.length) parts.push(e.modified.length + ' modified');
		if (e.removed && e.removed.length) parts.push(e.removed.length + ' removed');
		if (e.added && e.added.length) parts.push(e.added.length + ' added');
		const sev = (e.severity || 'info').toUpperCase().padEnd(8);
		console.log('  ' + sev + e.at + '  [' + e.kind + ']  ' + parts.join(' · '));
	}
}

async function cmdPack(pos, flags) {
	const [target, out] = pos;
	if (!target) throw new Error('Usage: ' + Brand.cli + ' pack <path> [output.vdisk]');
	// --keys <id1,id2>: share with only these key slots (from "vdisk keys"), so a password left out cannot
	// open the packed copy. Omit to include every key, as before.
	const keepSlots = flags.keys ? splitList(flags.keys) : undefined;
	console.log('Packing…');
	const r = await vdisk.pack(target, out, { overwrite: !!flags.force, keepSlots });
	console.log('Packed to ' + r.file + (keepSlots ? ' (opens with ' + keepSlots.length + ' selected key' + (keepSlots.length === 1 ? '' : 's') + ' only)' : ''));
}

async function cmdUnpack(pos) {
	const [file, dest] = pos;
	if (!file) throw new Error('Usage: ' + Brand.cli + ' unpack <file.vdisk> [destination]');
	console.log('Unpacking…');
	const r = await vdisk.unpack(file, dest);
	console.log('Unpacked to ' + r.vault);
}

// Browse the prior versions of files kept at the vault's backup destination.
async function cmdVersions(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' versions <path>');
	const password = await prompt.hidden('Password: ');
	const rep = await vdisk.listVersions(target, { password });
	if (!rep.hasStore) { console.log('This vault has no backup or mirror, so it has no version history. Back it up ("' + Brand.cli + ' backup") or mirror it ("' + Brand.cli + ' mirror") first.'); return; }
	if (!rep.snapshots.length) { console.log('No prior versions yet — they are captured each time a backup or mirror runs after a file changes.'); return; }
	console.log('Version history (' + rep.snapshots.length + ' snapshot' + (rep.snapshots.length === 1 ? '' : 's') + ', newest first):');
	for (const s of rep.snapshots) {
		console.log('\n  [' + (s.originLabel || s.origin) + ']  ' + s.timestamp + '   (' + (s.at ? fmtTime(s.at) : '?') + ')');
		for (const f of (s.files || []).slice(0, 50)) console.log('      ' + f);
		if ((s.files || []).length > 50) console.log('      … and ' + (s.files.length - 50) + ' more');
	}
	console.log('\nRestore a file with "' + Brand.cli + ' restore-version ' + target + ' <timestamp> <file>" (add --from <backup|mirror-dest|mirror-local> to pick a store).');
}
async function cmdRestoreVersion(pos, flags) {
	const [target, timestamp, ...fileParts] = pos;
	const file = fileParts.join(' ');
	if (!target || !timestamp || !file) throw new Error('Usage: ' + Brand.cli + ' restore-version <path> <timestamp> <file> [--from <backup|mirror-dest|mirror-local>]');
	const password = await prompt.hidden('Password: ');
	const r = await vdisk.restoreVersion(target, { password, origin: flags && flags.from, timestamp, file });
	console.log('Restored as "' + r.restoredAs + '" inside the vault — the current file was left untouched. Open the vault to find it.');
}

async function cmdBackup(pos) {
	const [target, dest] = pos;
	if (!target || !dest) throw new Error('Usage: ' + Brand.cli + ' backup <path> <destination-folder>');
	console.log('Backing up (encrypted)…');
	const r = await vdisk.backup(target, dest);
	console.log('Backed up to ' + r.dest + '. The backup is encrypted; restore it with "' + Brand.cli + ' restore".');
}

async function cmdMirror(pos) {
	const [target, dest] = pos;
	if (!target || !dest) throw new Error('Usage: ' + Brand.cli + ' mirror <path> <folder | sftp:<id> | webdav:<id>>');
	await vdisk.setMirrorDest(target, dest);
	console.log('Mirror set to ' + dest + '. Priming (making the destination match this vault)…');
	const prog = cliProgress();
	const r = await vdisk.syncMirror(target, { prime: true, onProgress: prog }); prog.done();
	console.log('Primed. The mirror is two-way from now on — "' + Brand.cli + ' sync ' + target + '" (or unmounting the vault) syncs both sides.');
	if (r.conflicts) console.log('Note: some files differed on both sides and were kept as ".sync-conflict" copies — run "' + Brand.cli + ' verify" to review them.');
}

async function cmdSync(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' sync <path>');
	const dest = await vdisk.mirrorDestFor(target);
	if (!dest) { console.log('This vault has no mirror. Set one up with "' + Brand.cli + ' mirror ' + target + ' <folder>".'); process.exitCode = 1; return; }
	console.log('Syncing the mirror with ' + dest + ' (both directions)…');
	const prog = cliProgress();
	const r = await vdisk.syncMirror(target, { onProgress: prog }); prog.done();
	console.log(r.primed ? 'Primed and synced.' : 'Synced.');
	if (r.conflicts) console.log('Some files differed on both sides and were kept as ".sync-conflict" copies — run "' + Brand.cli + ' verify" to review them.');
}

async function cmdUnmirror(pos) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' unmirror <path>');
	await vdisk.removeMirror(target);
	console.log('Stopped mirroring ' + target + '. The copy at the destination was left untouched.');
}

// Tier 2 "Anywhere access": serve a vault's ciphertext as a node another machine can mirror against.
async function cmdServe(pos, flags) {
	const target = pos[0];
	if (!target) throw new Error('Usage: ' + Brand.cli + ' serve <path> [--bind <ip>] [--port <n>] [--read-only]');
	ProcRegistry.beResilient(); // a stray error must never take the node down while it is serving
	// --relay <host[:port]> reaches this node from anywhere through a self-hosted hub (no port
	// forwarding); it needs --token (the hub's token).
	let relay = null;
	if (flags.relay) {
		const { host: rh, port: rp } = Common.splitHostPort(flags.relay, 7443); // bracket-aware, so an IPv6 hub literal ([::1]:7443) is parsed correctly
		const { token } = await resolveToken(flags, { required: true, what: 'the relay hub token, needed with --relay' }); // --token or --token-file, off the command line
		relay = { host: rh, port: rp, token };
	}
	console.log('Starting a node for this vault — only the encrypted files are served; the password and contents never leave this machine…');
	const onEvent = (e) => {
		if (e.type === 'down') console.error('\nThe server stopped unexpectedly — recovering…');
		else if (e.type === 'restarting') console.error('Restarting in ' + Math.round(e.delay / 1000) + 's (attempt ' + e.attempt + ')…');
		else if (e.type === 'reconnecting') console.error('Relay link lost — reconnecting in ' + Math.round(e.delay / 1000) + 's (attempt ' + e.attempt + ')…');
		else if (e.type === 'up') console.log('Connected — reachable on the same address.');
		else if (e.type === 'error') console.error('Relay issue: ' + e.error);
		else if (e.type === 'gaveup') { console.error('The server could not be kept running after repeated attempts. Exiting.'); ProcRegistry.gracefulExit(1); } // run the registered cleanup (mark the stop intentional, stop the node) rather than a bare exit
	};
	requireStringFlag(flags, 'bind', '--bind 0.0.0.0');
	const h = await vdisk.serveVault(target, { bind: flags.bind, port: parsePort(flags.port, undefined), readOnly: !!flags['read-only'], onEvent, relay });
	// Stop the node cleanly on shutdown — and mark the stop intentional BEFORE the tracked engine
	// process is killed, so the supervisor does not treat Ctrl+C as a crash and try to restart it.
	ProcRegistry.onShutdown(() => h.stop());
	const bind = relay ? 'relay' : (flags.bind || '127.0.0.1');
	console.log('\n  Address:   ' + h.url);
	console.log('  Username:  ' + h.user);
	console.log('  Password:  ' + h.pass + '\n');
	if (bind === 'relay') {
		console.log('One-paste connection code for the other machine:\n  ' + vdisk.makePeerCode({ url: h.url, user: h.user, pass: h.pass, ca: h.ca }) + '\n');
		console.log('On the other machine: "' + Brand.cli + ' peer-add <that-code>", then "' + Brand.cli + ' mirror <vault> webdav:<id>".');
		console.log(h.secure
			? 'Reachable from anywhere through the relay — no port forwarding. The hop is encrypted end to end (the client pins this node\'s certificate), so the hub only ever relays scrambled data.'
			: 'Reachable through the relay — no port forwarding. NOTE: serving over plain HTTP (a TLS certificate could not be made), so the hop is not encrypted. The vault contents are encrypted either way; serve again to retry the certificate.');
	} else {
		console.log('On the other machine: "' + Brand.cli + ' peer-add ' + h.url + ' --user ' + h.user + '", then "' + Brand.cli + ' mirror <vault> webdav:<id>".');
		if (bind === '127.0.0.1' || bind === 'localhost') console.log('Bound to this machine only — reach it from elsewhere through a tunnel or VPN you run (which also encrypts the connection), or add "--relay <hub-host> --token <token>" to reach it through a relay with no port forwarding.');
		else console.log('Bound to ' + bind + ' — anyone who can reach that address and has the password above can fetch the (encrypted) files. Prefer a tunnel/VPN or a private network.');
	}
	console.log('\nServing. Press Ctrl+C to stop.');
	await new Promise(() => {}); // run until interrupted; the shutdown handler stops the server
}

// Run the relay hub (on a machine with a public address, e.g. a small VPS) so nodes behind NAT are
// reachable without port forwarding. Nodes and clients both reach it outbound.
async function cmdRelay(pos, flags) {
	const Relay = require('./Relay');
	ProcRegistry.beResilient();
	// The hub runs on a public/shared host, where argv is world-readable via /proc/<pid>/cmdline, so offer
	// --token-file to keep the token off the command line (a file, not an env var). A token the user
	// SUPPLIED is never echoed below — it would otherwise leak into captured logs; a generated one is shown
	// once so it can be recorded.
	let { token, provided } = await resolveToken(flags); // --token or --token-file (kept off argv); a generated one is minted below
	if (!token) token = Relay.nodeId() + Relay.nodeId();
	const port = parsePort(flags.port, 7443);
	let range = [20000, 20099];
	if (flags.ports !== undefined && flags.ports !== true) {
		const m = /^(\d+)\s*-\s*(\d+)$/.exec(String(flags.ports));
		if (!m) throw new Error('--ports must be a range like 20000-20099 (a hyphen between two port numbers).');
		const lo = parseInt(m[1], 10), hi = parseInt(m[2], 10);
		if (lo < 1 || hi > 65535 || lo > hi) throw new Error('--ports must be a range within 1-65535 with the low port first, for example 20000-20099.');
		range = [lo, hi];
	}
	console.log('Relay hub — give this machine a public address (a VPS) and open these ports in its firewall:');
	console.log('  Control port:  ' + port);
	console.log('  Public ports:  ' + range[0] + '-' + range[1]);
	console.log('  Token:         ' + (provided ? '(as supplied — keep it secret)' : token + '   (generated — save it and reuse it with --token-file so nodes stay valid)'));
	const hub = Relay.runHub({ controlPort: port, token, portRange: range, onLog: (l) => console.log('  ' + l) });
	ProcRegistry.onShutdown(() => { try { hub.close(); } catch (_) {} });
	console.log('\nOn each node:  ' + Brand.cli + ' serve <vault> --relay <this-host>:' + port + ' --token ' + (provided ? '<your-token>' : token));
	console.log('Press Ctrl+C to stop.');
	await new Promise(() => {});
}

async function cmdPeers() {
	const peers = await vdisk.listPeers();
	if (!peers.length) { console.log('No peers yet. Add one with "' + Brand.cli + ' peer-add <address> --user <user>".'); return; }
	for (const p of peers) console.log(p.id + '  ' + (p.label || p.url) + '  (' + p.url + ', user ' + p.user + ')');
}

async function cmdPeerAdd(pos, flags) {
	const arg = pos[0];
	if (!arg) throw new Error('Usage: ' + Brand.cli + ' peer-add <connection-code | address> [--label <name>] [--user <user>]');
	// A connection code (printed by "serve --relay") carries the address, login, and pinned cert in one
	// string — one paste, no prompts. Otherwise treat the argument as a plain address and prompt.
	const code = vdisk.parsePeerCode(arg);
	const { id } = code
		? await vdisk.savePeer({ label: flags.label, url: code.url, user: code.user, password: code.password, ca: code.ca })
		: await vdisk.savePeer({ label: flags.label, url: arg, user: flags.user || 'vd', password: await prompt.hidden('Peer password: ') });
	console.log('Added peer ' + id + (code ? ' (from a connection code).' : '.') + ' Test it with "' + Brand.cli + ' peer-test ' + id + '", then mirror a vault to it with "' + Brand.cli + ' mirror <vault> webdav:' + id + '".');
}

async function cmdPeerRemove(pos) {
	const id = pos[0];
	if (!id) throw new Error('Usage: ' + Brand.cli + ' peer-remove <id>');
	await vdisk.removePeer(id);
	console.log('Removed peer ' + id + '.');
}

async function cmdPeerTest(pos) {
	const id = pos[0];
	if (!id) throw new Error('Usage: ' + Brand.cli + ' peer-test <id>');
	const r = await vdisk.testPeer(id);
	console.log(r.ok ? 'Peer is reachable and the login works.' : 'Could not connect: ' + (r.error || 'unknown error') + ' (is the other machine serving, and reachable?)');
	if (!r.ok) process.exitCode = 1;
}

async function cmdRestore(pos, flags) {
	const [src, dest] = pos;
	if (!src || !dest) throw new Error('Usage: ' + Brand.cli + ' restore <backup.vault> <destination-folder>');
	console.log('Restoring…');
	const r = await vdisk.restore(src, dest, { overwrite: !!flags.force });
	console.log('Restored to ' + r.vault + '. Mount it with:  ' + Brand.cli + ' mount "' + r.vault + '"');
}

async function cmdDoctor() {
	const d = await vdisk.doctor();
	console.log('Platform:      ' + d.platform + '/' + d.arch);
	console.log('Engine:        ' + (d.engine.ok ? 'ready' : 'NOT available — run "' + Brand.cli + ' setup" while online'));
	console.log('Mount driver:  ' + (d.driver.ok ? d.driver.name + ' — ' + d.driver.detail : 'MISSING — ' + d.driver.detail));
	if (d.driver.warn) console.log('\nHeads up: ' + d.driver.warn);
	if (d.driver.install && (!d.driver.ok || d.driver.warn)) console.log('\n' + d.driver.install);
	const ready = d.engine.ok && d.driver.ok;
	console.log('\n' + (ready ? 'Ready to create and mount vaults.' : 'Not ready yet — address the items above.'));
	// Run the integrity self-check too, so "doctor" is one place to confirm the whole install is sound.
	// Reuses the precomputed doctor snapshot so the engine/driver are not probed twice.
	const findings = await vdisk.selfCheck({ doctor: d, label: 'doctor', quiet: true });
	console.log('\nIntegrity self-check: ' + (findings.length ? findings.length + ' finding(s):' : 'all checks passed.'));
	for (const f of findings) console.log('  [' + f.level + '] ' + f.message + (f.fix ? '\n         ' + f.fix : ''));
	if (!ready) process.exitCode = 1;
}

// Manually check whether a newer release has been published. Read-only: it compares version numbers and prints the
// result — it never downloads or installs anything (that stays your deliberate choice, and a download is still
// verified by the signed verifier). `--url` overrides the source, so the check is not locked to one host.
async function cmdUpdateCheck(pos, flags) {
	const UpdateCheck = require('./UpdateCheck');
	const r = await UpdateCheck.checkForUpdate({ url: (typeof flags.url === 'string' && flags.url) ? flags.url : undefined });
	console.log('Installed version: ' + r.current);
	if (!r.ok) {
		console.log('Could not check for updates: ' + (r.error || 'unknown error') + '\nThis check is best-effort and never required — ' + Brand.name + ' works normally without it.');
		process.exitCode = 1;
		return;
	}
	console.log('Latest published:  ' + r.latest);
	if (r.updateAvailable) {
		console.log('\nAn update is available. Get it from:\n  ' + r.releasesUrl + '\nDownloading is manual on purpose, and the download is verified by "' + Brand.cli + ' verify" before you trust it.');
	} else if (r.ahead) {
		console.log('\nThis build is newer than the latest published release (expected for a pre-release) — nothing to do.');
	} else {
		console.log('\nYou are on the latest version.');
	}
}

// Start the web UI. Returns true when a server was actually started (the process must stay alive for it), false when
// one was already running (nothing started — the process should exit). Reused by the launcher via dispatch's keepAlive.
async function cmdUi(pos, flags) {
	const port = parsePort(flags.port, Common.DEFAULT_UI_PORT);
	requireStringFlag(flags, 'bind', '--bind 0.0.0.0');
	const bind = flags.bind ? String(flags.bind) : undefined; // omit -> loopback only (no login needed)
	// If a Vaultonaut is ALREADY serving this port, don't fail with a port-in-use error (or start a duplicate) —
	// say where it is and how to reach or stop it. Only for the default loopback interface; an explicit --bind is a
	// deliberate (re)configuration the user is driving. Both probes are bounded and spawn-free (non-blocking).
	if (!bind && ((await OwnerClient.find()) || await serviceResponding(port))) {
		console.log(Brand.name + ' is already running at http://localhost:' + port + '.');
		console.log('Open it with "' + Brand.cli + ' open", or stop it with "' + Brand.cli + ' stop".');
		return false; // nothing started — let the process exit rather than fight for the port
	}
	// Crash-restart. On macOS and Linux the OS supervisor (launchd KeepAlive / systemd Restart=on-failure)
	// relaunches the service after a crash, so --supervised is a no-op there. Windows has no such mechanism,
	// so under --supervised this process becomes a tiny supervisor that forks the real server and respawns it
	// on an unclean exit (a clean stop or Ctrl+C does NOT respawn). The --child marker runs the actual server.
	if (flags.supervised && !flags.child && process.platform === 'win32') return runWindowsSupervisor(port, bind, { allowIp: flags['allow-ip'], denyIp: flags['deny-ip'] });
	const { start } = require('./webserver');
	// Optional access list for an exposed interface (--bind). Restricts which client addresses may reach it, on top
	// of the mandatory password and TLS. Comma-separated exact addresses, CIDR ranges, or IPv4 wildcards; loopback
	// is always allowed. Ignored on the default loopback interface.
	await start(port, { bind, allowIp: flags['allow-ip'], denyIp: flags['deny-ip'] });
	// The server logs its own address (scheme, host, and whether a login is required); no need to repeat it.
	console.log('Press Ctrl+C to stop.');
	return true; // server running — keep the process alive
}

// Stop the running background service cleanly. Refuses if any vault is open (unless --force, which stops and lets the
// crash-safety guardian drain and lock them). Non-blocking throughout: a bounded async probe finds the service, a
// signal asks it to shut down gracefully (it drains writes and locks its own vaults on the way out — see the
// webserver's shutdown handler), and a bounded poll waits for the port to free. Cross-platform: POSIX SIGTERM runs
// that graceful handler; Windows has no graceful signal, so the terminate is safe because the idle case has nothing
// to drain, and with --force the separate guardian drains and locks any open vault when the service exits.
async function cmdStop(pos, flags) {
	const port = parsePort(flags.port, Common.DEFAULT_UI_PORT);
	const pid = await OwnerClient.servicePid();
	if (!pid && !(await serviceResponding(port))) { console.log(Brand.name + ' is not running.'); return; }
	const mounts = await vdisk.listMounts().catch(() => []);
	if (mounts.length && !flags.force) {
		const n = mounts.length, it = n === 1 ? 'it' : 'them';
		console.log(n + ' vault' + (n === 1 ? ' is' : 's are') + ' open. Unmount ' + it + ' first, or run "' + Brand.cli + ' stop --force" to stop and lock ' + it + '.');
		process.exitCode = 1;
		return;
	}
	if (!pid) { console.log(Brand.name + ' appears to be running but its process record is missing — stop it from the terminal it was started in.'); process.exitCode = 1; return; }
	// Prefer the cooperative HTTP stop channel over a signal: it runs the SAME graceful drain-and-lock on EVERY
	// platform, which closes the Windows gap where a SIGTERM is an uncatchable terminate that skips the flush. Fall
	// back to SIGTERM only if the loopback control API is unreachable (an older service, or a network-bound instance
	// whose advertised URL is not loopback). On POSIX the fallback is fully graceful; on Windows it terminates and the
	// guardian then locks any open vault when the process exits.
	let signaled = false;
	try {
		const own = await OwnerClient.find();
		if (own) { const resp = await OwnerClient.post(own.url, '/api/service-stop', { force: !!flags.force }, 30000); if (OwnerClient.isUsable(resp) && resp.ok) signaled = true; }
	} catch (_) {}
	if (!signaled) {
		try { process.kill(pid, 'SIGTERM'); } // POSIX: runs the graceful drain-and-lock shutdown. Windows: terminates (safe — the guardian locks open vaults on exit).
		catch (e) { if (e && e.code === 'ESRCH') { console.log(Brand.name + ' has already stopped.'); return; } throw e; }
	}
	console.log('Stopping ' + Brand.name + '…' + (mounts.length ? ' (locking open vaults first)' : ''));
	const stopped = await Common.pollUntil(async () => !Common.isProcessAlive(pid) && !(await serviceResponding(port)), { timeoutMs: 60000, stepMs: 300 }).then(() => true).catch(() => false);
	console.log(stopped ? Brand.name + ' stopped.' : Brand.name + ' is still finishing (draining writes) and will stop shortly in the background.');
}

// Windows-only crash supervisor: fork the server child and respawn it on an unclean exit, with exponential
// backoff and a crash-loop ceiling. Never respawns on a clean exit or a stop signal. Kept tiny so its own
// crash surface is minimal. macOS/Linux never reach this (the OS supervisor is strictly better).
function runWindowsSupervisor(port, bind, { allowIp, denyIp } = {}) {
	const node = require('./Launcher').ensure();
	const script = path.resolve(__dirname, '..', 'vaultonaut.js');
	const args = serviceLaunchArgs(script, { port, child: true, bind, allowIp, denyIp });
	let backoff = 1000, fastCrashes = 0, stopping = false;
	const stop = () => { stopping = true; };
	process.on('SIGINT', stop); process.on('SIGTERM', stop);
	const spawnChild = () => {
		if (stopping) return process.exit(0);
		const startedAt = Date.now();
		const child = spawn(node, args, { stdio: 'inherit' });
		child.on('error', () => { if (!stopping) setTimeout(spawnChild, backoff); });
		child.on('exit', (code, signal) => {
			if (stopping || code === 0 || signal === 'SIGINT' || signal === 'SIGTERM') return process.exit(0); // clean stop -> do not respawn
			const ranMs = Date.now() - startedAt;
			if (ranMs < 60000) { fastCrashes++; backoff = Math.min(backoff * 2, 30000); } else { fastCrashes = 0; backoff = 1000; } // reset after a stable run
			if (fastCrashes > 8) { console.error('The service crashed repeatedly and is not restarting. Check the logs and run "' + Brand.cli + ' doctor".'); return process.exit(1); }
			setTimeout(spawnChild, backoff);
		});
	};
	spawnChild();
	return new Promise(() => {}); // keep the supervisor alive
}

// Open the app in the default browser — the one-click way to reach it without remembering a URL.
// If the background service is already running, we open the address it advertises; otherwise we start
// it (detached, so it keeps running after this command returns) and open it once it is ready. This is
// the lightweight quick-access path: it drives the existing local service and never handles passwords.
function openInBrowser(url) { return Common.openExternal(url); } // single cross-platform opener lives in Common (shared with the desktop app's Recovery Kit)
// Build the argv for (re)launching the UI service. Shared by the detached-service starter and the Windows crash
// supervisor so both always forward the SAME base — above all the resolved --data-dir, so a --data-dir override is
// never dropped when the service is auto-started (the guardian forwards it the same way). Exported (underscored) so a
// test can assert the propagation without spawning anything.
function serviceLaunchArgs(script, { port, child = false, bind = null, allowIp = null, denyIp = null } = {}) {
	const args = [script, 'ui', '--port', String(port)];
	if (child) args.push('--child'); // Windows: run as the tiny crash-restart supervisor's server child
	args.push('--data-dir', Common.dataDir()); // always forward the resolved data dir (default when no override)
	if (bind) args.push('--bind', bind);
	if (allowIp) args.push('--allow-ip', String(allowIp)); // forward the access list to the real server child
	if (denyIp) args.push('--deny-ip', String(denyIp));
	return args;
}
function startDetachedService(port) {
	const node = require('./Launcher').ensure(); // the branded binary, so the service shows under the product name
	const script = path.resolve(__dirname, '..', 'vaultonaut.js');
	const child = spawn(node, serviceLaunchArgs(script, { port }), { detached: true, stdio: 'ignore', windowsHide: true });
	child.on('error', () => {});
	child.unref();
}
// Is a loopback service already answering on this port? A quick, bounded HTTP probe (cross-platform, no spawn).
// Used so `open` never starts a SECOND instance when one is already running but its pidfile is momentarily missing,
// url-less, or stale — the case that otherwise made every launch fight for the port and wait out the startup poll.
function serviceResponding(port, timeoutMs = 1500) {
	return new Promise((resolve) => {
		const http = require('http');
		const req = http.get({ hostname: '127.0.0.1', port, path: '/', family: 4, timeout: timeoutMs }, (res) => { res.resume(); resolve(true); });
		req.on('timeout', () => { req.destroy(); resolve(false); });
		req.on('error', () => resolve(false));
	});
}

async function cmdOpen(pos, flags) {
	const port = parsePort(flags.port, Common.DEFAULT_UI_PORT);
	let owner = await OwnerClient.find();
	// Even without a usable owner record, a service may already be serving this port (e.g. one started at login whose
	// pidfile is stale or url-less). Probe it before starting another, so we never spawn a doomed duplicate that
	// fights for the port and forces a needless startup wait — the cause of the multi-second launch delay.
	if (!owner && await serviceResponding(port)) owner = { url: 'http://127.0.0.1:' + port };
	if (!owner) {
		console.log('Starting ' + Brand.name + '…');
		startDetachedService(port);
		// Wait until the freshly started service is reachable — either it advertises its loopback address (a usable
		// owner record) OR it simply answers on the port. Bounded, so this never hangs, and it returns as soon as the
		// service is actually up rather than always running out the clock.
		await Common.pollUntil(async () => !!(owner = await OwnerClient.find()) || await serviceResponding(port), { timeoutMs: 15000, stepMs: 300 }).catch(() => {});
	}
	const url = (owner && owner.url) || ('http://localhost:' + port);
	if (!openInBrowser(url)) { console.log('Open ' + Brand.name + ' in your browser at: ' + url); return; }
	console.log(Brand.name + ' is open in your browser at ' + url + '.');
}

// A platform-tailored tip for keeping the launcher one click away, shown right after it is created. This is the
// reliable, dependency-free stand-in for a system-tray icon: the OS's own dock/taskbar pins the branded launcher.
function pinHint(platform) {
	if (platform === 'macos') return 'Tip: keep it one click away in your Dock — drag it there from Applications, or right-click its Dock icon while open and choose Options → Keep in Dock.';
	if (platform === 'windows') return 'Tip: keep it one click away — right-click it and choose "Pin to taskbar" (or "Pin to Start").';
	return 'Tip: keep it one click away by adding it to your dock or favorites (right-click it in the app menu).';
}

// Create or remove a clickable desktop/menu launcher that opens the app (runs "open"). The one-click,
// no-terminal way in for everyday use. Best-effort and cross-platform.
async function cmdShortcut(pos) {
	const Shortcut = require('./Shortcut');
	// Default to create ONLY when no subcommand is given; a present-but-unrecognized one (a typo like
	// "instal") must not silently fall through to create — reject it with a usage line, like the other
	// subcommand dispatchers.
	const sub = pos[0] === undefined ? 'create' : String(pos[0]).toLowerCase();
	if (sub === 'remove' || sub === 'uninstall' || sub === 'delete') {
		await Shortcut.remove();
		console.log('Desktop launcher removed.');
		return;
	}
	if (sub === 'status') {
		const s = await Shortcut.status();
		if (!s.supported) console.log('A desktop launcher is not supported on this platform.');
		else console.log('Desktop launcher is ' + (s.installed ? 'installed' : 'not installed') + (s.path ? ' (' + s.path + ')' : ''));
		return;
	}
	if (sub !== 'create') throw new Error('Usage: ' + Brand.cli + ' shortcut [create | remove | status]   (no subcommand creates one)');
	const r = await Shortcut.create();
	console.log('Desktop launcher created: ' + r.path);
	console.log('Open it any time to launch ' + Brand.name + ' in your browser — no terminal needed.');
	console.log(pinHint(r.platform));
}

// Set, change, or clear the web-interface password. Off by default (the loopback UI needs no login),
// but required before the UI may bind to a network address with `ui --bind <address>`.
async function cmdWebPassword(pos) {
	const sub = (pos[0] || 'set').toLowerCase();
	if (sub === 'clear' || sub === 'off' || sub === 'remove') {
		await vdisk.clearUiPassword();
		console.log('Web-interface password cleared. The interface now opens without a login (loopback only).');
		return;
	}
	if (sub !== 'set') throw new Error('Usage: ' + Brand.cli + ' web-password [set|clear]');
	const pw = await prompt.newPassword('Web-interface password (min 8 chars)');
	await vdisk.setUiPassword(pw);
	console.log('Web-interface password set. A login is now required whenever the interface runs, and it may be exposed with "' + Brand.cli + ' ui --bind <address>".');
}

async function cmdAutostart(pos, flags) {
	const Autostart = require('./Autostart');
	const Shortcut = require('./Shortcut');
	const sub = (pos[0] || 'status').toLowerCase();
	if (sub === 'install') {
		// --bind makes the auto-started interface reachable from other devices (a phone on the same network). Like a
		// live `ui --bind`, an exposed interface always requires a login, so refuse until a web password is set —
		// with the same guidance the live server gives, rather than installing a service that would fail to start.
		requireStringFlag(flags, 'bind', '--bind 0.0.0.0');
		const bind = flags.bind ? String(flags.bind).trim() : null;
		if (bind && !Common.isLoopbackHost(bind) && !(await vdisk.getUiAuth()).enabled) {
			throw new Error('Set a web-interface password first with "' + Brand.cli + ' web-password set" before starting on a network address — a network-reachable interface always requires a login.');
		}
		const r = await Autostart.install(parsePort(flags.port, Common.DEFAULT_UI_PORT), { bind });
		console.log('Autostart installed (' + r.platform + '). The UI will start at login on port ' + r.port + (r.bind ? ', reachable on your network at ' + r.bind + ' over a secure https address (login required).' : ' (this computer only).'));
		console.log('Service: ' + r.servicePath);
		// Also add the clickable launcher, so a single "install" gives a one-click icon as most people expect.
		// Best-effort: a launcher problem must never fail the autostart install (the login service is the point).
		// Opt out with --no-shortcut for a headless/service-only setup, and skip it automatically when running as
		// the packaged desktop app (which is already that clickable app — a second one would collide with it).
		if (!flags['no-shortcut'] && !Common.isDesktopApp()) {
			try { const s = await Shortcut.create(); console.log('Launcher added: ' + s.path + ' — open it any time to launch ' + Brand.name + ' in your browser.'); console.log(pinHint(s.platform)); }
			catch (_) { console.log('(Could not add the clickable launcher on this platform; run "' + Brand.cli + ' shortcut create" to try again.)'); }
		}
	} else if (sub === 'uninstall' || sub === 'remove') {
		// Undo both halves so "uninstall" is the inverse of "install" and never leaves a stray launcher behind.
		await Autostart.uninstall();
		try { await Shortcut.remove(); } catch (_) {}
		console.log('Autostart and the launcher removed.');
	} else {
		const s = await Autostart.status();
		if (!s.supported) console.log('Autostart is not supported on this platform.');
		else {
			let line = 'Autostart is ' + (s.installed ? 'installed' : 'not installed');
			if (s.installed) line += s.bind ? ', reachable on your network at ' + s.bind + ' over a secure https address (login required)' : ' (this computer only)';
			if (s.servicePath) line += '\nService: ' + s.servicePath;
			console.log(line);
		}
	}
}

// Cleanly undo what install created: the login/autostart entry and the app shortcut. Never touches vaults. This
// exists so a user does not just delete the program folder and leave an orphaned autostart entry behind — on macOS
// that entry would otherwise keep trying to relaunch the now-missing program every few seconds.
async function cmdUninstall() {
	const Autostart = require('./Autostart');
	const Shortcut = require('./Shortcut');
	console.log('Removing ' + Brand.name + '\'s startup and shortcut entries. Your vaults are NOT touched.');
	try { await Autostart.uninstall(); console.log('  • Removed the login/autostart entry (and stopped the background service where the system supports it).'); } catch (_) { console.log('  • Autostart: nothing to remove.'); }
	try { await Shortcut.remove(); console.log('  • Removed the app shortcut.'); } catch (_) { console.log('  • Shortcut: nothing to remove.'); }
	console.log('\nIf the web interface is still running, stop it (Ctrl+C in its window).');
	const C = require('./Common');
	let ddir = '', vdir = ''; try { ddir = C.dataDir(); vdir = C.vaultsDir(); } catch (_) {}
	console.log('\nYour data lives OUTSIDE the program folder, so deleting the program does not touch it:');
	if (ddir) console.log('  data and settings:  ' + ddir);
	if (vdir) console.log('  plain-name vaults:  ' + vdir);
	console.log('To remove everything, delete that data folder too (back up any vaults you want to keep first).\nVaults you created at their own path (an external drive, another folder) are separate and unaffected.');
}

async function cmdInstallDriver() {
	const DriverInstall = require('./DriverInstall');
	console.log('Setting up the mount driver for this system…');
	const r = await DriverInstall.install();
	if (r.launched) console.log('The ' + r.driver + ' installer is now open. Complete it, then run "' + Brand.cli + ' doctor" to confirm.');
	else if (r.instructions) { console.log('Install the mount driver with your package manager:\n\n' + r.instructions); }
}

async function cmdSetup(pos, flags) {
	console.log('Setting up the bundled engine…');
	const r = await vdisk.setup({ latest: !!flags.latest });
	console.log(r.ok ? 'Engine ready.' : 'Setup failed — check your connection and try again.');
	if (!r.ok) process.exitCode = 1;
}

// Run one command. Returns { keepAlive } — true for the long-running commands (the web UI, a served
// node, the guardian) so the launcher does not exit the process after they start.
async function dispatch(cmd, positionals, flags) {
	let keepAlive = false;
	switch (cmd) {
		case '_guard': keepAlive = true; await require('./Guardian').watch(parseInt(positionals[0], 10), positionals[1] || 'ui'); break;
		case 'create': await cmdCreate(positionals, flags); break;
		case 'cloud': await cmdCloud(positionals, flags); break;
		case 'import': await cmdImport(positionals, flags); break;
		case 'passwd': case 'password': await cmdPasswd(positionals); break;
		case 'keys': await cmdKeys(positionals); break;
		case 'addkey': await cmdAddKey(positionals, flags); break;
		case 'read-only': case 'readonly': await cmdReadOnly(positionals); break;
		case 'read-cap': case 'readcap': await cmdReadCap(positionals, flags); break;
		case 'share-keypair': case 'sharekeypair': await cmdShareKeypair(); break;
		case 'share-seal': case 'shareseal': await cmdShareSeal(positionals, flags); break;
		case 'share-open': case 'shareopen': await cmdShareOpen(positionals, flags); break;
		case 'team-enable': case 'teamenable': await cmdTeamEnable(positionals); break;
		case 'member-add': case 'memberadd': await cmdMemberAdd(positionals, flags); break;
		case 'members': await cmdMembers(positionals); break;
		case 'member-remove': case 'memberremove': await cmdMemberRemove(positionals, flags); break;
		case 'member-promote': case 'memberpromote': await cmdMemberPromote(positionals, flags, false); break;
		case 'member-demote': case 'memberdemote': await cmdMemberPromote(positionals, flags, true); break;
		case 'member-add-device': case 'memberadddevice': await cmdMemberAddDevice(positionals, flags); break;
		case 'member-remove-device': case 'memberremovedevice': await cmdMemberRemoveDevice(positionals, flags); break;
		case 'owner-recovery': case 'ownerrecovery': await cmdOwnerRecovery(positionals, flags); break;
		case 'recovery-share': case 'recoveryshare': await cmdRecoveryShare(positionals, flags); break;
		case 'owner-recover': case 'ownerrecover': await cmdOwnerRecover(positionals, flags); break;
		case 'shares': await cmdShares(positionals); break;
		case 'revoke-share': case 'revokeshare': await cmdRevokeShare(positionals); break;
		case 'prune-shares': case 'pruneshares': await cmdPruneShares(positionals); break;
		case 'rotate': case 're-encrypt': case 'reencrypt': await cmdRotate(positionals, flags); break;
		case 'decoy': await cmdDecoy(positionals); break;
		case 'travel': await cmdTravel(positionals); break;
		case 'wedge-restart': await cmdWedgeRestart(positionals); break;
		case 'emergency': await cmdEmergency(positionals, flags); break;
		case 'emergency-open': await cmdEmergencyOpen(positionals, flags); break;
		case 'addkeyfile': await cmdAddKeyfile(positionals, flags); break;
		case 'recovery': await cmdRecovery(positionals); break;
		case 'rmkey': case 'removekey': await cmdRmKey(positionals); break;
		case 'mount': await cmdMount(positionals, flags); break;
		case 'unmount': case 'umount': await cmdUnmount(positionals, flags); break;
		case 'repair': await cmdRepair(); break;
		case 'lock': await cmdLock(); break;
		case 'autolock': await cmdAutolock(positionals); break;
		case 'lock-on-sleep': await cmdLockOnSleep(positionals); break;
		case 'auto-timestamp': await cmdAutoTimestamp(positionals); break;
		case 'bandwidth': await cmdBandwidth(positionals); break;
		case 'status': await cmdStatus(); break;
		case 'list': case 'ls': await cmdList(positionals); break;
		case 'search': case 'find': await cmdSearch(positionals, flags); break;
		case 'reindex': await cmdReindex(positionals); break;
		case 'verify': case 'check': await cmdVerify(positionals, flags); break;
		case 'protect': await cmdProtect(positionals, flags); break;
		case 'heal': await cmdHeal(positionals, flags); break;
		case 'unprotect': await cmdUnprotect(positionals, flags); break;
		case 'secure-remove': await cmdSecureRemove(positionals, flags); break;
		case 'snapshot': await cmdSnapshot(positionals, flags); break;
		case 'seal': await cmdSeal(positionals); break;
		case 'unseal': await cmdUnseal(positionals); break;
		case 'audit': await cmdAudit(positionals); break;
		case 'tamper-log': case 'tamperlog': await cmdTamperLog(positionals); break;
		case 'fingerprint': await cmdFingerprint(positionals); break;
		case 'recovery-kit': case 'recoverykit': case 'kit': await cmdRecoveryKit(positionals, flags); break;
		case 'attest': case 'timestamp': await cmdAttest(positionals, flags); break;
		case 'make-bundle': await cmdMakeBundle(positionals, flags); break;
		case 'verify-bundle': await cmdVerifyBundle(positionals, flags); break;
		case 'pack': await cmdPack(positionals, flags); break;
		case 'unpack': await cmdUnpack(positionals); break;
		case 'backup': await cmdBackup(positionals); break;
		case 'versions': case 'history': await cmdVersions(positionals); break;
		case 'restore-version': case 'restoreversion': await cmdRestoreVersion(positionals, flags); break;
		case 'mirror': await cmdMirror(positionals); break;
		case 'sync': await cmdSync(positionals); break;
		case 'unmirror': await cmdUnmirror(positionals); break;
		case 'serve': keepAlive = true; await cmdServe(positionals, flags); break;
		case 'relay': keepAlive = true; await cmdRelay(positionals, flags); break;
		case 'peers': await cmdPeers(); break;
		case 'peer-add': await cmdPeerAdd(positionals, flags); break;
		case 'peer-remove': await cmdPeerRemove(positionals); break;
		case 'peer-test': await cmdPeerTest(positionals); break;
		case 'restore': await cmdRestore(positionals, flags); break;
		case 'doctor': await cmdDoctor(); break;
		case 'disperse': await cmdDisperse(positionals, flags); break;
		case 'reconstruct': await cmdReconstruct(positionals, flags); break;
		case 'shards': await cmdShards(positionals); break;
		case 'repair-shards': await cmdRepairShards(positionals); break;
		case 'verify-backup': await cmdVerifyBackup(positionals, flags); break;
		case 'scrub': await cmdScrub(positionals, flags); break;
		case 'backup-schedule': await cmdBackupSchedule(positionals, flags); break;
		case 'scrub-schedule': await cmdScrubSchedule(positionals, flags); break;
		case 'repair-schedule': await cmdRepairSchedule(positionals, flags); break;
		case 'threshold-key': await cmdThresholdKey(positionals, flags); break;
		case 'emergency-access': await cmdThresholdKey(positionals, flags, { emergency: true }); break;
		case 'ui': case 'web': keepAlive = await cmdUi(positionals, flags); break; // true only if a server actually started
		case 'open': await cmdOpen(positionals, flags); break;
		case 'stop': await cmdStop(positionals, flags); break;
		case 'shortcut': case 'launcher': await cmdShortcut(positionals); break;
		case 'web-password': case 'webpassword': await cmdWebPassword(positionals); break;
		case 'autostart': await cmdAutostart(positionals, flags); break;
		case 'uninstall': await cmdUninstall(); break;
		case 'install-driver': await cmdInstallDriver(); break;
		case 'setup': await cmdSetup(positionals, flags); break;
		case 'update-check': case 'check-update': await cmdUpdateCheck(positionals, flags); break;
		case 'help': case '--help': case '-h': case undefined: help(); break;
		default: console.error('Unknown command: ' + cmd + '\n'); help(); process.exitCode = 1;
	}
	return { keepAlive };
}

module.exports = { parse, dispatch, help, _serviceLaunchArgs: serviceLaunchArgs };
