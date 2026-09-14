# Security

Vaultonaut keeps your files in encrypted vaults. Because security is the whole point, this document explains how to
report a problem, what the tool is designed to protect, and — just as important — what it does not protect. Please
read the limitations: knowing them is part of using any encryption tool safely.

## Reporting a vulnerability

Please report security issues privately, not in a public issue tracker, so a fix can be prepared before the details
are public. Use either channel:

- Preferred: GitHub's private vulnerability reporting. On the repository page, open the **Security** tab and choose
  **Report a vulnerability**. This opens a private advisory that only the maintainers can see.
- By email: `code@3cqs.com`, for anyone who would rather not use GitHub.

Please include:

- what you found and how to reproduce it,
- the version or commit you tested, and
- the impact you believe it has.

You can expect an acknowledgment, an honest assessment of severity, and coordination on a fix and a disclosure
timeline. Reporters who want credit are named. Please do not test against data or systems that are not yours.

## Supported versions

Security fixes go into the latest release and the latest commit on the default branch. Older releases do not receive
back-ported fixes, so always update to the newest release.

## What Vaultonaut protects

- **Confidentiality of your files at rest.** File contents and both file and directory names are always encrypted.
  There is no setting that weakens or turns off name encryption.
- **Your password.** The password is never written anywhere. It is stretched with Argon2id and used only to unwrap a
  random master key held in memory; only non-secret key parameters and a random salt are stored.
- **No plaintext on the persistent disk.** An open vault is served from memory, so decrypted file data is not written
  to the physical disk in the clear, even while you work in the vault.
- **Detection of tampering.** A vault is signed and can prove it has not been altered. It keeps a tamper log and
  snapshots, can attach trusted timestamps, and can export a proof bundle that a third party verifies offline. Rollback
  to an older signed state is detected by local monotonic anchors.
- **Recovery without a single point of failure.** Recovery keys, split "any k of n" trustee recovery, self-healing
  parity data, off-site backups, mirrors, and dispersal across locations all guard against losing access or data.
- **Controlled access.** Read-only credentials and read links, team vaults with per-member sealed key slots and roles,
  one-command key rotation that truly re-encrypts to revoke access, and optional Touch ID, Windows Hello, security
  keys, or keyfiles.
- **Private access over a network.** The interface is loopback-only by default. Exposing it to other devices requires
  a login password and TLS. The phone viewer is zero-knowledge: files are decrypted on the phone, and only ciphertext
  ever leaves the computer.
- **A verified engine.** The bundled encryption engine is pinned to a tested version, checked against a checksum
  shipped inside Vaultonaut before it runs, and never taken from the system path.

## What Vaultonaut does not protect against

No file encryptor can defend against everything. Vaultonaut deliberately does not claim to protect against:

- **A compromised computer while a vault is unlocked.** When a vault is open, its files are decrypted in memory and on
  the mounted drive. Malware, a keylogger, or another user with access to your account can read them then, and can
  capture your password as you type it. Vaultonaut protects data at rest, not a machine that is already owned.
- **A weak password.** Argon2id makes guessing far more expensive, but it cannot rescue a password that is easy to
  guess. Use a strong, unique passphrase.
- **Anyone who has your password or keys.** Possession of a valid credential is, by design, the ability to open the
  vault. Guard your password, recovery keys, and keyfiles accordingly.
- **Traces other software leaves.** The operating system and other applications can copy decrypted content into
  preview caches, thumbnails, recent-file lists, or swap while a vault is open. Vaultonaut clears what it can and
  documents the rest; full-disk encryption on the host is strongly recommended as the backstop.
- **Metadata.** Encryption hides file and folder names and contents. It does not hide that a vault exists, roughly how
  much data it holds, how many files it contains, or the shape of its folder tree. A network or cloud observer can
  also see the size and timing of transfers.
- **Denial of access by whoever holds your data.** A cloud provider or anyone holding a copy cannot read your files,
  but they can withhold or delete them. Mirrors, off-site backups, and dispersal are the defense against that.

## Cryptography

Vaultonaut does not invent cryptography. The vault format is an open, publicly documented format built on standard,
audited building blocks: file contents are sealed in 64 KiB chunks with XSalsa20-Poly1305, file and directory names
are encrypted with AES-256 in the EME wide-block mode, and keys are derived with scrypt, with Argon2id layered in front for the password itself. The app also ships a small,
dependency-free reference decryptor (the same code the phone viewer uses), and the test suite checks it against real
vault files byte for byte, so the format can be read by more than one independent implementation.

Authenticity uses two signature schemes together: Ed25519 (classical) and ML-DSA-65 (FIPS 204, post-quantum). Every
integrity record — a vault's tamper baseline, its manifest seal, its self-healing data, the team roster, the
key-rotation history, and each signed release — carries both signatures and is trusted only if both verify, so its
authenticity holds even against a future quantum computer. Where confidentiality is sealed to a public key (a read
share, emergency access), the key exchange is a hybrid of X25519 and ML-KEM-768 (FIPS 203), post-quantum by the same
principle. The symmetric encryption above is already quantum-resistant, so a password-locked vault needs no change.

## Verifying a release

A release carries a signed manifest and checksums so you can confirm the files are authentic and unaltered before you
run them. Individual vaults can also produce an offline-verifiable proof bundle that confirms a vault's identity and
that its contents have not changed. See the README for the exact commands.
