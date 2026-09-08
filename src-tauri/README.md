# Desktop packaging

This directory wraps the application as a native desktop app with a normal installer, using a small native
shell around the existing web interface. It is development-only tooling: the published package never includes
it (the package's file allowlist excludes it, and a test enforces that).

## How it works

The native shell does three things and nothing more:

1. It bundles the Node runtime as a "sidecar" binary, so the user needs no separate Node installation.
2. On launch it runs the application (`vaultonaut.js ui`) through that bundled runtime, on the loopback
   interface, and waits for the local server to come up.
3. It shows that interface in a native window, and stops the backend when the window closes.

All of the product's real logic stays in the Node application. The shell holds no vault logic.

## Prerequisites

- The Rust toolchain (`rustc`, `cargo`).
- The packaging tools, installed once here: `npm install` (in this directory).
- The platform's normal build essentials:
  - **macOS:** the Command Line Tools (`xcode-select --install`).
  - **Windows:** the Microsoft C++ Build Tools; the WebView2 runtime ships with current Windows.
  - **Linux (Debian/Ubuntu):** the WebKitGTK and related development libraries:
    ```
    sudo apt install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
      libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
    ```
    Other distributions ship the same libraries under their own package names (for example
    `webkit2gtk4.1-devel` on Fedora).

## Building

From this directory:

```
npm run build
```

That stages the app and the Node runtime, signs the bundle when a signing key is present (see below), and
produces the installer under `target/release/bundle/`. Use `npm run dev` for a fast debug run while iterating.

Build every platform on the same pinned Node version (`PINNED_NODE` in `prepare-sidecar.js`).
The bundle ships whatever Node runs the build, so each platform's installer must use the identical version to
avoid drift. It must also be 24.7 or newer so every feature is enabled — the post-quantum seals need it. The
staging step refuses to build on any other version. Bump `PINNED_NODE` deliberately with a release.

The staged application is not a hand-maintained list: it is taken from the package's own file allowlist, so
the desktop bundle always ships exactly what the package ships (plus the production dependencies). A test
guards against drift.

## Getting installers for every platform

A native build runs on its own operating system — you cannot cross-build the Windows and Linux installers from
macOS. Two practical ways to get all of them:

- **A continuous-integration matrix** (macOS + Windows + Linux runners). This is the least effort and the most
  private: each installer is built on a clean virtual machine, so nothing about your own computer ends up in
  the artifact.
- **Local virtual machines** (for example with Parallels): a Windows VM builds the Windows installer and a
  Linux VM builds the Linux packages, while macOS builds natively. This keeps everything on one computer. On
  Apple Silicon the VMs are ARM, so they produce ARM builds; producing Intel (x86-64) builds for older machines
  needs an x86-64 environment (an Intel CI runner, or an x86-64 VM).

On any one machine, `npm run clean-build` does the whole identity-free build in one command: it copies the
project to a neutral path, uses a neutral dependency cache, builds there, and runs the leak scan. For building
across several machines routinely, a self-hosted continuous-integration runner on each one is the standard
approach. The runner is generic, so it can build any project, and each project supplies its own build steps. Its
workspace path is already neutral, and the built installers are collected automatically.

Building locally on a fresh VM has a few one-time prerequisites beyond the toolchain above: on Windows, the
Microsoft C++ Build Tools (WebView2 ships with current Windows); on Linux, the development libraries listed
under Prerequisites. Note also that a macOS build is for the architecture of the Mac that produced it — an
Apple Silicon Mac makes an arm64 app, so an Intel build needs an Intel Mac (or a universal build).

## Continuous integration (all platforms at once)

`.github/workflows/release.yml` builds macOS, Windows, and Linux together and collects the installers as
downloadable artifacts. It is standard GitHub-Actions syntax:

- **On GitHub:** it runs on GitHub's hosted runners — free for a public repository, including the macOS and
  Windows runners — so tagging a release (`vX.Y.Z`) or starting it by hand builds every platform with nothing to
  install locally.
- **Self-hosted (Forgejo Actions, later):** the same file runs on your own runners — copy it to
  `.forgejo/workflows/` or point Forgejo at `.github/workflows/`. Each runner needs Node (the pinned version),
  a Rust toolchain, and the platform build dependencies listed above; macOS must be a real Mac, since it cannot
  be virtualized.

Pushing a version tag (`vX.Y.Z`) also attaches every platform's installer to a draft GitHub Release, which you
review and publish by hand. Nothing goes public automatically — that suits a security app, and it lets you add
the host-independent signature and notes first. (That release step is GitHub-specific; on Forgejo, swap it for
Forgejo's release API. The build jobs are identical on both.)

To build without changing the version, start the workflow by hand (the "Run workflow" button, or
`workflow_dispatch`) and leave the release tag blank: it builds every platform and uploads the installers as
downloadable artifacts, with no tag and no version bump. Supply a release tag to also draft or refresh a release
at that tag. Locally, `npm run clean-build` rebuilds the current code at any time, no version bump involved.

Either way the runner's workspace path is neutral, so builds carry no personal identity, and the leak scan
confirms it (it treats a CI/build account as non-personal). CI builds are unsigned — see below for signing.

## Not leaking the build machine's identity

A compiled binary embeds the paths it was built from — the build directory and the dependency cache — and those
normally contain the operating-system username (for example `/Users/<name>/...` or `/home/<name>/...`). Compiler
path-remapping features do not fully remove them: build scripts and code generation embed some paths as plain
string literals, and the common `strings` check even misses them. The reliable way, verified on macOS with the
build user's own account, is to build where those paths carry no username, then prove it:

1. **Build at a neutral path** — a checkout location with no username in it: `/opt/vaultonaut` on Linux,
   `C:\build\vaultonaut` on Windows, or `/Users/Shared/vaultonaut` on macOS (world-writable, no username; avoid
   anything under `/Users/<you>` or `C:\Users\<you>`).
2. **Point `CARGO_HOME` at a neutral path too** (for example `<that dir>/.cargo`), so the dependency cache the
   compiler references is neutral as well, not `~/.cargo`. With both of these, every embedded path is neutral —
   a build under the build user's own account then contains no username, hostname, or home path at all.
3. **The leak scan is the guarantee.** `scan-leaks.js` runs after every build (wired into `npm run build`) and
   FAILS the build if any file in the bundle contains the build machine's username, hostname, or home path. It
   is enforced on every platform, so a build that would expose you never ships. Do not skip it. The manual
   double-check is a byte-accurate search (not `strings`, which misses paths): `node scan-leaks.js <bundle dir>`.

A disposable build machine or a container makes steps 1 and 2 automatic. Release builds also strip symbols, and
no operating-system code-signing identity is added (the macOS bundle is ad-hoc signed, with no developer account
or team identifier).

## Authenticity and verification

Two independent layers, either or both:

- **Host-independent (no cost, no platform account):** the build signs a manifest scoped to the bundle with the
  project's own key, so the bundled `verify.js` (and the app's boot-time self-check) confirm the installed app
  against the public key published in the main README, independent of any operating-system signing. The easiest
  way to produce a signed, identity-free release is `npm run clean-build` on the machine that holds the signing
  key: it builds at a neutral path (no personal identity) and signs automatically when the key is present, so
  a release is never accidentally left unsigned. Use `--no-sign` to skip signing, or `--key <path>` for a key
  kept outside the default location. Without a key the bundle is still fully functional; its self-check simply
  stays inert. The manifest covers the application, its bundled runtime, and its bundled dependencies; it does
  not cover the small native window shell around them, which is the operating-system signing layer's job.
- **Operating-system signing (optional, paid):** code-signing and notarization on macOS, and Authenticode on
  Windows, remove the first-run security prompts. These require paid developer accounts and can be added later
  with no change to the app itself; until then, users approve the app once on first launch.
