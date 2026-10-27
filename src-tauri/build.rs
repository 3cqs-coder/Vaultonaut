// Keep the Rust crate version equal to the root package.json version. package.json is the single source for the
// shipped app version; tauri.conf.json reads it directly, but Cargo cannot read JSON, so sync-version.js mirrors the
// value into Cargo.toml and Cargo.lock. This build-time guard turns a missed mirror into a clear failure instead of a
// binary or installer whose version disagrees with the signed release manifest.
//
// The normal build paths run sync-version.js first (the npm scripts and tauri.conf.json's beforeDev/beforeBuild
// hooks). A direct `cargo build` that skipped that step fails here with the exact command to run.
fn main() {
    println!("cargo:rerun-if-changed=../package.json");

    let package_json = std::fs::read_to_string("../package.json")
        .expect("read ../package.json (the desktop crate must build from its repository checkout)");
    let key = "\"version\"";
    let version = (|| {
        let start = package_json.find(key)? + key.len();
        let rest = &package_json[start..];
        let colon = rest.find(':')?;
        let rest = &rest[colon + 1..];
        let first_quote = rest.find('"')?;
        let rest = &rest[first_quote + 1..];
        let second_quote = rest.find('"')?;
        Some(rest[..second_quote].to_string())
    })()
    .expect("../package.json must contain a string version field");

    let cargo_version = env!("CARGO_PKG_VERSION");
    if version != cargo_version {
        panic!(
            "desktop crate version {cargo_version} does not match root package.json version {version}. \
             Run `node src-tauri/sync-version.js` (or `npm run sync-version` in src-tauri) and build again."
        );
    }

    tauri_build::build()
}
