fn main() {
    // The crate version is a fixed placeholder. The shipped app version comes from the root package.json through
    // tauri.conf.json's "version": "../package.json"; Tauri uses that for the bundle, installers, and Windows
    // version resource. There is no second release literal to validate here.
    tauri_build::build()
}
