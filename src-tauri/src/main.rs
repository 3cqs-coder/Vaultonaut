// Prevents a second console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The desktop shell is deliberately thin. All of Vaultonaut's logic — the vault engine, the crypto
// orchestration, the web interface — lives in the Node application. This shell only does three things:
// launch that application through a bundled Node runtime (so the user needs no separate Node install),
// wait for its loopback web server to come up, and show that interface in a native window. When the window
// closes, the Node process is asked to stop cleanly so nothing is left running and in-flight writes flush.
//
// The bundled Node lives under Contents/Resources/app/runtime (not Contents/MacOS). That matters on macOS: an
// executable inside Contents/MacOS inherits the app bundle's foreground Info.plist and the system gives it its
// own Dock tile, so a Node process placed there would appear as a second icon in the Dock. Run from Resources,
// Node is an ordinary background process with no Dock presence. Keeping it inside `app/` also means the bundle's
// signed manifest covers the interpreter itself.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::Manager;

// The interface is served on the loopback interface only (no login is required there, and nothing is
// reachable from the network). This matches the application's own default port (Common.DEFAULT_UI_PORT); a
// drift-guard test keeps the two in sync.
const UI_PORT: u16 = 7420;
// How long to wait for the backend to start serving before giving up and showing the fallback message. Generous,
// because a cold first run can be slow — on Windows especially, the OS antivirus scans the freshly installed
// runtime and its modules the first time they are executed and read. A real crash does NOT wait this out: the
// poll returns immediately when the child process exits, so only a slow-but-alive startup uses the full budget.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);
// How long to allow the backend to drain and lock vaults on exit before forcing it down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

// The running Node backend, shared between the readiness thread and the exit handler.
type SharedChild = Arc<Mutex<Option<Child>>>;
struct Backend(SharedChild);

// The bundled Node runtime, under Contents/Resources/app/runtime (see the note at the top of the file).
fn node_binary(resource_dir: &Path) -> PathBuf {
    let name = if cfg!(windows) { "node.exe" } else { "node" };
    resource_dir.join("app").join("runtime").join(name)
}

// Best-effort: make sure the bundled runtime is executable. Some Linux resource packagers drop the +x bit; if
// that happens the spawn fails with EACCES and the app never starts, so restore it defensively before launch.
#[cfg(unix)]
fn ensure_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(p) {
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o755);
        let _ = std::fs::set_permissions(p, perms);
    }
}
#[cfg(not(unix))]
fn ensure_executable(_p: &Path) {}

// Capture the backend's stdout and stderr to a log file, so a startup failure is diagnosable — under the packaged
// app the process is otherwise silent. A regular file never blocks the writer (unlike a pipe, which could fill and
// stall it), it is truncated each launch, and it holds only ordinary startup output (engine setup, self-check
// notes), never vault contents. Falls back to discarding output if the log cannot be opened, so logging can never
// keep the app from starting.
fn backend_log_stdio() -> (Stdio, Stdio) {
    let path = std::env::temp_dir().join("vaultonaut-backend.log");
    if let Ok(f) = std::fs::File::create(&path) {
        if let Ok(f2) = f.try_clone() {
            return (Stdio::from(f), Stdio::from(f2));
        }
    }
    (Stdio::null(), Stdio::null())
}

// Has our spawned backend already exited? If it has (for example it hit EADDRINUSE because an unrelated program
// holds the port, or it crashed), we must NOT navigate to whatever is on that port — it would not be ours.
fn child_has_exited(child: &SharedChild) -> bool {
    if let Ok(mut guard) = child.lock() {
        if let Some(c) = guard.as_mut() {
            return matches!(c.try_wait(), Ok(Some(_)));
        }
    }
    false
}

// Return true once OUR backend is serving on the loopback port. Bounded poll; returns false early if the child
// exits first (so a foreign process holding the port can never be shown in the trusted window).
fn wait_for_server(port: u16, timeout: Duration, child: &SharedChild) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child_has_exited(child) {
            return false;
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

// On the main thread, either point the window at the running interface or show the error state. The initial
// state (`data-state="starting"`) is set on the root <html> element, so the error flag must be set there too —
// setting it on <body> would leave both states active and render a blank panel.
fn show_outcome<R: tauri::Runtime>(handle: &tauri::AppHandle<R>, ready: bool) {
    let h = handle.clone();
    let _ = handle.run_on_main_thread(move || {
        if let Some(window) = h.get_webview_window("main") {
            if ready {
                if let Ok(url) = format!("http://127.0.0.1:{}", UI_PORT).parse() {
                    let _ = window.navigate(url);
                }
            } else {
                let _ = window.eval("document.documentElement.setAttribute('data-state','error')");
            }
        }
    });
}

// Ask the backend to stop cleanly (its SIGTERM handler drains writes and locks each vault), wait briefly, then
// force it down if it has not exited. Windows has no graceful signal, so terminate directly there — the external
// guardian still unmounts and locks any open vault when the backend disappears.
fn stop_backend(child: &mut Child) {
    #[cfg(unix)]
    {
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let _ = child.kill();
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Launch the Node application through the bundled runtime on the fixed loopback port. Its output is
            // captured to a log file (see backend_log_stdio) so a startup failure is diagnosable; a file, unlike a
            // pipe, can never fill and stall the writer. --desktop tells the backend it is the packaged app.
            let resource_dir = app.path().resource_dir()?;
            let node = node_binary(&resource_dir);
            ensure_executable(&node);
            let entry = resource_dir.join("app").join("vaultonaut.js");

            let mut cmd = Command::new(&node);
            cmd.arg(&entry)
                .arg("ui")
                .arg("--port")
                .arg(UI_PORT.to_string())
                .arg("--desktop")
                .stdin(Stdio::null());
            let (out, err) = backend_log_stdio();
            cmd.stdout(out).stderr(err);
            // On Windows a GUI process launching a console binary would pop a console window without this flag.
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }

            let handle = app.handle().clone();
            match cmd.spawn() {
                Ok(child) => {
                    let shared: SharedChild = Arc::new(Mutex::new(Some(child)));
                    app.manage(Backend(shared.clone()));
                    // Wait for the server off the main thread (so the window and its "starting" splash stay
                    // responsive), then, back on the main thread, show the interface or the error state.
                    std::thread::spawn(move || {
                        let ready = wait_for_server(UI_PORT, STARTUP_TIMEOUT, &shared);
                        show_outcome(&handle, ready);
                    });
                }
                // The backend could not even be launched (a missing or unrunnable runtime). Show the friendly
                // error state rather than panicking with no window.
                Err(_) => show_outcome(&handle, false),
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to start the Vaultonaut desktop shell")
        .run(|app_handle, event| {
            // On exit, stop the backend cleanly so vaults are locked and in-flight writes flush.
            if let tauri::RunEvent::Exit = event {
                if let Some(backend) = app_handle.try_state::<Backend>() {
                    if let Some(mut child) = backend.0.lock().ok().and_then(|mut g| g.take()) {
                        stop_backend(&mut child);
                    }
                }
            }
        });
}
