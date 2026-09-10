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
use std::sync::atomic::{AtomicBool, Ordering};
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
// Last-resort cap for the main-thread exit fallback: short, so a fallback exit can never freeze the UI thread.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
// The responsive close/quit path drains on a BACKGROUND thread (the window is already hidden), so it can wait out a
// long but legitimate flush — a large cloud-backed vault can take a while to finish uploading — before force-killing.
// The backend's own drain is internally bounded, so this only escalates to a hard kill against a genuinely wedged
// backend, and the user never sees the wait (the window is gone). Prefers not-losing-data over a fast process exit.
const BACKGROUND_DRAIN_GRACE: Duration = Duration::from_secs(300);

// Shutdown state, so a SECOND quit gesture while the background drain is still running cannot abort it mid-flush.
// SHUTTING_DOWN is set the moment a shutdown begins; DRAIN_DONE is set by the drain thread immediately before its
// final exit. The exit handler prevents any exit while SHUTTING_DOWN is set and DRAIN_DONE is not — the only exit it
// lets through in that state is the drain thread's own, which sets DRAIN_DONE first.
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static DRAIN_DONE: AtomicBool = AtomicBool::new(false);

// The running Node backend, shared between the readiness thread and the exit handler.
type SharedChild = Arc<Mutex<Option<Child>>>;
struct Backend(SharedChild);

// The bundled Node runtime, under Contents/Resources/app/runtime (see the note at the top of the file).
fn node_binary(resource_dir: &Path) -> PathBuf {
    let name = if cfg!(windows) { "node.exe" } else { "node" };
    resource_dir.join("app").join("runtime").join(name)
}

// Strip the Windows "verbatim" path prefix (\\?\) that Tauri's resource_dir() returns. Node's module resolver
// cannot handle that prefix on its main-script argument — it tries to lstat "C:" and aborts with EISDIR before
// any of our code runs — so every path handed to Node must be plain. A UNC verbatim path (\\?\UNC\server\share)
// is rewritten to its normal \\server\share form; a no-op on non-verbatim paths and on every non-Windows platform.
fn plain_path(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(s) = p.to_str() {
            if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
                return PathBuf::from(format!(r"\\{}", rest));
            }
            if let Some(rest) = s.strip_prefix(r"\\?\") {
                return PathBuf::from(rest);
            }
        }
    }
    p
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
    // On Unix /tmp is shared between users, so name the log per-uid and create it 0600. Without that, a second user's
    // create-truncate would hit the first user's file (EACCES → the fallback below discards output, exactly when a
    // startup failure needs it), and the log would be world-readable. On Windows the temp dir is already per-user, so
    // the plain name is fine.
    #[cfg(unix)]
    let name = format!("vaultonaut-backend-{}.log", unsafe { libc::getuid() });
    #[cfg(not(unix))]
    let name = String::from("vaultonaut-backend.log");
    let path = std::env::temp_dir().join(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    if let Ok(f) = opts.open(&path) {
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

// Ask the backend to stop cleanly (it drains writes and locks each vault on the way out), wait up to `grace` for it to
// exit, then force it down if it has not. The clean-stop request is cross-platform: on Unix, SIGTERM (its handler runs
// the graceful shutdown); on Windows, which has no such signal for a windowless child, a "quit" line on the backend's
// stdin, which the desktop backend listens for and treats exactly like SIGTERM. Either way `grace` is honored, so a
// large in-flight cloud upload can finish on every platform before any force-kill.
fn stop_backend(child: &mut Child, grace: Duration) {
    #[cfg(unix)]
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
    #[cfg(windows)]
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        let _ = stdin.write_all(b"quit\n");
        let _ = stdin.flush();
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
}

// Hide the window (so it vanishes at once) and drain-and-lock the backend on a BACKGROUND thread, then exit — so no
// quit path blocks the UI thread and triggers the desktop's "application is not responding" dialog. Safe to call
// more than once: the child is taken out of the shared slot, so a second call finds nothing and just exits.
fn shutdown_in_background<R: tauri::Runtime>(handle: tauri::AppHandle<R>, shared: SharedChild) {
    SHUTTING_DOWN.store(true, Ordering::SeqCst); // from here on, a second quit gesture is held off until the drain finishes
    if let Some(win) = handle.get_webview_window("main") { let _ = win.hide(); }
    std::thread::spawn(move || {
        if let Some(mut child) = shared.lock().ok().and_then(|mut g| g.take()) {
            stop_backend(&mut child, BACKGROUND_DRAIN_GRACE);
        }
        DRAIN_DONE.store(true, Ordering::SeqCst); // set BEFORE exit so the re-entrant ExitRequested this triggers is allowed through
        handle.exit(0);
    });
}

// On Linux the interface runs inside a WebKitGTK WebView, whose DMABUF-based accelerated-compositing renderer
// fails on a wide range of GPU + driver + compositor combinations (NVIDIA especially, and many Wayland setups):
// the GTK window paints its background color but the WebView surface never composites, so the app shows a blank
// dark window instead of the interface or the loading splash. It often appears only on a RELAUNCH, once the
// driver/compositor state differs from the very first run — which is exactly the "black screen when you reopen it"
// report. Disabling the DMABUF renderer makes the WebView paint reliably on every Linux machine; the small loss of
// rendering acceleration is irrelevant for this simple interface. NVIDIA's explicit-sync path is disabled too — it
// is free and heads off a related Wayland crash. This is Linux-only, so macOS (WKWebView) and Windows (WebView2)
// are untouched. WebKitGTK reads these only from the environment and offers no command-line or config equivalent
// (the same reason the FUSE-T library path is set via the environment), so this is a deliberate, documented
// exception to the project's configure-by-argument rule — and only a DEFAULT: an advanced user who sets either
// variable themselves keeps their choice, so a future driver that prefers the accelerated path can opt back in.
#[cfg(target_os = "linux")]
fn tune_linux_webview() {
    for (key, value) in [
        ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
        ("__NV_DISABLE_EXPLICIT_SYNC", "1"),
    ] {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn tune_linux_webview() {}

fn main() {
    // Must run BEFORE any WebView is created (the window is built from the config below), so the renderer choice is
    // in effect for the very first paint.
    tune_linux_webview();

    tauri::Builder::default()
        .setup(|app| {
            // Launch the Node application through the bundled runtime on the fixed loopback port. Its output is
            // captured to a log file (see backend_log_stdio) so a startup failure is diagnosable; a file, unlike a
            // pipe, can never fill and stall the writer. --desktop tells the backend it is the packaged app.
            // plain_path: resource_dir() is a \\?\ verbatim path on Windows, which Node cannot use as its entry
            // script (it crashes in module resolution before running anything). Strip it here so node, the entry,
            // and everything derived from them are plain paths.
            let resource_dir = plain_path(app.path().resource_dir()?);
            let node = node_binary(&resource_dir);
            ensure_executable(&node);
            let entry = resource_dir.join("app").join("vaultonaut.js");

            let mut cmd = Command::new(&node);
            cmd.arg(&entry)
                .arg("ui")
                .arg("--port")
                .arg(UI_PORT.to_string())
                .arg("--desktop")
                .stdin(Stdio::piped()); // kept open so the shell can send a cross-platform "quit" line on shutdown (see stop_backend)
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

                    // Close WITHOUT freezing the window. On a close request, hide the window immediately (so it
                    // vanishes at once) and run the backend's drain-and-lock on a BACKGROUND thread, then exit.
                    // Doing that multi-second shutdown on the UI thread (as the RunEvent::Exit handler alone would)
                    // makes the desktop pop an "application is not responding" dialog before the app finally closes.
                    // The full shutdown that locks every open vault still runs — only its thread moves off the UI.
                    if let Some(win) = app.get_webview_window("main") {
                        let close_shared = shared.clone();
                        let close_handle = app.handle().clone();
                        win.on_window_event(move |event| {
                            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                                api.prevent_close();
                                shutdown_in_background(close_handle.clone(), close_shared.clone());
                            }
                        });
                    }

                    // Wait for the server off the main thread (so the window and its "starting" splash stay
                    // responsive), then, back on the main thread, show the interface or the error state.
                    std::thread::spawn(move || {
                        let ready = wait_for_server(UI_PORT, STARTUP_TIMEOUT, &shared);
                        show_outcome(&handle, ready);
                        // Never leave an orphan holding the port: if the backend is alive but never bound (a timeout,
                        // not a crash), stop it now instead of waiting for the user to close the error window. Taking
                        // the child here also means the close/quit handlers find nothing left to do. No-op if it exited.
                        if !ready {
                            if let Some(mut child) = shared.lock().ok().and_then(|mut g| g.take()) {
                                stop_backend(&mut child, SHUTDOWN_GRACE);
                            }
                        }
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
            match event {
                // Every quit gesture that is NOT the window close button (which is handled per-window above) —
                // macOS Cmd+Q, the Dock's Quit, a logout — arrives here as ExitRequested. Route it through the same
                // responsive path: prevent the immediate exit, then hide the window and drain-and-lock on a
                // background thread before exiting, so a quit never freezes the UI thread. The has-child peek stops
                // the exit(0) that the background thread later calls from re-entering here and preventing its own exit.
                tauri::RunEvent::ExitRequested { api, .. } => {
                    if DRAIN_DONE.load(Ordering::SeqCst) {
                        // The background drain has finished — this is its own final exit (or a quit after it). Let it through.
                    } else if SHUTTING_DOWN.load(Ordering::SeqCst) {
                        // A drain is already running (e.g. the window was closed, or a first Cmd+Q): a SECOND quit gesture
                        // must not abort it mid-flush, so hold the exit off. The drain thread's own exit sets DRAIN_DONE first.
                        api.prevent_exit();
                    } else if let Some(backend) = app_handle.try_state::<Backend>() {
                        let shared = backend.0.clone();
                        let has_child = shared.lock().map(|g| g.is_some()).unwrap_or(false);
                        if has_child {
                            api.prevent_exit();
                            shutdown_in_background(app_handle.clone(), shared);
                        }
                    }
                }
                // Last-resort backstop: if the app ever exits without going through the responsive path, stop the
                // backend here so vaults are still locked and in-flight writes flush. Short grace — runs on the main thread.
                tauri::RunEvent::Exit => {
                    if let Some(backend) = app_handle.try_state::<Backend>() {
                        if let Some(mut child) = backend.0.lock().ok().and_then(|mut g| g.take()) {
                            stop_backend(&mut child, SHUTDOWN_GRACE);
                        }
                    }
                }
                _ => {}
            }
        });
}
