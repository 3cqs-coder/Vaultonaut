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

// True once the interface has been shown (the window navigated to the running backend). Before that the window
// shows only the "starting"/error splash, where nothing is unlocked and there is no one to confirm with — so a
// close then just quits, as it always did. After it, a close asks first when a vault is open.
static UI_READY: AtomicBool = AtomicBool::new(false);
// True while a quit-confirmation dialog is open, so a second close/quit gesture cannot stack a second dialog.
static CONFIRMING: AtomicBool = AtomicBool::new(false);
// The per-launch token, shared with the backend, that gates the loopback mount-count probe used by the quit
// confirmation. Set once at launch; read from both the window-close and the app-quit handlers.
static QUIT_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

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

// A per-launch, hard-to-predict token the backend echoes at /__ready so the shell can prove the responding server
// is the backend it just started. It need not be cryptographically strong: a process that squatted the loopback
// port BEFORE this launch never sees the token (it is passed to our child as an argument, never over the network)
// and gets a single blind attempt to echo it during the readiness poll, so entropy from the launch instant, this
// process id, and an address-space-randomized pointer is ample. Pure std — no dependency is added.
fn ready_token() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut out = String::new();
    for i in 0..2u64 {
        let mut h = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        std::process::id().hash(&mut h);
        i.hash(&mut h);
        let probe = Box::new(0u8);
        (&*probe as *const u8 as usize).hash(&mut h); // ASLR pointer entropy
        std::time::SystemTime::now().hash(&mut h);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

// GET /__ready over loopback and return the response text, or None. HTTP/1.0 with Connection: close means the
// server closes the socket after the body, so reading to EOF gets the whole (tiny) response without parsing
// chunked/keep-alive framing. Read/write timeouts bound it so a silent or dribbling peer never stalls the poll,
// and the read is capped so a foreign server on the port cannot stream an unbounded body at us.
fn probe_ready(port: u16, timeout: Duration) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream
        .write_all(b"GET /__ready HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

// Return true once OUR backend is serving on the loopback port — proven by the readiness endpoint echoing the
// per-launch token, NOT merely by the port accepting a connection. A foreign process that squatted the port
// answers the TCP connect but cannot echo the token, so it is never mistaken for our backend and shown in the
// trusted window. Bounded poll; returns false early if the child exits first (a crash, or EADDRINUSE).
fn wait_for_server(port: u16, timeout: Duration, token: &str, child: &SharedChild) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child_has_exited(child) {
            return false;
        }
        if let Some(resp) = probe_ready(port, Duration::from_secs(2)) {
            if !token.is_empty() && resp.contains(token) {
                return true;
            }
            // The port answered but did not echo our token — a foreign/other server, or our backend has bound the
            // port but not finished starting. Keep polling until it answers with the token, or the child exits.
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
                    // The interface is now what the window shows, so a close from here on may need to lock open
                    // vaults — the quit confirmation applies only past this point.
                    UI_READY.store(true, Ordering::SeqCst);
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

// Ask the backend, over loopback, how many vaults are currently unlocked (mounted). Same request shape as
// probe_ready, but with the per-launch token in a header so only this shell can read the count. Returns None on
// any failure (no connection, a timeout, a foreign server, an unparsable body) — the caller treats None as "ask
// to be safe", so a probe failure never lets a close tear vaults down without confirmation.
fn probe_mounted(port: u16, token: &str, timeout: Duration) -> Option<u32> {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let req = format!(
        "GET /__mounted HTTP/1.0\r\nHost: 127.0.0.1\r\nX-Vaultonaut-Token: {}\r\nConnection: close\r\n\r\n",
        token
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    parse_mounted(&String::from_utf8_lossy(&buf))
}

// Pull the integer out of the tiny {"mounted":N} body without a JSON dependency. None if the key is absent (for
// example a 404 from the token check or a foreign server), which the caller reads as "ask to be safe".
fn parse_mounted(text: &str) -> Option<u32> {
    let key = "\"mounted\"";
    let start = text.find(key)? + key.len();
    let digits: String = text[start..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u32>().ok()
}

// A window-close or app-quit gesture. Closing locks and unmounts every open vault, so confirm first when at least
// one is open (or when the count cannot be read, so an uncertain probe never tears vaults down silently); with
// nothing open it quits straight away, as it always did. The backend probe and the native dialog run OFF the main
// thread — the dialog's blocking_show requires it, and it keeps the UI responsive — and the dialog always offers
// Quit, so this can never make the app unclosable. Before the interface is shown (the splash) it just quits.
fn request_quit_confirmation<R: tauri::Runtime>(handle: tauri::AppHandle<R>, shared: SharedChild) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        return; // a drain is already running — nothing to confirm
    }
    if CONFIRMING.swap(true, Ordering::SeqCst) {
        return; // a confirmation dialog is already open; don't stack another
    }
    if !UI_READY.load(Ordering::SeqCst) {
        shutdown_in_background(handle, shared); // splash/error state: nothing open, close immediately
        return;
    }
    std::thread::spawn(move || {
        let token = QUIT_TOKEN.get().map(String::as_str).unwrap_or("");
        let count = probe_mounted(UI_PORT, token, Duration::from_millis(2000));
        let proceed = match count {
            Some(0) => true, // nothing unlocked — no need to ask
            _ => {
                let body = match count {
                    Some(1) => "One vault is unlocked. Quitting will lock and unmount it. Quit Vaultonaut now?".to_string(),
                    Some(n) => format!("{} vaults are unlocked. Quitting will lock and unmount them. Quit Vaultonaut now?", n),
                    None => "Any unlocked vaults will be locked and unmounted. Quit Vaultonaut now?".to_string(),
                };
                handle
                    .dialog()
                    .message(body)
                    .title("Quit Vaultonaut?")
                    .kind(MessageDialogKind::Warning)
                    .buttons(MessageDialogButtons::OkCancelCustom("Quit".into(), "Keep running".into()))
                    .blocking_show()
            }
        };
        if proceed {
            shutdown_in_background(handle, shared); // sets SHUTTING_DOWN; CONFIRMING stays set as the shutdown proceeds
        } else {
            CONFIRMING.store(false, Ordering::SeqCst); // user kept it running — a later close asks again
        }
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
        .plugin(tauri_plugin_dialog::init()) // native quit-confirmation dialog, shown from Rust only (no frontend IPC)
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

            // A per-launch readiness token: the backend echoes it at /__ready, and the shell confirms that echo
            // before navigating the trusted window, so a foreign process squatting the loopback port is never shown.
            let ready_tok = ready_token();
            let _ = QUIT_TOKEN.set(ready_tok.clone()); // so the quit-confirmation probe can authenticate to the backend
            let mut cmd = Command::new(&node);
            cmd.arg(&entry)
                .arg("ui")
                .arg("--port")
                .arg(UI_PORT.to_string())
                .arg("--desktop")
                .arg("--ready-token")
                .arg(&ready_tok)
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

                    // Close WITHOUT freezing the window, and without losing work to a stray click. A close request
                    // first confirms with the user when a vault is open (request_quit_confirmation), since closing
                    // locks and unmounts every open vault. Once confirmed, the window hides immediately (so it
                    // vanishes at once) and the backend's drain-and-lock runs on a BACKGROUND thread, then exit.
                    // Doing that multi-second shutdown on the UI thread (as the RunEvent::Exit handler alone would)
                    // makes the desktop pop an "application is not responding" dialog before the app finally closes.
                    // The full shutdown that locks every open vault still runs — only its thread moves off the UI.
                    if let Some(win) = app.get_webview_window("main") {
                        let close_shared = shared.clone();
                        let close_handle = app.handle().clone();
                        win.on_window_event(move |event| {
                            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                                api.prevent_close();
                                request_quit_confirmation(close_handle.clone(), close_shared.clone());
                            }
                        });
                    }

                    // Wait for the server off the main thread (so the window and its "starting" splash stay
                    // responsive), then, back on the main thread, show the interface or the error state.
                    let wait_tok = ready_tok.clone();
                    std::thread::spawn(move || {
                        let ready = wait_for_server(UI_PORT, STARTUP_TIMEOUT, &wait_tok, &shared);
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
                            request_quit_confirmation(app_handle.clone(), shared);
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
