//! What exists only in a test build (the `test-surface` feature): overrides of
//! timing and version, and, from the next step on, the scripted prompt surface.
//!
//! The shipped `vahta` has none of it. [`ENABLED`] says which build this is, so
//! the command line can tell a person that a test build is running without
//! itself carrying any `cfg`. CI fails if `vahta-cli` ever sees the feature.

use crate::server::Options;
use crate::surface::PromptSurface;

/// Whether this is a test build.
pub const ENABLED: bool = cfg!(feature = "test-surface");

/// The scripted surface named by `VAHTA_TEST_SURFACE`, if this is a test build
/// and the variable is set.
pub fn scripted_from_env() -> Option<Box<dyn PromptSurface>> {
    #[cfg(feature = "test-surface")]
    {
        scripted::ScriptedSurface::from_env().map(|s| Box::new(s) as Box<dyn PromptSurface>)
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, an executable name that counts as every harness for the
/// check of `vahta run --connector`'s parent (`VAHTA_TEST_CONNECTOR_PARENT`),
/// so a test can stand in for the harness. Always `None` in the shipped build.
pub fn connector_parent_alias() -> Option<String> {
    #[cfg(feature = "test-surface")]
    {
        std::env::var("VAHTA_TEST_CONNECTOR_PARENT")
            .ok()
            .filter(|v| !v.is_empty())
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, the socket a test's fake okono listens on
/// (`VAHTA_TEST_OKONO_SOCKET`). The shipped build asks `/run/okono/okono.sock`
/// and nothing else.
pub(crate) fn okono_socket() -> Option<std::path::PathBuf> {
    #[cfg(feature = "test-surface")]
    {
        std::env::var_os("VAHTA_TEST_OKONO_SOCKET")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, how long the okono exchange may take
/// (`VAHTA_TEST_OKONO_TIMEOUT_MS`); the shipped build gives it 60 seconds.
pub(crate) fn okono_timeout() -> Option<std::time::Duration> {
    #[cfg(feature = "test-surface")]
    {
        std::env::var("VAHTA_TEST_OKONO_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(std::time::Duration::from_millis)
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// Where desktop notifications go instead of the screen. `None` in the shipped
/// build: they are shown. In a test build they are never shown: they are
/// appended, one line each, to the file `VAHTA_TEST_NOTIFY_LOG` names, or
/// dropped when it is not set.
pub fn notify_log() -> Option<Option<std::path::PathBuf>> {
    #[cfg(feature = "test-surface")]
    {
        Some(std::env::var_os("VAHTA_TEST_NOTIFY_LOG").map(std::path::PathBuf::from))
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, whether refusals by a secret's rules are kept out of the
/// alarm (`VAHTA_TEST_MUTE_REFUSAL_ALARM` set). Always `false` in the shipped
/// build.
pub fn refusal_alarm_muted() -> bool {
    #[cfg(feature = "test-surface")]
    {
        std::env::var_os("VAHTA_TEST_MUTE_REFUSAL_ALARM").is_some()
    }
    #[cfg(not(feature = "test-surface"))]
    {
        false
    }
}

/// In a test build, how often the hook watchdog looks at its files
/// (`VAHTA_TEST_GUARD_POLL_MS`); the shipped build polls every two seconds.
pub fn guard_poll() -> Option<std::time::Duration> {
    #[cfg(feature = "test-surface")]
    {
        std::env::var("VAHTA_TEST_GUARD_POLL_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(std::time::Duration::from_millis)
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, the PEM root that `vahta http` also trusts, read from the
/// file `VAHTA_TEST_HTTP_ROOT` names (a test HTTPS server's certificate
/// authority). The shipped build trusts the public roots alone.
#[cfg(all(feature = "http", feature = "test-surface"))]
pub(crate) fn http_root() -> Option<Vec<u8>> {
    std::env::var_os("VAHTA_TEST_HTTP_ROOT").and_then(|p| std::fs::read(p).ok())
}

/// In a test build, the address every connection of the host relay goes to
/// instead of the host's own (`VAHTA_TEST_RELAY_CONNECT`, an IP address), so a
/// test can stand a local server in for an allowed host. Always `None` in the
/// shipped build.
pub(crate) fn relay_connect_override() -> Option<std::net::IpAddr> {
    #[cfg(feature = "test-surface")]
    {
        std::env::var("VAHTA_TEST_RELAY_CONNECT")
            .ok()
            .and_then(|v| v.parse().ok())
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// Where the commands of a login autostart (`systemctl`, `launchctl`, `reg`)
/// go instead of being run. `None` in the shipped build: they are run. In a
/// test build they are never run: they are appended, one line each, to the
/// file `VAHTA_TEST_SERVICE_LOG` names, or dropped when it is not set.
pub fn service_log() -> Option<Option<std::path::PathBuf>> {
    #[cfg(feature = "test-surface")]
    {
        Some(std::env::var_os("VAHTA_TEST_SERVICE_LOG").map(std::path::PathBuf::from))
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// The directory the administrator-policy paths (`/etc/claude-code/...`) are
/// re-rooted under. `None` in the shipped build. A test build always has one,
/// so it can never write the real system paths: `VAHTA_TEST_MANAGED_ROOT`, or
/// a directory in the temp dir.
pub fn managed_root() -> Option<std::path::PathBuf> {
    #[cfg(feature = "test-surface")]
    {
        Some(
            std::env::var_os("VAHTA_TEST_MANAGED_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("vahta-test-managed-root")),
        )
    }
    #[cfg(not(feature = "test-surface"))]
    {
        None
    }
}

/// In a test build, stand in for logind: when the file named by
/// `VAHTA_TEST_SLEEP_TRIGGER` appears, the machine "went to sleep". The same
/// path as the real signal, so a test can show the sessions end.
pub(crate) fn start_sleep_trigger(sink: &crate::lock::LockSink) {
    #[cfg(feature = "test-surface")]
    if let Some(path) = std::env::var_os("VAHTA_TEST_SLEEP_TRIGGER") {
        let sink = sink.clone();
        std::thread::spawn(move || {
            while !sink.stopping() {
                if std::path::Path::new(&path).exists() {
                    let _ = std::fs::remove_file(&path);
                    sink.lock("test trigger");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
    #[cfg(not(feature = "test-surface"))]
    let _ = sink;
}

/// Apply the test overrides to the daemon's options: the version it reports
/// (`VAHTA_TEST_DAEMON_VERSION`, to stand in for an old daemon), how long it
/// idles before it exits (`VAHTA_TEST_IDLE_SECONDS`), how long a copied value
/// stays on the clipboard (`VAHTA_TEST_CLIPBOARD_SECONDS`), and the scripted
/// surface with the cheap vault KDF that goes with it (`VAHTA_TEST_SURFACE`).
/// Does nothing in a shipped build.
pub fn apply_overrides(options: &mut Options) {
    #[cfg(feature = "test-surface")]
    {
        if let Some(v) = std::env::var_os("VAHTA_TEST_DAEMON_VERSION") {
            options.version = v.to_string_lossy().into_owned();
        }
        if let Some(secs) = std::env::var("VAHTA_TEST_IDLE_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            options.idle = std::time::Duration::from_secs(secs);
        }
        if let Some(secs) = std::env::var("VAHTA_TEST_CLIPBOARD_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            options.clipboard_clear = std::time::Duration::from_secs(secs);
        }
        if let Some(links) = vahta_auth::loopback::LoopbackLinks::from_env() {
            options.links = Some(Box::new(links));
        }
        // The real phone link over the LAN transport alone, with the pairing
        // phone at a fixed address (no multicast in a test): a test's fake
        // phone listens there.
        if let Some(addr) = std::env::var("VAHTA_TEST_PHONE_ADDR")
            .ok()
            .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        {
            options.links = Some(Box::new(
                crate::LinkDevices::with_transports(
                    options.paths.data.join("link"),
                    vec![std::sync::Arc::new(vahta_link::lan::LanTransport::new())],
                )
                .with_pair_hint(addr),
            ));
        }
        if let Some(surface) = scripted_from_env() {
            options.surface = Some(surface);
            options.kdf = vahta_vault::KdfParams::TEST;
        }
        // The real terminal surface with the cheap KDF, for a test of the
        // window process itself.
        if std::env::var_os("VAHTA_TEST_KDF").is_some() {
            options.kdf = vahta_vault::KdfParams::TEST;
        }
    }
    #[cfg(not(feature = "test-surface"))]
    let _ = options;
}

#[cfg(feature = "test-surface")]
pub mod scripted {
    //! A prompt surface that answers from a script, for tests that drive a real
    //! daemon without a person or a terminal.
    //!
    //! The script is a file of JSON lines, one answer per question, consumed
    //! from the top as the questions come (the file is rewritten without the
    //! line it gave, so a test can append more between steps):
    //!
    //! * `{"secret": "..."}` answers a password or a value;
    //! * `{"cancel": true}` cancels;
    //! * `{"yes": true}`, `{"no": true}` and `{"noanswer": true}` answer a
    //!   confirmation;
    //! * `{"choose": N}` picks option N of a choice;
    //! * `{"text": "..."}` answers a plain-text question;
    //! * `{"ack": true}` acknowledges something shown;
    //! * `{"wait": true}` leaves a pairing code on screen until the phone
    //!   connects (the log entry of kind `pairing` carries the code, `qr` and
    //!   `code`, for a test's phone to read);
    //! * `{"devicewait": "wait"}` answers a device wait (`{"ask":"device_wait",
    //!   "device":"A32"}` in the log): it stays until the phone answers;
    //!   `{"devicewait": "password"}` chooses the password instead and
    //!   `{"devicewait": "close"}` closes the window. A device wait with no
    //!   such line next in the script is not logged and shows nothing: the
    //!   phone is asked as if the window could not show it.
    //!
    //! Any answer may carry `"after_ms": N`: the window then holds the answer
    //! back for N milliseconds after the question is logged (with the script
    //! unlocked, so other windows go on), as a person who takes their time.
    //! `{"hang": true}` never answers. A window the daemon withdraws (the
    //! client that asked for it went away) ends a held or hanging question as
    //! closed and logs `{"close": "withdrawn"}`.
    //!
    //! Every question is appended to the log (`VAHTA_TEST_SURFACE_LOG`) with
    //! what the window would have shown: its lines, warning and agent note, and
    //! for something revealed the value itself, because the log stands for the
    //! window. A question with no answer left, or an answer of the wrong kind,
    //! is an error that fails the request, so a test that asked more than it
    //! expected shows it.

    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};

    use crate::protocol::{Panel, Secret};
    use crate::surface::{DeviceWait, PromptSurface, SurfaceError, Window};

    /// Set when the daemon withdraws the window.
    type Cancelled = Arc<(Mutex<bool>, Condvar)>;

    struct Inner {
        script: PathBuf,
        log: Option<PathBuf>,
        io: Mutex<()>,
    }

    pub struct ScriptedSurface {
        inner: Arc<Inner>,
    }

    impl ScriptedSurface {
        pub fn from_env() -> Option<ScriptedSurface> {
            let script = std::env::var_os("VAHTA_TEST_SURFACE")?;
            let log = std::env::var_os("VAHTA_TEST_SURFACE_LOG").map(PathBuf::from);
            Some(ScriptedSurface {
                inner: Arc::new(Inner {
                    script: PathBuf::from(script),
                    log,
                    io: Mutex::new(()),
                }),
            })
        }
    }

    impl Inner {
        fn log(&self, entry: Value) {
            let Some(path) = &self.log else { return };
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{entry}");
            }
        }

        /// Whether the next answer is for a device wait.
        fn next_is_device_wait(&self) -> bool {
            let Ok(_guard) = self.io.lock() else {
                return false;
            };
            std::fs::read_to_string(&self.script)
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find(|l| !l.trim().is_empty())
                        .and_then(|l| serde_json::from_str::<Value>(l).ok())
                })
                .is_some_and(|v| v.get("devicewait").is_some())
        }

        /// The next answer, removed from the script.
        fn pop(&self, cancelled: &Cancelled) -> Result<Value, SurfaceError> {
            let guard = self.io.lock().map_err(|_| unavailable("poisoned"))?;
            let text = std::fs::read_to_string(&self.script)
                .map_err(|_| unavailable("the scripted surface has no script"))?;
            let mut lines = text.lines().filter(|l| !l.trim().is_empty());
            let Some(first) = lines.next() else {
                return Err(unavailable("the scripted surface has no answer left"));
            };
            let first = first.to_string();
            let rest: Vec<&str> = lines.collect();
            let mut remaining = rest.join("\n");
            if !remaining.is_empty() {
                remaining.push('\n');
            }
            std::fs::write(&self.script, remaining)
                .map_err(|_| unavailable("cannot update the script"))?;
            drop(guard);
            let answer: Value = serde_json::from_str(&first)
                .map_err(|_| unavailable("a bad line in the script"))?;
            // `hang` never answers; `after_ms` answers late. Either ends at
            // once, as a closed window, when the daemon withdraws the window
            // (the client that asked for it went away).
            let wait = if answer.get("hang").is_some() {
                Some(Duration::from_secs(600))
            } else {
                answer
                    .get("after_ms")
                    .and_then(Value::as_u64)
                    .map(Duration::from_millis)
            };
            if let Some(wait) = wait {
                let (lock, cv) = &**cancelled;
                let guard = lock.lock().map_err(|_| unavailable("poisoned"))?;
                let (withdrawn, _) = cv
                    .wait_timeout_while(guard, wait, |c| !*c)
                    .map_err(|_| unavailable("poisoned"))?;
                if *withdrawn {
                    self.log(json!({"close": "withdrawn"}));
                    return Err(SurfaceError::Closed);
                }
            }
            Ok(answer)
        }
    }

    fn unavailable(why: &str) -> SurfaceError {
        SurfaceError::Unavailable(why.to_string())
    }

    fn panel_json(panel: &Panel) -> Value {
        json!({
            "title": panel.title,
            "lines": panel.lines,
            "warning": panel.warning,
            "agent_note": panel.agent_note,
        })
    }

    impl PromptSurface for ScriptedSurface {
        fn open(&self, title: &str) -> Result<Box<dyn Window>, SurfaceError> {
            self.inner.log(json!({"open": title}));
            Ok(Box::new(ScriptedWindow {
                inner: self.inner.clone(),
                cancelled: Arc::default(),
                pair_stopped: Arc::default(),
                wait_stopped: Arc::default(),
            }))
        }
    }

    struct ScriptedWindow {
        inner: Arc<Inner>,
        cancelled: Cancelled,
        /// Set when the daemon says the phone has connected.
        pair_stopped: Arc<(Mutex<bool>, Condvar)>,
        /// Set when the daemon says the phone has answered an unlock.
        wait_stopped: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ScriptedWindow {
        fn secret(
            &self,
            kind: &str,
            panel: &Panel,
            prompt: &str,
        ) -> Result<Option<Secret>, SurfaceError> {
            self.inner
                .log(json!({"ask": kind, "prompt": prompt, "panel": panel_json(panel)}));
            let answer = self.inner.pop(&self.cancelled)?;
            if answer.get("cancel").is_some() {
                return Ok(None);
            }
            match answer.get("secret").and_then(Value::as_str) {
                Some(s) => Ok(Some(Secret::new(s.to_string()))),
                None => Err(unavailable(
                    "the script answered a question with the wrong kind",
                )),
            }
        }
    }

    impl Window for ScriptedWindow {
        fn ask_password(
            &mut self,
            panel: &Panel,
            prompt: &str,
            _confirm: bool,
        ) -> Result<Option<Secret>, SurfaceError> {
            self.secret("password", panel, prompt)
        }

        fn ask_value(
            &mut self,
            panel: &Panel,
            prompt: &str,
            _confirm: bool,
        ) -> Result<Option<Secret>, SurfaceError> {
            self.secret("value", panel, prompt)
        }

        fn confirm(
            &mut self,
            panel: &Panel,
            question: &str,
            _timeout: Option<Duration>,
        ) -> Result<Option<bool>, SurfaceError> {
            self.inner
                .log(json!({"ask": "confirm", "prompt": question, "panel": panel_json(panel)}));
            let answer = self.inner.pop(&self.cancelled)?;
            if answer.get("yes").is_some() {
                Ok(Some(true))
            } else if answer.get("no").is_some() {
                Ok(Some(false))
            } else if answer.get("noanswer").is_some() || answer.get("cancel").is_some() {
                Ok(None)
            } else {
                Err(unavailable(
                    "the script answered a confirmation with the wrong kind",
                ))
            }
        }

        fn choose(
            &mut self,
            panel: &Panel,
            question: &str,
            options: &[String],
        ) -> Result<Option<usize>, SurfaceError> {
            self.inner.log(json!({
                "ask": "choose", "prompt": question, "options": options, "panel": panel_json(panel)
            }));
            let answer = self.inner.pop(&self.cancelled)?;
            if answer.get("cancel").is_some() || answer.get("noanswer").is_some() {
                return Ok(None);
            }
            match answer.get("choose").and_then(Value::as_u64) {
                Some(n) if (n as usize) < options.len() => Ok(Some(n as usize)),
                _ => Err(unavailable(
                    "the script answered a choice with the wrong kind",
                )),
            }
        }

        fn ask_text(
            &mut self,
            panel: &Panel,
            prompt: &str,
        ) -> Result<Option<String>, SurfaceError> {
            self.inner
                .log(json!({"ask": "text", "prompt": prompt, "panel": panel_json(panel)}));
            let answer = self.inner.pop(&self.cancelled)?;
            if answer.get("cancel").is_some() || answer.get("noanswer").is_some() {
                return Ok(None);
            }
            match answer.get("text").and_then(Value::as_str) {
                Some(s) => Ok(Some(s.to_string())),
                None => Err(unavailable(
                    "the script answered a text question with the wrong kind",
                )),
            }
        }

        fn show_value(
            &mut self,
            panel: &Panel,
            what: &str,
            value: &Secret,
            _seconds: u32,
        ) -> Result<(), SurfaceError> {
            self.inner.log(json!({
                "ask": "show", "prompt": what, "shown": value.expose(), "panel": panel_json(panel)
            }));
            self.inner.pop(&self.cancelled).map(|_| ())
        }

        fn show_recovery_key(&mut self, panel: &Panel, key: &Secret) -> Result<bool, SurfaceError> {
            self.inner.log(json!({
                "ask": "recovery", "shown": key.expose(), "panel": panel_json(panel)
            }));
            let answer = self.inner.pop(&self.cancelled)?;
            Ok(answer.get("ack").is_some())
        }

        fn show_pairing(
            &mut self,
            panel: &Panel,
            qr: &str,
            text: &str,
            wait: Duration,
        ) -> Result<bool, SurfaceError> {
            self.inner.log(json!({
                "ask": "pairing", "qr": qr, "code": text, "panel": panel_json(panel)
            }));
            let answer = self.inner.pop(&self.cancelled)?;
            if answer.get("cancel").is_some() {
                return Ok(false);
            }
            if answer.get("wait").is_none() {
                return Err(unavailable(
                    "the script answered a pairing code with the wrong kind",
                ));
            }
            // Until the daemon stops it (the phone connected) or `wait` ends.
            let (lock, cv) = &*self.pair_stopped;
            let guard = lock.lock().map_err(|_| unavailable("poisoned"))?;
            let (stopped, _) = cv
                .wait_timeout_while(guard, wait, |s| !*s)
                .map_err(|_| unavailable("poisoned"))?;
            Ok(*stopped)
        }

        fn pairing_stopper(&self) -> Option<Box<dyn FnOnce() + Send>> {
            let state = self.pair_stopped.clone();
            Some(Box::new(move || {
                let (lock, cv) = &*state;
                if let Ok(mut s) = lock.lock() {
                    *s = true;
                    cv.notify_all();
                }
            }))
        }

        fn show_device_wait(
            &mut self,
            panel: &Panel,
            device: &str,
            wait: Duration,
        ) -> Result<DeviceWait, SurfaceError> {
            if !self.inner.next_is_device_wait() {
                return Err(unavailable("no device wait in the script"));
            }
            self.inner.log(json!({
                "ask": "device_wait", "device": device, "panel": panel_json(panel)
            }));
            let answer = self.inner.pop(&self.cancelled)?;
            match answer.get("devicewait").and_then(Value::as_str) {
                Some("password") => return Ok(DeviceWait::Password),
                Some("close") => return Ok(DeviceWait::Closed),
                Some("wait") => {}
                _ => {
                    return Err(unavailable(
                        "the script answered a device wait with the wrong kind",
                    ));
                }
            }
            let (lock, cv) = &*self.wait_stopped;
            let guard = lock.lock().map_err(|_| unavailable("poisoned"))?;
            let _ = cv
                .wait_timeout_while(guard, wait, |s| !*s)
                .map_err(|_| unavailable("poisoned"))?;
            Ok(DeviceWait::Over)
        }

        fn device_wait_stopper(&self) -> Option<Box<dyn FnOnce() + Send>> {
            let state = self.wait_stopped.clone();
            if let Ok(mut s) = state.0.lock() {
                *s = false;
            }
            Some(Box::new(move || {
                let (lock, cv) = &*state;
                if let Ok(mut s) = lock.lock() {
                    *s = true;
                    cv.notify_all();
                }
            }))
        }

        fn canceller(&self) -> Option<Box<dyn FnOnce() + Send>> {
            let state = self.cancelled.clone();
            Some(Box::new(move || {
                let (lock, cv) = &*state;
                if let Ok(mut c) = lock.lock() {
                    *c = true;
                    cv.notify_all();
                }
            }))
        }

        fn close(self: Box<Self>, message: Option<&str>) {
            self.inner.log(json!({"close": message}));
        }
    }
}
