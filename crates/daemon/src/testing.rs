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

/// In a test build, stand in for logind: when the file named by
/// `VAHTA_TEST_SLEEP_TRIGGER` appears, the machine "went to sleep". The same
/// path as the real signal, so a test can show the sessions end.
pub(crate) fn start_sleep_trigger(shared: &std::sync::Arc<crate::server::Shared>) {
    #[cfg(feature = "test-surface")]
    if let Some(path) = std::env::var_os("VAHTA_TEST_SLEEP_TRIGGER") {
        let shared = shared.clone();
        std::thread::spawn(move || {
            while !shared.stopping() {
                if std::path::Path::new(&path).exists() {
                    let _ = std::fs::remove_file(&path);
                    crate::sleep::lock_now(&shared, "test trigger");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
    #[cfg(not(feature = "test-surface"))]
    let _ = shared;
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
    //! * `{"ack": true}` acknowledges something shown.
    //!
    //! Every question is appended to the log (`VAHTA_TEST_SURFACE_LOG`) with
    //! what the window would have shown: its lines, warning and agent note, and
    //! for something revealed the value itself, because the log stands for the
    //! window. A question with no answer left, or an answer of the wrong kind,
    //! is an error that fails the request, so a test that asked more than it
    //! expected shows it.

    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};

    use crate::protocol::{Panel, Secret};
    use crate::surface::{PromptSurface, SurfaceError, Window};

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

        /// The next answer, removed from the script.
        fn pop(&self) -> Result<Value, SurfaceError> {
            let _guard = self.io.lock().map_err(|_| unavailable("poisoned"))?;
            let text = std::fs::read_to_string(&self.script)
                .map_err(|_| unavailable("the scripted surface has no script"))?;
            let mut lines = text.lines().filter(|l| !l.trim().is_empty());
            let Some(first) = lines.next() else {
                return Err(unavailable("the scripted surface has no answer left"));
            };
            let rest: Vec<&str> = lines.collect();
            let mut remaining = rest.join("\n");
            if !remaining.is_empty() {
                remaining.push('\n');
            }
            std::fs::write(&self.script, remaining)
                .map_err(|_| unavailable("cannot update the script"))?;
            serde_json::from_str(first).map_err(|_| unavailable("a bad line in the script"))
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
            }))
        }
    }

    struct ScriptedWindow {
        inner: Arc<Inner>,
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
            let answer = self.inner.pop()?;
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
            let answer = self.inner.pop()?;
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
            self.inner.pop().map(|_| ())
        }

        fn show_recovery_key(&mut self, panel: &Panel, key: &Secret) -> Result<bool, SurfaceError> {
            self.inner.log(json!({
                "ask": "recovery", "shown": key.expose(), "panel": panel_json(panel)
            }));
            let answer = self.inner.pop()?;
            Ok(answer.get("ack").is_some())
        }

        fn close(self: Box<Self>, message: Option<&str>) {
            self.inner.log(json!({"close": message}));
        }
    }
}
