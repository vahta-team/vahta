//! The prompt surface: where the person reads what Vahta is about to do and
//! types a password or a value.
//!
//! A [`PromptSurface`] opens a [`Window`] for one request; the window asks its
//! questions and is closed when the request is over. The real surface,
//! [`TerminalSurface`], opens a *new* terminal window running `vahta _surface`
//! (never the caller's terminal) that connects back to the daemon with a
//! one-time token. That connection is the only one that carries a password, a
//! typed value or a value to show. Tests use a scripted surface instead (see
//! [`crate::testing`]), which is why this is a trait.
//!
//! What the person approves is what Vahta renders into the [`Panel`]: project,
//! vault path, names, duration and anchor. The one thing an agent writes, a
//! `--label`, is sanitised by [`sanitize_label`] and shown marked as unverified.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vahta_os::ProcessId;
use vahta_os::ipc::{Address, Stream};

use crate::protocol::{
    Panel, ProtocolError, Secret, SurfaceAnswer, SurfaceRequest, read_frame, write_frame,
};
use crate::terminal::{self, Environment, Launch};

/// Why a window could not do what was asked.
#[derive(Debug)]
pub enum SurfaceError {
    /// No window could be opened (no display, no terminal, a script that has
    /// run out). The request fails closed: nothing was done.
    Unavailable(String),
    /// The person did not answer in time.
    Timeout,
    /// The window was closed before it answered.
    Closed,
    /// The window said something this daemon does not understand.
    Protocol(String),
}

impl fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SurfaceError::Unavailable(why) => f.write_str(why),
            SurfaceError::Timeout => f.write_str("the prompt window was not answered in time"),
            SurfaceError::Closed => f.write_str("the prompt window was closed"),
            SurfaceError::Protocol(why) => write!(f, "the prompt window misbehaved: {why}"),
        }
    }
}

impl std::error::Error for SurfaceError {}

/// Opens windows.
pub trait PromptSurface: Send + Sync {
    /// A window for one request, titled `title`.
    fn open(&self, title: &str) -> Result<Box<dyn Window>, SurfaceError>;
}

/// One window, for one request. It may be asked several things in turn (the
/// password, then a value twice) and is closed by [`Window::close`] or by being
/// dropped.
pub trait Window: Send {
    /// A password. `None` is the person cancelling. With `confirm` it is asked
    /// twice and only a matching pair comes back.
    fn ask_password(
        &mut self,
        panel: &Panel,
        prompt: &str,
        confirm: bool,
    ) -> Result<Option<Secret>, SurfaceError>;

    /// A value to store, hidden as it is typed; `None` is cancelling.
    fn ask_value(
        &mut self,
        panel: &Panel,
        prompt: &str,
        confirm: bool,
    ) -> Result<Option<Secret>, SurfaceError>;

    /// Yes or no, for as long as `timeout`. `None` is no answer: cancelled, or
    /// the time ran out.
    fn confirm(
        &mut self,
        panel: &Panel,
        question: &str,
        timeout: Option<Duration>,
    ) -> Result<Option<bool>, SurfaceError>;

    /// One of `options`; `None` is cancelling.
    fn choose(
        &mut self,
        panel: &Panel,
        question: &str,
        options: &[String],
    ) -> Result<Option<usize>, SurfaceError>;

    /// A line of plain text typed in the open (a name, never a value); `None`
    /// is cancelling.
    fn ask_text(&mut self, panel: &Panel, prompt: &str) -> Result<Option<String>, SurfaceError>;

    /// Show a value until a key is pressed or `seconds` pass.
    fn show_value(
        &mut self,
        panel: &Panel,
        what: &str,
        value: &Secret,
        seconds: u32,
    ) -> Result<(), SurfaceError>;

    /// Show the recovery key once and ask for an acknowledgement. `false` is
    /// the window being closed or cancelled without one.
    fn show_recovery_key(&mut self, panel: &Panel, key: &Secret) -> Result<bool, SurfaceError>;

    /// End the conversation, with a last line for the person.
    fn close(self: Box<Self>, message: Option<&str>);
}

// --- What an agent may write ---------------------------------------------------------

/// The longest description from an agent that a window shows.
pub const MAX_LABEL: usize = 200;

/// An agent's `--label`, made safe to put in front of a person: control
/// characters and ANSI escape sequences removed, line breaks turned into
/// spaces, one line, at most [`MAX_LABEL`] characters. `None` when nothing is
/// left.
pub fn sanitize_label(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                // CSI (`ESC [ ... final`), OSC (`ESC ] ... BEL or ST`), or a
                // two-character escape: all dropped, with their parameters.
                match chars.peek() {
                    Some('[') => {
                        chars.next();
                        for n in chars.by_ref() {
                            if ('\u{40}'..='\u{7e}').contains(&n) {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        chars.next();
                        while let Some(n) = chars.next() {
                            if n == '\u{7}' {
                                break;
                            }
                            if n == '\u{1b}' {
                                chars.next();
                                break;
                            }
                        }
                    }
                    Some(_) => {
                        chars.next();
                    }
                    None => {}
                }
            }
            '\n' | '\r' | '\t' | '\u{85}' | '\u{2028}' | '\u{2029}' => out.push(' '),
            c if c.is_control() => {}
            // Bidirectional overrides and zero-width characters can make one
            // line read as another.
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {}
            c => out.push(c),
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let truncated: String = collapsed.chars().take(MAX_LABEL).collect();
    (!truncated.is_empty()).then_some(truncated)
}

// --- The registry of windows waiting for their connection ------------------------

/// A window's connection, with the kernel-verified process that made it.
pub type Arrival = (Stream, ProcessId);

/// The one-time tokens the daemon has issued, each for one window of one
/// request. A window's connection presents its token in the hello; the server
/// hands the connection to whoever is waiting on it, and the token is gone.
///
/// A token alone does not prove the window: it travels in the environment,
/// which other processes of the same user can read. [`TerminalSurface`] also
/// checks the process that arrived with it.
#[derive(Default)]
pub struct SurfaceRegistry {
    pending: Mutex<HashMap<String, SyncSender<Arrival>>>,
}

impl SurfaceRegistry {
    /// A new token and the channel its window's connection will arrive on.
    pub fn issue(&self) -> Result<(String, Receiver<Arrival>), SurfaceError> {
        let bytes = vahta_vault::crypto::random::<32>()
            .map_err(|_| SurfaceError::Unavailable("the system random generator failed".into()))?;
        let token = vahta_vault::hex_encode(&bytes);
        let (tx, rx) = mpsc::sync_channel(1);
        self.pending
            .lock()
            .map_err(|_| SurfaceError::Unavailable("poisoned".into()))?
            .insert(token.clone(), tx);
        Ok((token, rx))
    }

    /// Hand `stream` to the request waiting on `token`. The token is used up
    /// either way; an unknown or spent one gives the stream back.
    pub fn claim(&self, token: &str, stream: Stream, peer: ProcessId) -> Result<(), Stream> {
        let tx = self.pending.lock().ok().and_then(|mut p| p.remove(token));
        match tx {
            Some(tx) => tx.send((stream, peer)).map_err(|e| e.0.0),
            None => Err(stream),
        }
    }

    /// Whether `token` is waiting for its window.
    pub fn has(&self, token: &str) -> bool {
        self.pending
            .lock()
            .map(|p| p.contains_key(token))
            .unwrap_or(false)
    }

    /// Withdraw a token whose request has given up.
    pub fn cancel(&self, token: &str) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(token);
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }
}

// --- The terminal surface -----------------------------------------------------------------

/// How long a person gets to answer a password prompt.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Opens a new terminal window per request.
pub struct TerminalSurface {
    registry: Arc<SurfaceRegistry>,
    address: Address,
    /// `terminal` from config.toml.
    terminal: String,
    /// This executable, which also runs the window (`vahta _surface`).
    exe: PathBuf,
}

impl TerminalSurface {
    pub fn new(
        registry: Arc<SurfaceRegistry>,
        address: Address,
        terminal: String,
        exe: PathBuf,
    ) -> TerminalSurface {
        TerminalSurface {
            registry,
            address,
            terminal,
            exe,
        }
    }
}

impl PromptSurface for TerminalSurface {
    fn open(&self, _title: &str) -> Result<Box<dyn Window>, SurfaceError> {
        let (token, rx) = self.registry.issue()?;
        let launch = Launch {
            program: self.exe.clone(),
            args: vec!["_surface".to_string()],
            env: vec![
                ("VAHTA_SURFACE_TOKEN".to_string(), token.clone()),
                (
                    "VAHTA_SURFACE_ADDR".to_string(),
                    self.address.as_os_str().to_string_lossy().into_owned(),
                ),
            ],
        };
        let opened = terminal::open(
            &launch,
            &self.terminal,
            &Environment::from_process(),
            &mut |wait| rx.recv_timeout(wait).ok(),
        );
        self.registry.cancel(&token);
        let (child, (stream, peer)) =
            opened.map_err(|e| SurfaceError::Unavailable(e.to_string()))?;
        if !window_is_ours(child.as_ref(), peer, &self.exe) {
            // Whoever read the token answered first. The real window then finds
            // its token spent and says so; nothing is asked of this one.
            let _ = stream.shutdown();
            return Err(SurfaceError::Unavailable(
                "a process other than the window Vahta opened answered it; refused".to_string(),
            ));
        }
        Ok(Box::new(TerminalWindow::new(stream, child)))
    }
}

/// Whether `peer`, which presented a window's token, is that window: a process
/// started inside the terminal this daemon launched (on Windows, the console
/// process itself). Without this, a process that read the token from the
/// environment could answer a yes/no question (extending a session) or choose
/// the password of a new vault.
///
/// macOS opens Terminal.app through `osascript`, so the window is not our
/// descendant there; it is accepted when it runs this executable under
/// Terminal. That is weaker, and the hook keeps agents from running
/// `vahta _surface` themselves.
fn window_is_ours(child: Option<&Child>, peer: ProcessId, exe: &Path) -> bool {
    let chain = vahta_os::ancestor_chain(peer.pid, 64);
    if chain.first() != Some(&peer) {
        return false;
    }
    if let Some(child) = child {
        let launched = vahta_os::identity_of(child.id()).ok();
        if chain.iter().any(|p| Some(*p) == launched) {
            return true;
        }
    }
    if cfg!(target_os = "macos") {
        let ours = exe.file_name().and_then(|n| n.to_str());
        return ours.is_some()
            && vahta_os::exe_name(peer.pid).as_deref() == ours
            && chain
                .iter()
                .any(|p| vahta_os::exe_name(p.pid).as_deref() == Some("Terminal"));
    }
    false
}

/// A window on the far end of a surface connection.
struct TerminalWindow {
    stream: Stream,
    answers: Receiver<Result<SurfaceAnswer, ProtocolError>>,
    _child: Option<Child>,
}

impl TerminalWindow {
    fn new(stream: Stream, child: Option<Child>) -> TerminalWindow {
        let (tx, answers) = mpsc::channel();
        // A reader thread turns the blocking socket into something that can be
        // waited on with a timeout.
        if let Ok(mut reader) = stream.try_clone() {
            std::thread::spawn(move || {
                loop {
                    match read_frame::<SurfaceAnswer>(&mut reader) {
                        Ok(Some(answer)) => {
                            if tx.send(Ok(answer)).is_err() {
                                return;
                            }
                        }
                        Ok(None) => return,
                        Err(e) => {
                            let _ = tx.send(Err(e));
                            return;
                        }
                    }
                }
            });
        }
        TerminalWindow {
            stream,
            answers,
            _child: child,
        }
    }

    fn exchange(
        &mut self,
        request: &SurfaceRequest,
        timeout: Duration,
    ) -> Result<SurfaceAnswer, SurfaceError> {
        write_frame(&mut self.stream, request).map_err(|_| SurfaceError::Closed)?;
        match self.answers.recv_timeout(timeout) {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(ProtocolError::Garbage(why))) => Err(SurfaceError::Protocol(why)),
            Ok(Err(_)) => Err(SurfaceError::Closed),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // End the conversation: the reader thread returns with it.
                let _ = self.stream.shutdown();
                Err(SurfaceError::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SurfaceError::Closed),
        }
    }

    fn secret(&mut self, request: SurfaceRequest) -> Result<Option<Secret>, SurfaceError> {
        match self.exchange(&request, ANSWER_TIMEOUT)? {
            SurfaceAnswer::Secret { value } => Ok(Some(value)),
            SurfaceAnswer::Cancel {} => Ok(None),
            _ => Err(SurfaceError::Protocol("unexpected answer".to_string())),
        }
    }
}

impl Window for TerminalWindow {
    fn ask_password(
        &mut self,
        panel: &Panel,
        prompt: &str,
        confirm: bool,
    ) -> Result<Option<Secret>, SurfaceError> {
        self.secret(SurfaceRequest::Password {
            panel: panel.clone(),
            prompt: prompt.to_string(),
            confirm,
        })
    }

    fn ask_value(
        &mut self,
        panel: &Panel,
        prompt: &str,
        confirm: bool,
    ) -> Result<Option<Secret>, SurfaceError> {
        self.secret(SurfaceRequest::Value {
            panel: panel.clone(),
            prompt: prompt.to_string(),
            confirm,
        })
    }

    fn confirm(
        &mut self,
        panel: &Panel,
        question: &str,
        timeout: Option<Duration>,
    ) -> Result<Option<bool>, SurfaceError> {
        let wait = timeout.unwrap_or(ANSWER_TIMEOUT);
        let request = SurfaceRequest::Confirm {
            panel: panel.clone(),
            question: question.to_string(),
            timeout_secs: timeout.map(|t| t.as_secs().max(1)),
        };
        // A little longer than the window itself waits, so its own timeout
        // answers first.
        match self.exchange(&request, wait + Duration::from_secs(5)) {
            Ok(SurfaceAnswer::Yes {}) => Ok(Some(true)),
            Ok(SurfaceAnswer::No {}) => Ok(Some(false)),
            Ok(SurfaceAnswer::Cancel {}) | Err(SurfaceError::Timeout | SurfaceError::Closed) => {
                Ok(None)
            }
            Ok(_) => Err(SurfaceError::Protocol("unexpected answer".to_string())),
            Err(e) => Err(e),
        }
    }

    fn choose(
        &mut self,
        panel: &Panel,
        question: &str,
        options: &[String],
    ) -> Result<Option<usize>, SurfaceError> {
        let request = SurfaceRequest::Choose {
            panel: panel.clone(),
            question: question.to_string(),
            options: options.to_vec(),
        };
        match self.exchange(&request, ANSWER_TIMEOUT)? {
            SurfaceAnswer::Choice { index } if index < options.len() => Ok(Some(index)),
            SurfaceAnswer::Cancel {} => Ok(None),
            _ => Err(SurfaceError::Protocol("unexpected answer".to_string())),
        }
    }

    fn ask_text(&mut self, panel: &Panel, prompt: &str) -> Result<Option<String>, SurfaceError> {
        let request = SurfaceRequest::Text {
            panel: panel.clone(),
            prompt: prompt.to_string(),
        };
        match self.exchange(&request, ANSWER_TIMEOUT)? {
            SurfaceAnswer::Text { value } => Ok(Some(value)),
            SurfaceAnswer::Cancel {} => Ok(None),
            _ => Err(SurfaceError::Protocol("unexpected answer".to_string())),
        }
    }

    fn show_value(
        &mut self,
        panel: &Panel,
        what: &str,
        value: &Secret,
        seconds: u32,
    ) -> Result<(), SurfaceError> {
        let request = SurfaceRequest::Show {
            panel: panel.clone(),
            what: what.to_string(),
            value: value.clone(),
            seconds: Some(seconds),
            acknowledge: false,
        };
        let wait = Duration::from_secs(u64::from(seconds) + 15);
        match self.exchange(&request, wait)? {
            SurfaceAnswer::Done {} | SurfaceAnswer::Cancel {} => Ok(()),
            _ => Err(SurfaceError::Protocol("unexpected answer".to_string())),
        }
    }

    fn show_recovery_key(&mut self, panel: &Panel, key: &Secret) -> Result<bool, SurfaceError> {
        let request = SurfaceRequest::Show {
            panel: panel.clone(),
            what: "recovery key".to_string(),
            value: key.clone(),
            seconds: None,
            acknowledge: true,
        };
        match self.exchange(&request, ANSWER_TIMEOUT)? {
            SurfaceAnswer::Done {} => Ok(true),
            SurfaceAnswer::Cancel {} => Ok(false),
            _ => Err(SurfaceError::Protocol("unexpected answer".to_string())),
        }
    }

    fn close(mut self: Box<Self>, message: Option<&str>) {
        let _ = write_frame(
            &mut self.stream,
            &SurfaceRequest::Close {
                message: message.map(str::to_string),
            },
        );
    }
}

impl Drop for TerminalWindow {
    fn drop(&mut self) {
        // Give the window a moment to show its last line before the
        // connection goes; the window ends when the connection does.
        let _ = self.stream.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_one_plain_line_of_at_most_200_characters() {
        assert_eq!(
            sanitize_label("deploy the site").unwrap(),
            "deploy the site"
        );
        // ANSI and control characters are removed, not shown.
        assert_eq!(
            sanitize_label("\u{1b}[31mred\u{1b}[0m \u{7}bell\u{1b}]0;title\u{7}x").unwrap(),
            "red bellx"
        );
        // Line breaks cannot fake a second line of the window.
        assert_eq!(
            sanitize_label("harmless\nProject: /etc\r\nApprove: yes").unwrap(),
            "harmless Project: /etc Approve: yes"
        );
        // Bidi overrides and zero-width characters are dropped.
        assert_eq!(sanitize_label("a\u{202e}b\u{200b}c").unwrap(), "abc");
        // Long labels are cut.
        let long = "x".repeat(500);
        assert_eq!(sanitize_label(&long).unwrap().chars().count(), MAX_LABEL);
        // Nothing left means no label.
        assert_eq!(sanitize_label("\u{1b}[0m \n\t"), None);
        assert_eq!(sanitize_label(""), None);
        // A lone escape at the end does not panic.
        assert_eq!(sanitize_label("ok\u{1b}").unwrap(), "ok");
    }

    fn me() -> ProcessId {
        vahta_os::identity_of(std::process::id()).unwrap()
    }

    #[test]
    #[cfg(unix)]
    fn a_window_must_be_inside_the_terminal_we_launched() {
        let exe = std::env::current_exe().unwrap();
        // A process we started stands in for the terminal. A window that is
        // the launched process itself (as on Windows) is ours.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let child_id = vahta_os::identity_of(child.id()).unwrap();
        assert!(window_is_ours(Some(&child), child_id, &exe));
        // This test process is not inside that child.
        assert!(!window_is_ours(Some(&child), me(), &exe));
        // No launcher to compare with (a server-mode terminal).
        assert!(!window_is_ours(None, me(), &exe));
        // An identity that no longer matches: gone, or a reused pid.
        let stale = ProcessId {
            pid: child_id.pid,
            start_time: child_id.start_time.wrapping_add(1),
        };
        assert!(!window_is_ours(Some(&child), stale, &exe));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_token_is_single_use() {
        let registry = SurfaceRegistry::default();
        let (token, rx) = registry.issue().unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(registry.pending(), 1);
        // A different token is not this one.
        let (a, _b) = pair();
        assert!(registry.claim("not-a-token", a, me()).is_err());
        assert_eq!(registry.pending(), 1);
        let (c, _d) = pair();
        registry.claim(&token, c, me()).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
        // Used up.
        let (e, _f) = pair();
        assert!(registry.claim(&token, e, me()).is_err());
        assert_eq!(registry.pending(), 0);
        // Two tokens differ.
        let (t1, _r1) = registry.issue().unwrap();
        let (t2, _r2) = registry.issue().unwrap();
        assert_ne!(t1, t2);
        registry.cancel(&t1);
        assert_eq!(registry.pending(), 1);
    }

    /// Two connected streams, through a throwaway listener.
    fn pair() -> (Stream, Stream) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vahta-surf-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let addr = Address::for_runtime_dir(&dir).unwrap();
        let listener = vahta_os::ipc::Listener::bind(&addr).unwrap();
        let server = std::thread::spawn(move || listener.accept().unwrap());
        let client = Stream::connect(&addr).unwrap();
        let server = server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (client, server)
    }
}
