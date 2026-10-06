//! The daemon's accept loop.
//!
//! One daemon per user: it holds an exclusive lock on `daemon.lock` in the
//! runtime directory for as long as it lives, and owns the socket. One thread
//! per connection (std threads, no async runtime). It exits when it has been
//! idle, with no connections and no sessions, for the configured time.
//!
//! Every connection starts with a [`Hello`]; the peer's process is taken from
//! the kernel at accept, and a connection from another user is dropped before a
//! byte is read.

use std::fmt;
use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vahta_os::ipc::{Address, Listener, Stream};
use vahta_vault::KdfParams;
use vahta_vault::store::LocalStore;

use crate::config::Config;
use crate::journal::Entry as JournalEntry;
use crate::journal::{Entry, Journal};
use crate::ops::{self, Ctx};
use crate::output::{self, Outputs};
use crate::paths::{PathError, Paths};
use crate::protocol::{
    ClientReply, ClientRequest, Hello, HelloKind, HelloReply, PROTOCOL, ProtocolError, StatusInfo,
    read_frame, write_frame,
};
use crate::session::{EXTEND_BY, ExtensionAsk, Sessions};
use crate::session_ops;
use crate::surface::{PromptSurface, SurfaceRegistry, TerminalSurface};
use crate::{run, run_ops};

#[derive(Debug)]
pub enum ServerError {
    /// Another daemon holds the lock.
    AlreadyRunning,
    Path(PathError),
    Io(&'static str, io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::AlreadyRunning => f.write_str("a Vahta daemon is already running"),
            ServerError::Path(e) => e.fmt(f),
            ServerError::Io(what, e) => write!(f, "cannot {what}: {e}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<PathError> for ServerError {
    fn from(e: PathError) -> Self {
        ServerError::Path(e)
    }
}

pub struct Options {
    pub paths: Paths,
    pub config: Config,
    /// What the handshake reports; [`crate::VERSION`] outside tests.
    pub version: String,
    /// Exit after this long with no connection and no session.
    pub idle: Duration,
    /// Apply the process hardening (not dumpable, no core files, locked
    /// memory). On for the real daemon; a test that runs the server inside its
    /// own process leaves it off.
    pub harden: bool,
    /// What opens the prompt window. `None` is the real one, a new terminal
    /// window; a test build supplies a scripted one.
    pub surface: Option<Box<dyn PromptSurface>>,
    /// The cost of a new vault's password hash.
    pub kdf: KdfParams,
    /// How long a copied value stays on the clipboard.
    pub clipboard_clear: Duration,
    /// The executable that runs the prompt window; this one when `None`.
    pub exe: Option<PathBuf>,
}

impl Options {
    pub fn new(paths: Paths, config: Config) -> Options {
        let idle = Duration::from_secs(config.idle_minutes * 60);
        Options {
            paths,
            config,
            version: crate::VERSION.to_string(),
            idle,
            harden: true,
            surface: None,
            kdf: KdfParams::PRODUCTION,
            clipboard_clear: Duration::from_secs(30),
            exe: None,
        }
    }
}

/// What every connection thread shares.
pub(crate) struct Shared {
    pub(crate) options: Options,
    pub(crate) journal: Arc<Journal>,
    pub(crate) address: Address,
    pub(crate) surface: Box<dyn PromptSurface>,
    pub(crate) registry: Arc<SurfaceRegistry>,
    pub(crate) store: LocalStore,
    pub(crate) sessions: Mutex<Sessions>,
    /// Tool outputs kept for the agent to ask about, and what the person has
    /// let through (see `output.rs`).
    pub(crate) outputs: Mutex<Outputs>,
    started: Instant,
    stop: AtomicBool,
    connections: AtomicUsize,
    last_activity: Mutex<Instant>,
}

impl Shared {
    pub(crate) fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn live_sessions(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub(crate) fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Ask the accept loop to end, and wake it: it is blocked in `accept`, so
    /// a connection to ourselves is what lets it see the flag.
    pub(crate) fn request_stop(&self) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            let _ = Stream::connect(&self.address);
        }
    }

    pub(crate) fn status(&self) -> StatusInfo {
        StatusInfo {
            version: self.options.version.clone(),
            pid: std::process::id(),
            sessions: self.live_sessions(),
            connections: self.connections.load(Ordering::SeqCst),
            uptime_secs: self.started.elapsed().as_secs(),
            runtime_dir: self.options.paths.runtime.display().to_string(),
        }
    }
}

/// Counts a connection while it is open and counts the quiet from its end.
struct ConnectionGuard(Arc<Shared>);

impl ConnectionGuard {
    fn new(shared: &Arc<Shared>) -> ConnectionGuard {
        shared.connections.fetch_add(1, Ordering::SeqCst);
        shared.touch();
        ConnectionGuard(shared.clone())
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

/// Run the daemon in this process until it is stopped or idle. Returns when it
/// has cleaned up.
pub fn run(mut options: Options) -> Result<(), ServerError> {
    options.paths.ensure_runtime_dir()?;
    options.paths.ensure_data_dir()?;

    // The lock is held by the open file, for the life of the process.
    let lock_path = options.paths.lock_file();
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| ServerError::Io("open the daemon lock", e))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(ServerError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(ServerError::Io("take the daemon lock", e));
        }
    }

    let journal = Arc::new(Journal::open(&options.paths.journal_file()));
    if options.harden {
        if let Err(e) = vahta_os::harden_process() {
            journal.record(Entry::new("harden").result("partial", Some(&e.to_string())));
        }
        vahta_os::detach_session();
    }

    let address = options.paths.address()?;
    let listener =
        Listener::bind(&address).map_err(|e| ServerError::Io("listen on the socket", e))?;
    journal.record(Entry::new("daemon_start").result("ok", Some(&options.version)));

    let registry = Arc::new(SurfaceRegistry::default());
    let surface: Box<dyn PromptSurface> = match options.surface.take() {
        Some(s) => s,
        None => {
            let exe = match options.exe.clone() {
                Some(e) => e,
                None => std::env::current_exe()
                    .map_err(|e| ServerError::Io("find its own executable", e))?,
            };
            Box::new(TerminalSurface::new(
                registry.clone(),
                address.clone(),
                options.config.terminal.clone(),
                exe,
            ))
        }
    };
    let store = LocalStore::new(options.paths.data.clone());
    let outputs = Outputs::new().ok_or_else(|| {
        ServerError::Io(
            "draw a key",
            io::Error::other("the system random generator failed"),
        )
    })?;
    let shared = Arc::new(Shared {
        options,
        journal,
        address,
        surface,
        registry,
        store,
        sessions: Mutex::new(Sessions::default()),
        outputs: Mutex::new(outputs),
        started: Instant::now(),
        stop: AtomicBool::new(false),
        connections: AtomicUsize::new(0),
        last_activity: Mutex::new(Instant::now()),
    });

    let idle_shared = shared.clone();
    std::thread::spawn(move || idle_watch(&idle_shared));
    let sweep_shared = shared.clone();
    std::thread::spawn(move || sweep_sessions(&sweep_shared));
    crate::sleep::start(&shared);

    while !shared.stopping() {
        match listener.accept() {
            Ok(stream) => {
                if shared.stopping() {
                    break;
                }
                let conn_shared = shared.clone();
                // A failure to start a thread drops the connection; the daemon
                // carries on.
                let _ = std::thread::Builder::new()
                    .name("vahta-conn".to_string())
                    .spawn(move || handle_connection(&conn_shared, stream));
            }
            Err(_) if shared.stopping() => break,
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    // Every session ends with the daemon, keys overwritten.
    shared.end_all_sessions("daemon_stop");
    shared
        .journal
        .record(Entry::new("daemon_stop").result("ok", None));
    if let Some(sock) = shared.address.socket_path() {
        let _ = std::fs::remove_file(sock);
    }
    drop(lock);
    Ok(())
}

fn idle_watch(shared: &Arc<Shared>) {
    while !shared.stopping() {
        std::thread::sleep(Duration::from_millis(250));
        if shared.connections.load(Ordering::SeqCst) == 0
            && shared.live_sessions() == 0
            && shared.idle_for() >= shared.options.idle
        {
            shared
                .journal
                .record(Entry::new("daemon_idle_exit").result("ok", None));
            shared.request_stop();
        }
    }
}

/// Once a half second: end sessions that have run out or lost their anchor,
/// ask about extending the ones near their end, and let go of tool outputs
/// and released values whose time is up.
fn sweep_sessions(shared: &Arc<Shared>) {
    let alive = |p: &vahta_os::ProcessId| vahta_os::identity_of(p.pid).is_ok_and(|id| id == *p);
    while !shared.stopping() {
        std::thread::sleep(Duration::from_millis(500));
        let swept = match shared.sessions.lock() {
            Ok(mut sessions) => sessions.sweep(Instant::now(), &alive),
            Err(_) => continue,
        };
        // Taken one after the other, never one inside the other.
        let live: Vec<String> = shared
            .sessions
            .lock()
            .map(|s| s.infos(Instant::now()).into_iter().map(|i| i.id).collect())
            .unwrap_or_default();
        if let Ok(mut outputs) = shared.outputs.lock() {
            outputs.sweep(Instant::now(), &alive, &|id| live.iter().any(|l| l == id));
        }
        shared.record_ended(swept.ended);
        for ask in swept.ask {
            let shared = shared.clone();
            let _ = std::thread::Builder::new()
                .name("vahta-extend".to_string())
                .spawn(move || ask_to_extend(&shared, ask));
        }
    }
}

/// Two minutes before a session ends: "Extend by 30 minutes?". Yes or no, no
/// password, because the keys are still in memory. With no answer the session
/// ends at its deadline.
fn ask_to_extend(shared: &Arc<Shared>, ask: ExtensionAsk) {
    let record = |result: &str, reason: &str| {
        shared.journal.record(
            JournalEntry::new("session_extension")
                .session(&ask.id, None)
                .names(&ask.scope)
                .result(result, Some(reason)),
        );
    };
    let mut window = match shared.surface.open("Extend a session") {
        Ok(w) => w,
        Err(_) => {
            record("not_asked", "no window could be opened");
            return;
        }
    };
    let left = ask.deadline.saturating_duration_since(Instant::now());
    let panel = crate::protocol::Panel {
        title: "Extend a session".to_string(),
        lines: vec![
            format!("Project: {}", ask.project.display()),
            format!("Secrets: {}", ask.scope.join(", ")),
            format!("Belongs to: {} (pid {})", ask.anchor_exe, ask.anchor_pid),
            format!("It ends in {} seconds.", left.as_secs()),
        ],
        warning: None,
        agent_note: None,
    };
    match window.confirm(&panel, "Extend by 30 minutes?", Some(left)) {
        Ok(Some(true)) => {
            let extended = shared
                .sessions
                .lock()
                .map(|mut s| s.extend(&ask.id, Instant::now(), EXTEND_BY))
                .unwrap_or(false);
            if extended {
                record("extended", "30 minutes");
            } else {
                record("not_extended", "the session had already ended");
            }
        }
        Ok(Some(false)) => record("declined", "the person said no"),
        _ => record("no_answer", "it ends at its deadline"),
    }
    window.close(None);
}

fn reject(stream: &mut Stream, shared: &Shared, why: &str) {
    let reply = HelloReply {
        ok: false,
        protocol: PROTOCOL,
        version: shared.options.version.clone(),
        pid: std::process::id(),
        sessions: shared.live_sessions(),
        error: Some(why.to_string()),
    };
    let _ = write_frame(stream, &reply);
}

fn handle_connection(shared: &Arc<Shared>, mut stream: Stream) {
    let _guard = ConnectionGuard::new(shared);
    // Who connected comes from the kernel. Another user's connection is
    // dropped without reading a byte.
    let peer = match stream.peer() {
        Ok(p) if p.same_user => p,
        Ok(_) | Err(_) => {
            shared.journal.record(
                Entry::new("connection").result("refused", Some("unknown or foreign peer")),
            );
            return;
        }
    };
    let hello: Hello = match read_frame(&mut stream) {
        Ok(Some(h)) => h,
        _ => return,
    };
    if hello.protocol != PROTOCOL {
        reject(&mut stream, shared, "protocol version mismatch");
        return;
    }
    let ok = HelloReply {
        ok: true,
        protocol: PROTOCOL,
        version: shared.options.version.clone(),
        pid: std::process::id(),
        sessions: shared.live_sessions(),
        error: None,
    };
    let hello_ok = match &hello.kind {
        HelloKind::Surface { token } => shared.registry.has(token),
        HelloKind::Client => true,
    };
    if !hello_ok {
        reject(&mut stream, shared, "no request is waiting for a window");
        return;
    }
    if write_frame(&mut stream, &ok).is_err() {
        return;
    }
    match hello.kind {
        HelloKind::Client => client_loop(shared, &mut stream, &peer),
        HelloKind::Surface { token } => {
            // If the token is spent between the check above and here, there is
            // no request to hand the window to and the connection just ends.
            if let Err(stream) = shared.registry.claim(&token, stream, peer.id) {
                let _ = stream.shutdown();
            }
        }
    }
}

fn client_loop(shared: &Arc<Shared>, stream: &mut Stream, peer: &vahta_os::Peer) {
    loop {
        let request: ClientRequest = match read_frame(stream) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(ProtocolError::Io(_)) | Err(ProtocolError::Truncated) => return,
            Err(e) => {
                let _ = write_frame(
                    stream,
                    &ClientReply::Error {
                        message: e.to_string(),
                    },
                );
                return;
            }
        };
        shared.touch();
        let ctx = Ctx {
            shared,
            exe: vahta_os::exe_name(peer.id.pid),
            pid: peer.id.pid,
            peer: peer.id,
        };
        let (reply, stop) = match request {
            ClientRequest::Status {} => (ClientReply::Status(shared.status()), false),
            ClientRequest::Stop {} => (ClientReply::Ok {}, true),
            ClientRequest::Init { cwd } => (ops::init(&ctx, &cwd).unwrap_or_else(|r| r), false),
            ClientRequest::Set {
                cwd,
                name,
                tier,
                file,
            } => (
                ops::set(&ctx, &cwd, &name, ops::vault_tier(tier), file.as_deref())
                    .unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::Remove { cwd, name } => {
                (ops::remove(&ctx, &cwd, &name).unwrap_or_else(|r| r), false)
            }
            ClientRequest::Import { cwd, source } => (
                ops::import(&ctx, &cwd, &source).unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::Reveal { cwd, name } => {
                (ops::reveal(&ctx, &cwd, &name).unwrap_or_else(|r| r), false)
            }
            ClientRequest::Copy { cwd, name } => {
                (ops::copy(&ctx, &cwd, &name).unwrap_or_else(|r| r), false)
            }
            ClientRequest::Unlock {
                cwd,
                names,
                duration,
                label,
            } => (
                session_ops::unlock_session(&ctx, &cwd, names, duration, label)
                    .unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::Lock { cwd, all } => (
                session_ops::lock(&ctx, &cwd, all).unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::Run {
                cwd,
                argv,
                env,
                names,
                renames,
                label,
            } => {
                // A run is the one request that goes on after its reply: the
                // connection then carries the command's input and output.
                match run_ops::prepare(&ctx, &cwd, argv, env, names, renames, label) {
                    Ok(prepared) => {
                        if write_frame(stream, &ClientReply::RunStarted {}).is_ok() {
                            run::execute(shared, stream, prepared, (ctx.exe.clone(), ctx.pid));
                        }
                        return;
                    }
                    Err(reply) => (reply, false),
                }
            }
            ClientRequest::Delegate {
                cwd,
                names,
                duration,
                label,
            } => (
                run_ops::delegate(&ctx, &cwd, names, duration, label).unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::OutputScan {
                cwd,
                tool,
                texts,
                spans,
                possible,
            } => (
                output::scan(&ctx, cwd, tool, texts, spans, possible).unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::OutputAllow { reference, reason } => (
                output::allow(&ctx, &reference, reason).unwrap_or_else(|r| r),
                false,
            ),
            ClientRequest::Sessions {} => (session_ops::list(&ctx).unwrap_or_else(|r| r), false),
            ClientRequest::SessionKill { id } => {
                (session_ops::kill(&ctx, &id).unwrap_or_else(|r| r), false)
            }
        };
        if write_frame(stream, &reply).is_err() {
            return;
        }
        if stop {
            shared
                .journal
                .record(Entry::new("daemon_stop_requested").result("ok", None));
            shared.request_stop();
            return;
        }
    }
}
