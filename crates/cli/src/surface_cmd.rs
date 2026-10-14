//! `vahta _surface`: the prompt window.
//!
//! Not a command anyone types. The daemon opens a new terminal window running
//! this, with a one-time ticket and its address in the environment (on macOS, in
//! a file named by `--env-file`, which is read and deleted). It connects back,
//! proves itself with the ticket, and then does what the daemon asks: show what
//! is about to happen, read a password or a value with the terminal's echo off,
//! ask yes or no, show a value for a while. Everything on its screen is
//! rendered from what the daemon sent, with control characters made harmless.
//!
//! This is the only process outside the daemon that ever holds a password, a
//! typed value or a revealed value, and it holds each for as long as a prompt
//! takes.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vahta_ipc::protocol::{
    Hello, HelloKind, HelloReply, PROTOCOL, Panel, Secret, SurfaceAnswer, SurfaceRequest,
    read_frame, write_frame,
};
use vahta_os::ipc::{Address, Stream};

use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_USAGE};

/// Text from the daemon, safe to print: control characters and escapes become
/// `?`, so nothing in a name or a path can move the cursor or recolour the
/// screen.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The one-time ticket and the daemon's address, from the environment or, with
/// `--env-file`, from a file that is deleted once read.
fn credentials(args: &[String]) -> Result<(String, String), String> {
    let mut ticket = std::env::var("VAHTA_SURFACE_TOKEN").ok();
    let mut addr = std::env::var("VAHTA_SURFACE_ADDR").ok();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--env-file" {
            let path = it.next().ok_or("--env-file expects a path")?;
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read the environment file: {e}"))?;
            // Read once, then gone: it holds the ticket.
            let _ = std::fs::remove_file(path);
            for line in text.lines() {
                match line.split_once('=') {
                    Some(("VAHTA_SURFACE_TOKEN", v)) => ticket = Some(v.to_string()),
                    Some(("VAHTA_SURFACE_ADDR", v)) => addr = Some(v.to_string()),
                    _ => {}
                }
            }
        } else {
            return Err(format!("unrecognised argument: {a}"));
        }
    }
    match (ticket, addr) {
        (Some(t), Some(a)) if !t.is_empty() && !a.is_empty() => Ok((t, a)),
        _ => {
            Err("this is the daemon's prompt window; it is started by `vahta`, not by hand".into())
        }
    }
}

/// How the window reads the person. The test build can read from standard
/// input instead of the terminal, so a test can drive the real window process.
struct Console {
    plain: bool,
}

/// What was read from standard input and not yet taken as a line.
static TYPED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

impl Console {
    fn new() -> Console {
        Console {
            plain: vahta_daemon::testing::ENABLED
                && std::env::var_os("VAHTA_TEST_SURFACE_PLAIN").is_some(),
        }
    }

    fn say(&self, text: &str) {
        println!("{text}");
        let _ = std::io::stdout().flush();
    }

    fn clear(&self) {
        if !self.plain && !cfg!(windows) {
            print!("\x1b[2J\x1b[H");
            let _ = std::io::stdout().flush();
        }
    }

    /// A line typed with the echo off. `None` at end of input.
    fn hidden(&self, prompt: &str) -> Option<Secret> {
        if self.plain {
            print!("{prompt}: ");
            let _ = std::io::stdout().flush();
            return Console::line().map(Secret::new);
        }
        rpassword::prompt_password(format!("{prompt}: "))
            .ok()
            .map(Secret::new)
    }

    fn line() -> Option<String> {
        Console::line_within(None).ok().flatten()
    }

    /// A line typed in the open, waiting at most `limit` (for ever with
    /// `None`). `Err` is the time running out; a part-typed line stays for the
    /// next call. Standard input is read here and nowhere else, and only while
    /// a prompt waits on it, so no reader is left blocked when a wait ends.
    fn line_within(limit: Option<Duration>) -> Result<Option<String>, ()> {
        let until = limit.map(|l| Instant::now() + l);
        let mut typed = TYPED.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(end) = typed.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = typed.drain(..=end).collect();
                let text = String::from_utf8_lossy(&line);
                return Ok(Some(text.trim_end_matches(['\n', '\r']).to_string()));
            }
            let wait = match until {
                Some(t) => {
                    let left = t.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(());
                    }
                    left
                }
                None => Duration::from_secs(3600),
            };
            let mut chunk = [0u8; 1024];
            match vahta_os::read_stdin(&mut chunk, wait) {
                Ok(Some(0)) | Err(_) => {
                    // The end of input: a part-typed last line still counts.
                    if typed.is_empty() {
                        return Ok(None);
                    }
                    let text = String::from_utf8_lossy(&typed).into_owned();
                    typed.clear();
                    return Ok(Some(text.trim_end_matches('\r').to_string()));
                }
                Ok(Some(n)) => typed.extend_from_slice(&chunk[..n]),
                Ok(None) => {}
            }
        }
    }

    /// Throws away what was typed while a wait ran, so the next prompt does
    /// not take a stray Enter for its answer.
    fn discard_typed() {
        let mut typed = TYPED.lock().unwrap_or_else(|e| e.into_inner());
        typed.clear();
        let mut chunk = [0u8; 1024];
        while let Ok(Some(n)) = vahta_os::read_stdin(&mut chunk, Duration::ZERO) {
            if n == 0 {
                break;
            }
        }
    }

    fn panel(&self, panel: &Panel) {
        self.say("");
        self.say(&format!("=== Vahta: {} ===", safe(&panel.title)));
        for line in &panel.lines {
            self.say(&format!("  {}", safe(line)));
        }
        if let Some(note) = &panel.agent_note {
            self.say(&format!(
                "  From the agent, not verified by Vahta: {}",
                safe(note)
            ));
        }
        if let Some(warning) = &panel.warning {
            self.say(&format!("  ! {}", safe(warning)));
        }
        self.say("");
    }

    /// A hidden entry, asked twice when `confirm` and only returned when the
    /// two match.
    fn entry(&self, prompt: &str, confirm: bool) -> Option<Secret> {
        for _ in 0..3 {
            let first = self.hidden(prompt)?;
            if !confirm {
                return Some(first);
            }
            let again = self.hidden("Again to confirm")?;
            if first == again {
                return Some(first);
            }
            self.say("The two entries differ. Try again.");
        }
        None
    }
}

/// The answer to one request, or `None` for the one that needs none (the end).
fn answer_for(console: &Console, request: &SurfaceRequest) -> Option<SurfaceAnswer> {
    match request {
        SurfaceRequest::Password {
            panel,
            prompt,
            confirm,
        }
        | SurfaceRequest::Value {
            panel,
            prompt,
            confirm,
        } => {
            console.panel(panel);
            Some(match console.entry(&safe(prompt), *confirm) {
                Some(value) => SurfaceAnswer::Secret { value },
                None => SurfaceAnswer::Cancel {},
            })
        }
        SurfaceRequest::Confirm {
            panel,
            question,
            timeout_secs,
        } => {
            console.panel(panel);
            console.say(&format!("{} [y/N]", safe(question)));
            let limit = timeout_secs.map(Duration::from_secs);
            Some(match Console::line_within(limit) {
                Ok(Some(line)) => {
                    if matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                        SurfaceAnswer::Yes {}
                    } else {
                        SurfaceAnswer::No {}
                    }
                }
                Ok(None) | Err(()) => SurfaceAnswer::Cancel {},
            })
        }
        SurfaceRequest::Choose {
            panel,
            question,
            options,
            timeout_secs,
        } => {
            console.panel(panel);
            console.say(&safe(question));
            for (i, option) in options.iter().enumerate() {
                console.say(&format!("  {}) {}", i + 1, safe(option)));
            }
            // A number from the list; anything else asks again, and the end
            // of input, or the time running out, cancels.
            let until = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
            // One option is a confirmation: Enter takes it.
            let single = options.len() == 1;
            for _ in 0..3 {
                if single {
                    console.say(&format!(
                        "Press Enter to {}:",
                        safe(&options[0]).to_lowercase()
                    ));
                } else {
                    console.say(&format!("Choose 1-{}:", options.len()));
                }
                let Some(line) = line_until(until) else {
                    return Some(SurfaceAnswer::Cancel {});
                };
                if single && matches!(line.trim(), "" | "1") {
                    return Some(SurfaceAnswer::Choice { index: 0 });
                }
                if let Ok(n) = line.trim().parse::<usize>()
                    && (1..=options.len()).contains(&n)
                {
                    return Some(SurfaceAnswer::Choice { index: n - 1 });
                }
            }
            Some(SurfaceAnswer::Cancel {})
        }
        SurfaceRequest::Text {
            panel,
            prompt,
            timeout_secs,
        } => {
            console.panel(panel);
            print!("{}: ", safe(prompt));
            let _ = std::io::stdout().flush();
            let until = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
            Some(match line_until(until) {
                Some(value) => SurfaceAnswer::Text { value },
                None => SurfaceAnswer::Cancel {},
            })
        }
        SurfaceRequest::Show {
            panel,
            what,
            value,
            seconds,
            acknowledge,
        } => {
            console.panel(panel);
            console.say(&format!("{}:", safe(what)));
            console.say("");
            console.say(&format!("    {}", safe(value.expose())));
            console.say("");
            if *acknowledge {
                console.say("Press Enter when you have written it down.");
                return Some(match Console::line() {
                    Some(_) => SurfaceAnswer::Done {},
                    None => SurfaceAnswer::Cancel {},
                });
            }
            console.say("Press Enter to hide it.");
            let limit = seconds.map(|s| Duration::from_secs(u64::from(s)));
            let _ = Console::line_within(limit);
            console.clear();
            Some(SurfaceAnswer::Done {})
        }
        // Handled by the loop (`pair_wait`, `device_wait`, and a stop with
        // nothing pending).
        SurfaceRequest::Pair { .. }
        | SurfaceRequest::PairStop {}
        | SurfaceRequest::DeviceWait { .. }
        | SurfaceRequest::DeviceWaitStop {} => None,
        SurfaceRequest::Close { message } => {
            if let Some(m) = message {
                console.say(&safe(m));
                if !console.plain {
                    std::thread::sleep(Duration::from_millis(1500));
                }
            }
            None
        }
    }
}

pub fn run(args: &[String]) -> i32 {
    let (ticket, addr) = match credentials(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("vahta _surface: {msg}");
            return EXIT_USAGE;
        }
    };
    let mut stream = match Stream::connect(&Address::from_os_string(addr.into())) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vahta: cannot reach the daemon: {e}");
            return EXIT_DAEMON;
        }
    };
    let hello = Hello {
        protocol: PROTOCOL,
        version: vahta_daemon::VERSION.to_string(),
        kind: HelloKind::Surface { token: ticket },
    };
    if write_frame(&mut stream, &hello).is_err() {
        return EXIT_DAEMON;
    }
    match read_frame::<HelloReply>(&mut stream) {
        Ok(Some(r)) if r.ok => {}
        _ => {
            eprintln!("vahta: the daemon is not waiting for this window");
            return EXIT_DAEMON;
        }
    }
    let console = Console::new();
    let requests = match watch(&stream) {
        Some(r) => r,
        None => return EXIT_DAEMON,
    };
    while let Ok(request) = requests.queue.recv() {
        // A stop with no code waiting (the code was already answered).
        if matches!(
            request,
            SurfaceRequest::PairStop {} | SurfaceRequest::DeviceWaitStop {}
        ) {
            continue;
        }
        // Close only prints; the daemon may hang up while it does. Anything
        // else waits on the person, so a hang-up from here on ends the window.
        if !matches!(request, SurfaceRequest::Close { .. }) {
            requests.answering.store(true, Ordering::SeqCst);
            // The daemon hung up after sending this, before the window got to
            // it: the reader saw `answering` still false.
            if requests.closed.load(Ordering::SeqCst) {
                break;
            }
        }
        let answer = match &request {
            SurfaceRequest::Pair {
                panel,
                qr,
                text,
                seconds,
            } => Some(pair_wait(
                &console,
                panel,
                qr,
                text,
                *seconds,
                &requests.queue,
            )),
            SurfaceRequest::DeviceWait {
                panel,
                device,
                seconds,
            } => Some(device_wait(
                &console,
                panel,
                device,
                *seconds,
                &requests.queue,
            )),
            _ => answer_for(&console, &request),
        };
        requests.answering.store(false, Ordering::SeqCst);
        match answer {
            Some(answer) => {
                if write_frame(&mut stream, &answer).is_err() {
                    break;
                }
            }
            None => break,
        }
    }
    EXIT_CLEAN
}

/// Shows the pairing code and waits for the phone: the daemon's `PairStop`
/// ends it with `Done`; Enter, end of input or the time running out with
/// `Cancel`. (The line is read in short turns, so the wait can also watch the
/// daemon and no reader is left blocked when it ends.)
fn pair_wait(
    console: &Console,
    panel: &Panel,
    qr: &str,
    text: &str,
    seconds: u32,
    queue: &mpsc::Receiver<SurfaceRequest>,
) -> SurfaceAnswer {
    console.panel(panel);
    console.say("Scan this code with the Vahta app on your phone:");
    console.say("");
    for line in qr.lines() {
        console.say(&format!("    {}", safe(line)));
    }
    console.say("");
    console.say("No camera? Give the app this code instead:");
    console.say(&format!("    {}", safe(text)));
    console.say("");
    console.say(&format!(
        "Waiting for the phone ({} min). Press Enter to cancel.",
        seconds.div_ceil(60)
    ));
    let until = Instant::now() + Duration::from_secs(u64::from(seconds));
    loop {
        match queue.try_recv() {
            Ok(SurfaceRequest::PairStop {}) => {
                Console::discard_typed();
                console.say("Phone connected.");
                return SurfaceAnswer::Done {};
            }
            Ok(_) | Err(mpsc::TryRecvError::Disconnected) => return SurfaceAnswer::Cancel {},
            Err(mpsc::TryRecvError::Empty) => {}
        }
        // Also the pause between looks at the daemon.
        if Console::line_within(Some(Duration::from_millis(50))).is_ok() {
            return SurfaceAnswer::Cancel {};
        }
        if Instant::now() >= until {
            return SurfaceAnswer::Cancel {};
        }
    }
}

/// Tells the person the phone is being asked and waits: the daemon's
/// `DeviceWaitStop` (the phone answered) or the time running out ends it with
/// `Done`; Enter answers `Choice { index: 0 }` (use the password instead); end
/// of input is `Cancel`. The line is read in short turns so the wait can also
/// watch the daemon and leaves no reader blocked when it ends; what was typed
/// during a wait the daemon ended is dropped.
fn device_wait(
    console: &Console,
    panel: &Panel,
    device: &str,
    seconds: u32,
    queue: &mpsc::Receiver<SurfaceRequest>,
) -> SurfaceAnswer {
    console.panel(panel);
    console.say(&format!(
        "Confirm on your phone \"{}\"... Waiting.",
        safe(device)
    ));
    console.say("");
    console.say("Press Enter to use the password instead.");
    let until = Instant::now() + Duration::from_secs(u64::from(seconds));
    loop {
        match queue.try_recv() {
            Ok(SurfaceRequest::DeviceWaitStop {}) => {
                Console::discard_typed();
                return SurfaceAnswer::Done {};
            }
            Ok(_) | Err(mpsc::TryRecvError::Disconnected) => return SurfaceAnswer::Cancel {},
            Err(mpsc::TryRecvError::Empty) => {}
        }
        // Also the pause between looks at the daemon.
        match Console::line_within(Some(Duration::from_millis(50))) {
            Ok(Some(_)) => return SurfaceAnswer::Choice { index: 0 },
            Ok(None) => return SurfaceAnswer::Cancel {},
            Err(()) => {}
        }
        if Instant::now() >= until {
            Console::discard_typed();
            return SurfaceAnswer::Done {};
        }
    }
}

/// The daemon's requests, read on their own thread.
struct Requests {
    queue: mpsc::Receiver<SurfaceRequest>,
    /// Set while the window waits on the person.
    answering: Arc<AtomicBool>,
    /// Set when the daemon hangs up.
    closed: Arc<AtomicBool>,
}

/// Reads the daemon's requests on a thread of their own, so the window learns
/// at once when the daemon gives up on it. The daemon hangs up when its time to
/// answer runs out, while this window may sit in a password read that only
/// returns on Enter: without the watch, the window would stay open, take a
/// password, and do nothing with it. So when the daemon hangs up while the
/// person is being asked, the window says so and exits.
fn watch(stream: &Stream) -> Option<Requests> {
    let mut reader = stream.try_clone().ok()?;
    let (tx, queue) = mpsc::channel();
    let answering = Arc::new(AtomicBool::new(false));
    let closed = Arc::new(AtomicBool::new(false));
    let (asking, hung_up) = (Arc::clone(&answering), Arc::clone(&closed));
    // `main` holds the stdout lock for the whole command, so this thread
    // writes through a handle of its own.
    let screen = own_stdout();
    std::thread::spawn(move || {
        while let Ok(Some(request)) = read_frame::<SurfaceRequest>(&mut reader) {
            if tx.send(request).is_err() {
                return;
            }
        }
        // Either the main thread sees `closed` before it waits on the person,
        // or this thread sees `answering`: both are SeqCst.
        hung_up.store(true, Ordering::SeqCst);
        if asking.load(Ordering::SeqCst) {
            if let Some(mut screen) = screen {
                let _ = screen.write_all(
                    b"\nThe time to answer ran out, or Vahta stopped; nothing was done.\n\
                      This window closes now.\n",
                );
                let _ = screen.flush();
            }
            std::thread::sleep(Duration::from_secs(3));
            std::process::exit(EXIT_DAEMON);
        }
    });
    Some(Requests {
        queue,
        answering,
        closed,
    })
}

/// A second handle on standard output, which does not go through the lock
/// that `main` holds.
fn own_stdout() -> Option<std::fs::File> {
    #[cfg(unix)]
    let handle = std::os::fd::AsFd::as_fd(&std::io::stdout()).try_clone_to_owned();
    #[cfg(windows)]
    let handle = std::os::windows::io::AsHandle::as_handle(&std::io::stdout()).try_clone_to_owned();
    handle.ok().map(std::fs::File::from)
}

/// A line before `until` (or with no limit), `None` at the end of input or
/// when the time is up.
fn line_until(until: Option<Instant>) -> Option<String> {
    match until {
        None => Console::line(),
        Some(t) => {
            let left = t.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            Console::line_within(Some(left)).ok().flatten()
        }
    }
}
