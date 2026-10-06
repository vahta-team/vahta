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

use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::time::Duration;

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
        let mut text = String::new();
        match std::io::stdin().lock().read_line(&mut text) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(text.trim_end_matches(['\n', '\r']).to_string()),
        }
    }

    /// A line typed in the open, waiting at most `limit`. `Err` is the time
    /// running out.
    fn line_within(limit: Option<Duration>) -> Result<Option<String>, ()> {
        let Some(limit) = limit else {
            return Ok(Console::line());
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(Console::line());
        });
        rx.recv_timeout(limit).map_err(|_| ())
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
        } => {
            console.panel(panel);
            console.say(&safe(question));
            for (i, option) in options.iter().enumerate() {
                console.say(&format!("  {}) {}", i + 1, safe(option)));
            }
            // A number from the list; anything else asks again, and the end
            // of input cancels.
            for _ in 0..3 {
                console.say(&format!("Choose 1-{}:", options.len()));
                let Some(line) = Console::line() else {
                    return Some(SurfaceAnswer::Cancel {});
                };
                if let Ok(n) = line.trim().parse::<usize>()
                    && (1..=options.len()).contains(&n)
                {
                    return Some(SurfaceAnswer::Choice { index: n - 1 });
                }
            }
            Some(SurfaceAnswer::Cancel {})
        }
        SurfaceRequest::Text { panel, prompt } => {
            console.panel(panel);
            print!("{}: ", safe(prompt));
            let _ = std::io::stdout().flush();
            Some(match Console::line() {
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
    loop {
        let request: SurfaceRequest = match read_frame(&mut stream) {
            Ok(Some(r)) => r,
            // The daemon ended the conversation.
            Ok(None) | Err(_) => break,
        };
        match answer_for(&console, &request) {
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
