//! `vahta run` and `vahta delegate`.
//!
//! **`vahta run`** asks the daemon to start the command. The daemon gives it the
//! secrets in its environment, and sends the command's output back with the
//! values taken out, so this process never holds one. It relays the standard
//! input, forwards Ctrl-C and termination, and exits with the command's code.
//! If this process goes away the daemon ends the command.
//!
//! **`vahta delegate`** narrows the caller's session for a sub-agent and runs
//! the sub-agent: the new session belongs to this process, and ends when the
//! command does.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use vahta_daemon::protocol::{
    ClientReply, ClientRequest, DurationSpec, RunInput, RunOutput, RunSignal, b64_decode,
    b64_encode, read_frame, write_frame,
};
use vahta_os::ipc::Stream;

use crate::daemon_cmd;
use crate::session_cmds::parse_duration;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

pub const RUN_USAGE: &str = "\
usage: vahta run [--secret NAME]... [--as NAME=VAR]... [--label TEXT] [--] COMMAND [ARGS...]

Run COMMAND with secrets in its environment. The daemon starts it, so this
process never holds a value, and its output comes back with every value
replaced by ***REDACTED(NAME)***.

  --secret NAME     a secret to inject (repeatable); without it, every name in
                    vahta.toml that the vault holds
  --as NAME=VAR     put NAME in the variable VAR (default: the `env` of NAME in
                    vahta.toml, else NAME itself)
  --label TEXT      a description for the window, shown marked as coming from
                    the agent and not verified

With a session from `vahta unlock` that covers every name, there is no window.
Otherwise a window asks for the password for this one run and no session is
opened. An each-use secret always asks.

The command gets this process's arguments, directory and environment (minus
LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, DYLD_* and VAHTA_*), standard input as a
pipe, and pipes for output: a command that needs a terminal does not get one,
and a value that appears encoded (base64, say) is not recognised. The exit code
is the command's.
";

pub const DELEGATE_USAGE: &str = "\
usage: vahta delegate --secret NAME [--secret NAME]... [--for DURATION] [--label TEXT] [--] COMMAND [ARGS...]

Narrow your session for a sub-agent and run it. The new session covers only the
named secrets, lasts no longer than yours (--for makes it shorter), belongs to
this process, and ends when COMMAND exits. A secret your session does not
cover, or a longer time, is refused with no window. `vahta run` from inside
COMMAND uses the narrow session.
";

struct Parsed {
    names: Vec<String>,
    renames: Vec<(String, String)>,
    duration: DurationSpec,
    label: Option<String>,
    command: Vec<String>,
}

enum Args {
    Run(Box<Parsed>),
    Help,
    Error(String),
}

fn parse(args: &[String], delegate: bool) -> Args {
    let mut p = Parsed {
        names: Vec::new(),
        renames: Vec::new(),
        duration: DurationSpec::Default {},
        label: None,
        command: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            p.command = args[i..].to_vec();
            break;
        }
        if !a.starts_with('-') || a == "-" {
            p.command = args[i - 1..].to_vec();
            break;
        }
        let mut value = |what: &str| -> Result<String, String> {
            let v = args
                .get(i)
                .cloned()
                .ok_or_else(|| format!("{what} expects a value"))?;
            i += 1;
            Ok(v)
        };
        let result = match a {
            "-h" | "--help" => return Args::Help,
            "--secret" => value("--secret").map(|v| p.names.push(v)),
            "--as" if !delegate => value("--as").and_then(|v| match v.split_once('=') {
                Some((n, var)) if !n.is_empty() && !var.is_empty() => {
                    p.renames.push((n.to_string(), var.to_string()));
                    Ok(())
                }
                _ => Err("--as expects NAME=VAR".to_string()),
            }),
            "--for" if delegate => value("--for")
                .and_then(|v| parse_duration(&v))
                .map(|d| p.duration = d),
            "--label" => value("--label").map(|v| p.label = Some(v)),
            other => Err(format!("unrecognised option: {other}")),
        };
        if let Err(e) = result {
            return Args::Error(e);
        }
    }
    if p.command.is_empty() {
        return Args::Error("no command given".to_string());
    }
    Args::Run(Box::new(p))
}

/// The caller's environment as text, for the daemon to make the command's of.
fn environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

type Shared = Arc<Mutex<Stream>>;

fn send_input(writer: &Shared, message: &RunInput) -> bool {
    match writer.lock() {
        Ok(mut s) => write_frame(&mut *s, message).is_ok(),
        Err(_) => false,
    }
}

/// Forward the signals that mean "stop" to the command.
#[cfg(unix)]
fn forward_signals(writer: Shared) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    let Ok(mut signals) = Signals::new([SIGINT, SIGTERM, SIGHUP]) else {
        return;
    };
    std::thread::spawn(move || {
        for sig in signals.forever() {
            let signal = match sig {
                SIGINT => RunSignal::Interrupt,
                SIGHUP => RunSignal::Hangup,
                _ => RunSignal::Terminate,
            };
            send_input(&writer, &RunInput::Signal { signal });
        }
    });
}

#[cfg(not(unix))]
fn forward_signals(_writer: Shared) {}

/// Relay a started run: input to the command, its output to ours.
fn relay(stream: &mut Stream, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Ok(clone) = stream.try_clone() else {
        let _ = writeln!(stderr, "vahta run: error: cannot use the connection");
        return EXIT_DAEMON;
    };
    let writer: Shared = Arc::new(Mutex::new(clone));
    forward_signals(writer.clone());
    {
        let writer = writer.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        send_input(&writer, &RunInput::StdinEof {});
                        return;
                    }
                    Ok(n) => {
                        let data = b64_encode(&buf[..n]);
                        if !send_input(&writer, &RunInput::Stdin { data }) {
                            return;
                        }
                    }
                }
            }
        });
    }
    loop {
        match read_frame::<RunOutput>(stream) {
            Ok(Some(RunOutput::Stdout { data })) => {
                if let Some(bytes) = b64_decode(&data) {
                    let _ = stdout.write_all(&bytes);
                    let _ = stdout.flush();
                }
            }
            Ok(Some(RunOutput::Stderr { data })) => {
                if let Some(bytes) = b64_decode(&data) {
                    let _ = stderr.write_all(&bytes);
                    let _ = stderr.flush();
                }
            }
            Ok(Some(RunOutput::Exit { code, .. })) => return code,
            Ok(Some(RunOutput::Failed { message })) => {
                let _ = writeln!(stderr, "vahta run: error: {message}");
                return EXIT_FAILED;
            }
            Ok(None) | Err(_) => {
                let _ = writeln!(
                    stderr,
                    "vahta run: error: lost the connection to the daemon"
                );
                return EXIT_DAEMON;
            }
        }
    }
}

pub fn run_run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let parsed = match parse(args, false) {
        Args::Help => {
            let _ = stdout.write_all(RUN_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta run: error: {msg}\n\n{RUN_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let request = ClientRequest::Run {
        cwd: env.cwd.to_string_lossy().into_owned(),
        argv: parsed.command,
        env: environment(),
        names: (!parsed.names.is_empty()).then_some(parsed.names),
        renames: parsed.renames,
        label: parsed.label,
    };
    let mut conn = match daemon_cmd::connect(env, "run", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(&request) {
        Ok(ClientReply::RunStarted {}) => relay(conn.stream(), stdout, stderr),
        Ok(other) => daemon_cmd::report("run", &other, false, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta run: error: {e}");
            EXIT_DAEMON
        }
    }
}

/// How a command that ended is reported as an exit code.
fn code_of(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(EXIT_FAILED)
}

pub fn run_delegate(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let parsed = match parse(args, true) {
        Args::Help => {
            let _ = stdout.write_all(DELEGATE_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta delegate: error: {msg}\n\n{DELEGATE_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let request = ClientRequest::Delegate {
        cwd: env.cwd.to_string_lossy().into_owned(),
        names: parsed.names,
        duration: parsed.duration,
        label: parsed.label,
    };
    let mut conn = match daemon_cmd::connect(env, "delegate", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let info = match conn.request(&request) {
        Ok(ClientReply::Session(info)) => info,
        Ok(other) => return daemon_cmd::report("delegate", &other, false, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta delegate: error: {e}");
            return EXIT_DAEMON;
        }
    };
    // Ctrl-C goes to the command as well (it shares our process group); this
    // process stays until the command has had its say, so the session does too.
    #[cfg(unix)]
    {
        let ignore = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, ignore);
    }
    let mut command = std::process::Command::new(&parsed.command[0]);
    command.args(&parsed.command[1..]);
    let code = match command.status() {
        Ok(status) => code_of(status),
        Err(e) => {
            let _ = writeln!(
                stderr,
                "vahta delegate: error: cannot start {}: {e}",
                parsed.command[0]
            );
            127
        }
    };
    // The session ends with the command, now and not at the next sweep.
    let _ = conn.request(&ClientRequest::SessionKill {
        id: info.id.clone(),
    });
    code
}
