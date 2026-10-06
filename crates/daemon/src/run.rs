//! Running a command for a client and relaying it.
//!
//! The daemon starts the command (so no value ever reaches the client), with
//! the client's argv, working directory and environment, minus the variables
//! that load code into it and Vahta's own controls, plus the injected values.
//!
//! * **stdin** is relayed from the client; **stdout** and **stderr** come back
//!   through the streaming scrubber, so a value the command prints is replaced
//!   by `***REDACTED(NAME)***`. Commands that need a terminal get pipes, and a
//!   value that appears encoded is not recognised; both are documented.
//! * The **exit code** passes through (128 plus the signal for a command a
//!   signal ended).
//! * **Ctrl-C and termination** are forwarded: the client sends them as frames
//!   and the daemon signals the command's process group.
//! * If the **client goes away** the command is ended: terminated, and killed
//!   if it does not go within two seconds.
//! * The command runs in its own process group, and the daemon remembers it
//!   under its session, so a `vahta run` from inside it uses that session.
//!
//! What this cannot do: a value the command was given can be read by that
//! command and by anything of the same user that can read its
//! `/proc/<pid>/environ`. Ending a session cannot take a value back from a
//! command already running.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vahta_os::ipc::Stream;

use crate::journal::Entry;
use crate::protocol::{
    RunInput, RunOutput, RunSignal, b64_decode, b64_encode, read_frame, write_frame,
};
use crate::run_ops::Prepared;
use crate::scrub::Scrubber;
use crate::server::Shared;

/// How much of a command's output goes in one frame, before base64.
const CHUNK: usize = 16 * 1024;
/// How long a command that was asked to stop is given before it is killed.
const KILL_AFTER: Duration = Duration::from_secs(2);
/// How long after the command exits its output is waited for. A background
/// process that inherited the pipes can keep them open for ever.
const DRAIN: Duration = Duration::from_secs(3);

type Writer = Arc<Mutex<Stream>>;

fn send(writer: &Writer, message: &RunOutput) -> bool {
    match writer.lock() {
        Ok(mut s) => write_frame(&mut *s, message).is_ok(),
        Err(_) => false,
    }
}

/// Read one of the command's output streams, scrub it, and send it on.
fn pump(
    mut source: impl Read,
    mut scrubber: Scrubber,
    writer: Writer,
    stderr: bool,
    finished: Arc<AtomicBool>,
) {
    let frame = |bytes: &[u8]| {
        let data = b64_encode(bytes);
        if stderr {
            RunOutput::Stderr { data }
        } else {
            RunOutput::Stdout { data }
        }
    };
    let emit = |bytes: Vec<u8>| -> bool {
        if finished.load(Ordering::SeqCst) {
            return false;
        }
        bytes.chunks(CHUNK).all(|c| send(&writer, &frame(c)))
    };
    let mut buf = vec![0u8; CHUNK];
    loop {
        match source.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !emit(scrubber.push(&buf[..n])) {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    emit(scrubber.finish());
}

/// End a command: asked nicely, then not.
fn end_command(pid: u32) {
    #[cfg(unix)]
    {
        let _ = vahta_os::signal_process_group(pid, vahta_os::Signal::Terminate);
        std::thread::spawn(move || {
            std::thread::sleep(KILL_AFTER);
            // A group that is already gone is not an error worth reporting.
            let _ = vahta_os::signal_process_group(pid, vahta_os::Signal::Kill);
        });
    }
    #[cfg(not(unix))]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn forward(pid: u32, signal: RunSignal) {
    #[cfg(unix)]
    {
        let sig = match signal {
            RunSignal::Interrupt => vahta_os::Signal::Interrupt,
            RunSignal::Terminate => vahta_os::Signal::Terminate,
            RunSignal::Hangup => vahta_os::Signal::Hangup,
        };
        let _ = vahta_os::signal_process_group(pid, sig);
    }
    #[cfg(not(unix))]
    {
        // Windows has no signal to send a process: Ctrl-C and termination end
        // the command.
        let _ = signal;
        end_command(pid);
    }
}

fn exit_of(status: ExitStatus) -> (i32, Option<i32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return (128 + sig, Some(sig));
        }
    }
    (status.code().unwrap_or(1), None)
}

/// Start `prepared` and relay it over `stream` until it ends.
pub(crate) fn execute(
    shared: &Arc<Shared>,
    stream: &mut Stream,
    prepared: Prepared,
    peer: (Option<String>, u32),
) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let writer: Writer = Arc::new(Mutex::new(clone));
    let Prepared {
        argv,
        cwd,
        env,
        values,
        session,
        names,
    } = prepared;

    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(&cwd)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            // The program name is the caller's; the reason is the system's.
            let message = format!("cannot start {}: {e}", argv[0]);
            send(&writer, &RunOutput::Failed { message });
            return;
        }
    };
    drop(command);
    drop(env);
    let pid = child.id();

    let launched = vahta_os::identity_of(pid).ok();
    if let (Some(id), Some(sid)) = (launched, &session)
        && let Ok(mut sessions) = shared.sessions.lock()
    {
        sessions.note_launch(id, sid);
    }

    let finished = Arc::new(AtomicBool::new(false));
    let mut pumps: Vec<JoinHandle<()>> = Vec::new();
    if let Some(out) = child.stdout.take() {
        let (w, f, s) = (
            writer.clone(),
            finished.clone(),
            Scrubber::new(values.clone()),
        );
        pumps.push(std::thread::spawn(move || pump(out, s, w, false, f)));
    }
    if let Some(err) = child.stderr.take() {
        let (w, f, s) = (
            writer.clone(),
            finished.clone(),
            Scrubber::new(values.clone()),
        );
        pumps.push(std::thread::spawn(move || pump(err, s, w, true, f)));
    }
    drop(values);

    // The client's input and signals, and the client going away.
    if let Ok(mut reader) = stream.try_clone() {
        let mut stdin = child.stdin.take();
        std::thread::spawn(move || {
            loop {
                match read_frame::<RunInput>(&mut reader) {
                    Ok(Some(RunInput::Stdin { data })) => {
                        if let (Some(input), Some(bytes)) = (stdin.as_mut(), b64_decode(&data)) {
                            // A command that closed its input is not an error.
                            if input.write_all(&bytes).is_err() {
                                stdin = None;
                            }
                        }
                    }
                    Ok(Some(RunInput::StdinEof {})) => stdin = None,
                    Ok(Some(RunInput::Signal { signal })) => forward(pid, signal),
                    // The client is gone or sent nonsense: the command ends.
                    Ok(None) | Err(_) => {
                        drop(stdin.take());
                        end_command(pid);
                        return;
                    }
                }
            }
        });
    }

    let (status_tx, status_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = status_tx.send(child.wait());
    });
    let status = status_rx.recv();

    // The command has ended; its output is let drain for a little.
    let deadline = Instant::now() + DRAIN;
    while pumps.iter().any(|p| !p.is_finished()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    finished.store(true, Ordering::SeqCst);

    let (code, signal) = match status {
        Ok(Ok(s)) => exit_of(s),
        _ => (1, None),
    };
    send(&writer, &RunOutput::Exit { code, signal });
    if let Some(id) = launched
        && let Ok(mut sessions) = shared.sessions.lock()
    {
        sessions.forget_launch(&id);
    }
    let mut entry = Entry::new("run_end")
        .names(&names)
        .peer(peer.0.as_deref(), peer.1)
        .result("ended", Some(&format!("exit {code}")));
    if let Some(sid) = &session {
        entry = entry.session(sid, None);
    }
    shared.journal.record(entry);
    let _ = stream.shutdown();
}
