//! `vahta scrub --transcript [--all]`: take secrets out of the harnesses'
//! transcript files on disk.
//!
//! Meant to be run by the agent, with no window: it only removes. The daemon
//! does the work, because it knows the values (see `crates/daemon/src/
//! transcript.rs` for what is looked for and where). This command says where
//! the harnesses keep their files (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, else the
//! home directory's `.claude` and `.codex`) and prints what the daemon
//! answers: counts and paths, never a value or the text around one.
//!
//! Exit codes as for the other daemon commands: 0 done, 1 a file could not be
//! rewritten (run it again), 3 refused, 5 no daemon.

use std::io::Write;

use serde_json::json;
use vahta_ipc::protocol::{
    ClientReply, ClientRequest, TranscriptReport, TranscriptRoots, TranscriptState,
};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

pub const SCRUB_USAGE: &str = "\
usage: vahta scrub --transcript [--all] [--json]

Take secrets out of the transcript files your coding agent keeps on disk: the
values Vahta holds for this agent (in every form it knows) and what looks like
a key or token. Each is replaced by ***REDACTED(NAME)*** and every line stays
valid JSON. Prints counts and file paths, never a value.

  Claude Code   ~/.claude/projects/<this project>/**.jsonl
                (under $CLAUDE_CONFIG_DIR if set)
  Codex         ~/.codex/sessions/**/rollout-*.jsonl for this directory
                (under $CODEX_HOME if set)
  Cursor        not covered: it keeps chats in a SQLite database

The transcript of a running session is not rewritten while the harness is
writing to it. It is read, marked, and cleaned when the session ends (the
SessionEnd hook). Every secret found is also marked as exposed: `vahta list`
and `vahta check` say to rotate it until it is reset (`vahta reset NAME`).

This cannot clean the conversation the model is in. A value that is in the
context stays there until /clear or a new session.

options:
  --transcript           required: what to scrub
  --all                  every project's transcripts, not just this one's
  --json                 machine-readable result
  -h, --help             show this help
";

/// Where this process says the harnesses keep their transcripts.
pub fn roots(env: &Env) -> TranscriptRoots {
    TranscriptRoots::from_env(env.home.as_deref())
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (mut transcript, mut all, mut json) = (false, false, false);
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                let _ = stdout.write_all(SCRUB_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--transcript" => transcript = true,
            "--all" => all = true,
            "--json" => json = true,
            other => return usage(stderr, &format!("unrecognised argument: {other}")),
        }
    }
    if !transcript {
        return usage(stderr, "say what to scrub: --transcript");
    }
    let mut conn = match daemon_cmd::connect(env, "scrub", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let request = ClientRequest::TranscriptScrub {
        cwd: env.cwd.display().to_string(),
        all,
        roots: roots(env),
    };
    let reply = match conn.request(&request) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "vahta scrub: error: {e}");
            return EXIT_DAEMON;
        }
    };
    match reply {
        ClientReply::Transcripts(report) => print(&report, all, json, stdout),
        other => daemon_cmd::report("scrub", &other, json, stdout, stderr),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn print(r: &TranscriptReport, all: bool, json: bool, stdout: &mut dyn Write) -> i32 {
    let failed = r.files.iter().any(|f| f.state == TranscriptState::Failed);
    let code = if failed { EXIT_FAILED } else { EXIT_CLEAN };
    if json {
        let doc =
            json!({"ok": !failed, "scanned": r.scanned, "files": r.files, "exposed": r.exposed});
        let _ = writeln!(stdout, "{doc}");
        return code;
    }
    let scope = if all { "all projects" } else { "this project" };
    let _ = writeln!(
        stdout,
        "vahta scrub: read {} ({scope}).",
        plural(r.scanned, "transcript file", "transcript files")
    );
    if r.files.is_empty() {
        let _ = writeln!(stdout, "Nothing to remove.");
        return code;
    }
    for f in &r.files {
        let what = format!(
            "{}, {}",
            plural(f.values, "known value", "known values"),
            plural(f.patterns, "secret-like", "secret-like")
        );
        let (state, tail) = match f.state {
            TranscriptState::Cleaned => ("cleaned ", ""),
            TranscriptState::Deferred => (
                "deferred",
                "; its session is running, so it is cleaned when the session ends",
            ),
            TranscriptState::Failed => (
                "FAILED  ",
                "; it changed while being cleaned or could not be written, run this again",
            ),
        };
        let _ = writeln!(stdout, "  {state} {} ({what}){tail}", f.path);
    }
    if !r.exposed.is_empty() {
        let _ = writeln!(
            stdout,
            "Exposed in a transcript: {}. Rotate them: the person runs `vahta reset NAME` \
             after changing the value at its source.",
            r.exposed.join(", ")
        );
    }
    let _ = writeln!(
        stdout,
        "The conversation you are in still holds what it held: it is cleaned only by /clear or \
         a new session."
    );
    code
}

fn usage(stderr: &mut dyn Write, msg: &str) -> i32 {
    let _ = write!(stderr, "vahta scrub: error: {msg}\n\n{SCRUB_USAGE}");
    EXIT_USAGE
}
