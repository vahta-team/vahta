//! `vahta allow REF [--reason TEXT]`: the agent asks the person about one tool
//! call Vahta's secret detector refused.
//!
//! Meant to be run by the agent: the hook's refusal names the reference. The
//! daemon checks that the agent asking is the one whose hook made it, and asks
//! the person in a window, which shows the tool, the directory, the agent's
//! reason (marked unverified), the rule and what matched. The person may let
//! that exact call through once (the agent retries it unchanged), save the
//! value in the project's vault (the agent is told its name), or refuse.
//!
//! Exit codes as for the other daemon commands: 0 allowed once or saved, 3
//! refused (an unknown or another agent's reference), 4 the person said no or
//! did not answer, 5 no daemon.

use std::io::Write;

use vahta_ipc::protocol::ClientRequest;

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const ALLOW_USAGE: &str = "\
usage: vahta allow REF [--reason TEXT] [--json]

Ask the person about a tool call Vahta refused because it looked like it
carried a secret. REF is the reference in Vahta's message about the refusal.
A window shows the person what was refused and what matched, and your reason.
They may:
  - let that exact call through once: retry it unchanged within 5 minutes;
  - say it is a secret and save it in the project's vault: you are told its
    name, and use it with `vahta run --secret NAME -- COMMAND`;
  - refuse.
Without an answer in time the call stays refused.

options:
  --reason TEXT          why it is not a secret; shown to the person as
                         unverified
  --json                 machine-readable result
  -h, --help             show this help

If it is a secret, do not ask: put it in Vahta and use `vahta run -- ...`.
";

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut json = false;
    let mut reason: Option<String> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(ALLOW_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => json = true,
            "--reason" => match args.get(i) {
                Some(v) => {
                    reason = Some(v.clone());
                    i += 1;
                }
                None => return usage(stderr, "--reason expects a value"),
            },
            s if s.starts_with('-') => return usage(stderr, &format!("unrecognised option: {s}")),
            s => positional.push(s),
        }
    }
    let reference = match positional.as_slice() {
        [reference] => reference.to_string(),
        [] => return usage(stderr, "expected the reference: vahta allow REF"),
        _ => return usage(stderr, "expected one reference"),
    };
    daemon_cmd::request(
        env,
        "allow",
        &ClientRequest::ToolAllow { reference, reason },
        json,
        stdout,
        stderr,
    )
}

fn usage(stderr: &mut dyn Write, msg: &str) -> i32 {
    let _ = write!(stderr, "vahta allow: error: {msg}\n\n{ALLOW_USAGE}");
    EXIT_USAGE
}
