//! `vahta output allow <ref> [--reason TEXT]`: the agent asks the person to
//! see what the hook cut out of a tool's output.
//!
//! Meant to be run by the agent: the hook's message names the reference. The
//! daemon checks that the agent asking is the one whose hook made it, and asks
//! the person in a window, which shows the tool, the directory, the agent's
//! reason (marked unverified) and what was cut, masked: never a value. With a
//! session open for the agent the person only chooses; without one, showing
//! needs the vault password. "Show to the agent" prints the output here, as
//! the tool gave it, and from then on the hook lets those values through for
//! this agent. "Save as a secret" stores one of them in the vault, and the
//! output stays redacted.
//!
//! Exit codes as for the other daemon commands: 0 shown or saved, 3 refused
//! (an unknown or another agent's reference, no vault), 4 the person said no
//! or did not answer, 5 no daemon.

use std::io::Write;

use vahta_ipc::protocol::{ClientReply, ClientRequest};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_USAGE, Env};

pub const OUTPUT_USAGE: &str = "\
usage: vahta output allow REF [--reason TEXT] [--json]

Ask the person to let you see what Vahta cut out of a tool's output. REF is
the reference in Vahta's message about the cut. A window shows the person
what was cut (never the values) and your reason; if they agree, the output is
printed here as the tool gave it. They may instead save a value as a secret,
and the output stays cut.

options:
  --reason TEXT          why you need it; shown to the person as unverified
  --json                 machine-readable result
  -h, --help             show this help

To use a secret without seeing it, run the command with `vahta run`.
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
                let _ = stdout.write_all(OUTPUT_USAGE.as_bytes());
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
        ["allow", reference] => reference.to_string(),
        ["allow"] => return usage(stderr, "expected the reference: vahta output allow REF"),
        _ => return usage(stderr, "expected `allow REF`"),
    };
    let mut conn = match daemon_cmd::connect(env, "output allow", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let reply = match conn.request(&ClientRequest::OutputAllow { reference, reason }) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "vahta output allow: error: {e}");
            return EXIT_DAEMON;
        }
    };
    match reply {
        ClientReply::OutputReleased { text } => {
            if json {
                let doc = serde_json::json!({"ok": true, "output": text});
                let _ = writeln!(stdout, "{doc}");
            } else {
                let _ = stdout.write_all(text.as_bytes());
                if !text.ends_with('\n') {
                    let _ = writeln!(stdout);
                }
            }
            EXIT_CLEAN
        }
        other => daemon_cmd::report("output allow", &other, json, stdout, stderr),
    }
}

fn usage(stderr: &mut dyn Write, msg: &str) -> i32 {
    let _ = write!(stderr, "vahta output: error: {msg}\n\n{OUTPUT_USAGE}");
    EXIT_USAGE
}
