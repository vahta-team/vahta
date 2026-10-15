//! `vahta role`: propose an agent role for the person's approval.
//!
//! The role is written in `vahta.toml` (`[roles.NAME]`); this command asks the
//! person to approve it. Nothing here changes anything by itself, so an agent
//! may call it: it only asks.

use std::io::Write;

use vahta_ipc::protocol::ClientRequest;

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const ROLE_USAGE: &str = "\
usage: vahta role NAME [--reason TEXT] [--json]
       vahta role [--reason TEXT] [--json]
       vahta role --remove NAME [--reason TEXT] [--json]

Ask the person to approve an agent role: a named delegation template for one
kind of task. You write the proposal in vahta.toml:

  [roles.deploy-check]
  secrets = [\"STRIPE_KEY\"]         # the secrets the role covers
  allow   = [\"stripe balance\"]     # commands, narrower than the secret's own
  deny    = [\"@shells\"]            # more commands that never run (only adds)
  network = \"none\"                 # none, app or hosts (with hosts = [...]);
                                   # leave out to keep each secret's own
  dirs    = [\".\"]                  # folders (narrower than the secret's)
  for     = \"2h\"                   # the longest one grant lasts
  uses    = 20                     # runs and requests one grant gives
  actions = [\"run\"]                # run and/or http (default: run)
  ask     = false                  # true: the person says yes to every use

then run `vahta role deploy-check`. A window shows the person the role in plain
words; on \"Approve\" plus the vault password it is stored, signed, in the vault.
Only that copy counts: a hand edit of vahta.toml changes nothing until it is
approved here, and `vahta check` reports the difference.

A role can only narrow. Every secret it names must exist and have approved
rules, and the role must be no wider than each of them: its allow rules inside
the secret's, its hosts inside the secret's hosts (none < hosts < app), its
folders inside the secret's. A role that is wider is refused at once, saying
what is wider, and the person is not asked.

Then the agent works inside it with no further window:
  vahta delegate --role NAME -- COMMAND       narrow your session to the role
  vahta unlock --role NAME                    (the person) open a session for it
A role session may only run commands and send requests (those in `actions`),
and only as the role says. Revealing, copying, adding, binding, unlocking and
changing roles are refused for it.

With no NAME, every role in vahta.toml that differs from the vault's is shown.

options:
  --remove NAME   take a role away (the person approves; sessions limited to it
                  end)
  --reason TEXT   why, for the window; shown marked as unverified
  --json          machine-readable result
  -h, --help      show this help
";

struct Parsed {
    name: Option<String>,
    remove: bool,
    reason: Option<String>,
    json: bool,
}

enum Args {
    Run(Parsed),
    Help,
    Error(String),
}

fn parse(args: &[String]) -> Args {
    let mut p = Parsed {
        name: None,
        remove: false,
        reason: None,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        let result = match a {
            "-h" | "--help" => return Args::Help,
            "--json" => {
                p.json = true;
                Ok(())
            }
            "--remove" => {
                p.remove = true;
                Ok(())
            }
            "--reason" => match args.get(i) {
                Some(v) => {
                    p.reason = Some(v.clone());
                    i += 1;
                    Ok(())
                }
                None => Err("--reason expects a value".to_string()),
            },
            s if s.starts_with('-') => Err(format!("unrecognised option: {s}")),
            s if p.name.is_none() => {
                p.name = Some(s.to_string());
                Ok(())
            }
            _ => Err("expected at most one NAME".to_string()),
        };
        if let Err(e) = result {
            return Args::Error(e);
        }
    }
    if p.remove && p.name.is_none() {
        return Args::Error("--remove needs the NAME of the role".to_string());
    }
    Args::Run(p)
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let parsed = match parse(args) {
        Args::Help => {
            let _ = stdout.write_all(ROLE_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta role: error: {msg}\n\n{ROLE_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let request = ClientRequest::Role {
        cwd: env.cwd.to_string_lossy().into_owned(),
        name: parsed.name,
        remove: parsed.remove,
        reason: parsed.reason,
        path: std::env::var_os("PATH").map(|p| p.to_string_lossy().into_owned()),
    };
    daemon_cmd::request(env, "role", &request, parsed.json, stdout, stderr)
}
