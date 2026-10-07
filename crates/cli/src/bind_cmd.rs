//! `vahta bind`: propose which commands may use a secret.
//!
//! The agent (or the person) names the rules; a window shows them to the
//! person, who approves with the vault password. Nothing here changes
//! anything by itself, so an agent may call it: it only asks.

use std::io::Write;

use vahta_ipc::protocol::ClientRequest;

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const BIND_USAGE: &str = "\
usage: vahta bind NAME [--allow RULE]... [--deny RULE]... [--reason TEXT] [--json]
       vahta bind NAME --clear [--reason TEXT] [--json]
       vahta bind [--json]

Say which commands may use a secret. A window shows the person the old and the
new rules, where each allowed program resolves to, and your reason (marked as
unverified); on \"Approve\" plus the vault password the rules are written to
vahta.toml and to the vault. Nothing changes without that. Only the vault's
approved copy is enforced: a hand edit of vahta.toml changes nothing until it is
approved here.

With NAME, the rules given REPLACE the ones it has. With no NAME, the rules in
vahta.toml are approved as written (the window shows what differs).

A rule is one string: the program, then optional leading arguments.
  stripe                  a program found in your PATH
  ./scripts/deploy.sh     a path, relative to the project root
  git push                `git` with `push` as its first argument
  @network @shells @interpreters   (deny only) groups of programs
No quotes and no patterns. A secret with no rules works with any command.

`allow` is the real guard: with it, only those programs (by resolved path) get
the secret. `deny` only slows an agent down: a program that is in no group, or
a renamed copy of one, gets past it. An allowed script inside the project can
be edited by the agent, and an allowed program can pass the secret on.

options:
  --allow RULE      a command that may use the secret (repeatable)
  --deny RULE       a command that may not, checked first (repeatable)
  --clear           remove NAME's rules: any command may use it again
  --reason TEXT     why, for the window; shown marked as unverified
  --json            machine-readable result
  -h, --help        show this help
";

struct Parsed {
    name: Option<String>,
    allow: Vec<String>,
    deny: Vec<String>,
    clear: bool,
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
        allow: Vec::new(),
        deny: Vec::new(),
        clear: false,
        reason: None,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
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
            "--json" => {
                p.json = true;
                Ok(())
            }
            "--clear" => {
                p.clear = true;
                Ok(())
            }
            "--allow" => value("--allow").map(|v| p.allow.push(v)),
            "--deny" => value("--deny").map(|v| p.deny.push(v)),
            "--reason" => value("--reason").map(|v| p.reason = Some(v)),
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
    if p.name.is_none() && (p.clear || !p.allow.is_empty() || !p.deny.is_empty()) {
        return Args::Error(
            "--allow, --deny and --clear need a NAME; `vahta bind` alone approves vahta.toml"
                .to_string(),
        );
    }
    Args::Run(p)
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let parsed = match parse(args) {
        Args::Help => {
            let _ = stdout.write_all(BIND_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta bind: error: {msg}\n\n{BIND_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let request = ClientRequest::Bind {
        cwd: env.cwd.to_string_lossy().into_owned(),
        name: parsed.name,
        allow: parsed.allow,
        deny: parsed.deny,
        clear: parsed.clear,
        reason: parsed.reason,
        path: std::env::var_os("PATH").map(|p| p.to_string_lossy().into_owned()),
    };
    daemon_cmd::request(env, "bind", &request, parsed.json, stdout, stderr)
}
