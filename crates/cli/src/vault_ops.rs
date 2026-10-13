//! `vahta init`, `add`, `reset`, `tier`, `remove`, `import`, `reveal` and `copy`: the
//! commands that change or show a vault.
//!
//! None of them takes a secret, a password or a value as an argument, or reads
//! one from standard input. They ask the daemon, and the daemon opens a prompt
//! window (a new terminal window, never this one) where the person types the
//! password and any value. What comes back here is only what was done.

use std::io::Write;

use vahta_ipc::protocol::Tier;
use vahta_ipc::protocol::{ClientRequest, ImportSource};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const INIT_USAGE: &str = "\
usage: vahta init [--json]

Create this directory's vault, .vahta/vault.vht. A window opens where you
choose the password; the recovery key is shown there once and never again.

options:
  --json                 machine-readable result
  -h, --help             show this help
";

pub const ADD_USAGE: &str = "\
usage: vahta add NAME [--category C] [--allow RULE]... [--deny RULE]...
                      [--dir PATH]... [--net none|app|hosts:H[,H...]]
                      [--reason TEXT] [--tier session|each-use]
                      [--file FILENAME] [--json]

Store a new secret together with the rules that say what may use it. A window
opens where you type the vault password and then the value, hidden, twice; the
value never passes through this command. Then the same window shows the rules in
plain words and the person chooses: Accept, Use the default set for the
category, or Cancel. A NAME the vault already has is refused: use `vahta reset
NAME` to replace its value.

Every secret must have rules: without them nothing may use it. Think them
through once, now, so the person approves once and is rarely asked later, and
close the ways a prompt injection could misuse the key (network tools,
interpreters, shells, writing the value to a file, sending it to another host).

options:
  --category C           payment, server, ordinary, database, publish or
                         local-only. Left out, Vahta suggests one from the
                         value and the name. A category lower than the one the
                         value looks like is allowed but shown as a downgrade.
  --allow RULE           a program that may use it, with optional leading
                         arguments (`stripe`, `git push`, `./scripts/x.sh`)
  --deny RULE            a program that may not (`@network`, `@shells`,
                         `@interpreters`, or a name); the category adds its own
  --dir PATH             a folder whose programs may use it and in which it may
                         be used (`PATH:ro` for read-only)
  --net WHAT             none (no network), app (the program's own) or
                         hosts:H[,H...] (only these hosts, through `vahta http`)
  --reason TEXT          why, for the window; shown marked as unverified
  --tier TIER            session: a session may hold it, so `vahta run` can use
                         it without a window while one is open. each-use: it
                         needs the password every time. Default: the category's.
  --file FILENAME        the secret is a file with this name, not a variable
  --json                 machine-readable result
  -h, --help             show this help
";

pub const RESET_USAGE: &str = "\
usage: vahta reset NAME [--tier session|each-use] [--file FILENAME] [--json]

Replace the value of a secret the vault has, as when rotating it. A window
opens where you type the vault password and then the new value, hidden, twice.
A NAME the vault does not have is refused: use `vahta add NAME` to create it.
The secret keeps its tier and kind unless --tier or --file is given.

options:
  --tier TIER            session or each-use (see `vahta add --help`)
  --file FILENAME        the secret is a file with this name, not a variable
  --json                 machine-readable result
  -h, --help             show this help
";

pub const TIER_USAGE: &str = "\
usage: vahta tier NAME session|each-use [--json]

Change a secret's tier without typing its value again. A window opens for the
vault password.

  session    a session may hold it, so `vahta run` can use it without a
             window while one is open
  each-use   it needs the password every time, even in a session

options:
  --json                 machine-readable result
  -h, --help             show this help
";

pub const REMOVE_USAGE: &str = "\
usage: vahta remove NAME [--json]

Remove a secret from the vault. A window opens for the vault password.

options:
  --json                 machine-readable result
  -h, --help             show this help
";

pub const IMPORT_USAGE: &str = "\
usage: vahta import --ka PATH | --dotenv PATH [--json]

Add the secrets in a ka vault or a .env file to this project's vault. The
daemon reads the file itself. A window opens for the vault password (and, for
ka, the ka password). A name the vault already has refuses the whole import.

options:
  --ka PATH              a ka vault (KAM1 or KAM2)
  --dotenv PATH          a .env file
  --json                 machine-readable result
  -h, --help             show this help
";

pub const REVEAL_USAGE: &str = "\
usage: vahta reveal NAME [--json]

Show a secret's value in a window, after the vault password, until a key is
pressed or 60 seconds pass. The value is never printed here.

options:
  --json                 machine-readable result
  -h, --help             show this help
";

pub const COPY_USAGE: &str = "\
usage: vahta copy NAME [--json]

Put a secret's value on the clipboard, after the vault password, and clear it
after 30 seconds if it is unchanged. The value is never printed here.

options:
  --json                 machine-readable result
  -h, --help             show this help
";

fn usage_of(command: &str) -> &'static str {
    match command {
        "init" => INIT_USAGE,
        "add" => ADD_USAGE,
        "reset" => RESET_USAGE,
        "tier" => TIER_USAGE,
        "remove" => REMOVE_USAGE,
        "import" => IMPORT_USAGE,
        "reveal" => REVEAL_USAGE,
        _ => COPY_USAGE,
    }
}

struct Parsed {
    json: bool,
    positional: Vec<String>,
    tier: Option<Tier>,
    file: Option<String>,
    ka: Option<String>,
    dotenv: Option<String>,
    rules: vahta_ipc::protocol::RuleArgs,
}

enum Args {
    Run(Box<Parsed>),
    Help,
    Error(String),
}

fn parse(command: &str, args: &[String]) -> Args {
    let mut p = Parsed {
        json: false,
        positional: Vec::new(),
        tier: None,
        file: None,
        ka: None,
        dotenv: None,
        rules: Default::default(),
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
        match a {
            "-h" | "--help" => return Args::Help,
            "--json" => p.json = true,
            "--tier" if matches!(command, "add" | "reset") => match value("--tier") {
                Ok(v) => match v.as_str() {
                    "session" => p.tier = Some(Tier::Session),
                    "each-use" | "each_use" => p.tier = Some(Tier::EachUse),
                    other => {
                        return Args::Error(format!(
                            "invalid --tier value: {other:?} (choose session or each-use)"
                        ));
                    }
                },
                Err(e) => return Args::Error(e),
            },
            "--file" if matches!(command, "add" | "reset") => match value("--file") {
                Ok(v) => p.file = Some(v),
                Err(e) => return Args::Error(e),
            },
            "--category" if command == "add" => match value("--category") {
                Ok(v) => p.rules.category = Some(v),
                Err(e) => return Args::Error(e),
            },
            "--allow" if command == "add" => match value("--allow") {
                Ok(v) => p.rules.allow.push(v),
                Err(e) => return Args::Error(e),
            },
            "--deny" if command == "add" => match value("--deny") {
                Ok(v) => p.rules.deny.push(v),
                Err(e) => return Args::Error(e),
            },
            "--dir" if command == "add" => match value("--dir") {
                Ok(v) => p.rules.dirs.push(v),
                Err(e) => return Args::Error(e),
            },
            "--net" if command == "add" => match value("--net") {
                Ok(v) => p.rules.net = Some(v),
                Err(e) => return Args::Error(e),
            },
            "--reason" if command == "add" => match value("--reason") {
                Ok(v) => p.rules.reason = Some(v),
                Err(e) => return Args::Error(e),
            },
            "--ka" if command == "import" => match value("--ka") {
                Ok(v) => p.ka = Some(v),
                Err(e) => return Args::Error(e),
            },
            "--dotenv" if command == "import" => match value("--dotenv") {
                Ok(v) => p.dotenv = Some(v),
                Err(e) => return Args::Error(e),
            },
            s if s.starts_with('-') => return Args::Error(format!("unrecognised option: {s}")),
            s => p.positional.push(s.to_string()),
        }
    }
    Args::Run(Box::new(p))
}

pub fn run(
    command: &str,
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let usage = usage_of(command);
    let parsed = match parse(command, args) {
        Args::Help => {
            let _ = stdout.write_all(usage.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta {command}: error: {msg}\n\n{usage}");
            return EXIT_USAGE;
        }
        Args::Run(p) => p,
    };
    let cwd = env.cwd.to_string_lossy().into_owned();
    let wants_name = matches!(command, "add" | "reset" | "remove" | "reveal" | "copy");
    let wanted = match command {
        "tier" => 2,
        _ => usize::from(wants_name),
    };
    if parsed.positional.len() != wanted {
        let _ = write!(
            stderr,
            "vahta {command}: error: {}\n\n{usage}",
            if command == "tier" {
                "expected NAME and a tier (session or each-use)"
            } else if wants_name {
                "expected exactly one NAME"
            } else {
                "unexpected argument"
            }
        );
        return EXIT_USAGE;
    }
    let name = parsed.positional.first().cloned().unwrap_or_default();
    let request = match command {
        "init" => ClientRequest::Init { cwd },
        "add" => ClientRequest::Add {
            cwd,
            name,
            tier: parsed.tier,
            file: parsed.file,
            rules: vahta_ipc::protocol::RuleArgs {
                path: std::env::var_os("PATH").map(|p| p.to_string_lossy().into_owned()),
                ..parsed.rules
            },
        },
        "reset" => ClientRequest::Reset {
            cwd,
            name,
            tier: parsed.tier,
            file: parsed.file,
        },
        "tier" => {
            let tier = match parsed.positional[1].as_str() {
                "session" => Tier::Session,
                "each-use" | "each_use" => Tier::EachUse,
                other => {
                    let _ = write!(
                        stderr,
                        "vahta tier: error: invalid tier: {other:?} (choose session or each-use)\n\n{usage}"
                    );
                    return EXIT_USAGE;
                }
            };
            ClientRequest::SetTier { cwd, name, tier }
        }
        "remove" => ClientRequest::Remove { cwd, name },
        "reveal" => ClientRequest::Reveal { cwd, name },
        "copy" => ClientRequest::Copy { cwd, name },
        _ => {
            let source = match (parsed.ka, parsed.dotenv) {
                (Some(path), None) => ImportSource::Ka { path },
                (None, Some(path)) => ImportSource::Dotenv { path },
                _ => {
                    let _ = write!(
                        stderr,
                        "vahta import: error: give exactly one of --ka PATH or --dotenv PATH\n\n{usage}"
                    );
                    return EXIT_USAGE;
                }
            };
            ClientRequest::Import { cwd, source }
        }
    };
    daemon_cmd::request(env, command, &request, parsed.json, stdout, stderr)
}
