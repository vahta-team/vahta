//! `--connector`: the commands of the connectors vault.
//!
//! Harnesses start MCP servers at user scope, and the key of such a server
//! belongs to no project. The connectors vault is one per user, in Vahta's own
//! data directory, and it is set up by the person in their own terminal. The
//! commands are the ordinary ones with `--connector`: `init`, `add`, `list`,
//! `check`, `bind`, `unlock`, `run` and `remove`. `--connector` never uses a
//! project's vault, and a project's commands never use this one.
//!
//! `list` and `check` read the vault without a password or a daemon, and show
//! the launches that were refused when a daemon runs (`vahta daemon status`
//! shows them too).

use std::io::Write;

use serde_json::json;
use vahta_ipc::paths::{connectors_manifest, connectors_vault};
use vahta_ipc::protocol::{
    ClientReply, ClientRequest, ConnectorCmd, ConnectorRefusal, DurationSpec, RuleArgs, Tier,
};
use vahta_vault::manifest;
use vahta_vault::store::LocalStore;
use vahta_vault::{Peek, Vault, VaultKind};

use crate::daemon_cmd;
use crate::session_cmds::parse_duration;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

const COMMANDS: &[&str] = &[
    "init", "add", "list", "check", "bind", "unlock", "run", "remove",
];

pub const INIT_USAGE: &str = "\
usage: vahta init --connector [--json]

Create the connectors vault, once, in your own terminal: the one vault for the
keys of the MCP servers your coding agents (Claude Code, Codex, Cursor) start.
It lives in Vahta's data directory, not in a project. A window opens where you
choose the password; the recovery key is shown there once.
";

pub const ADD_USAGE: &str = "\
usage: vahta add --connector NAME --harness claude[,codex][,cursor]
                 --allow 'COMMAND ARGS' [--deny RULE]... [--category C]
                 [--net none|app|hosts:H[,H...]] [--reason TEXT] [--json]

Store the key of one MCP server. A window opens where you type the vault
password and then the value, hidden. NAME is the environment variable the
server reads its key from (GITHUB_PERSONAL_ACCESS_TOKEN, say).

  --harness H[,H]   the harnesses that may start this server (claude, codex,
                    cursor); the harness must start `vahta run --connector`
                    itself
  --allow RULE      the server's command, as the harness config starts it after
                    `--` (repeatable), for example
                    'npx -y @modelcontextprotocol/server-github@1.2.3'
                    Pin the version: the rule trusts what that command runs.

Without both, the connector has no rules and nothing may start it.
";

pub const BIND_USAGE: &str = "\
usage: vahta bind --connector NAME [--harness H[,H]] [--allow RULE]...
                  [--deny RULE]... [--category C] [--dir PATH]...
                  [--net none|app|hosts:H[,H...]] [--reason TEXT] [--json]
       vahta bind --connector NAME --clear [--json]

Change the harnesses or the command rules of a connector (the person approves
in a window with the vault password). `--from` does not apply.
";

pub const UNLOCK_USAGE: &str = "\
usage: vahta unlock --connector [--for DURATION] [--label TEXT] [--json]

Open the connectors session, in your own terminal, before you start the harness:
the password once, then `vahta run --connector` starts each server with no
window until the session ends. The harnesses give a server about 30 seconds to
start and show you nothing of its error output, so without a session a launch
is refused at once (see `vahta daemon status`). The session is yours, not a
process tree's: it covers a harness started from a launcher too.

  --for DURATION  end it after this long (for example 8h). Without it the session
                  lasts until the computer restarts (or `vahta lock --all`).
";

pub const RUN_USAGE: &str = "\
usage: vahta run --connector --secret NAME [--as NAME=VAR] [--] COMMAND [ARGS...]

How a harness starts the MCP server of a connector. Put it in the harness's
config in place of the server's own command (see docs/connectors.md). The
command must be one of NAME's allow rules, and the harness must be one NAME is
bound to. With no connectors session it is refused at once (exit 3).

  --as NAME=VAR   put the secret in the variable VAR, when the server reads its
                  key from a name other than NAME (as `vahta run --as` does)
";

pub const LIST_USAGE: &str = "\
usage: vahta list --connector [--json]

List the connectors: name, harnesses, command rules, and the last refused
launch of each (a name, a time and what to do). No password, no values.
";

pub const CHECK_USAGE: &str = "\
usage: vahta check --connector [--json]

Check the connectors vault: every connector has harnesses and an allow rule, and
connectors/vahta.toml proposes nothing the vault has not approved. Exit 1
otherwise.
";

pub const REMOVE_USAGE: &str = "\
usage: vahta remove --connector NAME [--json]

Remove a connector (the vault password, in a window).
";

/// Whether `--connector` is among the words this command takes as options. For
/// `run`, the words after `--` or the first non-option are the server's own.
fn wants_connector(command: &str, args: &[String]) -> bool {
    if command == "run" {
        let mut skip_value = false;
        for a in args {
            if skip_value {
                skip_value = false;
                continue;
            }
            match a.as_str() {
                "--connector" => return true,
                "--" => return false,
                "--secret" | "--label" | "--as" | "--vault" | "--reason" => skip_value = true,
                s if !s.starts_with('-') || s == "-" => return false,
                _ => {}
            }
        }
        return false;
    }
    args.iter().any(|a| a == "--connector")
}

/// Run `args` as a `--connector` command if it is one; `None` for any other.
pub fn dispatch(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<i32> {
    let command = args.first()?.as_str();
    if !COMMANDS.contains(&command) || !wants_connector(command, &args[1..]) {
        return None;
    }
    let usage = usage_of(command);
    let parsed = match parse(command, &args[1..]) {
        Parsed::Help => {
            let _ = stdout.write_all(usage.as_bytes());
            return Some(EXIT_CLEAN);
        }
        Parsed::Error(msg) => {
            let _ = write!(stderr, "vahta {command}: error: {msg}\n\n{usage}");
            return Some(EXIT_USAGE);
        }
        Parsed::Run(p) => *p,
    };
    Some(match command {
        "list" => list(&parsed, env, stdout, stderr),
        "check" => check(&parsed, env, stdout, stderr),
        "unlock" => unlock(&parsed, env, stdout, stderr),
        "run" => run(parsed, env, stdout, stderr),
        _ => {
            let json = parsed.json;
            match request_of(command, parsed) {
                Ok(cmd) => daemon_cmd::request(
                    env,
                    command,
                    &ClientRequest::Connector { cmd },
                    json,
                    stdout,
                    stderr,
                ),
                Err(msg) => {
                    let _ = write!(stderr, "vahta {command}: error: {msg}\n\n{usage}");
                    EXIT_USAGE
                }
            }
        }
    })
}

fn usage_of(command: &str) -> &'static str {
    match command {
        "init" => INIT_USAGE,
        "add" => ADD_USAGE,
        "bind" => BIND_USAGE,
        "unlock" => UNLOCK_USAGE,
        "run" => RUN_USAGE,
        "list" => LIST_USAGE,
        "check" => CHECK_USAGE,
        _ => REMOVE_USAGE,
    }
}

#[derive(Default)]
struct Args {
    json: bool,
    positional: Vec<String>,
    harnesses: Vec<String>,
    rules: RuleArgs,
    clear: bool,
    tier: Option<Tier>,
    duration: Option<DurationSpec>,
    label: Option<String>,
    named: Option<String>,
    renames: Vec<(String, String)>,
    command: Vec<String>,
}

enum Parsed {
    Run(Box<Args>),
    Help,
    Error(String),
}

fn parse(command: &str, args: &[String]) -> Parsed {
    let mut p = Args::default();
    let rules_ok = matches!(command, "add" | "bind");
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if command == "run" && a == "--" {
            p.command = args[i..].to_vec();
            break;
        }
        if command == "run" && (!a.starts_with('-') || a == "-") {
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
        let result: Result<(), String> = match a {
            "-h" | "--help" => return Parsed::Help,
            "--connector" => Ok(()),
            "--json" => {
                p.json = true;
                Ok(())
            }
            "--harness" if rules_ok => value("--harness").and_then(|v| {
                for h in v.split(',') {
                    let h = h.trim();
                    if h.is_empty() {
                        return Err("--harness expects claude, codex or cursor".to_string());
                    }
                    p.harnesses.push(h.to_string());
                }
                Ok(())
            }),
            "--allow" if rules_ok => value("--allow").map(|v| p.rules.allow.push(v)),
            "--deny" if rules_ok => value("--deny").map(|v| p.rules.deny.push(v)),
            "--category" if rules_ok => value("--category").map(|v| p.rules.category = Some(v)),
            "--dir" if rules_ok => value("--dir").map(|v| p.rules.dirs.push(v)),
            "--net" if rules_ok => value("--net").map(|v| p.rules.net = Some(v)),
            "--reason" if rules_ok => value("--reason").map(|v| p.rules.reason = Some(v)),
            "--clear" if command == "bind" => {
                p.clear = true;
                Ok(())
            }
            "--tier" if command == "add" => value("--tier").and_then(|v| match v.as_str() {
                "session" => {
                    p.tier = Some(Tier::Session);
                    Ok(())
                }
                other => Err(format!(
                    "invalid --tier value: {other:?} (a connector's secret is always session)"
                )),
            }),
            "--for" if command == "unlock" => value("--for")
                .and_then(|v| parse_duration(&v))
                .map(|d| p.duration = Some(d)),
            "--label" if matches!(command, "unlock" | "run") => {
                value("--label").map(|v| p.label = Some(v))
            }
            "--as" if command == "run" => value("--as").and_then(|v| match v.split_once('=') {
                Some((n, var)) if !n.is_empty() && !var.is_empty() => {
                    p.renames.push((n.to_string(), var.to_string()));
                    Ok(())
                }
                _ => Err("--as expects NAME=VAR".to_string()),
            }),
            "--secret" if command == "run" => value("--secret").and_then(|v| {
                if p.named.is_some() {
                    Err("a connector's server takes one --secret".to_string())
                } else {
                    p.named = Some(v);
                    Ok(())
                }
            }),
            s if s.starts_with('-') => Err(format!("unrecognised option: {s}")),
            s => {
                p.positional.push(s.to_string());
                Ok(())
            }
        };
        if let Err(e) = result {
            return Parsed::Error(e);
        }
    }
    Parsed::Run(Box::new(p))
}

/// The request for the commands that go to the daemon with a name.
fn request_of(command: &str, mut p: Args) -> Result<ConnectorCmd, String> {
    let one_name = |p: &Args| -> Result<String, String> {
        match p.positional.as_slice() {
            [n] => Ok(n.clone()),
            _ => Err("expected exactly one NAME".to_string()),
        }
    };
    let path = std::env::var_os("PATH").map(|v| v.to_string_lossy().into_owned());
    match command {
        "init" => {
            if !p.positional.is_empty() {
                return Err("unexpected argument".to_string());
            }
            Ok(ConnectorCmd::Init {})
        }
        "remove" => Ok(ConnectorCmd::Remove {
            name: one_name(&p)?,
        }),
        "add" => {
            let name = one_name(&p)?;
            p.rules.harnesses = std::mem::take(&mut p.harnesses);
            p.rules.path = path;
            Ok(ConnectorCmd::Add {
                name,
                tier: p.tier,
                rules: p.rules,
            })
        }
        _ => {
            let name = one_name(&p)?;
            Ok(ConnectorCmd::Bind {
                name,
                harnesses: p.harnesses,
                allow: p.rules.allow,
                deny: p.rules.deny,
                clear: p.clear,
                reason: p.rules.reason,
                path,
                category: p.rules.category,
                dirs: p.rules.dirs,
                net: p.rules.net,
            })
        }
    }
}

fn human_secs(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn unlock(p: &Args, env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if !p.positional.is_empty() {
        let _ = write!(
            stderr,
            "vahta unlock: error: unexpected argument\n\n{UNLOCK_USAGE}"
        );
        return EXIT_USAGE;
    }
    let request = ClientRequest::Connector {
        cmd: ConnectorCmd::Unlock {
            duration: p.duration.unwrap_or(DurationSpec::Default {}),
            label: p.label.clone(),
        },
    };
    let mut conn = match daemon_cmd::connect(env, "unlock", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(&request) {
        Ok(ClientReply::Session(info)) => {
            if p.json {
                let _ = writeln!(stdout, "{}", json!({"ok": true, "session": &*info}));
            } else {
                let _ = writeln!(
                    stdout,
                    "connectors session {} open for {}; {}",
                    info.id,
                    info.names.join(", "),
                    match info.remaining_secs {
                        _ if info.until_reboot => "lasts until this computer restarts".to_string(),
                        Some(s) => format!("lasts {}", human_secs(s)),
                        None => "lasts until revoked".to_string(),
                    }
                );
                let _ = writeln!(stdout, "Start the harness now.");
            }
            EXIT_CLEAN
        }
        Ok(other) => daemon_cmd::report("unlock", &other, p.json, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta unlock: error: {e}");
            EXIT_DAEMON
        }
    }
}

fn run(p: Args, env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(name) = p.named else {
        let _ = write!(
            stderr,
            "vahta run: error: --connector needs --secret NAME\n\n{RUN_USAGE}"
        );
        return EXIT_USAGE;
    };
    if p.command.is_empty() {
        let _ = write!(stderr, "vahta run: error: no command given\n\n{RUN_USAGE}");
        return EXIT_USAGE;
    }
    let request = ClientRequest::Connector {
        cmd: ConnectorCmd::Run {
            cwd: env.cwd.to_string_lossy().into_owned(),
            argv: p.command,
            env: crate::run_cmd::environment(),
            name,
            renames: p.renames,
            label: p.label,
        },
    };
    let mut conn = match daemon_cmd::connect(env, "run", stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(&request) {
        Ok(ClientReply::RunStarted {}) => crate::run_cmd::relay(conn.stream(), stdout, stderr),
        Ok(other) => daemon_cmd::report("run", &other, false, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta run: error: {e}");
            EXIT_DAEMON
        }
    }
}

/// `connector NAME was refused at <time>: <what to do>`, one per line.
pub fn refusal_lines(refusals: &[ConnectorRefusal]) -> Vec<String> {
    refusals
        .iter()
        .map(|r| {
            format!(
                "connector {} was refused at {}: {}",
                r.name,
                daemon_cmd::utc_text(r.at),
                r.hint
            )
        })
        .collect()
}

/// The refusals a running daemon remembers; none when it is not running.
fn refusals_now(env: &Env) -> Vec<ConnectorRefusal> {
    let mut sink = Vec::new();
    match daemon_cmd::running(env, &mut sink) {
        Ok(Some((_, mut conn))) => daemon_cmd::status_of(&mut conn)
            .map(|s| s.connector_refusals)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Open the connectors vault's index: a verified peek and the vault's path.
fn open(
    env: &Env,
    command: &str,
    stderr: &mut dyn Write,
) -> Result<(Peek, std::path::PathBuf), i32> {
    let Some(data) = env.data_dir.as_ref() else {
        let _ = writeln!(
            stderr,
            "vahta {command}: error: cannot tell where Vahta keeps its data on this machine \
             (set VAHTA_DATA_DIR)"
        );
        return Err(EXIT_FAILED);
    };
    let path = connectors_vault(data);
    if !path.is_file() {
        let _ = writeln!(
            stderr,
            "vahta {command}: there is no connectors vault yet; run `vahta init --connector`"
        );
        return Err(EXIT_FAILED);
    }
    let peek = Vault::peek(&path).map_err(|e| {
        let _ = writeln!(stderr, "vahta {command}: error: {e}");
        EXIT_FAILED
    })?;
    if peek.kind != VaultKind::Connectors {
        let _ = writeln!(
            stderr,
            "vahta {command}: error: {} is not a connectors vault",
            path.display()
        );
        return Err(EXIT_FAILED);
    }
    peek.verified(&LocalStore::new(data)).map_err(|e| {
        let _ = writeln!(stderr, "vahta {command}: error: {e}");
        EXIT_FAILED
    })?;
    Ok((peek, path))
}

/// `(harnesses, allow rules)` of a connector; empty for one with no rules.
fn rules_of(peek: &Peek, name: &str) -> (Vec<String>, Vec<String>) {
    match peek.bindings.iter().find(|b| b.name == name) {
        Some(b) => (
            b.harnesses.clone(),
            b.allow.iter().map(|r| r.text.clone()).collect(),
        ),
        None => (Vec::new(), Vec::new()),
    }
}

fn list(p: &Args, env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (peek, path) = match open(env, "list", stderr) {
        Ok(ok) => ok,
        Err(code) => return code,
    };
    let refusals = refusals_now(env);
    let mut names: Vec<&str> = peek.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort();
    if p.json {
        let secrets: Vec<_> = names
            .iter()
            .map(|n| {
                let (harnesses, allow) = rules_of(&peek, n);
                json!({"name": n, "harnesses": harnesses, "allow": allow,
                       "complete": !harnesses.is_empty() && !allow.is_empty()})
            })
            .collect();
        let doc = json!({
            "vault": path.display().to_string(),
            "secrets": secrets,
            "refusals": refusals,
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        );
        return EXIT_CLEAN;
    }
    if names.is_empty() {
        let _ = writeln!(stdout, "No connectors in the vault.");
    }
    for n in &names {
        let (harnesses, allow) = rules_of(&peek, n);
        if harnesses.is_empty() || allow.is_empty() {
            let _ = writeln!(stdout, "{n}  NO RULES (nothing may start it)");
        } else {
            let _ = writeln!(
                stdout,
                "{n}  harnesses: {}  allow: {}",
                harnesses.join(","),
                allow.join("; ")
            );
        }
    }
    for line in refusal_lines(&refusals) {
        let _ = writeln!(stdout, "{line}");
    }
    EXIT_CLEAN
}

fn check(p: &Args, env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (peek, path) = match open(env, "check", stderr) {
        Ok(ok) => ok,
        Err(code) => return code,
    };
    let mut problems: Vec<String> = Vec::new();
    for e in &peek.entries {
        let (harnesses, allow) = rules_of(&peek, &e.name);
        if harnesses.is_empty() || allow.is_empty() {
            problems.push(format!(
                "{0}: needs harnesses and an allow rule (`vahta bind --connector {0} --harness \
                 claude --allow 'COMMAND'`)",
                e.name
            ));
        }
    }
    if let Some(data) = env.data_dir.as_ref() {
        let manifest_path = connectors_manifest(data);
        if manifest_path.is_file() {
            match manifest::load(&manifest_path) {
                Ok(m) => {
                    for e in &peek.entries {
                        if !vahta_policy::rules_in_sync(
                            m.secrets.get(&e.name),
                            peek.bindings.iter().find(|b| b.name == e.name),
                        ) {
                            problems.push(format!(
                                "{}: connectors/vahta.toml proposes rules the vault has not \
                                 approved",
                                e.name
                            ));
                        }
                    }
                }
                Err(e) => problems.push(format!("connectors/vahta.toml: {e}")),
            }
        }
    }
    if p.json {
        let doc = json!({
            "ok": problems.is_empty(),
            "vault": path.display().to_string(),
            "problems": problems,
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        );
    } else if problems.is_empty() {
        let _ = writeln!(stdout, "Vault: {}\nOK", path.display());
    } else {
        let _ = writeln!(stderr, "Vault: {}", path.display());
        for pr in &problems {
            let _ = writeln!(stderr, "  {pr}");
        }
        let _ = writeln!(stderr, "FAIL");
    }
    if problems.is_empty() {
        EXIT_CLEAN
    } else {
        EXIT_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::wants_connector;

    fn w(command: &str, args: &[&str]) -> bool {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        wants_connector(command, &a)
    }

    #[test]
    fn the_flag_counts_only_where_it_is_an_option() {
        assert!(w("list", &["--connector"]));
        assert!(w("run", &["--connector", "--secret", "A", "--", "x"]));
        assert!(w("run", &["--secret", "A", "--connector", "--", "x"]));
        // After the command it is the command's own word.
        assert!(!w("run", &["--secret", "A", "--", "tool", "--connector"]));
        assert!(!w("run", &["tool", "--connector"]));
        assert!(!w("run", &["--secret", "--connector"]));
        assert!(!w("list", &[]));
    }
}
