//! `vahta id`, `vahta members`, `grant`, `revoke`, `share` and `join`: sharing a
//! vault with teammates through a chat. See `docs/team.md`.
//!
//! `id --show` and the listing need no password. Everything that changes who
//! may read what, makes a file for someone or installs one opens a window: the
//! owner's password, or the member's identity password. The verification words
//! are typed in that window, never as an argument.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use vahta_ipc::duration::{human, parse_secs, ymd};
use vahta_ipc::members::{MemberInfo, MemberOp};
use vahta_ipc::protocol::{ClientReply, ClientRequest};
use vahta_vault::identity;
use vahta_vault::member;

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_FAILED, EXIT_USAGE, Env};

/// How long a membership lasts unless `--for` says otherwise.
const DEFAULT_ACCESS: &str = "30d";

pub const ID_USAGE: &str = "\
usage: vahta id [--show]

Make your own key for joining a team vault. A window asks for a password that
protects it on this machine. The key is kept in the data directory
(identity.vht); nobody else ever has your password.

  (none)   create the identity and print your key (vh1...) and six words
  --show   print them again; no password

Send the key to the vault's owner in the chat. Read the six words to the owner
over a call or in person, NOT in the chat: they let the owner check the key was
not swapped on the way.
";

pub const MEMBERS_USAGE: &str = "\
usage: vahta members [list] [--json]
       vahta members add NAME --role runner|editor|admin --key vh1... [--for DURATION|never]
       vahta members extend NAME --for DURATION
       vahta members remove NAME
       vahta members words

The people who can have secrets from this vault.

  list     name, role, when access ends, state, which secrets each holds, and a
           short fingerprint of the key. No password.
  add      add a member by the key they sent. A window shows the name, role and
           end date, and asks you to TYPE the six words the member reads out to
           you (`vahta id --show` on their machine); a mismatch refuses the add
           and writes nothing. Then your password. Access lasts 30d unless
           --for says otherwise (--for never: no end).
  extend   give a member access for DURATION from now. Password.
  remove   remove a member and re-key the secrets they held; prints the secrets
           to rotate in the real services. Password.
  words    the six words that identify THIS vault's owner, to read to a member

Roles: runner runs commands with the secrets it is given; editor also adds and
changes its own secrets and can send them to you; admin also manages runners
and editors.

options:
  --for DURATION   30d, 12h ... (1 minute to 10 years)
  --json           machine-readable list
  -h, --help       show this help
";

pub const GRANT_USAGE: &str = "\
usage: vahta grant SECRET MEMBER
       vahta revoke SECRET MEMBER

grant lets a member read SECRET from the next package you send them; a window
asks you to confirm, then your password. revoke takes it back and re-keys the
secret; the member could already read it, so rotate it in the real service.
";

pub const SHARE_USAGE: &str = "\
usage: vahta share MEMBER -o FILE
       vahta share --to owner SECRET -o FILE

The first (the owner) writes a package for MEMBER: a file holding only that
member's entry and only the secrets they hold, signed by you. Send it to them
in the chat; they run `vahta join FILE`. Your password.

The second (an editor or admin) writes one secret for the vault's owner, sealed
so that only the owner can read it, and signed by you. Your identity password.
The owner runs `vahta join FILE` in the project and approves it.

FILE must not exist.
";

pub const JOIN_USAGE: &str = "\
usage: vahta join FILE

On a member's machine: install the package the owner sent as this project's
vault. The first time, a window shows the owner's six words to compare with
what the owner read to you. A package older than the one installed is refused.

On the owner's machine: import the secret an editor sent (`vahta share --to
owner`). A window shows its name and sender and asks first.
";

fn usage_error(stderr: &mut dyn Write, cmd: &str, usage: &str, msg: &str) -> i32 {
    let _ = write!(stderr, "vahta {cmd}: error: {msg}\n\n{usage}");
    EXIT_USAGE
}

fn absolute(env: &Env, p: &str) -> String {
    let path = Path::new(p);
    if path.is_absolute() {
        p.to_string()
    } else {
        env.cwd.join(path).to_string_lossy().into_owned()
    }
}

fn cwd(env: &Env) -> String {
    env.cwd.to_string_lossy().into_owned()
}

fn send(
    env: &Env,
    command: &str,
    what: MemberOp,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let request = ClientRequest::Members {
        cwd: cwd(env),
        what,
    };
    daemon_cmd::request(env, command, &request, false, stdout, stderr)
}

// --- id -----------------------------------------------------------------------------------------

pub fn run_id(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut show = false;
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                let _ = stdout.write_all(ID_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--show" => show = true,
            other => {
                return usage_error(
                    stderr,
                    "id",
                    ID_USAGE,
                    &format!("unrecognised argument: {other}"),
                );
            }
        }
    }
    if !show {
        return send(env, "id", MemberOp::Id {}, stdout, stderr);
    }
    let Some(dir) = &env.data_dir else {
        let _ = writeln!(
            stderr,
            "vahta id: error: cannot tell where this machine keeps its data"
        );
        return EXIT_FAILED;
    };
    let path: PathBuf = dir.join("identity.vht");
    if !identity::exists(&path) {
        let _ = writeln!(stderr, "vahta id: error: no identity yet; run `vahta id`");
        return EXIT_FAILED;
    }
    match identity::read_public(&path) {
        Ok(public) => {
            let _ = writeln!(
                stdout,
                "your key (send this in the chat):\n  {}\nyour six verification words (read these \
                 out over a call or in person, never in the chat):\n  {}",
                member::public_key_string(&public),
                member::words_line(&public)
            );
            EXIT_CLEAN
        }
        Err(e) => {
            let _ = writeln!(stderr, "vahta id: error: {e}");
            EXIT_FAILED
        }
    }
}

// --- members -------------------------------------------------------------------------------------

fn access(m: &MemberInfo) -> String {
    match m.expires_at {
        Some(t) => ymd(t),
        None => "no end".to_string(),
    }
}

fn table(members: &[MemberInfo]) -> String {
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ROLE".to_string(),
        "ACCESS UNTIL".to_string(),
        "STATE".to_string(),
        "KEY".to_string(),
        "SECRETS".to_string(),
    ]];
    for m in members {
        rows.push(vec![
            m.name.clone(),
            m.role.clone(),
            access(m),
            m.state.clone(),
            m.fingerprint.clone(),
            if m.secrets.is_empty() {
                "-".to_string()
            } else {
                m.secrets.join(", ")
            },
        ]);
    }
    let widths: Vec<usize> = (0..6)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    rows.iter()
        .map(|r| {
            r.iter()
                .enumerate()
                .map(|(c, cell)| format!("{cell:<w$}", w = widths[c]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run_members(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let usage =
        |stderr: &mut dyn Write, msg: &str| usage_error(stderr, "members", MEMBERS_USAGE, msg);
    let mut positional: Vec<&str> = Vec::new();
    let (mut role, mut key, mut json_out) = (None::<&str>, None::<&str>, false);
    let mut span: Option<Option<u64>> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(MEMBERS_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => json_out = true,
            "--role" | "--key" | "--for" => {
                let Some(v) = args.get(i) else {
                    return usage(stderr, &format!("{a} needs a value"));
                };
                i += 1;
                match a {
                    "--role" => role = Some(v),
                    "--key" => key = Some(v),
                    _ if v == "never" => span = Some(None),
                    _ => match parse_secs(v) {
                        Some(s) if s > 0 => span = Some(Some(s)),
                        _ => return usage(stderr, &format!("not a duration: {v}")),
                    },
                }
            }
            other if other.starts_with('-') => {
                return usage(stderr, &format!("unrecognised argument: {other}"));
            }
            other => positional.push(other),
        }
    }
    let loose = role.is_some() || key.is_some();
    match positional.as_slice() {
        [] | ["list"] if !loose && span.is_none() => {
            let request = ClientRequest::Members {
                cwd: cwd(env),
                what: MemberOp::List {},
            };
            let mut conn = match daemon_cmd::connect(env, "members", stderr) {
                Ok(c) => c,
                Err(code) => return code,
            };
            match conn.request(&request) {
                Ok(ClientReply::Members {
                    owner_words,
                    members,
                }) => {
                    if json_out {
                        let _ = writeln!(
                            stdout,
                            "{}",
                            serde_json::to_string_pretty(
                                &json!({"owner_words": owner_words, "members": members})
                            )
                            .unwrap_or_default()
                        );
                    } else {
                        if members.is_empty() {
                            let _ = writeln!(
                                stdout,
                                "no members yet; add one with `vahta members add`"
                            );
                        } else {
                            let _ = writeln!(stdout, "{}", table(&members));
                        }
                        let _ = writeln!(stdout, "owner's words: {owner_words}");
                    }
                    EXIT_CLEAN
                }
                Ok(other) => daemon_cmd::report("members", &other, json_out, stdout, stderr),
                Err(e) => {
                    let _ = writeln!(stderr, "vahta members: error: {e}");
                    EXIT_DAEMON
                }
            }
        }
        ["words"] if !loose && span.is_none() => {
            let request = ClientRequest::Members {
                cwd: cwd(env),
                what: MemberOp::List {},
            };
            let mut conn = match daemon_cmd::connect(env, "members", stderr) {
                Ok(c) => c,
                Err(code) => return code,
            };
            match conn.request(&request) {
                Ok(ClientReply::Members { owner_words, .. }) => {
                    let _ = writeln!(stdout, "{owner_words}");
                    EXIT_CLEAN
                }
                Ok(other) => daemon_cmd::report("members", &other, false, stdout, stderr),
                Err(e) => {
                    let _ = writeln!(stderr, "vahta members: error: {e}");
                    EXIT_DAEMON
                }
            }
        }
        ["add", name] => {
            let (Some(role), Some(key)) = (role, key) else {
                return usage(stderr, "add needs --role and --key");
            };
            let secs = match span {
                Some(s) => s,
                None => parse_secs(DEFAULT_ACCESS),
            };
            if let Some(s) = secs {
                let _ = writeln!(stderr, "(access for {})", human(s));
            }
            send(
                env,
                "members add",
                MemberOp::Add {
                    name: (*name).to_string(),
                    role: role.to_string(),
                    key: key.to_string(),
                    secs,
                },
                stdout,
                stderr,
            )
        }
        ["extend", name] if !loose => {
            let Some(Some(secs)) = span else {
                return usage(stderr, "extend needs --for DURATION");
            };
            send(
                env,
                "members extend",
                MemberOp::Extend {
                    name: (*name).to_string(),
                    secs,
                },
                stdout,
                stderr,
            )
        }
        ["remove", name] if !loose && span.is_none() => send(
            env,
            "members remove",
            MemberOp::Remove {
                name: (*name).to_string(),
            },
            stdout,
            stderr,
        ),
        _ => usage(
            stderr,
            "expected list, add NAME, extend NAME, remove NAME or words",
        ),
    }
}

// --- grant / revoke ------------------------------------------------------------------------------

pub fn run_grant(
    give: bool,
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let cmd = if give { "grant" } else { "revoke" };
    let mut positional = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                let _ = stdout.write_all(GRANT_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            other if other.starts_with('-') => {
                return usage_error(
                    stderr,
                    cmd,
                    GRANT_USAGE,
                    &format!("unrecognised argument: {other}"),
                );
            }
            other => positional.push(other),
        }
    }
    let [name, member] = positional.as_slice() else {
        return usage_error(stderr, cmd, GRANT_USAGE, "expected SECRET and MEMBER");
    };
    let (name, member) = ((*name).to_string(), (*member).to_string());
    let what = if give {
        MemberOp::Grant { name, member }
    } else {
        MemberOp::Revoke { name, member }
    };
    send(env, cmd, what, stdout, stderr)
}

// --- share / join -------------------------------------------------------------------------------

pub fn run_share(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let usage = |stderr: &mut dyn Write, msg: &str| usage_error(stderr, "share", SHARE_USAGE, msg);
    let mut positional: Vec<&str> = Vec::new();
    let (mut out, mut to) = (None::<&str>, None::<&str>);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(SHARE_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "-o" | "--out" | "--to" => {
                let Some(v) = args.get(i) else {
                    return usage(stderr, &format!("{a} needs a value"));
                };
                i += 1;
                if a == "--to" {
                    to = Some(v);
                } else {
                    out = Some(v);
                }
            }
            other if other.starts_with('-') => {
                return usage(stderr, &format!("unrecognised argument: {other}"));
            }
            other => positional.push(other),
        }
    }
    let Some(out) = out else {
        return usage(stderr, "share needs -o FILE");
    };
    let out = absolute(env, out);
    match (to, positional.as_slice()) {
        (None, [member]) => send(
            env,
            "share",
            MemberOp::Share {
                member: (*member).to_string(),
                out,
            },
            stdout,
            stderr,
        ),
        (Some("owner"), [name]) => send(
            env,
            "share",
            MemberOp::SendToOwner {
                name: (*name).to_string(),
                out,
            },
            stdout,
            stderr,
        ),
        (Some(other), _) if other != "owner" => usage(stderr, "--to takes only `owner`"),
        _ => usage(stderr, "expected MEMBER, or --to owner SECRET"),
    }
}

pub fn run_join(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match args {
        [a] if a == "-h" || a == "--help" => {
            let _ = stdout.write_all(JOIN_USAGE.as_bytes());
            EXIT_CLEAN
        }
        [file] if !file.starts_with('-') => send(
            env,
            "join",
            MemberOp::Join {
                file: absolute(env, file),
            },
            stdout,
            stderr,
        ),
        _ => usage_error(stderr, "join", JOIN_USAGE, "expected one FILE"),
    }
}
