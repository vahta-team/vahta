//! `vahta run` and `vahta delegate`, up to the point a command is started.
//!
//! **Run** (the daemon launches the command, so the client never holds a
//! value): the names come from `--secret`, else every name in `vahta.toml` that
//! the vault holds; `--as NAME=ENV` overrides the variable, which otherwise is
//! the manifest's `env`, else the name. Then:
//!
//! * if the caller's session covers every name and all are session-tier, the
//!   values are read with the session's keys and no window opens;
//! * if the session is a delegated one and does not cover a name, the request
//!   is refused outright, with no window: a sub-agent cannot ask the person for
//!   more than it was given;
//! * otherwise a window asks for the password for this one run, and no session
//!   is created. An each-use secret always asks, even inside a session.
//!
//! **Delegate** narrows the caller's session for a sub-agent: a subset of its
//! secrets and no later a deadline, anchored to the calling process. Anything
//! else is a hard refusal with no window.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

use vahta_vault::manifest;
use vahta_vault::{Error, Peek, SecretValue, Tier, Vault, valid_name};

use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, check_name, error, find_vault, from_vault, lines_for, refused, refused_names,
    unknown_name, unlock,
};
use crate::protocol::{ClientReply, DurationSpec, NameIssue, RefusalKind};
use crate::session::{DelegateRefusal, Role, Session, Sessions, ask_time, info_of};
use crate::session_ops::duration_of;
use crate::surface::sanitize_label;

/// Variables never passed on to a command: the ones that load code into it, and
/// Vahta's own controls.
pub fn is_reserved_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "LD_PRELOAD" | "LD_AUDIT" | "LD_LIBRARY_PATH"
    ) || upper.starts_with("DYLD_")
        || upper.starts_with("VAHTA_")
}

/// The caller's environment without [`is_reserved_env`] variables.
pub fn filter_env(env: Vec<(String, String)>) -> Vec<(String, String)> {
    env.into_iter()
        .filter(|(k, _)| !is_reserved_env(k) && !k.is_empty() && !k.contains('='))
        .collect()
}

/// A command ready to start, with the values it will be given.
pub(crate) struct Prepared {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
    /// `(name, value)` of everything injected, for the scrubber.
    pub values: Vec<(String, Vec<u8>)>,
    /// The session the command runs under, whose descendants inherit it.
    pub session: Option<String>,
    pub names: Vec<String>,
}

fn to_os(bytes: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(bytes).to_os_string()
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// The names to inject and the variable each goes in.
fn resolve(
    peek: &Peek,
    project: &vahta_vault::project::Project,
    names: Option<Vec<String>>,
    renames: Vec<(String, String)>,
) -> Flow<Vec<(String, String)>> {
    let manifest = {
        let path = project.manifest_path();
        if path.is_file() {
            Some(manifest::load(&path).map_err(from_vault)?)
        } else {
            None
        }
    };
    let names: Vec<String> = match names.filter(|n| !n.is_empty()) {
        Some(list) => {
            let mut out: Vec<String> = Vec::new();
            for n in list {
                check_name(&n)?;
                if !peek.entries.iter().any(|e| e.name == n) {
                    return Err(unknown_name(&n));
                }
                if !out.contains(&n) {
                    out.push(n);
                }
            }
            out
        }
        None => {
            let Some(m) = &manifest else {
                return Err(refused(
                    RefusalKind::NothingToDo,
                    "no secrets named: pass --secret NAME, or list them in vahta.toml",
                ));
            };
            let present: Vec<String> = m
                .secrets
                .keys()
                .filter(|n| peek.entries.iter().any(|e| &e.name == *n))
                .cloned()
                .collect();
            if present.is_empty() {
                return Err(refused(
                    RefusalKind::NothingToDo,
                    "vahta.toml names no secret that this vault holds",
                ));
            }
            present
        }
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (n, var) in &renames {
        if !names.contains(n) {
            return Err(error(format!(
                "--as {n}=...: {n} is not among the secrets being run"
            )));
        }
        if !valid_name(var) {
            return Err(error(
                "a variable name is letters, digits and underscores, not starting with a digit",
            ));
        }
        if is_reserved_env(var) {
            return Err(error(format!(
                "{var} is reserved and cannot be set from a secret"
            )));
        }
    }
    for n in names {
        let var = renames
            .iter()
            .find(|(name, _)| name == &n)
            .map(|(_, v)| v.clone())
            .or_else(|| {
                manifest
                    .as_ref()
                    .and_then(|m| m.secrets.get(&n))
                    .map(|e| e.env.clone())
            })
            .unwrap_or_else(|| n.clone());
        if is_reserved_env(&var) {
            return Err(error(format!(
                "{var} is reserved and cannot be set from a secret"
            )));
        }
        if pairs.iter().any(|(_, v)| v == &var) {
            return Err(error(format!("two secrets would be put in {var}")));
        }
        pairs.push((n, var));
    }
    Ok(pairs)
}

fn issue_list(names: &[String], why: RefusalKind) -> Vec<NameIssue> {
    names
        .iter()
        .map(|n| NameIssue {
            name: n.clone(),
            why,
        })
        .collect()
}

pub(crate) fn prepare(
    ctx: &Ctx<'_>,
    cwd: &str,
    argv: Vec<String>,
    client_env: Vec<(String, String)>,
    names: Option<Vec<String>>,
    renames: Vec<(String, String)>,
    label: Option<String>,
) -> Flow<Prepared> {
    if argv.is_empty() || argv[0].is_empty() {
        return Err(error("no command to run"));
    }
    let cwd_path = PathBuf::from(cwd);
    if !cwd_path.is_dir() {
        return Err(error("the current directory is not a directory"));
    }
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified(ctx.store()).map_err(from_vault)?;
    let pairs = resolve(&peek, &project, names, renames)?;
    let names: Vec<String> = pairs.iter().map(|(n, _)| n.clone()).collect();

    let tier_of = |n: &str| {
        peek.entries
            .iter()
            .find(|e| e.name == n)
            .map(|e| e.tier)
            .unwrap_or(Tier::EachUse)
    };
    let each_use: Vec<String> = names
        .iter()
        .filter(|n| tier_of(n) == Tier::EachUse)
        .cloned()
        .collect();

    // The caller's session, if any: the deepest one whose anchor is among its
    // ancestors, or under which one of them was launched.
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let found = {
        let sessions = ctx
            .shared
            .sessions
            .lock()
            .map_err(|_| error("the session table is unusable"))?;
        sessions
            .find(&chain, &peek.vault_id)
            .map(|s| (s.id.clone(), s.scope.clone(), s.parent.is_some()))
    };
    let mut via: Option<String> = None;
    let mut keys = None;
    if let Some((id, scope, delegated)) = found {
        let uncovered: Vec<String> = names
            .iter()
            .filter(|n| !scope.contains(n))
            .cloned()
            .collect();
        if uncovered.is_empty() && each_use.is_empty() {
            let mut sessions = ctx
                .shared
                .sessions
                .lock()
                .map_err(|_| error("the session table is unusable"))?;
            if let Some(s) = sessions.get_mut(&id) {
                keys = s.keys.narrowed(&names).ok();
                if keys.is_some() {
                    s.uses += 1;
                    via = Some(id);
                }
            }
        } else if delegated {
            // A sub-agent asks for nothing beyond what it was given, and the
            // person is not asked on its behalf.
            let kind = if each_use.is_empty() {
                RefusalKind::OutOfScope
            } else {
                RefusalKind::EachUse
            };
            let offending: Vec<String> = names
                .iter()
                .filter(|n| !scope.contains(n) || each_use.contains(n))
                .cloned()
                .collect();
            ctx.journal(
                Entry::new("run_refused")
                    .session(&id, None)
                    .vault(&peek.vault_id)
                    .names(&offending)
                    .result("refused", Some(&format!("{kind:?}"))),
            );
            return Err(refused_names(
                kind,
                "this delegated session does not cover these secrets, and a delegated session cannot \
                 ask for more; nothing was run",
                issue_list(&offending, kind),
            ));
        }
    }

    // The values.
    let mut values: Vec<(String, SecretValue)> = Vec::with_capacity(names.len());
    if let Some(keys) = &keys {
        let bytes = vahta_vault::read_file(&vault_path).map_err(from_vault)?;
        for n in &names {
            match keys.open(&bytes, n, ctx.store()) {
                Ok(v) => values.push((n.clone(), v)),
                Err(Error::SessionStale) => {
                    return Err(refused_names(
                        RefusalKind::Stale,
                        Error::SessionStale.to_string(),
                        issue_list(std::slice::from_ref(n), RefusalKind::Stale),
                    ));
                }
                Err(e) => return Err(from_vault(e)),
            }
        }
    } else {
        let mut window = ctx.window("Run a command")?;
        let mut lines = lines_for(&project, &vault_path);
        let shown: Vec<String> = pairs
            .iter()
            .map(|(n, v)| {
                if n == v {
                    n.clone()
                } else {
                    format!("{n} as {v}")
                }
            })
            .collect();
        lines.push(format!("Secrets: {}", shown.join(", ")));
        lines.push(format!("Command: {}", command_text(&argv)));
        lines.push("This run only; no session is opened.".to_string());
        let mut panel = ctx.panel("Run a command", lines);
        panel.agent_note = label.as_deref().and_then(sanitize_label);
        let vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
        for n in &names {
            let v = vault.get(n).map_err(|e| match e {
                Error::NotFound(_) => unknown_name(n),
                other => from_vault(other),
            })?;
            values.push((n.clone(), v));
        }
        window.close(None);
    }

    let mut env: Vec<(OsString, OsString)> = filter_env(client_env)
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    for ((name, var), (_, value)) in pairs.iter().zip(&values) {
        let _ = name;
        env.retain(|(k, _)| k != &OsString::from(var));
        env.push((OsString::from(var), to_os(value.expose())));
    }
    ctx.journal(
        Entry::new("run")
            .vault(&peek.vault_id)
            .names(&names)
            .result(
                "started",
                Some(&match &via {
                    Some(id) => format!("session {id}"),
                    None => "password".to_string(),
                }),
            ),
    );
    Ok(Prepared {
        argv,
        cwd: cwd_path,
        env,
        values: values
            .iter()
            .map(|(n, v)| (n.clone(), v.expose().to_vec()))
            .collect(),
        session: via,
        names,
    })
}

/// The command as the window shows it: one line, cut if long.
fn command_text(argv: &[String]) -> String {
    let joined = argv.join(" ");
    let one_line: String = joined
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if one_line.chars().count() > 200 {
        let cut: String = one_line.chars().take(200).collect();
        format!("{cut}...")
    } else {
        one_line
    }
}

pub(crate) fn delegate(
    ctx: &Ctx<'_>,
    cwd: &str,
    names: Vec<String>,
    duration: DurationSpec,
    label: Option<String>,
) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    if names.is_empty() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "name the secrets to delegate with --secret NAME",
        ));
    }
    let mut wanted: Vec<String> = Vec::new();
    for n in names {
        check_name(&n)?;
        if !wanted.contains(&n) {
            wanted.push(n);
        }
    }
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let now = Instant::now();
    let mut sessions = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| error("the session table is unusable"))?;
    let Some(parent) = sessions.find(&chain, &peek.vault_id) else {
        return Err(refused(
            RefusalKind::NoSession,
            "there is no session to narrow; run `vahta unlock` first",
        ));
    };
    let lasts = match duration {
        // As long as the parent has.
        DurationSpec::Default {} => parent.deadline.map(|d| d.saturating_duration_since(now)),
        other => duration_of(other, 0)?,
    };
    let deadline = match duration {
        DurationSpec::Default {} => parent.deadline,
        _ => lasts.map(|d| now + d),
    };
    if let Err(refusal) = Sessions::check_delegate(parent, &wanted, deadline) {
        let (kind, message, issues) = match refusal {
            DelegateRefusal::NotASubset(missing) => (
                RefusalKind::NotASubset,
                "a delegated session may only narrow its parent's; nothing was delegated",
                issue_list(&missing, RefusalKind::NotASubset),
            ),
            DelegateRefusal::LaterDeadline => (
                RefusalKind::LaterDeadline,
                "a delegated session cannot outlast its parent; nothing was delegated",
                Vec::new(),
            ),
        };
        let parent_id = parent.id.clone();
        drop(sessions);
        ctx.journal(
            Entry::new("delegate_refused")
                .session(&parent_id, None)
                .vault(&peek.vault_id)
                .names(&wanted)
                .result("refused", Some(&format!("{kind:?}"))),
        );
        return Err(refused_names(kind, message, issues));
    }
    let keys = parent.keys.narrowed(&wanted).map_err(from_vault)?;
    let parent_id = parent.id.clone();
    let id = crate::session::new_id().ok_or_else(|| error("the system random generator failed"))?;
    let anchor_exe = ctx.exe.clone().unwrap_or_default();
    let session = Session {
        id: id.clone(),
        tenant: "local",
        vault_id: peek.vault_id,
        vault_path,
        project: project.root,
        scope: wanted.clone(),
        keys,
        role: Role::Runner,
        // The process that asked: it runs the sub-agent and the session ends
        // with it.
        anchor: ctx.peer,
        anchor_exe,
        parent: Some(parent_id.clone()),
        deadline,
        ask_at: deadline.map(|d| ask_time(now, d)),
        extension_pending: false,
        label: label.as_deref().and_then(sanitize_label),
        uses: 0,
    };
    let info = info_of(&session, now);
    sessions.add(session);
    drop(sessions);
    ctx.journal(
        Entry::new("session_start")
            .session(&id, Some(&parent_id))
            .vault(&peek.vault_id)
            .names(&wanted)
            .result("ok", Some("delegated")),
    );
    Ok(ClientReply::Session(Box::new(info)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn the_variables_that_load_code_and_vahtas_own_are_not_passed_on() {
        let kept = filter_env(env(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/x"),
            ("LD_PRELOAD", "/evil.so"),
            ("LD_AUDIT", "/evil.so"),
            ("LD_LIBRARY_PATH", "/evil"),
            ("ld_preload", "/evil.so"),
            ("DYLD_INSERT_LIBRARIES", "/evil"),
            ("DYLD_LIBRARY_PATH", "/evil"),
            ("VAHTA_DATA_DIR", "/x"),
            ("VAHTA_TEST_SURFACE", "/x"),
            ("vahta_x", "1"),
            ("LD_DEBUG", "all"),
            ("BROKEN=NAME", "x"),
            ("", "x"),
        ]));
        let names: Vec<&str> = kept.iter().map(|(k, _)| k.as_str()).collect();
        // LD_DEBUG is not one of the three that load code.
        assert_eq!(names, ["PATH", "HOME", "LD_DEBUG"]);
        assert!(
            is_reserved_env("LD_PRELOAD")
                && is_reserved_env("DYLD_FOO")
                && is_reserved_env("VAHTA_X")
        );
        assert!(!is_reserved_env("PATH") && !is_reserved_env("VAHTA"));
    }

    #[test]
    fn a_command_is_shown_on_one_line_and_cut() {
        assert_eq!(command_text(&["printenv".into(), "A".into()]), "printenv A");
        assert_eq!(
            command_text(&["a\nb".into(), "\u{1b}[31m".into()]),
            "a b  [31m"
        );
        let long = command_text(&["x".repeat(500)]);
        assert_eq!(long.chars().count(), 203);
        assert!(long.ends_with("..."));
    }
}
