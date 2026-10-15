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
//! * every secret must have approved rules (see `vahta_policy`): one with none
//!   is refused (`NoRules`) with the command that proposes some, and the
//!   command must pass the rules first, before any session or window is looked
//!   at;
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

use vahta_policy::Verdict;

use crate::binding;
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, check_name, error, from_vault, lines_for, refused, refused_names, unknown_name,
    unlock_as,
};
use crate::pathfind;
use crate::protocol::{ClientReply, DurationSpec, NameIssue, RefusalKind};
use crate::remote::Target;
use crate::run_ask;
use crate::session::{DelegateRefusal, Role, Session, Sessions, ask_time, info_of};
use crate::session_ops::duration_of;
use crate::surface::sanitize_label;
use vahta_auth::Action;

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
    /// The canonical path of the program, found once with the caller's PATH.
    /// This is what runs, and what the command rules were checked against.
    pub program: PathBuf,
    /// Start the command with no network (a fresh network namespace). A run
    /// that asks for it where it cannot be had is refused, never run open.
    pub isolate_network: bool,
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

/// What a run's secrets add to the window, the journal and the environment:
/// the arguments beyond the allowed prefix, and the variables of the caller
/// that the secrets' categories keep out of the program.
struct Steering {
    /// The arguments the allow rule does not name, as one line (empty: none).
    extra: String,
    /// The caller's variable names that were dropped, never their values.
    dropped: Vec<String>,
    baseline: vahta_policy::EnvBaseline,
}

impl Steering {
    fn of(
        verdicts: &[(&vahta_vault::RuleSet, Verdict)],
        argv: &[String],
        program: Option<&std::path::Path>,
        env: &[(String, String)],
        injected: &[&str],
    ) -> Steering {
        let baseline = vahta_policy::EnvBaseline::of(verdicts.iter().map(|(b, _)| *b));
        let extra = verdicts
            .iter()
            .filter_map(|(b, _)| vahta_policy::extra_args(b, program, argv))
            .max_by_key(|e| e.len())
            .map(command_text)
            .unwrap_or_default();
        let mut dropped: Vec<String> = env
            .iter()
            .map(|(k, _)| k)
            .filter(|k| {
                !is_reserved_env(k)
                    && !k.is_empty()
                    && !k.contains('=')
                    && !baseline.keeps(k)
                    && !injected.contains(&k.as_str())
            })
            .cloned()
            .collect();
        dropped.sort();
        dropped.dedup();
        Steering {
            extra,
            dropped,
            baseline,
        }
    }

    /// The dropped names that could redirect or alter the program, and the
    /// count of the rest.
    fn split_dropped(&self) -> (Vec<&str>, usize) {
        let (redirecting, other): (Vec<&str>, Vec<&str>) = self
            .dropped
            .iter()
            .map(String::as_str)
            .partition(|n| vahta_policy::is_redirecting_env(n));
        (redirecting, other.len())
    }

    /// The window's lines for it: the redirecting names in full, as a
    /// warning, and a count for the rest (a real shell has hundreds).
    fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.extra.is_empty() {
            out.push(format!("Extra arguments: {}", self.extra));
        }
        let (redirecting, other) = self.split_dropped();
        if !redirecting.is_empty() {
            out.push(format!(
                "Your environment tried to point this at another place: {} - not passed on.",
                sanitize_for_message(&redirecting.join(", "))
            ));
        }
        if other > 0 {
            out.push(format!(
                "{}{other} other variable{} not passed on",
                if redirecting.is_empty() { "" } else { "and " },
                if other == 1 { "" } else { "s" }
            ));
        }
        out
    }

    /// The journal's words for it: names and arguments, never a value.
    fn journal_text(&self) -> String {
        let mut out = String::new();
        if !self.extra.is_empty() {
            out.push_str(&format!("; extra arguments: {}", self.extra));
        }
        let (redirecting, other) = self.split_dropped();
        if !redirecting.is_empty() {
            out.push_str(&format!("; env dropped: {}", redirecting.join(",")));
        }
        if other > 0 {
            out.push_str(&format!("; {other} other env variables dropped"));
        }
        out
    }
}

/// What a `Run` request asked for.
pub(crate) struct RunArgs {
    pub cwd: String,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub names: Option<Vec<String>>,
    pub renames: Vec<(String, String)>,
    pub label: Option<String>,
    pub ask: bool,
    pub reason: Option<String>,
    /// `--vault DIR`: the vault's project, when it is not the caller's.
    pub vault: Option<String>,
}

/// What every named secret's approved rules say about a command: the names
/// that have none, and a verdict for each that has. Shared by a run and by the
/// hook's `CheckRun`, so the two can never disagree.
struct Checked<'a> {
    missing: Vec<String>,
    verdicts: Vec<(&'a vahta_vault::RuleSet, Verdict)>,
}

fn check_rules<'a>(
    peek: &'a Peek,
    project: &vahta_vault::project::Project,
    names: &[String],
    argv: &[String],
    program: Option<&std::path::Path>,
    canonical_cwd: &std::path::Path,
) -> Checked<'a> {
    let missing: Vec<String> = names
        .iter()
        .filter(|n| !peek.bindings.iter().any(|b| &b.name == *n))
        .cloned()
        .collect();
    let isolation = vahta_os::network_isolation_available();
    let verdicts = names
        .iter()
        .filter_map(|n| peek.bindings.iter().find(|b| &b.name == n))
        .map(|b| {
            let v = vahta_policy::evaluate(
                b,
                &vahta_policy::Ctx {
                    program,
                    argv,
                    cwd: canonical_cwd,
                    project_root: &project.root,
                    network_isolation: isolation,
                },
            );
            (b, v)
        })
        .collect();
    Checked { missing, verdicts }
}

/// The hook's question (`CheckRun`): would this command run, with no window,
/// under the named secrets' own rules? `Allowed` only when the vault is found
/// and verified, every name is a secret it holds, none is each-use (that one
/// opens a window whatever the rules say), every one has approved rules, and
/// all of them allow the command. Everything else is `NoOpinion`, including
/// every refusal: the real run says why. Nothing is journaled and nothing is
/// started; the vault is only peeked at.
pub(crate) fn check(
    ctx: &Ctx<'_>,
    cwd: &str,
    argv: &[String],
    names: Vec<String>,
    path: Option<String>,
    vault: Option<String>,
) -> ClientReply {
    let allowed = (|| -> Option<()> {
        if argv.is_empty() || argv[0].is_empty() {
            return None;
        }
        let cwd_path = PathBuf::from(cwd);
        if !cwd_path.is_dir() {
            return None;
        }
        let target = Target::for_check(ctx, cwd, vault.as_deref()).ok()?;
        let (project, vault_path) = (&target.project, &target.vault_path);
        let peek = Vault::peek(vault_path).ok()?;
        peek.verified(ctx.store()).ok()?;
        let peek = target.view(peek);
        let pairs = resolve(&peek, project, Some(names), Vec::new()).ok()?;
        let names: Vec<String> = pairs.into_iter().map(|(n, _)| n).collect();
        let each_use = names.iter().any(|n| {
            peek.entries
                .iter()
                .find(|e| &e.name == n)
                .is_none_or(|e| e.tier == Tier::EachUse)
        });
        if each_use {
            return None;
        }
        let client_path = path.map(OsString::from);
        let program = pathfind::locate(&argv[0], client_path.as_ref(), &cwd_path)?;
        let canonical_cwd = pathfind::canonical(&cwd_path).unwrap_or_else(|| cwd_path.clone());
        let checked = check_rules(&peek, project, &names, argv, Some(&program), &canonical_cwd);
        (checked.missing.is_empty() && checked.verdicts.iter().all(|(_, v)| v.is_allowed()))
            .then_some(())
    })();
    match allowed {
        Some(()) => ClientReply::Allowed {},
        None => ClientReply::NoOpinion {},
    }
}

pub(crate) fn prepare(ctx: &Ctx<'_>, args: RunArgs) -> Flow<Prepared> {
    let RunArgs {
        cwd,
        argv,
        env: client_env,
        names,
        renames,
        label,
        ask,
        reason,
        vault,
    } = args;
    let cwd = cwd.as_str();
    if argv.is_empty() || argv[0].is_empty() {
        return Err(error("no command to run"));
    }
    if !PathBuf::from(cwd).is_dir() {
        return Err(error("the current directory is not a directory"));
    }
    let target = Target::resolve(ctx, cwd, vault.as_deref())?;
    // With `--vault`, the directory the kernel says the caller is in.
    let cwd_path = target.cwd.clone();
    let (project, vault_path) = (target.project.clone(), target.vault_path.clone());
    crate::guard_ops::note_project(ctx, &project.root);
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
    let peek = target.view(peek);
    let pairs = resolve(&peek, &project, names, renames)?;
    let names: Vec<String> = pairs.iter().map(|(n, _)| n.clone()).collect();

    let found = find_session(ctx, &peek, target.used_from.as_deref())?;
    // The program, found once. Its canonical path is what the command rules
    // are checked against and what is executed.
    let client_path: Option<OsString> = client_env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| OsString::from(v));
    let program = pathfind::locate(&argv[0], client_path.as_ref(), &cwd_path);
    let canonical_cwd = pathfind::canonical(&cwd_path).unwrap_or_else(|| cwd_path.clone());
    let checked = check_rules(
        &peek,
        &project,
        &names,
        &argv,
        program.as_deref(),
        &canonical_cwd,
    );
    if !checked.missing.is_empty() {
        crate::report::rule_refusal(ctx, &checked.missing, Some(&argv[0]), true);
        return Err(no_rules(ctx, &peek, &checked.missing));
    }
    let verdicts = checked.verdicts;
    let failures: Vec<(&vahta_vault::RuleSet, Verdict)> = verdicts
        .iter()
        .filter(|(_, v)| !v.is_allowed())
        .cloned()
        .collect();
    // Any secret that wants no network cuts it for the whole run.
    let isolate_network = verdicts.iter().any(|(_, v)| {
        matches!(
            v,
            Verdict::Allowed {
                isolate_network: true,
                ..
            }
        )
    });
    let unisolated_note = verdicts.iter().find_map(|(_, v)| match v {
        Verdict::Allowed { note: Some(n), .. } => Some(n.clone()),
        _ => None,
    });
    let injected: Vec<&str> = pairs.iter().map(|(_, v)| v.as_str()).collect();
    let steering = Steering::of(&verdicts, &argv, program.as_deref(), &client_env, &injected);
    if !failures.is_empty() {
        if !ask {
            let refused: Vec<String> = failures.iter().map(|(b, _)| b.name.clone()).collect();
            let shown = program
                .as_deref()
                .and_then(|p| p.file_name())
                .map_or_else(|| argv[0].clone(), |f| f.to_string_lossy().into_owned());
            crate::report::rule_refusal(ctx, &refused, Some(&shown), false);
            return Err(not_allowed(
                ctx,
                &peek,
                &project,
                program.as_deref(),
                &failures,
            ));
        }
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
        let delegated = found.as_ref().is_some_and(|(_, _, d)| *d);
        run_ask::ask(
            ctx,
            &project,
            &vault_path,
            &peek,
            &argv,
            program.as_deref(),
            &failures,
            format!("Secrets: {}", shown.join(", ")),
            format!("Command: {}", command_text(&argv)),
            steering.lines(),
            reason.as_deref(),
            delegated,
        )?;
    }
    let Some(program) = program else {
        return Err(error(format!(
            "cannot start {}: no such program (looked in the caller's PATH)",
            sanitize_for_message(&argv[0])
        )));
    };

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
    let (values, via) = unlock_values(
        ctx,
        Unlock {
            project: &project,
            vault_path: &vault_path,
            peek: &peek,
            names: &names,
            found,
            title: "Run a command",
            lines: {
                let mut lines = vec![
                    format!("Secrets: {}", shown.join(", ")),
                    format!("Command: {}", command_text(&argv)),
                ];
                lines.extend(steering.lines());
                lines.push("This run only; no session is opened.".to_string());
                lines
            },
            label: label.as_deref(),
            refused_event: "run_refused",
            nothing: "nothing was run",
            action: Action::RunEachUse {
                names: names.clone(),
                command: command_text(&argv),
            },
        },
    )?;

    let mut env: Vec<(OsString, OsString)> = filter_env(client_env)
        .into_iter()
        .filter(|(k, _)| steering.baseline.keeps(k))
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    for ((name, var), (_, value)) in pairs.iter().zip(&values) {
        let _ = name;
        env.retain(|(k, _)| k != &OsString::from(var));
        env.push((OsString::from(var), to_os(value.expose())));
    }
    // The values are looked for in what the agent's tools print later, for
    // a while: a command may write one where the next tool reads it.
    if let (Some((anchor, _)), Ok(mut outputs)) =
        (crate::output::anchor_of(ctx), ctx.shared.outputs.lock())
    {
        let given: Vec<(String, Vec<u8>)> = values
            .iter()
            .map(|(n, v)| (n.clone(), v.expose().to_vec()))
            .collect();
        outputs.note_run(anchor, &given, Instant::now());
    }
    ctx.journal(
        Entry::new("run")
            .vault(&peek.vault_id)
            .names(&names)
            .result(
                "started",
                Some(&{
                    let how = match &via {
                        Some(id) => format!("session {id}"),
                        None => "password".to_string(),
                    };
                    let how = match &unisolated_note {
                        Some(_) => format!("{how}; network not cut (not available here)"),
                        None => how,
                    };
                    format!("{how}{}", steering.journal_text())
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
        program,
        isolate_network,
    })
}

/// The caller's session, if any: the deepest one whose anchor is among its
/// ancestors, or under which one of them was launched. `(id, scope,
/// delegated)`.
pub(crate) fn find_session(
    ctx: &Ctx<'_>,
    peek: &Peek,
    used_from: Option<&std::path::Path>,
) -> Flow<Option<(String, Vec<String>, bool)>> {
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let sessions = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| error("the session table is unusable"))?;
    Ok(sessions
        .find(&chain, &peek.vault_id, used_from)
        .map(|s| (s.id.clone(), s.scope.clone(), s.parent.is_some())))
}

/// The values of [`unlock_values`], `(name, value)`, and the id of the session
/// that served them, if any.
pub(crate) type Unlocked = (Vec<(String, SecretValue)>, Option<String>);

/// What [`unlock_values`] needs to get the values of `names`.
pub(crate) struct Unlock<'a> {
    pub project: &'a vahta_vault::project::Project,
    pub vault_path: &'a std::path::Path,
    pub peek: &'a Peek,
    pub names: &'a [String],
    pub found: Option<(String, Vec<String>, bool)>,
    /// The window's title, and what it says after the project lines.
    pub title: &'a str,
    pub lines: Vec<String>,
    pub label: Option<&'a str>,
    /// The journal event for a delegated session that cannot have them.
    pub refused_event: &'static str,
    /// What did not happen, for that refusal: "nothing was run".
    pub nothing: &'static str,
    /// What the unlock is for, which decides what may open the vault.
    pub action: Action,
}

/// The values of `names` for one use, the way every use of a secret gets them:
///
/// * the caller's session covers every name and all are session-tier: the
///   session's keys open them, no window;
/// * a delegated session that does not cover a name (or holds an each-use one)
///   is refused outright: a sub-agent cannot ask the person for more;
/// * otherwise a window asks for the password for this one use and no session
///   is created. An each-use secret always asks, even inside a session.
///
/// Returns the values and the id of the session that served them, if any.
pub(crate) fn unlock_values(ctx: &Ctx<'_>, u: Unlock<'_>) -> Flow<Unlocked> {
    let Unlock {
        project,
        vault_path,
        peek,
        names,
        found,
        title,
        lines: extra,
        label,
        refused_event,
        nothing,
        action,
    } = u;
    let each_use: Vec<String> = names
        .iter()
        .filter(|n| {
            peek.entries
                .iter()
                .find(|e| &e.name == *n)
                .map(|e| e.tier)
                .unwrap_or(Tier::EachUse)
                == Tier::EachUse
        })
        .cloned()
        .collect();
    let mut via: Option<String> = None;
    let mut keys = None;
    if let Some((id, scope, delegated)) = found {
        let uncovered = names.iter().any(|n| !scope.contains(n));
        if !uncovered && each_use.is_empty() {
            let mut sessions = ctx
                .shared
                .sessions
                .lock()
                .map_err(|_| error("the session table is unusable"))?;
            if let Some(s) = sessions.get_mut(&id) {
                keys = s.keys.narrowed(names).ok();
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
                Entry::new(refused_event)
                    .session(&id, None)
                    .vault(&peek.vault_id)
                    .names(&offending)
                    .result("refused", Some(&format!("{kind:?}"))),
            );
            return Err(refused_names(
                kind,
                format!(
                    "this delegated session does not cover these secrets, and a delegated session \
                     cannot ask for more; {nothing}"
                ),
                issue_list(&offending, kind),
            ));
        }
    }

    let mut values: Vec<(String, SecretValue)> = Vec::with_capacity(names.len());
    if let Some(keys) = &keys {
        let bytes = vahta_vault::read_file(vault_path).map_err(from_vault)?;
        for n in names {
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
        let mut window = ctx.window(title)?;
        let mut lines = lines_for(project, vault_path);
        lines.extend(extra);
        let mut panel = ctx.panel(title, lines);
        panel.agent_note = label.and_then(sanitize_label);
        let vault = unlock_as(ctx, window.as_mut(), vault_path, &panel, action)?;
        for n in names {
            let v = vault.get(n).map_err(|e| match e {
                Error::NotFound(_) => unknown_name(n),
                other => from_vault(other),
            })?;
            values.push((n.clone(), v));
        }
        window.close(None);
    }
    Ok((values, via))
}

/// A program name as a message may carry it: one plain line.
fn sanitize_for_message(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(120)
        .collect()
}

/// The refusal for a command that the approved rules do not let a secret
/// have, with the fix, and the journal line (the resolved program, never the
/// arguments).
fn not_allowed(
    ctx: &Ctx<'_>,
    peek: &Peek,
    project: &vahta_vault::project::Project,
    program: Option<&std::path::Path>,
    failures: &[(&vahta_vault::RuleSet, Verdict)],
) -> ClientReply {
    let names: Vec<String> = failures.iter().map(|(b, _)| b.name.clone()).collect();
    let mut lines = Vec::new();
    let mut denied = false;
    for (b, verdict) in failures {
        match verdict {
            Verdict::Denied { rule } => {
                denied = true;
                lines.push(format!("{} denies this command (rule `{rule}`)", b.name));
            }
            Verdict::NotAllowed { why } => lines.push(format!(
                "{} is not for this command: {why} ({})",
                b.name,
                binding::rules_text(b)
            )),
            Verdict::Refused { why } => lines.push(format!("{}: {why}", b.name)),
            Verdict::Allowed { .. } => {}
        }
    }
    let mut message = format!("{}. Nothing was run.", lines.join("; "));
    let stale = unapproved_rules(project, peek, &names);
    if !stale.is_empty() {
        message.push_str(&format!(
            " The vahta.toml rules for {} are not approved; the person runs `vahta bind` to \
             approve the file.",
            stale.join(", ")
        ));
    }
    if denied {
        message.push_str(
            " If the command is legitimate, run it again with `vahta run --ask --reason \"WHY\" \
             -- COMMAND`: the person can allow it once, but a denied command cannot be added to \
             the list. `deny` only slows an agent down; the person's window is the check.",
        );
    } else {
        message.push_str(
            " If the command is legitimate, run it again with `vahta run --ask --reason \"WHY\" \
             -- COMMAND` and the person is asked, or propose a rule with `vahta bind NAME --allow \
             PROGRAM`. The person decides: `allow` is the guard, `deny` only slows an agent down.",
        );
    }
    let shown = match program {
        Some(p) => sanitize_for_message(&p.display().to_string()),
        None => "(not found)".to_string(),
    };
    ctx.journal(
        Entry::new("run_refused")
            .vault(&peek.vault_id)
            .names(&names)
            .result(
                "refused",
                Some(&format!("command_not_allowed; program {shown}")),
            ),
    );
    refused_names(
        RefusalKind::CommandNotAllowed,
        message,
        issue_list(&names, RefusalKind::CommandNotAllowed),
    )
}

/// The refusal for a secret that has no approved rules: it says how to
/// propose some.
fn no_rules(ctx: &Ctx<'_>, peek: &Peek, missing: &[String]) -> ClientReply {
    let mut hints = Vec::new();
    for n in missing {
        let class = peek
            .entries
            .iter()
            .find(|e| &e.name == n)
            .and_then(|e| e.class);
        let cat = vahta_policy::suggest(class, n);
        hints.push(format!(
            "{n}: `vahta bind {n} --category {} --allow PROGRAM[ ARGS] [--deny RULE] [--dir PATH] \
             [--net none|app|hosts:HOST] --reason \"WHY\"`",
            cat.id
        ));
    }
    ctx.journal(
        Entry::new("run_refused")
            .vault(&peek.vault_id)
            .names(missing)
            .result("refused", Some("no_rules")),
    );
    let class = peek
        .entries
        .iter()
        .find(|e| e.name == missing[0])
        .and_then(|e| e.class);
    let checklist: String = vahta_policy::suggest(class, &missing[0])
        .checklist
        .iter()
        .map(|c| format!("\n- {c}"))
        .collect();
    refused_names(
        RefusalKind::NoRules,
        format!(
            "{} no approved rules, so nothing may use {} yet. Design the rules once, up front \
             (see docs/agent-usage.md: the program(s), folders, network, and how a prompt \
             injection could misuse the secret); the person approves them in one window. \
             Propose with: {}. Nothing was run.\nBefore you propose, \
             close the paths a prompt injection would take (network tools, interpreters, shells, \
             writing the value to a file, sending it to another host):{checklist}",
            if missing.len() == 1 {
                "It has"
            } else {
                "They have"
            },
            missing.join(", "),
            hints.join("; ")
        ),
        issue_list(missing, RefusalKind::NoRules),
    )
}

/// Names whose `vahta.toml` rules are not the approved ones (the vault's copy
/// is what is enforced). An unreadable file counts as nothing proposed.
pub(crate) fn unapproved_rules(
    project: &vahta_vault::project::Project,
    peek: &Peek,
    names: &[String],
) -> Vec<String> {
    let Ok(m) = manifest::load(&project.manifest_path()) else {
        return Vec::new();
    };
    names
        .iter()
        .filter(|n| {
            !vahta_policy::rules_in_sync(
                m.secrets.get(*n),
                peek.bindings.iter().find(|b| &b.name == *n),
            )
        })
        .cloned()
        .collect()
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
    vault: Option<String>,
) -> Flow<ClientReply> {
    let target = Target::resolve(ctx, cwd, vault.as_deref())?;
    let (project, vault_path) = (target.project.clone(), target.vault_path.clone());
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    let peek = target.view(peek);
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
    let Some(parent) = sessions.find(&chain, &peek.vault_id, target.used_from.as_deref()) else {
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
    let forms = parent.forms.subset(&wanted);
    let parent_id = parent.id.clone();
    let id = crate::session::new_id().ok_or_else(|| error("the system random generator failed"))?;
    let anchor_exe = ctx.exe.clone().unwrap_or_default();
    let session = Session {
        id: id.clone(),
        tenant: "local",
        vault_id: peek.vault_id,
        vault_path,
        project: project.root,
        used_from: target.used_from.clone(),
        scope: wanted.clone(),
        keys,
        forms,
        role: Role::Runner,
        // The process that asked: it runs the sub-agent and the session ends
        // with it.
        anchor: ctx.peer,
        anchor_exe,
        parent: Some(parent_id.clone()),
        deadline,
        length: deadline.map(|d| d.saturating_duration_since(now)),
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
