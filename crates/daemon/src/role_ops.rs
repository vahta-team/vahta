//! Agent roles: a named delegation template, approved once by the person.
//!
//! An agent (or the person) writes a proposal in `vahta.toml` (`[roles.NAME]`,
//! see `vahta_vault::manifest_roles`); `vahta role NAME` shows it in a window
//! and, on "Approve" plus the vault password, stores it signed in the vault. A
//! role holds no key. It only narrows:
//!
//! ```text
//! effective = the secret's own rules  ∩  the role  ∩  the delegating session
//! ```
//!
//! **Before any window** the proposal is checked against each of its secrets'
//! approved rules ([`vahta_policy::role::too_wide`]); a role wider than a
//! secret is refused with a sentence that says what is wider, and the person
//! is never asked.
//!
//! **In a role session** (opened by `unlock --role` or `delegate --role`, and
//! inherited by every session delegated from it) the daemon allows only `run`
//! and `http`, and only those the role lists in `actions`. Every other request
//! is refused with `RoleForbids` ([`forbids`]). A run passes the secret's own
//! rules first and then the role's allow, deny, folders and network; the
//! stricter network of the two applies to the actual run. `uses` counts runs
//! and requests (and those of sessions delegated from it); `ask` puts a
//! window in front of each use.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vahta_auth::{Action, Request};
use vahta_policy::Verdict;
use vahta_vault::manifest::{self, network_word};
use vahta_vault::manifest_roles::{self, RoleEntry};
use vahta_vault::project::Project;
use vahta_vault::{AgentRole, Network, Peek, Vault};

use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, error, find_vault, from_surface, from_vault, lines_for, refused, refused_names,
    unknown_name, unlock_expecting,
};
use crate::proposal::{self, Args};
use crate::protocol::{ClientReply, ClientRequest, NameIssue, RefusalKind};
use crate::surface::sanitize_label;

const APPROVE: usize = 0;

/// What a `Role` request asked for.
pub(crate) struct RoleArgs {
    pub cwd: String,
    pub name: Option<String>,
    pub remove: bool,
    pub reason: Option<String>,
    pub path: Option<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn span_text(secs: u64) -> String {
    vahta_ipc::duration::human(secs)
}

fn actions_text(role: &AgentRole) -> String {
    role.actions
        .iter()
        .map(|a| match a {
            vahta_vault::Action::Run => "run commands",
            vahta_vault::Action::Http => "send requests",
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

fn hosts_text(n: &Network) -> String {
    match n {
        Network::Hosts(h) => h
            .iter()
            .map(|h| h.text.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

/// A role in plain words, one line each, for the window.
pub(crate) fn describe(role: &AgentRole) -> Vec<String> {
    let texts = |rules: &[vahta_vault::ApprovedRule]| {
        rules
            .iter()
            .map(|r| format!("`{}`", r.text))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = vec![
        format!("Role: {}", role.name),
        format!("Secrets: {}", role.secrets.join(", ")),
        if role.allow.is_empty() {
            "Commands: whatever each secret's own rules allow".to_string()
        } else {
            format!("Commands: only {}", texts(&role.allow))
        },
    ];
    if !role.deny.is_empty() {
        out.push(format!("Never: {}", texts(&role.deny)));
    }
    out.push(match &role.network {
        None => "Network: each secret's own".to_string(),
        Some(Network::None) => "Network: none".to_string(),
        Some(Network::App) => "Network: the application's own".to_string(),
        Some(n @ Network::Hosts(_)) => format!("Network: only {}", hosts_text(n)),
    });
    out.push(if role.dirs.is_empty() {
        "Folders: whichever each secret allows".to_string()
    } else {
        format!(
            "Folders: only {}",
            role.dirs
                .iter()
                .map(|d| d.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    out.push(match role.max_for_secs {
        Some(s) => format!("One grant lasts at most {}", span_text(s)),
        None => "No limit on how long one grant lasts".to_string(),
    });
    if let Some(n) = role.max_uses {
        out.push(format!("One grant gives at most {n} uses"));
    }
    out.push(format!("The agent may: {}", actions_text(role)));
    if role.ask_each_use {
        out.push("You are asked before every use".to_string());
    }
    out
}

/// A role on one line, for "now:" lines and messages.
fn summary(role: &AgentRole) -> String {
    describe(role)[1..].join("; ")
}

// --- Approval -----------------------------------------------------------------------------

struct Change {
    name: String,
    old: Option<AgentRole>,
    new: AgentRole,
    resolved: Vec<(String, PathBuf)>,
    warnings: Vec<String>,
}

/// A role, the programs its allow rules resolved to, and what to warn about.
type BuiltRole = (AgentRole, Vec<(String, PathBuf)>, Vec<String>);

fn network_of(e: &RoleEntry) -> Option<Network> {
    match e.network.as_deref() {
        Some("none") => Some(Network::None),
        Some("app") => Some(Network::App),
        Some("hosts") => Some(Network::Hosts(e.hosts.clone())),
        _ => None,
    }
}

/// The role as approved if the person says yes: programs and folders
/// resolved, nothing stored yet.
fn build(e: &RoleEntry, project: &Project, path: Option<&OsString>) -> Result<BuiltRole, String> {
    let args = Args {
        category: None,
        allow: e.allow.iter().map(|r| r.text.clone()).collect(),
        deny: e.deny.iter().map(|r| r.text.clone()).collect(),
        dirs: e.dirs.clone(),
        net: None,
        path: path.cloned(),
        from: Vec::new(),
    };
    let built = proposal::build(&e.name, None, &args, &project.root)?;
    let rs = built.rule_set;
    let role = AgentRole {
        name: e.name.clone(),
        secrets: e.secrets.clone(),
        allow: rs.allow,
        deny: rs.deny,
        network: network_of(e),
        dirs: rs.dirs,
        max_for_secs: e.max_for_secs,
        max_uses: e.max_uses,
        actions: e.actions.clone(),
        ask_each_use: e.ask_each_use,
        approved_at: 0,
    };
    vahta_vault::format::current::check_role(&role).map_err(|e| e.to_string())?;
    Ok((role, built.resolved, built.warnings))
}

/// Why each secret of `role` is wider than its approved rules, or a refusal
/// when a secret is missing or has none.
fn check_narrower(role: &AgentRole, peek: &Peek) -> Flow<()> {
    let mut wider: Vec<String> = Vec::new();
    for s in &role.secrets {
        if !peek.entries.iter().any(|e| &e.name == s) {
            return Err(unknown_name(s));
        }
        let Some(rules) = peek.bindings.iter().find(|b| &b.name == s) else {
            return Err(refused_names(
                RefusalKind::NoRules,
                format!(
                    "role {}: {s} has no approved rules, so a role cannot narrow them; the person \
                     approves rules first (`vahta bind {s} --category ... --allow PROGRAM`). \
                     Nothing was asked.",
                    role.name
                ),
                vec![NameIssue {
                    name: s.clone(),
                    why: RefusalKind::NoRules,
                }],
            ));
        };
        wider.extend(vahta_policy::role::too_wide(role, s, rules));
    }
    if wider.is_empty() {
        return Ok(());
    }
    Err(refused(
        RefusalKind::RoleTooWide,
        format!(
            "role {} is wider than its secrets' approved rules, and a role can only narrow: {}. \
             Narrow the role in vahta.toml and run `vahta role {}` again. No window was opened.",
            role.name,
            wider.join("; "),
            role.name
        ),
    ))
}

pub(crate) fn role(ctx: &Ctx<'_>, args: RoleArgs) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(&args.cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
    if args.remove {
        return remove(ctx, &args, &project, &vault_path, &peek);
    }
    let path: Option<OsString> = args.path.as_deref().map(OsString::from);
    let manifest_path = project.manifest_path();
    if !manifest_path.is_file() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "there is no vahta.toml here to read a role from; write a [roles.NAME] section in it \
             and run `vahta role NAME`",
        ));
    }
    let manifest = manifest::load(&manifest_path).map_err(from_vault)?;
    let wanted: Vec<&RoleEntry> = match &args.name {
        Some(name) => {
            crate::ops::check_name(name)?;
            match manifest.roles.get(name) {
                Some(e) => vec![e],
                None => {
                    return Err(refused(
                        RefusalKind::NothingToDo,
                        format!(
                            "vahta.toml has no [roles.{name}]; write the proposal there (secrets, \
                             allow, deny, network, dirs, for, uses, actions, ask) and run \
                             `vahta role {name}` again"
                        ),
                    ));
                }
            }
        }
        None => manifest
            .roles
            .values()
            .filter(|e| {
                !manifest_roles::role_in_sync(Some(e), peek.roles.iter().find(|r| r.name == e.name))
            })
            .collect(),
    };
    let mut changes: Vec<Change> = Vec::new();
    for e in wanted {
        let (new, resolved, warnings) = build(e, &project, path.as_ref())
            .map_err(|m| error(format!("role {}: {m}", e.name)))?;
        // Checked before any window: a role wider than a secret is never shown.
        if let Err(reply) = check_narrower(&new, &peek) {
            ctx.journal(
                Entry::new("role_refused")
                    .vault(&peek.vault_id)
                    .names(&new.secrets)
                    .role(Some(&new.name))
                    .result("refused", Some("too_wide_or_unknown")),
            );
            return Err(reply);
        }
        let old = peek.roles.iter().find(|r| r.name == e.name).cloned();
        changes.push(Change {
            name: e.name.clone(),
            old,
            new,
            resolved,
            warnings,
        });
    }
    if changes.is_empty() {
        return Ok(ClientReply::Done {
            message: "nothing to approve: vahta.toml and the vault have the same roles".to_string(),
        });
    }

    let title = "Approve an agent role";
    let mut lines = lines_for(&project, &vault_path);
    let mut warnings: Vec<String> = Vec::new();
    for c in &changes {
        lines.extend(describe(&c.new));
        for (text, program) in &c.resolved {
            lines.push(format!("`{text}` is {}", program.display()));
        }
        match &c.old {
            Some(old) => lines.push(format!("It replaces the approved role: {}", summary(old))),
            None => lines.push("It is not approved yet.".to_string()),
        }
        for w in &c.warnings {
            if !warnings.contains(w) {
                warnings.push(w.clone());
            }
        }
    }
    lines.push(
        "A role holds no key and can only narrow what each secret's own rules allow; Vahta \
         enforces it for any agent session that uses it."
            .to_string(),
    );
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = args.reason.as_deref().and_then(sanitize_label);
    if !warnings.is_empty() {
        panel.warning = Some(warnings.join(" "));
    }
    let names: Vec<String> = changes.iter().map(|c| c.name.clone()).collect();
    let secrets: Vec<String> = {
        let mut all: Vec<String> = changes
            .iter()
            .flat_map(|c| c.new.secrets.iter().cloned())
            .collect();
        all.sort();
        all.dedup();
        all
    };

    let mut window = ctx.window(title)?;
    let options = vec!["Approve".to_string(), "No".to_string()];
    let choice = window
        .choose(&panel, "Approve this role?", &options)
        .map_err(from_surface)?;
    if choice != Some(APPROVE) {
        ctx.journal(
            Entry::new("role_approved")
                .vault(&peek.vault_id)
                .names(&secrets)
                .role(Some(&names.join(",")))
                .result("declined", None),
        );
        window.close(None);
        return Err(ClientReply::Cancelled {
            message: "the person did not agree; the roles are unchanged".to_string(),
        });
    }
    panel.warning = None;
    let action = Action::Other {
        what: format!("approve the agent role {}", names.join(", ")),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    let approved_at = now_secs();
    for c in &changes {
        let mut role = c.new.clone();
        role.approved_at = approved_at;
        vault.set_role(role).map_err(from_vault)?;
    }
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    // A session that carries an older version of a role ends: it must not
    // outlive the approval it was opened under.
    let replaced: Vec<String> = changes
        .iter()
        .filter(|c| c.old.is_some())
        .map(|c| c.name.clone())
        .collect();
    end_role_sessions(ctx, &peek, &replaced, "role_changed");
    for c in &changes {
        ctx.journal(
            Entry::new("role_approved")
                .vault(&peek.vault_id)
                .names(&c.new.secrets)
                .role(Some(&c.name))
                .result("approved", Some(&summary(&c.new))),
        );
    }
    window.close(Some("Role saved."));
    Ok(ClientReply::Done {
        message: format!("approved the role {}", names.join(", ")),
    })
}

fn remove(
    ctx: &Ctx<'_>,
    args: &RoleArgs,
    project: &Project,
    vault_path: &std::path::Path,
    peek: &Peek,
) -> Flow<ClientReply> {
    let Some(name) = &args.name else {
        return Err(refused(
            RefusalKind::NothingToDo,
            "name the role to remove: `vahta role --remove NAME`",
        ));
    };
    crate::ops::check_name(name)?;
    let Some(old) = peek.roles.iter().find(|r| &r.name == name) else {
        return Err(refused(
            RefusalKind::UnknownRole,
            format!("no approved role named {name} in this vault"),
        ));
    };
    let title = "Remove an agent role";
    let mut lines = lines_for(project, vault_path);
    lines.extend(describe(old));
    lines.push("Sessions limited to this role end.".to_string());
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = args.reason.as_deref().and_then(sanitize_label);
    let mut window = ctx.window(title)?;
    let options = vec!["Remove".to_string(), "No".to_string()];
    let choice = window
        .choose(&panel, "Remove this role?", &options)
        .map_err(from_surface)?;
    if choice != Some(APPROVE) {
        window.close(None);
        return Err(ClientReply::Cancelled {
            message: "the person did not agree; the role stays".to_string(),
        });
    }
    let action = Action::Other {
        what: format!("remove the agent role {name}"),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), vault_path, &panel, action, peek)?;
    vault.remove_role(name).map_err(from_vault)?;
    // The file first, so it shows what is enforced; a failure leaves the vault.
    let manifest_path = project.manifest_path();
    if manifest_path.is_file() {
        let current = std::fs::read_to_string(&manifest_path).map_err(|e| {
            error(format!(
                "cannot read {}: {e}; nothing was done",
                manifest_path.display()
            ))
        })?;
        let updated = manifest_roles::remove_role_text(&current, name).map_err(from_vault)?;
        if updated != current {
            manifest::write_text(&manifest_path, &updated).map_err(from_vault)?;
        }
    }
    vault.save(vault_path, ctx.store()).map_err(from_vault)?;
    end_role_sessions(ctx, peek, std::slice::from_ref(name), "role_removed");
    ctx.journal(
        Entry::new("role_removed")
            .vault(&peek.vault_id)
            .names(&old.secrets)
            .role(Some(name))
            .result("removed", None),
    );
    window.close(Some("Role removed."));
    Ok(ClientReply::Done {
        message: format!("removed the role {name}"),
    })
}

fn end_role_sessions(ctx: &Ctx<'_>, peek: &Peek, names: &[String], reason: &'static str) {
    if names.is_empty() {
        return;
    }
    let ended = match ctx.shared.sessions.lock() {
        Ok(mut s) => s.end_where(
            |s| {
                s.vault_id == peek.vault_id
                    && s.agent_role
                        .as_ref()
                        .is_some_and(|r| names.contains(&r.name))
            },
            reason,
        ),
        Err(_) => return,
    };
    ctx.shared.record_ended(ended);
}

// --- Sessions ------------------------------------------------------------------------------

/// A role session's role, found for a request.
pub(crate) struct Active {
    pub session: String,
    pub role: AgentRole,
}

/// The role of session `id`, if it carries one.
pub(crate) fn active(ctx: &Ctx<'_>, id: Option<&str>) -> Flow<Option<Active>> {
    let Some(id) = id else {
        return Ok(None);
    };
    let sessions = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| error("the session table is unusable"))?;
    Ok(sessions.get(id).and_then(|s| {
        s.agent_role.as_ref().map(|r| Active {
            session: s.id.clone(),
            role: r.clone(),
        })
    }))
}

/// The approved role `name` of this vault, or the refusal.
pub(crate) fn find_role(peek: &Peek, name: &str) -> Flow<AgentRole> {
    crate::ops::check_name(name)?;
    peek.roles
        .iter()
        .find(|r| r.name == name)
        .cloned()
        .ok_or_else(|| {
            refused(
                RefusalKind::UnknownRole,
                format!(
                    "no approved role named {name} in this vault. A role is proposed in \
                     vahta.toml ([roles.{name}]) and approved by the person with \
                     `vahta role {name}`; vahta.toml alone changes nothing."
                ),
            )
        })
}

/// A refusal inside a role session, journaled.
pub(crate) fn forbid(
    ctx: &Ctx<'_>,
    a: &Active,
    vault_id: Option<&[u8; 16]>,
    names: &[String],
    kind: RefusalKind,
    message: String,
) -> ClientReply {
    let mut entry = Entry::new("role_refused")
        .session(&a.session, None)
        .role(Some(&a.role.name))
        .names(names)
        .result("refused", Some(&format!("{kind:?}")));
    if let Some(v) = vault_id {
        entry = entry.vault(v);
    }
    ctx.journal(entry);
    refused(kind, message)
}

/// The action a request is, must be one the role lists.
pub(crate) fn require_action(
    ctx: &Ctx<'_>,
    a: &Active,
    action: vahta_vault::Action,
    peek: &Peek,
    names: &[String],
) -> Flow<()> {
    if a.role.actions.contains(&action) {
        return Ok(());
    }
    let (what, ask) = match action {
        vahta_vault::Action::Run => ("run commands", "`vahta run`"),
        vahta_vault::Action::Http => ("send requests", "`vahta http`"),
    };
    Err(forbid(
        ctx,
        a,
        Some(&peek.vault_id),
        names,
        RefusalKind::RoleForbids,
        format!(
            "this session is limited to the role {}, which does not let it {what} ({ask}); it may: \
             {}. Nothing was done. If the task needs it, a new role is proposed in vahta.toml and \
             the person approves it with `vahta role`.",
            a.role.name,
            actions_text(&a.role)
        ),
    ))
}

/// The role's own check of a command, after the secrets' rules passed: its
/// allow, deny and folders. Returns whether the role asks for a run with no
/// network.
pub(crate) fn narrow_run(
    ctx: &Ctx<'_>,
    a: &Active,
    peek: &Peek,
    names: &[String],
    eval: &vahta_policy::Ctx<'_>,
) -> Flow<bool> {
    let narrowing = vahta_policy::role::narrowing(&a.role);
    let why = match vahta_policy::evaluate(&narrowing, eval) {
        Verdict::Allowed {
            isolate_network, ..
        } => return Ok(isolate_network),
        Verdict::Denied { rule } => format!("the role denies this command (rule `{rule}`)"),
        Verdict::NotAllowed { why } => format!("this command is not for the role: {why}"),
        Verdict::Refused { why } => why,
    };
    Err(forbid(
        ctx,
        a,
        Some(&peek.vault_id),
        names,
        RefusalKind::RoleForbids,
        format!(
            "this session is limited to the role {}: {why}. Nothing was run. The role allows: {}",
            a.role.name,
            describe(&a.role)[2..].join("; ")
        ),
    ))
}

/// Refuse when the role's uses are spent.
pub(crate) fn check_uses(ctx: &Ctx<'_>, a: &Active, peek: &Peek, names: &[String]) -> Flow<()> {
    let spent = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| error("the session table is unusable"))?
        .role_spent(&a.session);
    match spent {
        None => Ok(()),
        Some(role) => Err(forbid(
            ctx,
            a,
            Some(&peek.vault_id),
            names,
            RefusalKind::RoleExhausted,
            format!(
                "the uses of the role {role} are spent (it gives {} per grant); nothing was done. \
                 Open a new session with `vahta unlock --role {role}` if the person agrees.",
                a.role
                    .max_uses
                    .map_or("a few".to_string(), |n| n.to_string())
            ),
        )),
    }
}

/// A use happened: it counts against the roles above this session too.
pub(crate) fn note_use(ctx: &Ctx<'_>, a: &Active) {
    if let Ok(mut s) = ctx.shared.sessions.lock() {
        s.count_above(&a.session);
    }
}

/// A role with `ask`: the person says yes to this one use.
pub(crate) fn ask_use(
    ctx: &Ctx<'_>,
    a: &Active,
    project: &Project,
    vault_path: &std::path::Path,
    peek: &Peek,
    names: &[String],
    what: Vec<String>,
) -> Flow<()> {
    if !a.role.ask_each_use {
        return Ok(());
    }
    let title = "Use a secret under a role";
    let mut lines = lines_for(project, vault_path);
    lines.push(format!("Role: {}", a.role.name));
    lines.push(format!("Secrets: {}", names.join(", ")));
    lines.extend(what.clone());
    let panel = ctx.panel(title, lines);
    let mut window = ctx.window(title)?;
    let options = vec!["Allow this use".to_string(), "No".to_string()];
    let request = Request::new(
        Action::RunAsk {
            names: names.to_vec(),
            command: what.join("; "),
            reason: None,
        },
        &project.root.display().to_string(),
        peek.vault_id,
        Duration::from_secs(5 * 60),
    )
    .map_err(|e| error(e.to_string()))?
    .with_options(&options);
    let need = crate::authn::need_of(peek, &request.action);
    let choice = crate::authn::approve(
        ctx.shared,
        window.as_mut(),
        &panel,
        "Allow this use of the role?",
        vault_path,
        &request,
        need,
        Duration::from_secs(5 * 60),
    )
    .map_err(|e| match e {
        vahta_auth::AuthError::Denied => crate::authn::refused_on_phone(),
        other => error(other.to_string()),
    })?;
    window.close(None);
    if choice == Some(0) {
        return Ok(());
    }
    ctx.journal(
        Entry::new("role_refused")
            .session(&a.session, None)
            .vault(&peek.vault_id)
            .names(names)
            .role(Some(&a.role.name))
            .result("declined", Some("ask_each_use")),
    );
    Err(ClientReply::Cancelled {
        message: "the person did not agree to this use; nothing was done".to_string(),
    })
}

/// `vahta http` under a role: the role's network must allow the destination.
pub(crate) fn narrow_http(
    ctx: &Ctx<'_>,
    a: &Active,
    peek: &Peek,
    names: &[String],
    host: &str,
    host_ok: impl Fn(&[vahta_vault::HostRule]) -> bool,
) -> Flow<()> {
    let why = match &a.role.network {
        None | Some(Network::App) => return Ok(()),
        Some(Network::None) => "the role gives no network".to_string(),
        Some(Network::Hosts(hosts)) if host_ok(hosts) => return Ok(()),
        Some(n @ Network::Hosts(_)) => {
            format!("the role may only reach {}", hosts_text(n))
        }
    };
    Err(forbid(
        ctx,
        a,
        Some(&peek.vault_id),
        names,
        RefusalKind::RoleForbids,
        format!(
            "this session is limited to the role {}: {host} is not allowed, {why} (network {}). \
             Nothing was sent.",
            a.role.name,
            a.role.network.as_ref().map_or("unset", network_word)
        ),
    ))
}

/// The deadline a role allows: `wanted` (a length) and the role's longest
/// grant, whichever is shorter. `None`: no limit.
pub(crate) fn capped(wanted: Option<Duration>, role: &AgentRole) -> Option<Duration> {
    match (wanted, role.max_for_secs.map(Duration::from_secs)) {
        (Some(w), Some(m)) => Some(w.min(m)),
        (None, m) => m,
        (w, None) => w,
    }
}

// --- The gate -------------------------------------------------------------------------------

/// A request from inside a role session that the role does not give: the
/// refusal to send. Only running commands and sending requests (and what they
/// need around them: narrowing the session again, locking, listing sessions,
/// the hook's questions) pass; everything else, including every request added
/// later, is refused. `None` for a caller that is in no role session.
pub(crate) fn forbids(ctx: &Ctx<'_>, request: &ClientRequest) -> Option<ClientReply> {
    use ClientRequest::*;
    if matches!(
        request,
        Status {}
            | Stop {}
            | Run { .. }
            | Http { .. }
            | Delegate { .. }
            | DelegateRole { .. }
            | Lock { .. }
            | Sessions {}
            | SessionKill { .. }
            | OutputScan { .. }
            | OutputObserved { .. }
            | HookReport { .. }
            | ToolCheck { .. }
            | CheckRun { .. }
            | CheckHttp { .. }
            | GuardAsk { .. }
            | GuardNote { .. }
    ) {
        return None;
    }
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let found = {
        let sessions = ctx.shared.sessions.lock().ok()?;
        sessions.covering(&chain).into_iter().find_map(|s| {
            s.agent_role
                .as_ref()
                .map(|r| (s.id.clone(), r.name.clone(), s.vault_id))
        })
    };
    let (session, role, vault_id) = found?;
    ctx.journal(
        Entry::new("role_refused")
            .session(&session, None)
            .vault(&vault_id)
            .role(Some(&role))
            .result("refused", Some("RoleForbids")),
    );
    Some(refused(
        RefusalKind::RoleForbids,
        format!(
            "this session is limited to the role {role}: it may run commands and send requests as \
             the role says, and nothing else (no revealing, copying, adding, binding, removing, \
             unlocking or changing roles). Nothing was done. If the task needs more, ask the \
             person."
        ),
    ))
}
