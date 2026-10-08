//! The session requests: `unlock`, `lock`, `sessions` and `sessions kill`.
//!
//! `unlock` is meant to be called by the agent. A window opens, the person
//! reads what is being approved (the project, the vault, the names, how long,
//! and which process the session will belong to) and types the password. After
//! that, `vahta run` from that process tree needs no window.
//!
//! Revoking needs no password: `lock` and `sessions kill` can only take access
//! away.

use std::path::Path;
use std::time::{Duration, Instant};

use vahta_vault::project::Project;
use vahta_vault::{Peek, Tier, Vault, valid_name};

use crate::anchor::{self, Node};
use crate::encoded::EncodedSet;
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, check_name, find_vault, from_vault, lines_for, refused, refused_names, unlock,
};
use crate::protocol::{ClientReply, DurationSpec, NameIssue, RefusalKind};
use crate::server::Shared;
use crate::session::{self, Ended, Role, Session, ask_time, info_of};
use crate::surface::sanitize_label;

/// The most a session may be asked to last, short of `forever`: a year.
pub(crate) const MAX_SECS: u64 = 366 * 24 * 3600;

impl Shared {
    /// Journal sessions that have ended. Their keys are already overwritten.
    pub(crate) fn record_ended(&self, ended: Vec<Ended>) {
        for e in ended {
            self.journal.record(
                Entry::new("session_end")
                    .session(&e.session.id, e.session.parent.as_deref())
                    .vault(&e.session.vault_id)
                    .names(&e.session.scope)
                    .result("ended", Some(e.reason))
                    .uses(e.session.uses),
            );
        }
    }

    /// End every session now (the daemon stopping, the machine sleeping).
    pub(crate) fn end_all_sessions(&self, reason: &'static str) -> usize {
        let ended = match self.sessions.lock() {
            Ok(mut s) => s.end_all(reason),
            Err(_) => return 0,
        };
        let n = ended.len();
        self.record_ended(ended);
        n
    }
}

/// The nodes of the peer's ancestor chain, for the anchor choice.
pub(crate) fn nodes_of(ctx: &Ctx<'_>) -> Vec<Node> {
    vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS)
        .into_iter()
        .map(|id| Node {
            id,
            exe: vahta_os::exe_name(id.pid).unwrap_or_default(),
            mine: vahta_os::owned_by_me(id.pid),
        })
        .collect()
}

/// Which names a request names, or the refusal that says why not: an each-use
/// secret in an `unlock` refuses the whole request, as does an unknown name,
/// before any window opens, so a mistaken agent can rebuild the command.
fn resolve_names(peek: &Peek, requested: Option<Vec<String>>) -> Flow<Vec<String>> {
    let requested = requested.filter(|r| !r.is_empty());
    let Some(requested) = requested else {
        let mut all: Vec<String> = peek
            .entries
            .iter()
            .filter(|e| e.tier == Tier::Session)
            .map(|e| e.name.clone())
            .collect();
        all.sort();
        if all.is_empty() {
            return Err(refused(
                RefusalKind::NothingToDo,
                "this vault has no session-tier secrets to open a session for",
            ));
        }
        return Ok(all);
    };
    let mut names: Vec<String> = Vec::new();
    let mut issues = Vec::new();
    for name in requested {
        if names.contains(&name) {
            continue;
        }
        let entry = peek.entries.iter().find(|e| e.name == name);
        let shown = if valid_name(&name) {
            name.clone()
        } else {
            "<not a valid name>".to_string()
        };
        match entry {
            None => issues.push(NameIssue {
                name: shown,
                why: RefusalKind::UnknownName,
            }),
            Some(e) if e.tier == Tier::EachUse => issues.push(NameIssue {
                name: shown,
                why: RefusalKind::EachUse,
            }),
            Some(_) => names.push(name),
        }
    }
    if issues.is_empty() {
        return Ok(names);
    }
    let each_use = issues.iter().any(|i| i.why == RefusalKind::EachUse);
    let unknown = issues.iter().any(|i| i.why == RefusalKind::UnknownName);
    let kind = if each_use {
        RefusalKind::EachUse
    } else {
        RefusalKind::UnknownName
    };
    // Explain only the causes present, so the caller fixes the right thing.
    let mut message = String::from("cannot open a session for these names; nothing was opened.");
    if each_use {
        message.push_str(
            " An each-use secret needs the password every time and no session may hold it: \
             leave it out and `vahta run` will ask for it.",
        );
    }
    if unknown {
        message.push_str(" A name that is not in this vault: check `vahta list`.");
    }
    Err(refused_names(kind, &message, issues))
}

fn describe(d: Option<Duration>) -> String {
    match d {
        None => "until revoked".to_string(),
        Some(d) => {
            let s = d.as_secs();
            if s % 3600 == 0 {
                format!("{} hour(s)", s / 3600)
            } else if s % 60 == 0 {
                format!("{} minute(s)", s / 60)
            } else {
                format!("{s} second(s)")
            }
        }
    }
}

/// The length asked for, as a duration or `None` for until revoked.
pub(crate) fn duration_of(spec: DurationSpec, default_minutes: u64) -> Flow<Option<Duration>> {
    match spec {
        DurationSpec::Default {} => Ok(Some(Duration::from_secs(default_minutes * 60))),
        DurationSpec::Forever {} => Ok(None),
        DurationSpec::Secs { secs } if secs == 0 || secs > MAX_SECS => Err(crate::ops::error(
            "a session lasts from 1 second to a year, or `forever`",
        )),
        DurationSpec::Secs { secs } => Ok(Some(Duration::from_secs(secs))),
    }
}

pub(crate) fn unlock_session(
    ctx: &Ctx<'_>,
    cwd: &str,
    names: Option<Vec<String>>,
    duration: DurationSpec,
    label: Option<String>,
) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    // A swapped owner or a rolled-back file is refused here, before a window.
    peek.verified(ctx.store()).map_err(from_vault)?;
    let names = match resolve_names(&peek, names) {
        Ok(names) => names,
        Err(reply) => {
            // The refusal is also written to the journal: who asked for what,
            // and why it was not allowed.
            if let ClientReply::Refused(r) = &reply {
                let asked: Vec<String> = r.names.iter().map(|n| n.name.clone()).collect();
                ctx.journal(
                    Entry::new("session_refused")
                        .vault(&peek.vault_id)
                        .names(&asked)
                        .result("refused", Some(&format!("{:?}", r.kind))),
                );
            }
            return Err(reply);
        }
    };
    for n in &names {
        check_name(n)?;
    }
    let lasts = duration_of(duration, ctx.shared.options.config.session_minutes)?;

    let nodes = nodes_of(ctx);
    let anchor_index = anchor::select(&nodes, vahta_os::MIN_PID).map_err(|_| {
        refused(
            RefusalKind::NoAnchor,
            "cannot tell which process this session would belong to (the caller's ancestors are \
             all shells, other users' processes or too close to init); nothing was opened",
        )
    })?;
    let anchor_node = &nodes[anchor_index];
    let (anchor, anchor_exe) = (anchor_node.id, anchor_node.exe.clone());

    let mut window = ctx.window("Open a session")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Secrets: {}", names.join(", ")));
    lines.push(format!("Lasts: {}", describe(lasts)));
    lines.push(format!(
        "Belongs to: {anchor_exe} (pid {}), and everything it starts",
        anchor.pid
    ));
    lines.push(
        "Allows: running commands with these secrets, with no window. Not revealing, copying, \
         exporting or changing anything."
            .to_string(),
    );
    let mut panel = ctx.panel("Open a session", lines);
    panel.agent_note = label.as_deref().and_then(sanitize_label);
    let mut vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    if vault.upgrade_pending() {
        // A session reads the current format only; the first save writes it.
        vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    }
    let keys = vault.session_keys(&names).map_err(from_vault)?;
    // The values in their encoded forms, for the pre-tool check and the output
    // scan; held as long as the keys are, and not a moment longer.
    let held: Vec<(String, vahta_vault::SecretValue)> = names
        .iter()
        .filter_map(|n| vault.get(n).ok().map(|v| (n.clone(), v)))
        .collect();
    let forms = EncodedSet::build(held.iter().map(|(n, v)| (n.as_str(), v.expose())));
    drop(held);
    // Build the search tables now, not in the middle of a tool call.
    let _ = forms.find(b"");
    let vault_id = vault.vault_id();
    // From here on the vault key is gone: the session holds data keys only.
    drop(vault);

    let now = Instant::now();
    let deadline = lasts.map(|d| now + d);
    let id =
        session::new_id().ok_or_else(|| crate::ops::error("the system random generator failed"))?;
    let session = Session {
        id: id.clone(),
        tenant: "local",
        vault_id,
        vault_path: vault_path.clone(),
        project: project.root.clone(),
        scope: names.clone(),
        keys,
        forms,
        role: Role::Runner,
        anchor,
        anchor_exe: anchor_exe.clone(),
        parent: None,
        deadline,
        length: deadline.map(|d| d.saturating_duration_since(now)),
        ask_at: deadline.map(|d| ask_time(now, d)),
        extension_pending: false,
        label: panel.agent_note.clone(),
        uses: 0,
    };
    let info = info_of(&session, now);
    let replaced = {
        let mut sessions = ctx
            .shared
            .sessions
            .lock()
            .map_err(|_| crate::ops::error("the session table is unusable"))?;
        // A second unlock for the same process replaces the first.
        let replaced = sessions.end_where(
            |s| s.parent.is_none() && s.anchor == anchor && s.vault_id == vault_id,
            "replaced",
        );
        sessions.add(session);
        replaced
    };
    ctx.shared.record_ended(replaced);
    // Sessions are open again by the person's hand: the alarm is over.
    ctx.shared.alarm.clear_raised();
    ctx.journal(
        Entry::new("session_start")
            .session(&id, None)
            .vault(&vault_id)
            .names(&names)
            .result(
                "ok",
                Some(&format!(
                    "anchor {anchor_exe} pid {}; {}",
                    anchor.pid,
                    describe(lasts)
                )),
            ),
    );
    window.close(Some("Session open. This window can be closed."));
    Ok(ClientReply::Session(Box::new(info)))
}

fn all_or_project(
    sessions: &mut session::Sessions,
    project: Option<&Project>,
    vault_id: Option<[u8; 16]>,
    reason: &'static str,
) -> Vec<Ended> {
    match project {
        None => sessions.end_all(reason),
        Some(p) => {
            let vault_path = p.vault_path();
            sessions.end_where(
                |s| s.vault_path == vault_path || Some(s.vault_id) == vault_id,
                reason,
            )
        }
    }
}

pub(crate) fn lock(ctx: &Ctx<'_>, cwd: &str, all: bool) -> Flow<ClientReply> {
    let (project, vault_id) = if all {
        (None, None)
    } else {
        let (project, vault_path) = match find_vault(cwd) {
            Ok(found) => found,
            // A project whose vault is gone can still have sessions to end.
            Err(_) => match Project::find(Path::new(cwd)) {
                Some(p) => {
                    let path = p.vault_path();
                    (p, path)
                }
                None => {
                    return Err(crate::ops::refused(
                        RefusalKind::NoVault,
                        "no Vahta project here (no .vahta/ in this directory or above)",
                    ));
                }
            },
        };
        let id = Vault::peek(&vault_path).ok().map(|p| p.vault_id);
        (Some(project), id)
    };
    let ended = {
        let mut sessions = ctx
            .shared
            .sessions
            .lock()
            .map_err(|_| crate::ops::error("the session table is unusable"))?;
        all_or_project(&mut sessions, project.as_ref(), vault_id, "locked")
    };
    let n = ended.len();
    ctx.shared.record_ended(ended);
    ctx.journal(Entry::new("lock").result("ok", Some(&format!("{n} ended"))));
    Ok(ClientReply::Done {
        message: if n == 0 {
            "no sessions to end".to_string()
        } else {
            format!("ended {n} session(s)")
        },
    })
}

pub(crate) fn list(ctx: &Ctx<'_>) -> Flow<ClientReply> {
    let now = Instant::now();
    let sessions = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| crate::ops::error("the session table is unusable"))?;
    Ok(ClientReply::Sessions {
        sessions: sessions.infos(now),
        alarm_at: ctx.shared.alarm.raised_at(),
    })
}

pub(crate) fn kill(ctx: &Ctx<'_>, id: &str) -> Flow<ClientReply> {
    let ended = {
        let mut sessions = ctx
            .shared
            .sessions
            .lock()
            .map_err(|_| crate::ops::error("the session table is unusable"))?;
        sessions.end_tree(id, "killed")
    };
    if ended.is_empty() {
        return Err(refused(RefusalKind::UnknownName, "no session with that id"));
    }
    let n = ended.len();
    ctx.shared.record_ended(ended);
    Ok(ClientReply::Done {
        message: if n == 1 {
            format!("ended session {id}")
        } else {
            format!("ended session {id} and {} below it", n - 1)
        },
    })
}
