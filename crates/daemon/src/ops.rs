//! The vault operations a client can ask for: `init`, `add`, `reset`, `remove`,
//! `import`, `reveal` and `copy`.
//!
//! Every one needs a fresh password, typed in the prompt window, and never
//! enters a session: a session is a runner, and runs only. The window is the
//! only place the password, a typed value or a revealed value exists outside the
//! daemon; a reply to the client says what was done and never has a value.
//!
//! The vault file is only ever written by `Vault::save`, which refuses if the
//! file changed since it was loaded, so two writers cannot clobber each other.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vahta_auth::Action;
use vahta_vault::project::Project;
use vahta_vault::store::LocalStore;
use vahta_vault::{Class, Error, Kind, Peek, RuleSet, SecretValue, Tier, Vault, valid_name};
use zeroize::Zeroizing;

use crate::clipboard;
use crate::dotenv;
use crate::journal::Entry;
use crate::proposal;
use crate::protocol::{
    self, ClientReply, ImportSource, NameIssue, Panel, Refusal, RefusalKind, Secret,
};
use crate::server::Shared;
use crate::surface::{SurfaceError, Window};
use crate::valuecheck;

/// How long a revealed value stays on screen.
pub const REVEAL_SECONDS: u32 = 60;

/// Who asked: the kernel's account of the peer, for the window and the journal.
pub(crate) struct Ctx<'a> {
    pub shared: &'a Arc<Shared>,
    pub exe: Option<String>,
    pub pid: u32,
    /// The peer, with its start time, for the session lookups.
    pub peer: vahta_os::ProcessId,
    /// The calling project, once the request turned out to be remote use of
    /// another project's vault: every window and journal line then names it.
    pub used_from: std::sync::Mutex<Option<PathBuf>>,
    /// The request is for the connectors vault (`--connector`): every lookup
    /// of "the vault" goes to it, and to nothing found from a directory.
    pub connector: bool,
}

/// An early end: the reply to send.
pub(crate) type Flow<T> = Result<T, ClientReply>;

pub(crate) fn error(message: impl Into<String>) -> ClientReply {
    ClientReply::Error {
        message: message.into(),
    }
}

pub(crate) fn refused(kind: RefusalKind, message: impl Into<String>) -> ClientReply {
    ClientReply::Refused(Refusal {
        kind,
        message: message.into(),
        names: Vec::new(),
    })
}

pub(crate) fn refused_names(
    kind: RefusalKind,
    message: impl Into<String>,
    names: Vec<NameIssue>,
) -> ClientReply {
    ClientReply::Refused(Refusal {
        kind,
        message: message.into(),
        names,
    })
}

pub(crate) fn cancelled() -> ClientReply {
    ClientReply::Cancelled {
        message: "cancelled; nothing was done".to_string(),
    }
}

/// A window that did not answer is a cancellation; one that could not open is
/// an error that says nothing was done.
pub(crate) fn from_surface(e: SurfaceError) -> ClientReply {
    match e {
        SurfaceError::Timeout => ClientReply::Cancelled {
            message: "the prompt window was not answered in time; nothing was done".to_string(),
        },
        SurfaceError::Closed => cancelled(),
        other => error(other.to_string()),
    }
}

pub(crate) fn from_vault(e: Error) -> ClientReply {
    error(e.to_string())
}

/// The vault's tier for the one a client named. Two types because a client
/// does not link the vault crate; they mirror each other one for one.
pub(crate) fn vault_tier(tier: protocol::Tier) -> Tier {
    match tier {
        protocol::Tier::Session => Tier::Session,
        protocol::Tier::EachUse => Tier::EachUse,
    }
}

impl Ctx<'_> {
    /// The vault this request works on: the project's, found from `cwd`, or,
    /// for a `--connector` request, the connectors vault and never a project's.
    pub(crate) fn vault_for(&self, cwd: &str) -> Flow<(Project, PathBuf)> {
        if self.connector {
            crate::connector_ops::find(self)
        } else {
            find_vault(cwd)
        }
    }

    /// Who is asking, as the person should read it: the agent the request
    /// comes from (the anchor `unlock` would choose, e.g. `claude`), and the
    /// process that connected (usually `vahta` itself) when it is another.
    pub(crate) fn requested_by(&self) -> String {
        let caller = match &self.exe {
            Some(exe) => format!("{exe} (pid {})", self.pid),
            None => format!("pid {}", self.pid),
        };
        match crate::output::anchor_of(self) {
            Some((id, exe)) if id.pid != self.pid => {
                format!("{exe} (pid {}), through {caller}", id.pid)
            }
            _ => caller,
        }
    }

    pub(crate) fn journal(&self, entry: Entry) {
        let entry = entry.peer(self.exe.as_deref(), self.pid);
        let entry = match self.used_from() {
            Some(from) => entry.used_from(&from),
            None => entry,
        };
        self.shared.journal.record(entry);
    }

    /// The directory the peer process is really in, read from the kernel and
    /// checked against pid reuse. `None` where that cannot be done.
    pub(crate) fn peer_cwd(&self) -> Option<PathBuf> {
        let same = || vahta_os::identity_of(self.pid).is_ok_and(|id| id == self.peer);
        if !same() {
            return None;
        }
        let cwd = vahta_os::process_cwd(self.pid).ok()?;
        same().then_some(cwd)
    }

    /// The client's `cwd` is a claim; the kernel's account of where the peer
    /// is wins. Equal after canonicalisation, or the request is refused,
    /// journaled as suspicious and counted for the injection alarm. Where the
    /// kernel cannot be asked (Windows) the claim is believed, as before.
    pub(crate) fn check_cwd(&self, claimed: &str) -> Flow<PathBuf> {
        let claimed_path = crate::pathfind::canonical(Path::new(claimed));
        let Some(real) = self.peer_cwd() else {
            if cfg!(windows) {
                return Ok(claimed_path.unwrap_or_else(|| PathBuf::from(claimed)));
            }
            // On a system that can be asked, no answer is no trust.
            return Err(self.cwd_refused(claimed, None));
        };
        if claimed_path.as_deref() == Some(real.as_path()) {
            Ok(real)
        } else {
            Err(self.cwd_refused(claimed, Some(&real)))
        }
    }

    fn cwd_refused(&self, claimed: &str, real: Option<&Path>) -> ClientReply {
        let claimed: String = claimed
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(200)
            .collect();
        let real = real.map_or("unreadable".to_string(), |r| r.display().to_string());
        self.journal(Entry::new("cwd_refused").result(
            "refused",
            Some(&format!(
                "suspicious: the client claimed the directory {claimed} but runs in {real}"
            )),
        ));
        crate::report::not_from_here(self, "a request naming a directory it is not in");
        refused(
            RefusalKind::NotFromHere,
            "the working directory this request names is not where it runs; refused and noted",
        )
    }

    pub(crate) fn used_from(&self) -> Option<PathBuf> {
        self.used_from.lock().ok().and_then(|g| g.clone())
    }

    pub(crate) fn set_used_from(&self, from: PathBuf) {
        if let Ok(mut g) = self.used_from.lock() {
            *g = Some(from);
        }
    }

    pub(crate) fn store(&self) -> &LocalStore {
        &self.shared.store
    }

    pub(crate) fn panel(&self, title: &str, mut lines: Vec<String>) -> Panel {
        if self.connector {
            for line in lines.iter_mut().filter(|l| l.starts_with("Project: ")) {
                *line =
                    "Vault: the connectors vault (your own connections, not a project)".to_string();
            }
        }
        // Remote use names both ends: `Vault: <vault> · used from <project>`.
        if let Some(from) = self.used_from() {
            for line in lines.iter_mut().filter(|l| l.starts_with("Vault: ")) {
                line.push_str(&format!(" · used from {}", from.display()));
            }
        }
        lines.push(format!("Requested by: {}", self.requested_by()));
        Panel {
            title: title.to_string(),
            lines,
            warning: None,
            agent_note: None,
        }
    }

    /// Open a window, or the reply that says none could be.
    pub(crate) fn window(&self, title: &str) -> Flow<Box<dyn Window>> {
        self.shared.surface.open(title).map_err(from_surface)
    }
}

/// The project that holds `cwd` and its vault file.
pub(crate) fn find_vault(cwd: &str) -> Flow<(Project, PathBuf)> {
    let Some(project) = Project::find(Path::new(cwd)) else {
        return Err(refused(
            RefusalKind::NoVault,
            "no Vahta project here (no .vahta/ in this directory or above); run `vahta init`",
        ));
    };
    let vault = project.vault_path();
    if !vault.is_file() {
        return Err(refused(
            RefusalKind::NoVault,
            "this project has no vault yet; run `vahta init`",
        ));
    }
    // The connectors vault answers no lookup by directory, even if its file
    // was copied into a project.
    if crate::connector_ops::is_connectors_vault(&vault) {
        return Err(refused(
            RefusalKind::NoVault,
            "this project has no vault yet; run `vahta init`",
        ));
    }
    Ok((project, vault))
}

/// Unlock `path` for `action`: a paired device when the policy lets one, and
/// always the master password in `window` (asked up to three times in
/// the same window). What opens the vault is `vahta-auth`'s registry; this
/// only says what for.
pub(crate) fn unlock_as(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    action: Action,
) -> Flow<Vault> {
    crate::authn::unlock_for(ctx, window, path, panel, action).map(|(vault, _)| vault)
}

/// [`unlock_as`] for a flow that read the vault's plain index first (`peek`):
/// refuses if the file is not the one that was read. A device unlock writes the
/// slot again, one generation on, which is not a change.
pub(crate) fn unlock_expecting(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    action: Action,
    peek: &Peek,
) -> Flow<Vault> {
    let (vault, by) = crate::authn::unlock_for(ctx, window, path, panel, action)?;
    let rewrote = u64::from(by.rewrapped);
    if vault.vault_id() != peek.vault_id || vault.generation() != peek.generation + rewrote {
        return Err(error(
            "the vault changed while the window was open; nothing was done",
        ));
    }
    Ok(vault)
}

pub(crate) fn lines_for(project: &Project, vault: &Path) -> Vec<String> {
    vec![
        format!("Project: {}", project.root.display()),
        format!("Vault: {}", vault.display()),
    ]
}

pub(crate) fn check_name(name: &str) -> Flow<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(error(Error::InvalidName.to_string()))
    }
}

pub(crate) fn unknown_name(name: &str) -> ClientReply {
    refused_names(
        RefusalKind::UnknownName,
        format!("no secret named {name} in this vault"),
        vec![NameIssue {
            name: name.to_string(),
            why: RefusalKind::UnknownName,
        }],
    )
}

// --- init ---------------------------------------------------------------------------

pub(crate) fn init(ctx: &Ctx<'_>, cwd: &str) -> Flow<ClientReply> {
    let root = PathBuf::from(cwd);
    if !root.is_dir() {
        return Err(error("the current directory is not a directory"));
    }
    let project = Project { root: root.clone() };
    let vault_path = project.vault_path();
    if vault_path.exists() {
        return Err(refused(
            RefusalKind::Exists,
            "this directory already has a vault",
        ));
    }
    let mut window = ctx.window("Create a Vahta vault")?;
    let mut panel = ctx.panel("Create a Vahta vault", lines_for(&project, &vault_path));
    panel
        .lines
        .push("Choose the password that will open it.".to_string());
    let chosen = window
        .ask_password(&panel, "New vault password", true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if chosen.expose().is_empty() {
        return Err(error("the password cannot be empty; nothing was done"));
    }
    let (mut vault, recovery) =
        Vault::create(chosen.expose().as_bytes(), ctx.shared.options.kdf).map_err(from_vault)?;
    let paper = Secret::new(recovery.to_paper());
    // The key is shown, and acknowledged, before anything is written: if the
    // window dies first there is no vault whose key was never seen.
    panel.warning = Some(
        "Write this recovery key down and keep it somewhere safe. It opens the vault if the \
         password is lost, it is shown only now, and Vahta cannot show it again."
            .to_string(),
    );
    if !window
        .show_recovery_key(&panel, &paper)
        .map_err(from_surface)?
    {
        return Err(cancelled());
    }
    Project::init(&root).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    crate::guard_ops::note_project(ctx, &root);
    ctx.journal(
        Entry::new("init")
            .vault(&vault.vault_id())
            .result("ok", None),
    );
    window.close(Some("Vault created."));
    Ok(ClientReply::Done {
        message: format!("created {}", vault_path.display()),
    })
}

// --- add / reset / remove ------------------------------------------------------------

/// Whether a write makes a new secret or replaces the value of one there is.
/// Two commands, not one that does either: an agent that means to add a
/// secret must not overwrite one by a mistyped name, and one that means to
/// rotate a value must not quietly create a second secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreMode {
    Add,
    Reset,
}

/// What `add` and `reset` were asked to store, besides the value.
pub(crate) struct Store<'a> {
    pub name: &'a str,
    /// `None` on a reset keeps the tier the secret has; on an add it is the
    /// category's tier.
    pub tier: Option<Tier>,
    /// The rules proposed with an add (a reset keeps the rules it has).
    pub rules: Option<crate::protocol::RuleArgs>,
    /// `None` on a reset keeps the secret's kind; on an add it is a variable.
    pub file: Option<&'a str>,
}

fn tier_text(tier: Tier) -> &'static str {
    match tier {
        Tier::Session => "session",
        Tier::EachUse => "each-use",
    }
}

pub(crate) fn store(
    ctx: &Ctx<'_>,
    cwd: &str,
    mode: StoreMode,
    what: Store<'_>,
) -> Flow<ClientReply> {
    let name = what.name;
    check_name(name)?;
    let (project, vault_path) = ctx.vault_for(cwd)?;
    if ctx.connector {
        crate::connector_ops::check_add(mode == StoreMode::Add, &what)?;
    }
    // The plain index says whether the name is there, so the wrong command is
    // refused before a window opens and costs the person nothing.
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    let existing = peek.entries.iter().find(|e| e.name == name);
    match (mode, existing) {
        (StoreMode::Add, Some(_)) => {
            return Err(refused_names(
                RefusalKind::Exists,
                format!(
                    "the vault already has {name}; use `vahta reset {name}` to replace its value"
                ),
                vec![NameIssue {
                    name: name.to_string(),
                    why: RefusalKind::Exists,
                }],
            ));
        }
        (StoreMode::Reset, None) => {
            let mut reply = unknown_name(name);
            if let ClientReply::Refused(r) = &mut reply {
                r.message = format!(
                    "no secret named {name} in this vault; use `vahta add {name}` to create it"
                );
            }
            return Err(reply);
        }
        _ => {}
    }
    let kind = match (what.file, existing) {
        (Some(f), _) => Kind::File {
            file_name: f.to_string(),
        },
        (None, Some(e)) => e.kind.clone(),
        (None, None) => Kind::Env,
    };
    // A proposal that cannot be right is refused before any window opens.
    let proposal_args = what.rules.as_ref().map(|r| proposal::Args {
        category: r.category.clone(),
        allow: r.allow.clone(),
        deny: r.deny.clone(),
        dirs: r.dirs.clone(),
        net: r.net.clone(),
        path: r.path.as_deref().map(std::ffi::OsString::from),
        from: Vec::new(),
    });
    if mode == StoreMode::Add
        && let Some(a) = &proposal_args
        && let Some(id) = &a.category
    {
        let cat = proposal::find_category(id).map_err(error)?;
        proposal::build(name, Some(cat), a, &project.root).map_err(error)?;
    } else if mode == StoreMode::Add
        && let Some(a) = &proposal_args
        && !a.is_bare()
    {
        // No category: it is suggested after the value. Syntax errors now.
        proposal::build(name, None, a, &project.root).map_err(error)?;
    }
    if mode == StoreMode::Add {
        // Nothing but a name: the category the name suggests must be
        // buildable, so the person does not type a value for nothing.
        let default_args = proposal::Args::default();
        let a = proposal_args.as_ref().unwrap_or(&default_args);
        if a.category.is_none() && a.is_bare() {
            let cat = vahta_policy::suggest(Some(class_by_name(name)), name);
            if let Err(proposal::DefaultErr::Other(e)) =
                proposal::default_set(name, cat, a, None, &project.root)
            {
                return Err(error(format!(
                    "{e}. Propose the rules with the add: `vahta add {name} --category {} \
                     --allow PROGRAM ...`",
                    cat.id
                )));
            }
        }
    }
    let tier = what
        .tier
        .or(existing.map(|e| e.tier))
        .unwrap_or(Tier::Session);
    let (title, event, done) = match mode {
        StoreMode::Add => ("Add a secret", "add", "saved"),
        StoreMode::Reset => ("Replace a secret's value", "reset", "replaced"),
    };
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    if mode == StoreMode::Add && what.tier.is_none() {
        lines.push(format!("Name: {name}"));
    } else {
        lines.push(format!("Name: {name} (tier {})", tier_text(tier)));
    }
    if mode == StoreMode::Reset {
        lines.push("This replaces the value it has now.".to_string());
    }
    let panel = ctx.panel(title, lines);
    let action = match mode {
        StoreMode::Add => Action::Add {
            name: name.to_string(),
        },
        StoreMode::Reset => Action::Reset {
            name: name.to_string(),
        },
    };
    let mut vault = unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    // The file may have changed between the peek and the unlock.
    let there = vault.entries().iter().any(|e| e.name == name);
    if there != (mode == StoreMode::Reset) {
        return Err(error(
            "the vault changed while the window was open; nothing was done",
        ));
    }
    let typed = loop {
        let typed = window
            .ask_value(&panel, &format!("Value of {name}"), true)
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        if typed.expose().is_empty() {
            return Err(error("a secret cannot be empty; nothing was done"));
        }
        match check_typed(
            ctx,
            window.as_mut(),
            &panel,
            &vault.vault_id(),
            name,
            matches!(kind, Kind::File { .. }),
            typed,
        )? {
            Typed::Use(v) => break v,
            Typed::Again => {}
        }
    };
    // What the value looks like it guards: its vendor prefix first, then the
    // name. The agent chose the name, so the name may only raise the class
    // (one more question in this window), never lower it. The agent is told
    // the class, never the value.
    let class = match vahta_detect::secret_class(typed.expose()) {
        Some(vahta_detect::Class::Payment) => Class::Payment,
        Some(vahta_detect::Class::Cloud) => Class::Cloud,
        _ => class_by_name(name),
    };
    let mut tier = tier;
    let mut offered: Option<RuleSet> = None;
    if mode == StoreMode::Add {
        let default_args = proposal::Args::default();
        let o = crate::add_rules::offer(
            window.as_mut(),
            &panel,
            &crate::add_rules::Inputs {
                name,
                class,
                tier: what.tier,
                args: proposal_args.as_ref().unwrap_or(&default_args),
                reason: what.rules.as_ref().and_then(|r| r.reason.as_deref()),
                root: &project.root,
                harnesses: what.rules.as_ref().map_or(&[], |r| r.harnesses.as_slice()),
            },
        )?;
        // A connector's server starts with no window, so only a session can
        // open its secret.
        tier = if ctx.connector { Tier::Session } else { o.tier };
        offered = Some(o.rule_set);
    } else if tier == Tier::Session && matches!(class, Class::Payment | Class::Cloud) {
        // A key that moves money or opens an account is worth the password
        // every time; the person decides, here, where the value was typed.
        let question = format!(
            "This looks like a {} key. Ask for the password on each use?",
            class.as_str()
        );
        let options = [
            "Each use (recommended)".to_string(),
            "Keep session".to_string(),
        ];
        let picked = window
            .choose(&panel, &question, &options)
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        if picked == 0 {
            tier = Tier::EachUse;
        }
    }
    if let Some(rs) = &offered {
        // The file first, so the repository shows what is enforced; a failure
        // here leaves the vault as it was.
        crate::bind_ops::write_rules(&project, name, rs)?;
    }
    vault
        .set(name, typed.expose().as_bytes(), kind, tier)
        .map_err(from_vault)?;
    vault.set_class(name, Some(class)).map_err(from_vault)?;
    if let Some(rs) = &offered {
        vault
            .set_bindings(name, Some(rs.clone()))
            .map_err(from_vault)?;
    }
    let bound = vault.bindings().iter().any(|b| b.name == name);
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    if let Some(from) = offered.as_ref().and_then(|r| r.downgraded_from.as_deref()) {
        ctx.journal(
            Entry::new("category_downgraded")
                .vault(&vault.vault_id())
                .names(&[name.to_string()])
                .result(
                    "accepted",
                    Some(&format!(
                        "{from} -> {}",
                        offered
                            .as_ref()
                            .and_then(|r| r.category.as_deref())
                            .unwrap_or("?")
                    )),
                ),
        );
    }
    ctx.journal(
        Entry::new(event)
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", Some(class.as_str())),
    );
    let capitalised = match mode {
        StoreMode::Add => "Saved",
        StoreMode::Reset => "Replaced",
    };
    // A new value is not the one a transcript holds.
    crate::transcript::clear_exposed(ctx.shared, &vault.vault_id(), name);
    let note = match mode {
        StoreMode::Add => None,
        StoreMode::Reset => stale_sessions_note(ctx, &vault.vault_id(), name),
    };
    window.close(Some(&with_note(format!("{capitalised} {name}."), &note)));
    Ok(ClientReply::Done {
        message: with_note(
            done_message(done, name, class, tier, bound, offered.as_ref()),
            &note,
        ),
    })
}

/// What the person decided about a value with stray whitespace.
enum Typed {
    Use(Secret),
    Again,
}

/// A value with whitespace around it, a line break or a tab inside is almost
/// always a paste accident, and every later use would fail with nothing to
/// explain why. So the person is told, in words that never include the value,
/// and picks: trim it, keep it as typed, or type it again. A file secret or a
/// PEM block may have many lines and is not asked about them. The journal
/// records that the question was shown and the answer, never the value.
fn check_typed(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    panel: &Panel,
    vault_id: &[u8; 16],
    name: &str,
    is_file: bool,
    typed: Secret,
) -> Flow<Typed> {
    let multiline = is_file || valuecheck::looks_like_pem(typed.expose());
    let problems = valuecheck::check(typed.expose(), multiline);
    if !problems.any() {
        return Ok(Typed::Use(typed));
    }
    let trimmed = typed.expose().trim();
    let can_trim = problems.only_edges()
        && !trimmed.is_empty()
        && !valuecheck::check(trimmed, multiline).any();
    let mut options = Vec::new();
    if can_trim {
        options.push("Trim it and store".to_string());
    }
    options.push("Store exactly as typed".to_string());
    options.push("Type it again".to_string());
    options.push("Cancel".to_string());
    let picked = window
        .choose(panel, &valuecheck::describe(&problems), &options)
        .map_err(from_surface)?;
    let shown = |answer: &str| {
        ctx.journal(
            Entry::new("value_warning")
                .vault(vault_id)
                .names(&[name.to_string()])
                .result(answer, None),
        );
    };
    // Without the trim option every index is one lower.
    let at = |i: usize| picked.map(|p| if can_trim { p } else { p + 1 }) == Some(i);
    if at(0) {
        shown("trimmed");
        return Ok(Typed::Use(Secret::new(trimmed.to_string())));
    }
    if at(1) {
        shown("as_typed");
        return Ok(Typed::Use(typed));
    }
    if at(2) {
        shown("retype");
        return Ok(Typed::Again);
    }
    shown("cancelled");
    Err(cancelled())
}

/// After a secret's value, tier or presence changed: the open sessions that
/// hold the old one. They are refused at their next `run` (their key opens
/// nothing now), so the person and the agent are told up front which ones,
/// and the journal records it. `None` when no session holds it.
pub(crate) fn stale_sessions_note(
    ctx: &Ctx<'_>,
    vault_id: &[u8; 16],
    name: &str,
) -> Option<String> {
    let held: Vec<(String, String)> = {
        let sessions = ctx.shared.sessions.lock().ok()?;
        sessions
            .iter()
            .filter(|s| &s.vault_id == vault_id && s.scope.iter().any(|n| n == name))
            .map(|s| {
                let who = match &s.label {
                    Some(l) => format!("{} pid {}, \"{l}\"", s.anchor_exe, s.anchor.pid),
                    None => format!("{} pid {}", s.anchor_exe, s.anchor.pid),
                };
                (s.id.clone(), who)
            })
            .collect()
    };
    if held.is_empty() {
        return None;
    }
    let ids: Vec<String> = held.iter().map(|(id, _)| id.clone()).collect();
    ctx.journal(
        Entry::new("sessions_stale")
            .vault(vault_id)
            .names(&[name.to_string()])
            .result("stale", Some(&format!("sessions {}", ids.join(", ")))),
    );
    let who: Vec<&str> = held.iter().map(|(_, w)| w.as_str()).collect();
    let n = held.len();
    let (sessions, they) = if n == 1 {
        ("open session holds", "It")
    } else {
        ("open sessions hold", "They")
    };
    Some(format!(
        "{n} {sessions} the old {name} ({}). {they} will be refused until unlocked again: run \
         `vahta unlock` again in that agent, or restart the agent.",
        who.join("; ")
    ))
}

/// `message`, with the stale-session note on a line of its own when there is one.
fn with_note(message: String, note: &Option<String>) -> String {
    match note {
        Some(n) => format!("{message}\n{n}"),
        None => message,
    }
}

/// Words in a secret's name that say what it guards. Most cloud and payment
/// secrets have no vendor prefix (an AWS secret access key, a service-account
/// JSON, a PayPal secret), so the name is the only hint.
const PAYMENT_WORDS: &[&str] = &[
    "STRIPE",
    "PAYPAL",
    "ADYEN",
    "BRAINTREE",
    "KLARNA",
    "MOLLIE",
    "PADDLE",
    "PLAID",
    "PAYMENT",
    "PAYMENTS",
    "BILLING",
    "CHECKOUT",
    "YOOKASSA",
    "CLOUDPAYMENTS",
    "TINKOFF",
    "RAZORPAY",
];
const CLOUD_WORDS: &[&str] = &[
    "AWS",
    "GCP",
    "GCLOUD",
    "AZURE",
    "DIGITALOCEAN",
    "CLOUDFLARE",
    "HETZNER",
    "LINODE",
    "VULTR",
    "SCALEWAY",
    "OCI",
    "ALIYUN",
    "YANDEX",
    "YC",
];

/// The class a name suggests, by its words (split on `_`, `-` and `.`, any
/// case): `AWS_SECRET_ACCESS_KEY` is cloud, `stripe-key` payment.
pub(crate) fn class_by_name(name: &str) -> Class {
    let words: Vec<String> = name
        .split(['_', '-', '.'])
        .map(|w| w.to_ascii_uppercase())
        .collect();
    let has = |list: &[&str]| words.iter().any(|w| list.contains(&w.as_str()));
    if has(PAYMENT_WORDS) {
        Class::Payment
    } else if has(CLOUD_WORDS) {
        Class::Cloud
    } else {
        Class::Other
    }
}

/// What the agent is told after an add or reset: what was done, the class (a
/// word, never the value) and the rules. On an add the rules came with it;
/// otherwise a secret that has none is told how to get some, once, up front.
fn done_message(
    done: &str,
    name: &str,
    class: Class,
    tier: Tier,
    bound: bool,
    rules: Option<&RuleSet>,
) -> String {
    let mut text = match class {
        Class::Payment | Class::Cloud => {
            format!(
                "{done} {name} ({} key, {})",
                class.as_str(),
                tier_text(tier)
            )
        }
        Class::Other => format!("{done} {name}"),
    };
    if let Some(rs) = rules {
        let cat = rs.category.as_deref().and_then(vahta_policy::category);
        text.push_str(&format!(
            "\nRules approved with it: {}.\nUse it as `vahta run --secret {name} -- COMMAND` \
             with a command inside those rules; anything else is refused (or asked with \
             `--ask --reason`). Work freely inside the rules; to widen them, design the change \
             once and propose it with `vahta bind {name} ...` so the person is asked as rarely as \
             possible.",
            crate::binding::rules_text(rs)
        ));
        if let Some(c) = cat {
            text.push_str("\nCheck once that a prompt injection could not misuse it:");
            for item in c.checklist {
                text.push_str(&format!("\n- {item}"));
            }
        }
        return text;
    }
    if bound {
        return text;
    }
    let cat = vahta_policy::suggest(Some(class), name);
    text.push_str(&format!(
        "\n{name} has no rules, so nothing may use it yet. Design them once, up front, so the \
         person approves once and is rarely asked later: `vahta bind {name} --category {} \
         --allow PROGRAM [--net ...] --reason \"WHY\"`. Give the agent as much freedom as the \
         work needs inside the rules, and close the paths a prompt injection would take \
         (network tools, interpreters, shells, writing the value to a file, sending it to \
         another host):",
        cat.id
    ));
    for item in cat.checklist {
        text.push_str(&format!("\n- {item}"));
    }
    text
}

/// Refuse a name that is not in the vault. The index is plain, so this needs
/// no password and no window.
fn ensure_known(vault_path: &Path, name: &str) -> Flow<()> {
    let peek = Vault::peek(vault_path).map_err(from_vault)?;
    if peek.entries.iter().any(|e| e.name == name) {
        Ok(())
    } else {
        Err(unknown_name(name))
    }
}

/// `vahta tier`: move a secret between session and each-use without typing
/// its value again. Either way needs the password: loosening to session is
/// exactly what an injected agent would want, and tightening costs nothing.
pub(crate) fn set_tier(ctx: &Ctx<'_>, cwd: &str, name: &str, tier: Tier) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    let Some(entry) = peek.entries.iter().find(|e| e.name == name) else {
        return Err(unknown_name(name));
    };
    if entry.tier == tier {
        return Err(refused(
            RefusalKind::NothingToDo,
            format!("{name} is already {}; nothing was done", tier_text(tier)),
        ));
    }
    let title = "Change a secret's tier";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!(
        "{name}: {} -> {}",
        tier_text(entry.tier),
        tier_text(tier)
    ));
    lines.push(match tier {
        Tier::Session => "A session may then hold it: `vahta run` uses it with no window while \
                          one is open."
            .to_string(),
        Tier::EachUse => "Every use will then need the password, even in a session.".to_string(),
    });
    let panel = ctx.panel(title, lines);
    let action = Action::SetTier {
        name: name.to_string(),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    vault.set_tier(name, tier).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("tier")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", Some(tier_text(tier))),
    );
    // Moving to each-use takes it out of every session; moving to session
    // puts it in none.
    let note = match tier {
        Tier::EachUse => stale_sessions_note(ctx, &vault.vault_id(), name),
        Tier::Session => None,
    };
    window.close(Some(&with_note(
        format!("{name} is now {}.", tier_text(tier)),
        &note,
    )));
    Ok(ClientReply::Done {
        message: with_note(format!("{name} is now {}", tier_text(tier)), &note),
    })
}

pub(crate) fn remove(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = ctx.vault_for(cwd)?;
    ensure_known(&vault_path, name)?;
    let mut window = ctx.window("Remove a secret")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Remove: {name}"));
    let panel = ctx.panel("Remove a secret", lines);
    let action = Action::Remove {
        name: name.to_string(),
    };
    let mut vault = unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    vault.remove(name).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("remove")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    crate::transcript::clear_exposed(ctx.shared, &vault.vault_id(), name);
    let note = stale_sessions_note(ctx, &vault.vault_id(), name);
    window.close(Some(&with_note(format!("Removed {name}."), &note)));
    Ok(ClientReply::Done {
        message: with_note(format!("removed {name}"), &note),
    })
}

// --- import ------------------------------------------------------------------------------

/// The largest ka vault read.
const MAX_KA_FILE: u64 = 16 * 1024 * 1024;

pub(crate) fn import(ctx: &Ctx<'_>, cwd: &str, source: &ImportSource) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    // What can be read and parsed without a password is checked before any
    // window opens: a wrong path or a malformed file costs the person nothing.
    let (shown_path, dotenv_items, ka_path) = match source {
        ImportSource::Dotenv { path } => {
            let full = Path::new(cwd).join(path);
            let meta = std::fs::metadata(&full)
                .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?;
            if !meta.is_file() {
                return Err(error(format!("{} is not a file", full.display())));
            }
            if meta.len() > dotenv::MAX_DOTENV {
                return Err(error(format!("{} is too large", full.display())));
            }
            let bytes = Zeroizing::new(
                std::fs::read(&full)
                    .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?,
            );
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| error(format!("{} is not UTF-8 text", full.display())))?;
            let parsed =
                dotenv::parse(text).map_err(|e| error(format!("{}: {e}", full.display())))?;
            if parsed.items.is_empty() {
                return Err(refused(
                    RefusalKind::NothingToDo,
                    format!("{} holds no values to import", full.display()),
                ));
            }
            (full.display().to_string(), Some(parsed), None)
        }
        ImportSource::Ka { path } => {
            let full = Path::new(cwd).join(path);
            let meta = std::fs::metadata(&full)
                .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?;
            if !meta.is_file() || meta.len() > MAX_KA_FILE {
                return Err(error(format!("{} is not a ka vault file", full.display())));
            }
            (full.display().to_string(), None, Some(full))
        }
    };
    let names: Vec<String> = dotenv_items
        .as_ref()
        .map(|p| p.items.iter().map(|(n, _)| n.clone()).collect())
        .unwrap_or_default();
    if !names.is_empty() {
        // Refused before the window, not after the password: a name already
        // in the vault is visible in the plain index.
        let peek = Vault::peek(&vault_path).map_err(from_vault)?;
        let clashes: Vec<NameIssue> = names
            .iter()
            .filter(|n| peek.entries.iter().any(|e| &&e.name == n))
            .map(|n| NameIssue {
                name: n.clone(),
                why: RefusalKind::Exists,
            })
            .collect();
        if !clashes.is_empty() {
            return Err(refused_names(
                RefusalKind::Exists,
                "the vault already has secrets with these names; nothing was imported",
                clashes,
            ));
        }
    }
    let mut window = ctx.window("Import secrets")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Import from: {shown_path}"));
    if !names.is_empty() {
        lines.push(format!("Names: {}", names.join(", ")));
    }
    let panel = ctx.panel("Import secrets", lines);
    let action = Action::Import {
        source: shown_path.to_string(),
    };
    let mut vault = unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    let items: Vec<(String, SecretValue)> = match (dotenv_items, ka_path) {
        (Some(parsed), _) => parsed.into_secrets(),
        (None, Some(path)) => {
            let mut ka_panel = panel.clone();
            ka_panel
                .lines
                .push("Now the password of the ka vault being imported.".to_string());
            let ka_typed = window
                .ask_password(&ka_panel, "ka vault password", false)
                .map_err(from_surface)?
                .ok_or_else(cancelled)?;
            vahta_vault::ka::import_ka(&path, ka_typed.expose().as_bytes()).map_err(from_vault)?
        }
        (None, None) => return Err(error("nothing to import")),
    };
    let imported: Vec<String> = items.iter().map(|(n, _)| n.clone()).collect();
    vault.import(items).map_err(|e| match e {
        Error::ImportCollision(n) => refused_names(
            RefusalKind::Exists,
            "the vault already has a secret with one of these names; nothing was imported",
            vec![NameIssue {
                name: n,
                why: RefusalKind::Exists,
            }],
        ),
        other => from_vault(other),
    })?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("import")
            .vault(&vault.vault_id())
            .names(&imported)
            .result("ok", None),
    );
    window.close(Some(&format!("Imported {} secret(s).", imported.len())));
    Ok(ClientReply::Done {
        message: format!(
            "imported {} secret(s): {}",
            imported.len(),
            imported.join(", ")
        ),
    })
}

// --- reveal / copy -----------------------------------------------------------------------------

fn named_value(vault: &Vault, name: &str) -> Flow<SecretValue> {
    vault.get(name).map_err(|e| match e {
        Error::NotFound(_) => unknown_name(name),
        other => from_vault(other),
    })
}

pub(crate) fn reveal(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    ensure_known(&vault_path, name)?;
    let mut window = ctx.window("Reveal a secret")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Reveal: {name}"));
    let mut panel = ctx.panel("Reveal a secret", lines);
    let action = Action::Reveal {
        name: name.to_string(),
    };
    let vault = unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    let value = named_value(&vault, name)?;
    let text = String::from_utf8_lossy(value.expose()).into_owned();
    let shown = Secret::new(text);
    if std::str::from_utf8(value.expose()).is_err() {
        panel.warning = Some(
            "This value is not valid text; what follows has replacement characters.".to_string(),
        );
    }
    drop(value);
    window
        .show_value(&panel, name, &shown, REVEAL_SECONDS)
        .map_err(from_surface)?;
    ctx.journal(
        Entry::new("reveal")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(None);
    Ok(ClientReply::Done {
        message: format!("{name} was shown in the window"),
    })
}

pub(crate) fn copy(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    ensure_known(&vault_path, name)?;
    let Some(tool) = clipboard::detect(&clipboard::Environment::from_process()) else {
        return Err(error(
            "no clipboard tool found (wl-copy, xclip, xsel, pbcopy or clip); nothing was done",
        ));
    };
    let mut window = ctx.window("Copy a secret")?;
    let wait: Duration = ctx.shared.options.clipboard_clear;
    let seconds = wait.as_secs();
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Copy: {name}"));
    lines.push(format!("The clipboard is cleared after {seconds} seconds."));
    let panel = ctx.panel("Copy a secret", lines);
    let action = Action::Copy {
        name: name.to_string(),
    };
    let vault = unlock_as(ctx, window.as_mut(), &vault_path, &panel, action)?;
    let value = named_value(&vault, name)?;
    tool.set(value.expose())
        .map_err(|e| error(format!("cannot use the clipboard: {e}")))?;
    let remembered = Zeroizing::new(value.expose().to_vec());
    drop(value);
    ctx.journal(
        Entry::new("copy")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(Some(&format!("Copied {name}.")));
    // The clipboard is emptied if nobody has replaced what was put there.
    let journal = ctx.shared.journal.clone();
    let (exe, pid) = (ctx.exe.clone(), ctx.pid);
    let (vault_id, copied_name) = (vault.vault_id(), name.to_string());
    std::thread::spawn(move || {
        std::thread::sleep(wait);
        let (result, reason) = match tool.clear_if_unchanged(&remembered) {
            Ok(true) => ("ok", "cleared"),
            Ok(false) => ("ok", "changed by something else; left alone"),
            Err(_) => ("failed", "could not read or clear the clipboard"),
        };
        journal.record(
            Entry::new("copy_cleared")
                .vault(&vault_id)
                .names(std::slice::from_ref(&copied_name))
                .peer(exe.as_deref(), pid)
                .result(result, Some(reason)),
        );
    });
    Ok(ClientReply::Done {
        message: format!("{name} is on the clipboard for {seconds} seconds"),
    })
}

#[cfg(test)]
mod class_by_name_tests {
    use super::{Class, class_by_name};

    #[test]
    fn a_name_raises_the_class_by_whole_words_only() {
        assert_eq!(class_by_name("AWS_SECRET_ACCESS_KEY"), Class::Cloud);
        assert_eq!(class_by_name("azure-client-secret"), Class::Cloud);
        assert_eq!(class_by_name("STRIPE_KEY"), Class::Payment);
        assert_eq!(class_by_name("paypal.secret"), Class::Payment);
        // Payment wins when both appear.
        assert_eq!(class_by_name("AWS_BILLING_KEY"), Class::Payment);
        // Inside a word is not a word: LAWS, OCIO, PAYMENTSX.
        assert_eq!(class_by_name("LAWS_TOKEN"), Class::Other);
        assert_eq!(class_by_name("OCIO_KEY"), Class::Other);
        assert_eq!(class_by_name("GITHUB_TOKEN"), Class::Other);
    }
}
