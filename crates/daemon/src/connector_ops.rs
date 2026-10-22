//! The connectors vault: `--connector` on `init`, `add`, `bind`, `remove` and
//! `run`.
//!
//! Harnesses (Claude Code, Codex, Cursor) start MCP servers at user scope, and
//! such a server's API key belongs to no project. So there is **one connectors
//! vault per user**, in Vahta's own data directory (`connectors/vault.vht`, its
//! proposals in `connectors/vahta.toml` beside it). Unlike a project vault:
//!
//! * it is never found from a directory (`find_vault` refuses a vault of this
//!   kind even when its file was copied into a project), and `--connector` never
//!   uses a project's vault;
//! * each secret names the `harnesses` that may launch its server and the
//!   `allow` rules of the one command that is its server; without both it has no
//!   rules (`NoRules`);
//! * `remote` and `from` do not apply to it;
//! * its session belongs to a **harness process**, not to the person or the
//!   daemon: the first `vahta run --connector` from a Claude Code (or Codex, or
//!   Cursor) process opens a password window at once ("this process wants its
//!   MCP servers: ..."), and on the right password a session anchored to that
//!   process (pid and start time) covers the connectors bound to its harness.
//!   Its other servers, started by the same process, wait for that one window
//!   and then start with none. Another process has no session of its own and
//!   gets its own window; a session never passes between processes. It ends
//!   with the process (or `vahta lock --all`, `sessions kill`, a reboot);
//! * the password is all that opens it, so a harness that gives a server about
//!   30 seconds to start gets its window immediately. If the client goes away
//!   the window is withdrawn and nothing runs; if the person cancels or the
//!   password is wrong the server exits at once with a line on stderr that
//!   says to reconnect it in the harness after unlocking.
//!
//! **The harness check** is a speed bump, not a wall: the direct parent of the
//! `vahta run` client must be a process of a harness the secret is bound to.
//! The allow rule and the hook are the boundary. See [`parent_is_harness`].

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use vahta_os::ProcessId;

use vahta_vault::project::Project;
use vahta_vault::{Peek, RuleSet, Tier, Vault, VaultKind, valid_harnesses};

use crate::bind_ops::BindArgs;
use crate::encoded::EncodedSet;
use crate::gate::{Admission, UseKey};
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, Store, cancelled, check_name, error, from_surface, from_vault, lines_for, refused,
    refused_names,
};
use crate::protocol::{
    ClientReply, ConnectorCmd, ConnectorRefusal, NameIssue, RefusalKind, Secret,
};
use crate::run_ops::{Prepared, RunArgs};
use crate::session::{self, Role, Session};
use vahta_auth::Action;

/// The refusals kept for `vahta status`, one per secret, newest last.
const KEPT_REFUSALS: usize = 32;

/// What a connector request comes to.
pub(crate) enum Handled {
    /// Send this reply.
    Reply(ClientReply),
    /// A command to start: the server of one connector.
    Run(Box<Prepared>),
}

impl<'a> Ctx<'a> {
    /// The same peer, for a request that works on the connectors vault.
    fn for_connectors(&self) -> Ctx<'a> {
        Ctx {
            shared: self.shared,
            exe: self.exe.clone(),
            pid: self.pid,
            peer: self.peer,
            used_from: std::sync::Mutex::new(None),
            connector: true,
            gone: self.gone.clone(),
        }
    }
}

/// Serve one `--connector` request.
pub(crate) fn handle(ctx: &Ctx<'_>, cmd: ConnectorCmd) -> Handled {
    let c = ctx.for_connectors();
    let reply = match cmd {
        ConnectorCmd::Init {} => init(&c),
        ConnectorCmd::Add { name, tier, rules } => crate::ops::store(
            &c,
            "",
            crate::ops::StoreMode::Add,
            Store {
                name: &name,
                tier: tier.map(crate::ops::vault_tier),
                file: None,
                rules: Some(rules),
            },
        ),
        ConnectorCmd::Remove { name } => crate::ops::remove(&c, "", &name),
        ConnectorCmd::Bind {
            name,
            harnesses,
            allow,
            deny,
            clear,
            reason,
            path,
            category,
            dirs,
            net,
        } => crate::bind_ops::bind(
            &c,
            BindArgs {
                cwd: String::new(),
                name: Some(name),
                allow,
                deny,
                category,
                dirs,
                net,
                from: None,
                clear,
                reason,
                path,
                harnesses,
            },
        ),
        ConnectorCmd::Run {
            cwd,
            argv,
            env,
            name,
            renames,
            label,
        } => {
            return match run(&c, cwd, argv, env, name, renames, label) {
                Ok(prepared) => Handled::Run(Box::new(prepared)),
                Err(reply) => Handled::Reply(reply),
            };
        }
    };
    Handled::Reply(reply.unwrap_or_else(|r| r))
}

/// The connectors vault, and the "project" whose root holds its manifest.
pub(crate) fn find(ctx: &Ctx<'_>) -> Flow<(Project, PathBuf)> {
    let dir = ctx.shared.options.paths.connectors_dir();
    let vault = vahta_ipc::paths::connectors_vault(&ctx.shared.options.paths.data);
    let missing = || {
        refused(
            RefusalKind::NoVault,
            "there is no connectors vault yet; the person runs `vahta init --connector` in \
             their own terminal",
        )
    };
    if !vault.is_file() {
        return Err(missing());
    }
    if !is_connectors_vault(&vault) {
        return Err(missing());
    }
    Ok((Project { root: dir }, vault))
}

/// Whether the file at `path` is a vault of the connectors kind.
pub(crate) fn is_connectors_vault(path: &std::path::Path) -> bool {
    Vault::peek(path).is_ok_and(|p| p.kind == VaultKind::Connectors)
}

/// An add to the connectors vault needs harnesses and an allow rule, and has
/// no value to put in a file.
pub(crate) fn check_add(is_add: bool, what: &Store<'_>) -> Flow<()> {
    if !is_add {
        return Err(error(
            "a connector's value is replaced by removing it and adding it again",
        ));
    }
    if what.file.is_some() {
        return Err(error(
            "a connector's secret is an environment variable of its server, not a file",
        ));
    }
    if what.tier == Some(Tier::EachUse) {
        return Err(error(
            "a connector's server starts with no window, so its secret is held by the \
             connectors session: it cannot be each-use",
        ));
    }
    let rules = what.rules.as_ref();
    let harnesses = rules.map_or(&[][..], |r| r.harnesses.as_slice());
    check_harnesses(harnesses)?;
    if rules.is_none_or(|r| r.allow.is_empty()) {
        return Err(refused(
            RefusalKind::NoRules,
            "a connector needs the command that is its server: give --allow 'COMMAND ARGS' \
             (for example --allow 'npx -y @scope/server@1.2.3')",
        ));
    }
    Ok(())
}

/// The harnesses of a connector: some of the known ones, each once.
fn check_harnesses(harnesses: &[String]) -> Flow<()> {
    if harnesses.is_empty() {
        return Err(refused(
            RefusalKind::NoRules,
            "a connector needs the harnesses that may launch it: give --harness \
             claude[,codex][,cursor]",
        ));
    }
    if !valid_harnesses(harnesses) {
        return Err(error(
            "the harnesses are some of claude, codex and cursor, each once",
        ));
    }
    Ok(())
}

/// A bind for a connector names it, and any harnesses it gives are known ones.
pub(crate) fn check_bind(args: &BindArgs) -> Flow<()> {
    if args.name.is_none() {
        return Err(error(
            "name the connector: `vahta bind --connector NAME ...`",
        ));
    }
    if !args.harnesses.is_empty() {
        check_harnesses(&args.harnesses)?;
    }
    Ok(())
}

/// After the rules of a bind are built: a connector keeps both a harness and
/// an allow rule, or no rules at all.
pub(crate) fn check_rule_set(new: Option<&RuleSet>) -> Flow<()> {
    if let Some(rs) = new {
        if rs.harnesses.is_empty() {
            check_harnesses(&[])?;
        }
        if rs.allow.is_empty() {
            return Err(refused(
                RefusalKind::NoRules,
                "a connector needs the command that is its server: give --allow",
            ));
        }
    }
    Ok(())
}

// --- init ----------------------------------------------------------------------------

fn init(ctx: &Ctx<'_>) -> Flow<ClientReply> {
    let dir = ctx.shared.options.paths.connectors_dir();
    let vault_path = vahta_ipc::paths::connectors_vault(&ctx.shared.options.paths.data);
    let project = Project { root: dir.clone() };
    if vault_path.exists() {
        return Err(refused(
            RefusalKind::Exists,
            "the connectors vault already exists",
        ));
    }
    let title = "Create the connectors vault";
    let mut window = ctx.window(title)?;
    let mut panel = ctx.panel(title, lines_for(&project, &vault_path));
    panel.lines.push(
        "It holds the keys of the MCP servers your coding agents start. Choose the password that \
         will open it."
            .to_string(),
    );
    let chosen = window
        .ask_password(&panel, "New vault password", true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if chosen.expose().is_empty() {
        return Err(error("the password cannot be empty; nothing was done"));
    }
    let (mut vault, recovery) = Vault::create_with_kind(
        chosen.expose().as_bytes(),
        ctx.shared.options.kdf,
        VaultKind::Connectors,
    )
    .map_err(from_vault)?;
    let paper = Secret::new(recovery.to_paper());
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
    std::fs::create_dir_all(&dir).map_err(|e| {
        error(format!(
            "cannot create {}: {e}; nothing was done",
            dir.display()
        ))
    })?;
    private_dir(&dir);
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("init")
            .vault(&vault.vault_id())
            .result("ok", Some("connectors vault")),
    );
    window.close(Some("Connectors vault created."));
    Ok(ClientReply::Done {
        message: format!("created {}", vault_path.display()),
    })
}

/// The directory is the user's alone, where the system has modes.
fn private_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

// --- the harness's session -------------------------------------------------------------

/// The harness process that started the `vahta run --connector` client: what a
/// connectors session is anchored to.
pub(crate) struct Harness {
    /// Its pid and start time, so a reused pid is another process.
    pub id: ProcessId,
    /// `claude`, `codex` or `cursor`.
    pub kind: &'static str,
}

/// `(session id, scope, delegated)`, as `find_session` gives.
type Found = (String, Vec<String>, bool);

/// What the person does to start a server again once it is unlocked.
fn reconnect_hint(kind: &str) -> &'static str {
    match kind {
        "claude" => "reconnect the server in Claude Code (`/mcp`)",
        "codex" => "restart the Codex session",
        _ => "reload the MCP server in Cursor's settings",
    }
}

/// The open connectors session of this vault that belongs to `harness`.
pub(crate) fn session_of(
    ctx: &Ctx<'_>,
    peek: &Peek,
    harness: Option<&Harness>,
) -> Flow<Option<Found>> {
    let Some(harness) = harness else {
        return Ok(None);
    };
    let now = Instant::now();
    let sessions = ctx
        .shared
        .sessions
        .lock()
        .map_err(|_| error("the session table is unusable"))?;
    Ok(sessions
        .iter()
        .filter(|s| {
            s.connector
                && s.vault_id == peek.vault_id
                && s.parent.is_none()
                && s.anchor == harness.id
                && s.deadline.is_none_or(|d| d > now)
        })
        .last()
        .map(|s| (s.id.clone(), s.scope.clone(), false)))
}

/// A launch whose harness process has no session covering its secret opens a
/// password window at once, and on the right password a session anchored to
/// that process; then it goes on. Every launch of the same process waits for
/// that one window (`gate.rs`) and shares its answer.
///
/// A client that goes away takes the window with it and nothing runs. A "no" or
/// a wrong password ends the launch with the line the harness shows: the person
/// reconnects the server after unlocking.
pub(crate) fn ensure_session(
    ctx: &Ctx<'_>,
    project: &Project,
    vault_path: &Path,
    peek: &Peek,
    names: &[String],
    harness: Option<&Harness>,
    found: Option<Found>,
) -> Flow<Option<Found>> {
    let covers = |f: &Option<Found>| {
        f.as_ref()
            .is_some_and(|(_, scope, _)| names.iter().all(|n| scope.contains(n)))
    };
    if covers(&found) {
        return Ok(found);
    }
    let Some(harness) = harness else {
        return Err(error(
            "cannot tell which harness process started this; nothing was run",
        ));
    };
    let key = UseKey(format!(
        "connectors:{}:{}",
        harness.id.pid, harness.id.start_time
    ));
    loop {
        ctx.gone.watch();
        let turn = match ctx
            .shared
            .gates
            .enter(&peek.vault_id, Some(&key), ctx.gone.cancel())
        {
            Admission::Turn(turn) => turn,
            Admission::Refused(reply) => return Err(hint_reconnect(reply, harness.kind)),
            Admission::Gone => return Err(client_gone(ctx, peek, names)),
            Admission::Granted(_) | Admission::Look => {
                // The window of another request may have opened our session.
                let now = session_of(ctx, peek, Some(harness))?;
                if covers(&now) {
                    return Ok(now);
                }
                continue;
            }
        };
        let now = session_of(ctx, peek, Some(harness))?;
        if covers(&now) {
            turn.session_opened();
            return Ok(now);
        }
        let opened = open_session(ctx, project, vault_path, peek, harness);
        if ctx.gone.is_gone() {
            // Whatever the window came to, nobody is waiting for the server.
            turn.fell();
            return Err(client_gone(ctx, peek, names));
        }
        return match opened {
            Ok(session) => {
                turn.session_opened();
                Ok(Some(session))
            }
            Err(reply) => {
                let reply = hint_reconnect(reply, harness.kind);
                // The person's no, or a wrong password, is every waiter's of
                // this process; the others take their own turn.
                turn.refused(Some(key), &reply);
                Err(reply)
            }
        };
    }
}

/// The end of a launch whose client went away: the journal says so (never
/// "started").
fn client_gone(ctx: &Ctx<'_>, peek: &Peek, names: &[String]) -> ClientReply {
    ctx.journal(Entry::new("run").vault(&peek.vault_id).names(names).result(
        "cancelled",
        Some("the client went away before the command started; nothing was run"),
    ));
    cancelled()
}

/// Add to a "no" or a failure the line the harness shows the person.
fn hint_reconnect(reply: ClientReply, kind: &str) -> ClientReply {
    let tail = format!(
        " The connectors were not unlocked and the server did not start: {} to be asked for \
         the connectors password again.",
        reconnect_hint(kind)
    );
    match reply {
        ClientReply::Cancelled { message } => ClientReply::Cancelled {
            message: format!("{message}.{tail}"),
        },
        ClientReply::Error { message } => ClientReply::Error {
            message: format!("{message}.{tail}"),
        },
        ClientReply::Refused(mut r) => {
            r.message = format!("{}.{tail}", r.message);
            ClientReply::Refused(r)
        }
        other => other,
    }
}

/// The window and the session: the connectors password, and a session anchored
/// to `harness` that covers the connectors bound to its kind.
fn open_session(
    ctx: &Ctx<'_>,
    project: &Project,
    vault_path: &Path,
    peek: &Peek,
    harness: &Harness,
) -> Flow<Found> {
    let names: Vec<String> = {
        let mut names: Vec<String> = peek
            .entries
            .iter()
            .filter(|e| e.tier == Tier::Session)
            .filter(|e| {
                peek.bindings.iter().any(|b| {
                    b.name == e.name
                        && !b.allow.is_empty()
                        && b.harnesses.iter().any(|h| h == harness.kind)
                })
            })
            .map(|e| e.name.clone())
            .collect();
        names.sort();
        names
    };
    let who = format!(
        "{} (pid {})",
        crate::notify::harness_title(harness.kind),
        harness.id.pid
    );
    let title = "Unlock MCP servers";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(project, vault_path);
    lines.push(format!("{who} wants its MCP servers: {}", names.join(", ")));
    lines.push(format!(
        "Lasts: until {who} exits, or `vahta lock --all`. Another process asks for itself."
    ));
    lines.push(
        "Allows: the servers of these connectors to be started by that process with no window, \
         each by its own command. Not revealing, copying or changing anything."
            .to_string(),
    );
    lines.push("Enter the connectors password to allow it, or cancel.".to_string());
    let panel = ctx.panel(title, lines);
    let action = Action::Unlock {
        names: names.clone(),
        duration_secs: None,
    };
    let mut vault = crate::ops::unlock_as(ctx, window.as_mut(), vault_path, &panel, action)?;
    if vault.upgrade_pending() {
        vault.save(vault_path, ctx.store()).map_err(from_vault)?;
    }
    let keys = vault.session_keys(&names).map_err(from_vault)?;
    let held: Vec<(String, vahta_vault::SecretValue)> = names
        .iter()
        .filter_map(|n| vault.get(n).ok().map(|v| (n.clone(), v)))
        .collect();
    let forms = EncodedSet::build(held.iter().map(|(n, v)| (n.as_str(), v.expose())));
    drop(held);
    let _ = forms.find(b"");
    let vault_id = vault.vault_id();
    drop(vault);

    let id = session::new_id().ok_or_else(|| error("the system random generator failed"))?;
    let session = Session {
        id: id.clone(),
        tenant: "local",
        vault_id,
        vault_path: vault_path.to_path_buf(),
        project: project.root.clone(),
        used_from: None,
        scope: names.clone(),
        keys,
        forms,
        role: Role::Runner,
        agent_role: None,
        anchor: harness.id,
        anchor_exe: harness.kind.to_string(),
        parent: None,
        deadline: None,
        length: None,
        ask_at: None,
        extension_pending: false,
        label: None,
        uses: 0,
        connector: true,
    };
    let replaced = {
        let mut sessions = ctx
            .shared
            .sessions
            .lock()
            .map_err(|_| error("the session table is unusable"))?;
        // A session of this process that no longer covers all (a connector was
        // added since) is replaced by the new one.
        let replaced = sessions.end_where(
            |s| {
                s.connector
                    && s.parent.is_none()
                    && s.vault_id == vault_id
                    && s.anchor == harness.id
            },
            "replaced",
        );
        sessions.add(session);
        replaced
    };
    ctx.shared.record_ended(replaced);
    ctx.shared.alarm.clear_raised();
    ctx.journal(
        Entry::new("session_start")
            .session(&id, None)
            .vault(&vault_id)
            .names(&names)
            .result(
                "ok",
                Some(&format!(
                    "connectors; {} pid {}; until that process exits",
                    harness.kind, harness.id.pid
                )),
            ),
    );
    window.close(Some("MCP servers unlocked. This window can be closed."));
    Ok((id, names, false))
}

// --- run -----------------------------------------------------------------------------

fn run(
    ctx: &Ctx<'_>,
    cwd: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    name: String,
    renames: Vec<(String, String)>,
    label: Option<String>,
) -> Flow<Prepared> {
    check_name(&name)?;
    let result = crate::run_ops::prepare(
        ctx,
        RunArgs {
            cwd,
            argv,
            env,
            names: Some(vec![name.clone()]),
            renames,
            label,
            ask: false,
            reason: None,
            vault: None,
        },
    );
    match result {
        Err(ClientReply::Refused(mut r)) => {
            let hint = hint_for(r.kind, &name);
            ctx.shared.note_refusal(&name, r.kind, &hint);
            if r.kind == RefusalKind::Stale {
                // The vault changed under the session: it is of no use again.
                // End this process's, so the next start asks for the password.
                end_stale(ctx);
            }
            // The harness that started this reads none of it; the person may
            // run the server by hand to see why.
            r.message = match r.kind {
                // The advice of those two is for an agent (`--ask`, `bind`
                // with a category); a harness's launch has no one to take it.
                RefusalKind::CommandNotAllowed => {
                    let why = r.message.split("Nothing was run.").next().unwrap_or("");
                    format!("connector {name}: {hint}. {why}Nothing was run.")
                }
                RefusalKind::NoRules => format!("connector {name}: {hint}. Nothing was run."),
                _ => format!("connector {name}: {hint}. {}", r.message),
            };
            Err(ClientReply::Refused(r))
        }
        other => other,
    }
}

/// Tell the person a connector's launch was refused by its rules (a command
/// that is not the server it allows), and, when the refusals have added up to
/// the injection alarm's threshold, that too.
pub(crate) fn notify_refused(
    ctx: &Ctx<'_>,
    peek: &Peek,
    names: &[String],
    argv: &[String],
    raised: bool,
) {
    let words: Vec<&str> = argv.iter().take(4).map(String::as_str).collect();
    let shown: String = crate::run_ops::sanitize_for_message(&words.join(" "))
        .chars()
        .take(80)
        .collect();
    ctx.shared.notify_suspicious(
        &peek.vault_id,
        crate::notify::Kind::CommandNotAllowed,
        names,
        &shown,
    );
    if raised {
        burst(ctx, peek, names);
    }
}

fn burst(ctx: &Ctx<'_>, peek: &Peek, names: &[String]) {
    ctx.shared
        .notify_suspicious(&peek.vault_id, crate::notify::Kind::RefusalBurst, names, "");
}

/// End the connectors session of the harness process that started this client.
fn end_stale(ctx: &Ctx<'_>) {
    let Some(parent) = parent_facts(ctx) else {
        return;
    };
    let ended = match ctx.shared.sessions.lock() {
        Ok(mut sessions) => sessions.end_where(|s| s.connector && s.anchor == parent.id, "stale"),
        Err(_) => return,
    };
    ctx.shared.record_ended(ended);
}

/// What the person does about a refused launch.
fn hint_for(kind: RefusalKind, name: &str) -> String {
    match kind {
        RefusalKind::NotFromHarness => {
            "not started by a harness it is bound to (the harness must start `vahta run` \
             itself, not through a shell or a script)"
                .to_string()
        }
        RefusalKind::NoRules => format!(
            "it has no harnesses or no allow rule: run `vahta bind --connector {name} --harness \
             claude --allow 'COMMAND ARGS'`"
        ),
        RefusalKind::CommandNotAllowed => {
            "the command is outside its allow rules: compare the harness config with \
             `vahta list --connector`"
                .to_string()
        }
        RefusalKind::NoVault => {
            "there is no connectors vault: run `vahta init --connector`".to_string()
        }
        RefusalKind::UnknownName => {
            "there is no such connector: see `vahta list --connector`".to_string()
        }
        RefusalKind::Stale => {
            "the connectors vault changed since this harness process unlocked it: reconnect the \
             server in the harness and enter the connectors password again"
                .to_string()
        }
        _ => "refused".to_string(),
    }
}

impl crate::server::Shared {
    /// Remember a refused launch for `vahta status`: the newest per secret.
    pub(crate) fn note_refusal(&self, name: &str, kind: RefusalKind, hint: &str) {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Ok(mut list) = self.connector_refusals.lock() {
            list.retain(|r| r.name != name);
            list.push(ConnectorRefusal {
                name: name.to_string(),
                at,
                kind,
                hint: hint.to_string(),
            });
            let extra = list.len().saturating_sub(KEPT_REFUSALS);
            list.drain(..extra);
        }
    }

    pub(crate) fn connector_refusals(&self) -> Vec<ConnectorRefusal> {
        self.connector_refusals
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
    }
}

/// Secrets of `names` that cannot be launched: no approved rules, or rules
/// without a harness or without an allow rule.
pub(crate) fn unruled(peek: &Peek, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| {
            !peek
                .bindings
                .iter()
                .any(|b| &b.name == *n && !b.harnesses.is_empty() && !b.allow.is_empty())
        })
        .cloned()
        .collect()
}

/// A connector's server is started by the harness it is bound to: the direct
/// parent of the `vahta run` client. Refused otherwise, as `NotFromHarness`,
/// journaled as suspicious and counted for the injection alarm like a refusal
/// by the rules. Gives the harness process, which a session is anchored to.
pub(crate) fn check_harness(ctx: &Ctx<'_>, peek: &Peek, names: &[String]) -> Flow<Option<Harness>> {
    let parent = parent_facts(ctx);
    for n in names {
        let Some(binding) = peek.bindings.iter().find(|b| &b.name == n) else {
            continue; // No rules: refused as such next.
        };
        if binding.harnesses.is_empty() {
            continue;
        }
        if parent_is_harness(
            parent.as_ref().map(|p| p.exe.as_str()),
            parent.as_ref().and_then(|p| p.command.as_deref()),
            &binding.harnesses,
        ) {
            continue;
        }
        let shown = parent
            .as_ref()
            .map_or("an unreadable process".to_string(), |p| p.exe.clone());
        ctx.journal(
            Entry::new("run_refused")
                .vault(&peek.vault_id)
                .names(std::slice::from_ref(n))
                .result(
                    "refused",
                    Some(&format!(
                        "suspicious: not_from_harness; the connector is bound to {} but \
                         `vahta run --connector` was started by {}",
                        binding.harnesses.join(", "),
                        crate::run_ops::sanitize_for_message(&shown)
                    )),
                ),
        );
        let raised = crate::report::rule_refusal(ctx, std::slice::from_ref(n), None, false);
        ctx.shared.notify_suspicious(
            &peek.vault_id,
            crate::notify::Kind::NotFromHarness,
            std::slice::from_ref(n),
            &binding.harnesses.join(","),
        );
        if raised {
            burst(ctx, peek, std::slice::from_ref(n));
        }
        return Err(refused_names(
            RefusalKind::NotFromHarness,
            format!(
                "{n} is bound to {} and is started by that harness itself; this was not. Nothing \
                 was run.",
                binding.harnesses.join(", ")
            ),
            vec![NameIssue {
                name: n.clone(),
                why: RefusalKind::NotFromHarness,
            }],
        ));
    }
    // The harness kind this launch is of: one the parent is, and the secrets
    // are all bound to.
    Ok(parent.and_then(|p| {
        let kind = ["claude", "codex", "cursor"].into_iter().find(|h| {
            parent_is_harness(Some(&p.exe), p.command.as_deref(), &[h.to_string()])
                && names.iter().all(|n| {
                    peek.bindings
                        .iter()
                        .any(|b| &b.name == n && b.harnesses.iter().any(|x| x == h))
                })
        })?;
        Some(Harness { id: p.id, kind })
    }))
}

/// What is known of the process that started the `vahta run` client.
struct Parent {
    id: ProcessId,
    exe: String,
    command: Option<String>,
}

fn parent_facts(ctx: &Ctx<'_>) -> Option<Parent> {
    // The client's identity must still be the one that connected.
    if vahta_os::identity_of(ctx.pid).ok()? != ctx.peer {
        return None;
    }
    let ppid = vahta_os::parent_of(ctx.pid).ok()?;
    if ppid < vahta_os::MIN_PID || !vahta_os::owned_by_me(ppid) {
        return None;
    }
    let exe = vahta_os::exe_name(ppid)?;
    // The parent may have exited and its pid been reused since the exe was
    // read; the client's parent is checked again after.
    let command = vahta_os::command_line(ppid);
    let id = vahta_os::identity_of(ppid).ok()?;
    (vahta_os::parent_of(ctx.pid).ok()? == ppid).then_some(Parent { id, exe, command })
}

/// Whether a parent process with executable `exe` (and, where the system
/// gives it, command line `command`) is one of `harnesses`:
///
/// * `claude`: `claude`, or `node`/`bun` running something with `claude` in its
///   command line (an npm install of Claude Code);
/// * `codex`: `codex`;
/// * `cursor`: `cursor`, `cursor-agent`, `Cursor`.
///
/// Names are compared in lower case without `.exe`. Where the command line
/// cannot be read (macOS and Windows, see `vahta_os::command_line`) a `node` or
/// `bun` parent cannot be told, and counts as a Claude Code parent: the check is
/// a speed bump there, and the allow rule and the hook are the boundary. On
/// Linux an unreadable command line does not match. An unreadable parent never
/// matches.
pub(crate) fn parent_is_harness(
    exe: Option<&str>,
    command: Option<&str>,
    harnesses: &[String],
) -> bool {
    let Some(exe) = exe else { return false };
    let lower = exe.to_ascii_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    if crate::testing::connector_parent_alias().is_some_and(|alias| alias == exe) {
        return true;
    }
    harnesses.iter().any(|h| match h.as_str() {
        "claude" => {
            base == "claude"
                || (matches!(base, "node" | "bun")
                    && match command {
                        Some(c) => c.to_ascii_lowercase().contains("claude"),
                        None => !cfg!(target_os = "linux"),
                    })
        }
        "codex" => base == "codex",
        "cursor" => matches!(base, "cursor" | "cursor-agent"),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::parent_is_harness;

    fn h(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_parent_must_be_a_harness_the_secret_is_bound_to() {
        let claude = h(&["claude"]);
        assert!(parent_is_harness(Some("claude"), None, &claude));
        assert!(parent_is_harness(Some("Claude.exe"), None, &claude));
        assert!(!parent_is_harness(Some("bash"), None, &claude));
        assert!(!parent_is_harness(Some("codex"), None, &claude));
        assert!(parent_is_harness(
            Some("codex"),
            None,
            &h(&["claude", "codex"])
        ));
        for exe in ["cursor", "Cursor", "cursor-agent"] {
            assert!(parent_is_harness(Some(exe), None, &h(&["cursor"])), "{exe}");
        }
        assert!(!parent_is_harness(None, None, &claude));
        assert!(!parent_is_harness(Some("claude"), None, &[]));
    }

    #[test]
    fn node_counts_for_claude_only_when_its_command_line_says_so() {
        let claude = h(&["claude"]);
        assert!(parent_is_harness(
            Some("node"),
            Some("node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"),
            &claude
        ));
        assert!(parent_is_harness(
            Some("bun"),
            Some("bun /home/u/.bun/bin/claude"),
            &claude
        ));
        assert!(!parent_is_harness(
            Some("node"),
            Some("node server.js"),
            &claude
        ));
        assert!(!parent_is_harness(
            Some("node"),
            Some("node /x/claude-code/cli.js"),
            &h(&["codex"])
        ));
    }
}
