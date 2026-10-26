//! The hook watchdog's side of the daemon: `vahta hooks pause` and `resume`,
//! the window that opens when the watchdog finds Vahta's hooks tampered with,
//! and starting the watchdog (`vahta _guard`) when the person has agreed.
//!
//! The watchdog itself is a separate process (it outlives the daemon and holds
//! no vault key), so the password checks and the windows live here, where the
//! vaults and the prompt surface are. It asks; the daemon answers with the
//! person's choice; the watchdog acts on the files.
//!
//! A password here is a vault's, and the window says whose. The candidates are
//! the vault of the caller's project first, then every other vault the daemon
//! has seen whose file still exists (at most [`MAX_VAULTS`]). With more than
//! one, the person picks the vault in the window and types its password:
//! trying a typed password against each candidate would cost one Argon2id
//! (1 GiB, four passes: seconds) per vault per try. With no vault known there
//! is no password to ask, and nothing here can be approved: the person uses
//! their own terminal.
//!
//! `vahta hooks pause` does not turn Vahta off. It lets the agent change the
//! hook settings of a harness for a while (the hook's guard and the watchdog
//! step aside for that harness); every other check keeps running.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vahta_harness::Manifest;
use vahta_ipc::config::{Config, Guard};
use vahta_ipc::duration::human;
use vahta_ipc::protocol::{ClientReply, GuardChoice, GuardEvent, Panel, RefusalKind, Signal};
use vahta_setup::guard::{self, MAX_PAUSE_SECS, Pause, PauseKind};
use vahta_vault::project::Project;

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, cancelled, error, from_surface, refused, unlock_as};
use crate::server::Shared;
use crate::surface::{Window, sanitize_label};
use vahta_auth::{Action, AuthError};

/// How long the person has to answer the watchdog's question before the hooks
/// are put back on their own.
pub const ASK_WAIT: Duration = Duration::from_secs(120);

/// How long "Keep off" keeps them off.
pub const KEEP_OFF_SECS: u64 = 3600;

fn now() -> u64 {
    vahta_ipc::state::now()
}

fn manifests() -> Vec<Manifest> {
    vahta_harness::HARNESSES
        .iter()
        .filter_map(|h| vahta_harness::manifest(h).and_then(Result::ok))
        .collect()
}

/// The setup environment of this daemon: the home it runs in and the
/// `vahta-hook` next to its executable.
pub(crate) fn setup_env(shared: &Shared) -> Option<vahta_setup::Env> {
    let home = match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h),
        #[allow(deprecated)]
        _ => std::env::home_dir()?,
    };
    let exe = match shared.options.exe.clone() {
        Some(e) => e,
        None => std::env::current_exe().ok()?,
    };
    let hook = exe
        .parent()?
        .join(format!("vahta-hook{}", std::env::consts::EXE_SUFFIX));
    Some(vahta_setup::Env::from_process(home, hook))
}

/// Remember a project root for the watchdog.
pub(crate) fn note_project(ctx: &Ctx<'_>, root: &Path) {
    guard::note_project(&ctx.shared.options.paths.data, root);
}

/// The most vaults offered in the approval window; the rest are not asked.
pub(crate) const MAX_VAULTS: usize = 8;

/// The vaults whose password can approve: the caller's project first (when it
/// has one), then the projects seen before, whose vault file must exist. The
/// bool says whether the first is the caller's own.
fn approving_vaults(shared: &Shared, cwd: Option<&str>) -> (Vec<PathBuf>, bool) {
    let own = cwd
        .and_then(|c| Project::find(Path::new(c)))
        .map(|p| p.vault_path())
        .filter(|v| v.is_file());
    let has_own = own.is_some();
    let mut out: Vec<PathBuf> = own.into_iter().collect();
    for root in guard::read_projects(&shared.options.paths.data) {
        let v = Project { root }.vault_path();
        if v.is_file() && !out.contains(&v) {
            out.push(v);
        }
    }
    out.truncate(MAX_VAULTS);
    (out, has_own)
}

/// A path as the person reads it: the home directory is `~`.
fn tilde(path: &Path) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match home.as_deref().filter(|h| !h.as_os_str().is_empty()) {
        Some(h) => match path.strip_prefix(h) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        },
        None => path.display().to_string(),
    }
}

/// The project a vault file belongs to, as shown.
fn vault_label(vault: &Path) -> String {
    clean(&tilde(
        vault.parent().and_then(Path::parent).unwrap_or(vault),
    ))
}

/// Ask for the password of an approving vault in `window`, after saying
/// whose it is. There is no plain yes: with no vault known nothing can
/// approve, and the answer is a refusal that points the person to their own
/// terminal. `Ok(true)` is approval.
fn approve(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    panel: &Panel,
    cwd: Option<&str>,
    action: Action,
) -> Flow<bool> {
    let (vaults, has_own) = approving_vaults(ctx.shared, cwd);
    let labels: Vec<String> = vaults.iter().map(|v| vault_label(v)).collect();
    let picked = match vaults.len() {
        0 => return Err(no_vault()),
        1 => 0,
        _ => {
            // Which password is for the person to say; guessing would cost a
            // key derivation per vault.
            let options: Vec<String> = labels
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    if has_own && i == 0 {
                        format!("{l} (this project)")
                    } else {
                        l.clone()
                    }
                })
                .collect();
            let mut shown = panel.clone();
            shown
                .lines
                .push("Approving takes the password of one of your vaults.".to_string());
            let asked = window.choose_within(
                &shown,
                "Whose vault password will you type?",
                &options,
                ASK_WAIT,
            );
            match asked {
                Ok(Some(i)) if i < vaults.len() => i,
                Ok(_) => return Err(cancelled()),
                Err(e) => return Err(from_surface(e)),
            }
        }
    };
    let which = &labels[picked];
    let mut shown = panel.clone();
    shown
        .lines
        .push(format!("Type the password of the vault of {which}."));
    // The password only approves; the vault is not changed.
    match unlock_as(ctx, window, &vaults[picked], &shown, action) {
        Ok(opened) => {
            drop(opened);
            Ok(true)
        }
        // Not "your password is wrong": it may be the wrong vault.
        Err(ClientReply::Error { message }) if message == AuthError::TooManyTries.to_string() => {
            let others: Vec<&str> = labels
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != picked)
                .map(|(_, l)| l.as_str())
                .collect();
            let mut text = format!(
                "that was not the password of the vault of {which} (three tries); nothing was \
                 changed"
            );
            if !others.is_empty() {
                text.push_str(&format!(
                    ". Other vaults that could approve: {}",
                    others.join(", ")
                ));
            }
            Err(error(text))
        }
        Err(other) => Err(other),
    }
}

/// The guard's questions are put to the password, as they always were.
fn guard_action() -> Action {
    Action::Other {
        what: "hook guard".to_string(),
    }
}

fn no_vault() -> ClientReply {
    refused(
        RefusalKind::NoVault,
        "no vault is known on this machine, so there is no password to approve this; nothing \
         was changed. To turn Vahta's hooks off, the person runs `vahta setup --uninstall` or \
         `vahta setup --guard off` in their own terminal",
    )
}

fn clean(raw: &str) -> String {
    sanitize_label(raw).unwrap_or_default()
}

fn titles(ms: &[Manifest], names: &[String]) -> String {
    names
        .iter()
        .map(|n| {
            ms.iter()
                .find(|m| &m.name == n)
                .map_or(n.clone(), |m| m.title.clone())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// --- hooks pause / resume ----------------------------------------------------------------------------

pub(crate) fn hooks_pause(
    ctx: &Ctx<'_>,
    cwd: &str,
    harnesses: &[String],
    secs: u64,
    reason: Option<String>,
) -> Flow<ClientReply> {
    if secs == 0 || secs > MAX_PAUSE_SECS {
        return Err(refused(
            RefusalKind::NothingToDo,
            format!(
                "a pause lasts from 1 second to {} (asked for {}); nothing was changed",
                human(MAX_PAUSE_SECS),
                human(secs)
            ),
        ));
    }
    let Some(env) = setup_env(ctx.shared) else {
        return Err(error(
            "cannot tell where the harness configs are (no home directory)",
        ));
    };
    let ms = manifests();
    let mut chosen: Vec<&Manifest> = Vec::new();
    for name in harnesses {
        match ms.iter().find(|m| &m.name == name) {
            Some(m) => chosen.push(m),
            None => {
                return Err(refused(
                    RefusalKind::NothingToDo,
                    format!("{} is not a harness Vahta knows", clean(name)),
                ));
            }
        }
    }
    if harnesses.is_empty() {
        chosen = ms.iter().collect();
    }
    let chosen: Vec<&Manifest> = chosen
        .into_iter()
        .filter(|m| guard::has_entries(m, &env))
        .collect();
    if chosen.is_empty() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "Vahta's hooks are not set up in any of those harnesses; there is nothing to pause",
        ));
    }
    let names: Vec<String> = chosen.iter().map(|m| m.name.clone()).collect();
    let shown = titles(&ms, &names);
    let title = "Let the agent change Vahta's hook settings";
    let mut panel = ctx.panel(
        title,
        vec![
            format!(
                "The agent may change Vahta's hook settings in {shown} for {}. Vahta keeps \
                 watching everything else: secrets, files it protects, and the alarm.",
                human(secs)
            ),
            "When the time is up Vahta looks at the settings again and asks you about \
             anything that turned its hooks off."
                .to_string(),
        ],
    );
    panel.agent_note = reason.as_deref().and_then(sanitize_label);
    let record = |result: &str, why: &str| {
        ctx.journal(
            Entry::new("hooks_paused")
                .names(&names)
                .result(result, Some(why)),
        );
    };
    if approving_vaults(ctx.shared, Some(cwd)).0.is_empty() {
        record("refused", "no vault, so no password to approve it");
        return Err(no_vault());
    }
    let mut window = ctx.window(title)?;
    let approved = approve(
        ctx,
        window.as_mut(),
        &panel,
        Some(cwd),
        Action::HooksPause { secs },
    );
    match approved {
        Ok(true) => {}
        Ok(false) => {
            record("declined", "the person said no");
            window.close(None);
            return Err(ClientReply::Cancelled {
                message: "the person did not agree; the hook settings stay guarded".to_string(),
            });
        }
        Err(reply) => {
            record("not_approved", "no approval was given");
            window.close(None);
            return Err(reply);
        }
    }
    // The hooks stay where they are; the pause only tells the hook's guard and
    // the watchdog to step aside for these harnesses until `until`. A pause of
    // an older version (the hooks taken out) is kept: it still puts them back.
    let until = now() + secs;
    let said = reason
        .as_deref()
        .and_then(sanitize_label)
        .unwrap_or_default();
    let mut pauses = guard::read_pauses(&ctx.shared.options.paths.data);
    pauses.retain(|p| !(names.contains(&p.harness) && p.kind == PauseKind::Edit));
    for n in &names {
        pauses.push(Pause {
            harness: n.clone(),
            until,
            reason: said.clone(),
            kind: PauseKind::Edit,
        });
    }
    if let Err(e) = guard::write_pauses(&ctx.shared.options.paths.data, &pauses) {
        record("failed", &format!("cannot write the pause: {e}"));
        window.close(None);
        return Err(error(format!(
            "cannot write the pause: {e}; nothing was changed"
        )));
    }
    let why = if said.is_empty() {
        format!("{shown} for {}, hook settings may be changed", human(secs))
    } else {
        format!(
            "{shown} for {}, hook settings may be changed; the agent's reason: {said}",
            human(secs)
        )
    };
    record("ok", &why);
    window.close(Some(&format!(
        "Hook settings may change for {}.",
        human(secs)
    )));
    Ok(ClientReply::Done {
        message: format!(
            "You may now change the hook settings of {shown} for {}. Vahta's hooks stay on and \
             keep watching everything else; this does not turn anything off. When the time is up \
             the settings are checked again, and the person is asked about anything that turned \
             the hooks off.",
            human(secs)
        ),
    })
}

pub(crate) fn hooks_resume(ctx: &Ctx<'_>, harnesses: &[String]) -> Flow<ClientReply> {
    let Some(env) = setup_env(ctx.shared) else {
        return Err(error(
            "cannot tell where the harness configs are (no home directory)",
        ));
    };
    let data = &ctx.shared.options.paths.data;
    let ms = manifests();
    let pauses = guard::read_pauses(data);
    let names: Vec<String> = if harnesses.is_empty() {
        pauses.iter().map(|p| p.harness.clone()).collect()
    } else {
        harnesses.to_vec()
    };
    if names.is_empty() {
        return Ok(ClientReply::Done {
            message: "nothing is paused".to_string(),
        });
    }
    let mut back = Vec::new();
    let mut problems = Vec::new();
    for name in &names {
        let Some(m) = ms.iter().find(|m| &m.name == name) else {
            problems.push(format!("{} is not a harness Vahta knows", clean(name)));
            continue;
        };
        match guard::add_entries(m, &env) {
            Ok(_) => back.push(name.clone()),
            Err(e) => problems.push(format!("{}: {e}", m.title)),
        }
    }
    let rest: Vec<Pause> = pauses
        .into_iter()
        .filter(|p| !back.contains(&p.harness))
        .collect();
    let _ = guard::write_pauses(data, &rest);
    let shown = titles(&ms, &back);
    if problems.is_empty() {
        ctx.journal(
            Entry::new("hooks_resumed")
                .names(&back)
                .result("ok", Some(&shown)),
        );
        Ok(ClientReply::Done {
            message: format!("the pause is over in {shown}; Vahta's hooks are in place"),
        })
    } else {
        ctx.journal(
            Entry::new("hooks_resumed")
                .names(&back)
                .result("partial", Some(&problems.join("; "))),
        );
        Err(error(format!(
            "some hooks could not be put back: {}",
            problems.join("; ")
        )))
    }
}

// --- the watchdog asks ----------------------------------------------------------------------------

pub(crate) fn guard_ask(
    shared: &Arc<Shared>,
    ctx: &Ctx<'_>,
    harness: &str,
    file: &str,
    what: &str,
) -> Flow<ClientReply> {
    let (h, f, w) = (clean(harness), clean(file), clean(what));
    ctx.journal(Entry::new("hook_tamper").result("found", Some(&format!("{h}: {w} ({f})"))));
    // The alarm hears of it like any other report from a hook.
    let _ = crate::report::hook_report(
        shared,
        ctx,
        None,
        &h,
        &Signal::HookTamper {
            file: f.clone(),
            what: w.clone(),
        },
    );
    let restore = ClientReply::GuardChoice {
        choice: GuardChoice::Restore,
    };
    let title = "Vahta's hooks were changed";
    let Ok(mut window) = ctx.shared.surface.open(title) else {
        ctx.journal(
            Entry::new("hook_tamper").result("not_asked", Some("no window could be opened")),
        );
        return Ok(restore);
    };
    let can_approve = !approving_vaults(ctx.shared, None).0.is_empty();
    let mut panel = Panel {
        title: title.to_string(),
        lines: vec![
            format!("{w}: {f}"),
            "Was it an agent or a tool? Vahta cannot tell.".to_string(),
            "While the hooks are off, Vahta does not see what agents do.".to_string(),
            format!(
                "With no answer in {}, Vahta puts them back.",
                human(ASK_WAIT.as_secs())
            ),
        ],
        warning: None,
        agent_note: None,
    };
    // Only a password can keep them off. With no vault known, there is
    // nothing to ask for one with, so the only choice is to restore.
    let mut options = vec!["Restore".to_string()];
    if can_approve {
        options.push(format!("Keep off for {} (password)", human(KEEP_OFF_SECS)));
        options.push("Turn off protection (password)".to_string());
    } else {
        panel.lines.push(
            "To keep them off, run `vahta setup --guard off` in your own terminal.".to_string(),
        );
    }
    let choice = window.choose_within(&panel, "What should Vahta do?", &options, ASK_WAIT);
    let reply = match choice {
        Ok(Some(1)) => match approve(ctx, window.as_mut(), &panel, None, guard_action()) {
            Ok(true) => {
                let mut pauses = guard::read_pauses(&ctx.shared.options.paths.data);
                pauses.retain(|p| p.harness != h);
                pauses.push(Pause {
                    harness: h.clone(),
                    until: now() + KEEP_OFF_SECS,
                    reason: format!("kept off after a change to {f}"),
                    kind: PauseKind::Off,
                });
                let _ = guard::write_pauses(&ctx.shared.options.paths.data, &pauses);
                ctx.journal(Entry::new("hook_tamper_kept").result(
                    "kept_off",
                    Some(&format!("{h} for {}", human(KEEP_OFF_SECS))),
                ));
                GuardChoice::KeepOff {
                    secs: KEEP_OFF_SECS,
                }
            }
            _ => {
                ctx.journal(Entry::new("hook_tamper").result("not_approved", Some("restoring")));
                GuardChoice::Restore
            }
        },
        Ok(Some(2)) => match approve(ctx, window.as_mut(), &panel, None, guard_action()) {
            Ok(true) => {
                let cfg = ctx.shared.options.paths.config_file();
                let _ = vahta_ipc::config::set_guard(&cfg, Guard::Off);
                ctx.journal(
                    Entry::new("hook_tamper_kept")
                        .result("protection_off", Some("the person turned the watchdog off")),
                );
                GuardChoice::TurnOff
            }
            _ => {
                ctx.journal(Entry::new("hook_tamper").result("not_approved", Some("restoring")));
                GuardChoice::Restore
            }
        },
        Ok(Some(_)) => GuardChoice::Restore,
        _ => {
            ctx.journal(Entry::new("hook_tamper").result("no_answer", Some("restoring")));
            GuardChoice::Restore
        }
    };
    window.close(None);
    Ok(ClientReply::GuardChoice { choice: reply })
}

pub(crate) fn guard_note(
    ctx: &Ctx<'_>,
    harness: &str,
    file: &str,
    event: GuardEvent,
) -> ClientReply {
    let why = format!("{}: {}", clean(harness), clean(file));
    let (name, result) = match event {
        GuardEvent::Restored => ("hook_restored", "ok"),
        GuardEvent::RestoredAfterPause => ("hooks_restored", "ok"),
        GuardEvent::RestoreFailed => ("hook_restored", "failed"),
        GuardEvent::TurnedOff => ("guard_off", "ok"),
        GuardEvent::Unasked => ("hook_restored", "unasked"),
    };
    ctx.journal(Entry::new(name).result(result, Some(&why)));
    ClientReply::Ok {}
}

// --- starting the watchdog ----------------------------------------------------------------------------

/// Whether the person has agreed to the watchdog (`guard = "on"`), read from
/// the file each time, since `vahta setup` may have changed it since the
/// daemon started.
fn consent(shared: &Shared) -> bool {
    Config::load(&shared.options.paths.config_file())
        .map(|c| c.guard == Some(Guard::On))
        .unwrap_or(false)
}

/// Start the watchdog detached if the person agreed and none is running.
pub(crate) fn ensure_guard(shared: &Shared) {
    if !consent(shared) || shared.options.paths.guard_running() {
        return;
    }
    let exe = match shared.options.exe.clone() {
        Some(e) => e,
        None => match std::env::current_exe() {
            Ok(e) => e,
            Err(_) => return,
        },
    };
    let p = &shared.options.paths;
    let started = vahta_os::spawn_detached(
        std::process::Command::new(exe)
            .arg("_guard")
            .env("VAHTA_RUNTIME_DIR", &p.runtime)
            .env("VAHTA_DATA_DIR", &p.data)
            .env("VAHTA_CONFIG_DIR", &p.config),
    );
    shared.journal.record(match started {
        Ok(()) => Entry::new("guard_start").result("ok", None),
        Err(e) => Entry::new("guard_start").result("failed", Some(&e.to_string())),
    });
}

/// At startup, and then every half minute: the watchdog is running if the
/// person agreed to it, and an expired pause is ended when it is not (the
/// watchdog does that itself when it runs).
pub(crate) fn keep_guard(shared: &Arc<Shared>) {
    ensure_guard(shared);
    let mut ticks = 0u32;
    while !shared.stopping() {
        std::thread::sleep(Duration::from_millis(250));
        ticks += 1;
        if ticks.is_multiple_of(120) {
            ensure_guard(shared);
            end_expired_pauses(shared);
        }
    }
}

/// Put back the hooks of pauses that have run out, when no watchdog will.
fn end_expired_pauses(shared: &Shared) {
    if consent(shared) {
        return;
    }
    let data = &shared.options.paths.data;
    let pauses = guard::read_pauses(data);
    let (done, rest): (Vec<Pause>, Vec<Pause>) = pauses.into_iter().partition(|p| p.until <= now());
    if done.is_empty() {
        return;
    }
    let Some(env) = setup_env(shared) else { return };
    let ms = manifests();
    // An edit pause took nothing out; only the older kind has hooks to put back.
    for p in done.iter().filter(|p| p.kind == PauseKind::Off) {
        if let Some(m) = ms.iter().find(|m| m.name == p.harness) {
            let result = guard::add_entries(m, &env);
            shared.journal.record(match result {
                Ok(_) => Entry::new("hooks_restored").result("ok", Some(&p.harness)),
                Err(e) => Entry::new("hooks_restored")
                    .result("failed", Some(&format!("{}: {e}", p.harness))),
            });
        }
    }
    let _ = guard::write_pauses(data, &rest);
}

/// Whether a pause is running: the daemon stays up for it when no watchdog
/// would put the hooks back.
pub(crate) fn pause_pending(shared: &Shared) -> bool {
    !consent(shared)
        && guard::read_pauses(&shared.options.paths.data)
            .iter()
            .any(|p| p.kind == PauseKind::Off && p.until > now())
}
